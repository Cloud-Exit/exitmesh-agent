package protocol

import "fmt"

type resFold struct {
	absentBefore bool
	deleted      bool
	reason       DeleteReason
	kind, ns     string
	name         string
	fields       map[string]any
}

type edgeFold struct {
	before, now           bool
	beforeAttrs, nowAttrs map[string]any
}

// Fold coalesces a contiguous run of delta, range, and finding records into one range body (SPEC 5).
func Fold(records []*Record) (*Range, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: empty run", ErrFold)
	}
	first := records[0]
	g := &Range{From: first.Seq, To: records[len(records)-1].Seq}
	if first.Type == TypeRange {
		g.From = first.Range.From
	}
	res := map[string]*resFold{}
	edges := map[EdgeKey]*edgeFold{}
	scopes := map[string]ScopeStatus{}
	for i, r := range records {
		if i > 0 && r.Parent != records[i-1].Seq {
			return nil, fmt.Errorf("%w: record %d does not follow %d", ErrFold, r.Seq, records[i-1].Seq)
		}
		var ops []Op
		switch r.Type {
		case TypeDelta:
			ops = r.Delta.Ops
			g.Flags |= r.Delta.Flags
			if r.Delta.Uncertain != nil {
				g.Uncertain = append(g.Uncertain, *r.Delta.Uncertain)
			}
		case TypeRange:
			ops = r.Range.Ops
			g.Flags |= r.Range.Flags
			g.Uncertain = append(g.Uncertain, r.Range.Uncertain...)
			for _, f := range r.Range.Findings {
				g.Findings = append(g.Findings, RangeFinding{Seq: f.Seq, Finding: f.Finding.Clone()})
			}
		case TypeFinding:
			g.Findings = append(g.Findings, RangeFinding{Seq: r.Seq, Finding: r.Finding.Clone()})
		default:
			return nil, fmt.Errorf("%w: %s record %d cannot be coalesced", ErrFold, r.Type, r.Seq)
		}
		for j := range ops {
			if err := foldOp(&ops[j], res, edges, scopes); err != nil {
				return nil, fmt.Errorf("record %d: %w", r.Seq, err)
			}
		}
	}
	for uid, f := range res {
		switch {
		case f.absentBefore && f.deleted:
		case f.absentBefore:
			g.Ops = append(g.Ops, Create(uid, f.kind, f.ns, f.name, f.fields))
		case f.deleted:
			g.Ops = append(g.Ops, Delete(uid, f.reason))
		default:
			g.Ops = append(g.Ops, Update(uid, f.fields))
		}
	}
	for k, e := range edges {
		switch {
		case !e.before && !e.now:
		case !e.before:
			g.Ops = append(g.Ops, EdgeAdd(k.From, k.Type, k.To, e.nowAttrs))
		case !e.now:
			g.Ops = append(g.Ops, EdgeRemove(k.From, k.Type, k.To, e.beforeAttrs))
		case !ValueEqual(e.beforeAttrs, e.nowAttrs):
			g.Ops = append(g.Ops, EdgeReplace(k.From, k.Type, k.To, e.nowAttrs, e.beforeAttrs))
		}
	}
	for k, st := range scopes {
		g.Ops = append(g.Ops, ScopeSet(k, st))
	}
	SortOps(g.Ops)
	if err := g.validate(); err != nil {
		return nil, err
	}
	return g, nil
}

func foldOp(op *Op, res map[string]*resFold, edges map[EdgeKey]*edgeFold, scopes map[string]ScopeStatus) error {
	switch op.Kind {
	case OpCreate, OpUpdate, OpDelete:
		f, seen := res[op.UID]
		if !seen {
			f = &resFold{}
			res[op.UID] = f
			switch op.Kind {
			case OpCreate:
				f.absentBefore = true
				f.kind, f.ns, f.name = op.ResourceKind, op.Namespace, op.Name
				f.fields = CloneFields(op.Fields)
			case OpUpdate:
				f.fields = CloneFields(op.Fields)
			case OpDelete:
				f.deleted, f.reason = true, op.DeleteReason
			}
			return nil
		}
		if f.deleted {
			return fmt.Errorf("%w: %s after delete of uid %s", ErrFold, op.Kind, op.UID)
		}
		switch op.Kind {
		case OpCreate:
			return fmt.Errorf("%w: create of existing uid %s", ErrFold, op.UID)
		case OpUpdate:
			for k, v := range op.Fields {
				if f.absentBefore && v == nil {
					delete(f.fields, k)
				} else {
					f.fields[k] = CloneValue(v)
				}
			}
		case OpDelete:
			f.deleted, f.reason = true, op.DeleteReason
		}
	case OpEdgeAdd, OpEdgeRemove, OpEdgeReplace:
		k := op.EdgeKey()
		e, seen := edges[k]
		if !seen {
			e = &edgeFold{}
			edges[k] = e
			switch op.Kind {
			case OpEdgeAdd:
				e.now, e.nowAttrs = true, CloneFields(op.Attrs)
			case OpEdgeRemove:
				e.before, e.beforeAttrs = true, CloneFields(op.Attrs)
			case OpEdgeReplace:
				e.before, e.beforeAttrs = true, CloneFields(op.PrevAttrs)
				e.now, e.nowAttrs = true, CloneFields(op.Attrs)
			}
			return nil
		}
		switch op.Kind {
		case OpEdgeAdd:
			if e.now {
				return fmt.Errorf("%w: add of existing edge %v", ErrFold, k)
			}
			e.now, e.nowAttrs = true, CloneFields(op.Attrs)
		case OpEdgeRemove:
			if !e.now {
				return fmt.Errorf("%w: remove of absent edge %v", ErrFold, k)
			}
			e.now, e.nowAttrs = false, nil
		case OpEdgeReplace:
			if !e.now {
				return fmt.Errorf("%w: replace of absent edge %v", ErrFold, k)
			}
			e.nowAttrs = CloneFields(op.Attrs)
		}
	case OpScopeSet:
		scopes[op.ScopeKey] = op.Scope
	default:
		return fmt.Errorf("%w: op kind %d", ErrFold, uint64(op.Kind))
	}
	return nil
}
