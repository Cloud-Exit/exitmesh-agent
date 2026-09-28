package protocol

import (
	"fmt"
	"sort"
)

// State is the reconstructable state of an epoch (SPEC 6.1).
type State struct {
	Resources map[string]*Resource
	Edges     map[EdgeKey]map[string]any
	Scopes    map[string]ScopeStatus
}

// NewState returns an empty state.
func NewState() *State {
	return &State{
		Resources: map[string]*Resource{},
		Edges:     map[EdgeKey]map[string]any{},
		Scopes:    map[string]ScopeStatus{},
	}
}

// StateFromCheckpoint builds state from checkpoint content.
func StateFromCheckpoint(c *Checkpoint) *State {
	s := NewState()
	for _, r := range c.Resources {
		rc := r
		rc.Fields = CloneFields(r.Fields)
		s.Resources[r.UID] = &rc
	}
	for _, e := range c.Edges {
		s.Edges[e.Key()] = CloneFields(e.Attrs)
	}
	for k, v := range c.Scopes {
		s.Scopes[k] = v
	}
	return s
}

// Clone deep-copies the state.
func (s *State) Clone() *State {
	out := NewState()
	for uid, r := range s.Resources {
		rc := *r
		rc.Fields = CloneFields(r.Fields)
		out.Resources[uid] = &rc
	}
	for k, a := range s.Edges {
		out.Edges[k] = CloneFields(a)
	}
	for k, v := range s.Scopes {
		out.Scopes[k] = v
	}
	return out
}

// SortedResources returns resources ordered by UID.
func (s *State) SortedResources() []Resource {
	out := make([]Resource, 0, len(s.Resources))
	for _, r := range s.Resources {
		out = append(out, *r)
	}
	sortResources(out)
	return out
}

// SortedEdges returns edges ordered by edge key.
func (s *State) SortedEdges() []Edge {
	out := make([]Edge, 0, len(s.Edges))
	for k, a := range s.Edges {
		out = append(out, Edge{From: k.From, Type: k.Type, To: k.To, Attrs: a})
	}
	sortEdges(out)
	return out
}

// Hash is the state hash of SPEC 6.2.
func (s *State) Hash() Hash { return stateHash(s.SortedResources(), s.SortedEdges(), s.Scopes) }

// Checkpoint snapshots the state into a checkpoint body. Content is deep-copied.
func (s *State) Checkpoint(reason CheckpointReason, iv Interval, capabilities []string) *Checkpoint {
	c := s.Clone()
	caps := append([]string(nil), capabilities...)
	sort.Strings(caps)
	caps = uniqueStrings(caps)
	ck := &Checkpoint{
		Reason:       reason,
		Interval:     iv,
		Resources:    c.SortedResources(),
		Edges:        c.SortedEdges(),
		Scopes:       c.Scopes,
		Capabilities: caps,
	}
	ck.StateHash = ck.ContentHash()
	return ck
}

func uniqueStrings(s []string) []string {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, x := range s[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// check validates op against the current state without applying it.
func (s *State) check(op *Op) error {
	switch op.Kind {
	case OpCreate:
		if _, ok := s.Resources[op.UID]; ok {
			return fmt.Errorf("%w: create of existing uid %s", ErrInvalidOp, op.UID)
		}
	case OpUpdate, OpDelete:
		if _, ok := s.Resources[op.UID]; !ok {
			return fmt.Errorf("%w: %s of absent uid %s", ErrInvalidOp, op.Kind, op.UID)
		}
	case OpEdgeAdd:
		if _, ok := s.Edges[op.EdgeKey()]; ok {
			return fmt.Errorf("%w: add of existing edge %v", ErrInvalidOp, op.EdgeKey())
		}
	case OpEdgeRemove, OpEdgeReplace:
		if _, ok := s.Edges[op.EdgeKey()]; !ok {
			return fmt.Errorf("%w: %s of absent edge %v", ErrInvalidOp, op.Kind, op.EdgeKey())
		}
	case OpScopeSet:
	default:
		return fmt.Errorf("%w: op kind %d", ErrInvalidOp, uint64(op.Kind))
	}
	return nil
}

func (s *State) apply(op *Op) {
	switch op.Kind {
	case OpCreate:
		s.Resources[op.UID] = &Resource{UID: op.UID, Kind: op.ResourceKind, Namespace: op.Namespace, Name: op.Name, Fields: CloneFields(op.Fields)}
	case OpUpdate:
		r := s.Resources[op.UID]
		for k, v := range op.Fields {
			if v == nil {
				delete(r.Fields, k)
			} else {
				r.Fields[k] = CloneValue(v)
			}
		}
	case OpDelete:
		delete(s.Resources, op.UID)
	case OpEdgeAdd, OpEdgeReplace:
		s.Edges[op.EdgeKey()] = CloneFields(op.Attrs)
	case OpEdgeRemove:
		delete(s.Edges, op.EdgeKey())
	case OpScopeSet:
		s.Scopes[op.ScopeKey] = op.Scope
	}
}

// ApplyOps applies ops touching distinct keys atomically: all apply or the state is unchanged.
func (s *State) ApplyOps(ops []Op) error {
	for i := range ops {
		if err := s.check(&ops[i]); err != nil {
			return err
		}
	}
	for i := range ops {
		s.apply(&ops[i])
	}
	return nil
}

// ApplyRecord applies a delta or range record; checkpoints and findings leave state unchanged.
func (s *State) ApplyRecord(r *Record) error {
	switch r.Type {
	case TypeDelta:
		return s.ApplyOps(r.Delta.Ops)
	case TypeRange:
		return s.ApplyOps(r.Range.Ops)
	}
	return nil
}

// Diff returns the canonical ops that transform s into target. Delete ops use reason.
func (s *State) Diff(target *State, reason DeleteReason) []Op {
	var ops []Op
	for uid, t := range target.Resources {
		cur, ok := s.Resources[uid]
		if !ok {
			ops = append(ops, Create(uid, t.Kind, t.Namespace, t.Name, CloneFields(t.Fields)))
			continue
		}
		if ch := FieldChanges(cur.Fields, t.Fields); len(ch) > 0 {
			ops = append(ops, Update(uid, ch))
		}
	}
	for uid := range s.Resources {
		if _, ok := target.Resources[uid]; !ok {
			ops = append(ops, Delete(uid, reason))
		}
	}
	for k, ta := range target.Edges {
		ca, ok := s.Edges[k]
		switch {
		case !ok:
			ops = append(ops, EdgeAdd(k.From, k.Type, k.To, CloneFields(ta)))
		case !ValueEqual(ca, ta):
			ops = append(ops, EdgeReplace(k.From, k.Type, k.To, CloneFields(ta), CloneFields(ca)))
		}
	}
	for k, ca := range s.Edges {
		if _, ok := target.Edges[k]; !ok {
			ops = append(ops, EdgeRemove(k.From, k.Type, k.To, CloneFields(ca)))
		}
	}
	for k, ts := range target.Scopes {
		if cs, ok := s.Scopes[k]; !ok || cs != ts {
			ops = append(ops, ScopeSet(k, ts))
		}
	}
	SortOps(ops)
	return ops
}

// FieldChanges returns the update changes from cur to next: changed or added values, and nil for removed keys.
func FieldChanges(cur, next map[string]any) map[string]any {
	ch := map[string]any{}
	for k, v := range next {
		if c, ok := cur[k]; !ok || !ValueEqual(c, v) {
			ch[k] = CloneValue(v)
		}
	}
	for k := range cur {
		if _, ok := next[k]; !ok {
			ch[k] = nil
		}
	}
	return ch
}

// SortOps orders ops canonically (SPEC 5.3).
func SortOps(ops []Op) {
	sort.SliceStable(ops, func(i, j int) bool { return opLess(&ops[i], &ops[j]) })
}

// Equal reports whether two states have the same hash.
func (s *State) Equal(o *State) bool { return s.Hash() == o.Hash() }
