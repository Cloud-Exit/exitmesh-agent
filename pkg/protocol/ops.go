package protocol

import "fmt"

// OpKind is op key 0 (SPEC 4.3).
type OpKind uint64

const (
	OpCreate      OpKind = 1
	OpUpdate      OpKind = 2
	OpDelete      OpKind = 3
	OpEdgeAdd     OpKind = 4
	OpEdgeRemove  OpKind = 5
	OpEdgeReplace OpKind = 6
	OpScopeSet    OpKind = 7
)

func (k OpKind) String() string {
	switch k {
	case OpCreate:
		return "create"
	case OpUpdate:
		return "update"
	case OpDelete:
		return "delete"
	case OpEdgeAdd:
		return "edge_add"
	case OpEdgeRemove:
		return "edge_remove"
	case OpEdgeReplace:
		return "edge_replace"
	case OpScopeSet:
		return "scope_set"
	}
	return fmt.Sprintf("op(%d)", uint64(k))
}

// DeleteReason distinguishes deletion from scope removal (SPEC 4.3).
type DeleteReason uint64

const (
	DeleteDeleted      DeleteReason = 1
	DeleteScopeRemoved DeleteReason = 2
)

// Op is one state operation; the meaningful fields depend on Kind (SPEC 4.3), and edge ops use UID as the source.
type Op struct {
	Kind         OpKind
	UID          string
	ResourceKind string
	Namespace    string
	Name         string
	Fields       map[string]any
	DeleteReason DeleteReason
	EdgeType     string
	To           string
	Attrs        map[string]any
	PrevAttrs    map[string]any
	ScopeKey     string
	Scope        ScopeStatus
}

// Create returns a create op.
func Create(uid, kind, ns, name string, fields map[string]any) Op {
	return Op{Kind: OpCreate, UID: uid, ResourceKind: kind, Namespace: ns, Name: name, Fields: fields}
}

// Update returns an update op; nil values in changes remove fields.
func Update(uid string, changes map[string]any) Op {
	return Op{Kind: OpUpdate, UID: uid, Fields: changes}
}

// Delete returns a delete op.
func Delete(uid string, reason DeleteReason) Op {
	return Op{Kind: OpDelete, UID: uid, DeleteReason: reason}
}

// EdgeAdd returns an edge-add op.
func EdgeAdd(from, typ, to string, attrs map[string]any) Op {
	return Op{Kind: OpEdgeAdd, UID: from, EdgeType: typ, To: to, Attrs: attrs}
}

// EdgeRemove returns an edge-remove op carrying the removed attributes.
func EdgeRemove(from, typ, to string, attrs map[string]any) Op {
	return Op{Kind: OpEdgeRemove, UID: from, EdgeType: typ, To: to, Attrs: attrs}
}

// EdgeReplace returns an edge-replace op.
func EdgeReplace(from, typ, to string, attrs, prev map[string]any) Op {
	return Op{Kind: OpEdgeReplace, UID: from, EdgeType: typ, To: to, Attrs: attrs, PrevAttrs: prev}
}

// ScopeSet returns a scope-set op.
func ScopeSet(key string, st ScopeStatus) Op {
	return Op{Kind: OpScopeSet, ScopeKey: key, Scope: st}
}

// EdgeKey returns the edge key of an edge op.
func (o *Op) EdgeKey() EdgeKey { return EdgeKey{o.UID, o.EdgeType, o.To} }

func (o *Op) isResource() bool { return o.Kind >= OpCreate && o.Kind <= OpDelete }
func (o *Op) isEdge() bool     { return o.Kind >= OpEdgeAdd && o.Kind <= OpEdgeReplace }

func (o *Op) normalize() error {
	var err error
	switch o.Kind {
	case OpCreate:
		o.Fields, err = NormalizeFields(o.Fields, false)
	case OpUpdate:
		o.Fields, err = NormalizeFields(o.Fields, true)
	case OpEdgeAdd, OpEdgeRemove:
		o.Attrs, err = NormalizeFields(o.Attrs, false)
	case OpEdgeReplace:
		if o.Attrs, err = NormalizeFields(o.Attrs, false); err == nil {
			o.PrevAttrs, err = NormalizeFields(o.PrevAttrs, false)
		}
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w", o.Kind, o.UID, err)
	}
	return nil
}

func (o *Op) validate() error {
	switch o.Kind {
	case OpCreate:
		if o.UID == "" || o.ResourceKind == "" {
			return fmt.Errorf("%w: create requires uid and kind", ErrInvalidOp)
		}
	case OpUpdate:
		if o.UID == "" || len(o.Fields) == 0 {
			return fmt.Errorf("%w: update requires uid and changes", ErrInvalidOp)
		}
	case OpDelete:
		if o.UID == "" || (o.DeleteReason != DeleteDeleted && o.DeleteReason != DeleteScopeRemoved) {
			return fmt.Errorf("%w: delete requires uid and a valid reason", ErrInvalidOp)
		}
	case OpEdgeAdd, OpEdgeRemove, OpEdgeReplace:
		if o.UID == "" || o.EdgeType == "" || o.To == "" {
			return fmt.Errorf("%w: edge op requires from, type, to", ErrInvalidOp)
		}
	case OpScopeSet:
		if o.ScopeKey == "" || o.Scope.State > ScopeUnavailable {
			return fmt.Errorf("%w: scope-set requires a key and valid state", ErrInvalidOp)
		}
	default:
		return fmt.Errorf("%w: op kind %d", ErrInvalidOp, uint64(o.Kind))
	}
	return nil
}

func (o *Op) encode() map[uint64]any {
	m := map[uint64]any{0: uint64(o.Kind)}
	switch o.Kind {
	case OpCreate:
		m[1], m[2], m[3], m[4], m[5] = o.UID, o.ResourceKind, o.Namespace, o.Name, nonNil(o.Fields)
	case OpUpdate:
		m[1], m[5] = o.UID, nonNil(o.Fields)
	case OpDelete:
		m[1], m[6] = o.UID, uint64(o.DeleteReason)
	case OpEdgeAdd, OpEdgeRemove:
		m[1], m[7], m[8], m[9] = o.UID, o.EdgeType, o.To, nonNil(o.Attrs)
	case OpEdgeReplace:
		m[1], m[7], m[8], m[9], m[10] = o.UID, o.EdgeType, o.To, nonNil(o.Attrs), nonNil(o.PrevAttrs)
	case OpScopeSet:
		m[11], m[12] = o.ScopeKey, o.Scope.encode()
	}
	return m
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func encodeOps(ops []Op) []any {
	out := make([]any, len(ops))
	for i := range ops {
		out[i] = ops[i].encode()
	}
	return out
}

func decodeOps(a []any) ([]Op, error) {
	out := make([]Op, len(a))
	for i, x := range a {
		op, err := decodeOp(x)
		if err != nil {
			return nil, err
		}
		out[i] = op
	}
	return out, nil
}

func decodeOp(v any) (Op, error) {
	var o Op
	m, err := asIntKeyMap(v)
	if err != nil {
		return o, err
	}
	k, err := m.uint(0)
	if err != nil {
		return o, err
	}
	o.Kind = OpKind(k)
	switch o.Kind {
	case OpCreate:
		if o.UID, err = m.text(1); err != nil {
			return o, err
		}
		if o.ResourceKind, err = m.text(2); err != nil {
			return o, err
		}
		if o.Namespace, err = m.text(3); err != nil {
			return o, err
		}
		if o.Name, err = m.text(4); err != nil {
			return o, err
		}
		f, err := m.require(5)
		if err != nil {
			return o, err
		}
		if o.Fields, err = fieldsFromDecoded(f, false); err != nil {
			return o, err
		}
	case OpUpdate:
		if o.UID, err = m.text(1); err != nil {
			return o, err
		}
		f, err := m.require(5)
		if err != nil {
			return o, err
		}
		if o.Fields, err = fieldsFromDecoded(f, true); err != nil {
			return o, err
		}
	case OpDelete:
		if o.UID, err = m.text(1); err != nil {
			return o, err
		}
		r, err := m.uint(6)
		if err != nil {
			return o, err
		}
		o.DeleteReason = DeleteReason(r)
	case OpEdgeAdd, OpEdgeRemove, OpEdgeReplace:
		if o.UID, err = m.text(1); err != nil {
			return o, err
		}
		if o.EdgeType, err = m.text(7); err != nil {
			return o, err
		}
		if o.To, err = m.text(8); err != nil {
			return o, err
		}
		a, err := m.require(9)
		if err != nil {
			return o, err
		}
		if o.Attrs, err = fieldsFromDecoded(a, false); err != nil {
			return o, err
		}
		if o.Kind == OpEdgeReplace {
			p, err := m.require(10)
			if err != nil {
				return o, err
			}
			if o.PrevAttrs, err = fieldsFromDecoded(p, false); err != nil {
				return o, err
			}
		}
	case OpScopeSet:
		if o.ScopeKey, err = m.text(11); err != nil {
			return o, err
		}
		s, err := m.require(12)
		if err != nil {
			return o, err
		}
		if o.Scope, err = decodeScopeStatus(s); err != nil {
			return o, err
		}
		if sm, _ := asIntKeyMap(s); len(sm.extensions()) > 0 {
			return o, fmt.Errorf("%w: extension keys are not allowed inside ops", ErrUnsupportedField)
		}
	default:
		return o, fmt.Errorf("%w: op kind %d", ErrInvalidOp, k)
	}
	if err := m.unknown(); err != nil {
		return o, err
	}
	if len(m.extensions()) > 0 {
		return o, fmt.Errorf("%w: extension keys are not allowed inside ops", ErrUnsupportedField)
	}
	return o, nil
}

// opClass orders resource ops before edge ops before scope ops.
func opClass(o *Op) int {
	switch {
	case o.isResource():
		return 0
	case o.isEdge():
		return 1
	default:
		return 2
	}
}

func opLess(a, b *Op) bool {
	ca, cb := opClass(a), opClass(b)
	if ca != cb {
		return ca < cb
	}
	switch ca {
	case 0:
		return a.UID < b.UID
	case 1:
		return a.EdgeKey().Less(b.EdgeKey())
	default:
		return a.ScopeKey < b.ScopeKey
	}
}
