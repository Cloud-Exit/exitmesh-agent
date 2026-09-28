package protocol

import (
	"bytes"
	"fmt"
	"sort"
)

// Version is the protocol major version.
const Version = 1

// SchemaVersion is the state schema version written by this implementation.
const SchemaVersion = 1

// ExtensionKeyMin is the first extension key (SPEC 3.4).
const ExtensionKeyMin = 1000

// RecordType is envelope key 1.
type RecordType uint64

const (
	TypeCheckpoint RecordType = 1
	TypeDelta      RecordType = 2
	TypeRange      RecordType = 3
	TypeFinding    RecordType = 4
)

func (t RecordType) String() string {
	switch t {
	case TypeCheckpoint:
		return "checkpoint"
	case TypeDelta:
		return "delta"
	case TypeRange:
		return "range"
	case TypeFinding:
		return "finding"
	}
	return fmt.Sprintf("type(%d)", uint64(t))
}

// Envelope holds the record identity and chain position (SPEC 4.1).
type Envelope struct {
	Type        RecordType
	TargetID    string
	Epoch       EpochID
	Seq         uint64
	Writer      WriterID
	Incarnation uint64
	Parent      uint64
	Base        uint64
	Time        uint64
	Schema      uint64
}

// Record is one decoded or to-be-encoded history record. Exactly one body is set.
type Record struct {
	Envelope
	Checkpoint *Checkpoint
	Delta      *Delta
	Range      *Range
	Finding    *Finding
	Ext        map[uint64]any

	raw  []byte
	hash Hash
}

// RecordID is the (target_id, epoch, seq) identity of a record.
type RecordID struct {
	TargetID string
	Epoch    EpochID
	Seq      uint64
}

func (id RecordID) String() string { return fmt.Sprintf("%s/%s/%d", id.TargetID, id.Epoch, id.Seq) }

func (r *Record) ID() RecordID { return RecordID{r.TargetID, r.Epoch, r.Seq} }

// Bytes returns the exact encoded bytes; nil before Encode or Decode.
func (r *Record) Bytes() []byte { return r.raw }

// Hash returns the record hash of the exact bytes.
func (r *Record) Hash() Hash { return r.hash }

// Interval is a closed [Start, End] time interval in milliseconds.
type Interval struct{ Start, End uint64 }

// CheckpointReason is checkpoint body key 0.
type CheckpointReason uint64

const (
	ReasonInitial      CheckpointReason = 1
	ReasonAnchor       CheckpointReason = 2
	ReasonRebaseline   CheckpointReason = 3
	ReasonWriterChange CheckpointReason = 4
	ReasonReplayAnchor CheckpointReason = 5
)

// ScopeState is the completeness state of a scope.
type ScopeState uint64

const (
	ScopeComplete    ScopeState = 0
	ScopePartial     ScopeState = 1
	ScopeUnavailable ScopeState = 2
)

// ScopeStatus is the status of one collection scope.
type ScopeStatus struct {
	State  ScopeState
	Reason string
	Since  uint64
}

// Resource is one normalized resource in state.
type Resource struct {
	UID       string
	Kind      string
	Namespace string
	Name      string
	Fields    map[string]any
}

// Edge is one change-graph edge.
type Edge struct {
	From  string
	Type  string
	To    string
	Attrs map[string]any
}

// EdgeKey identifies an edge.
type EdgeKey struct{ From, Type, To string }

func (e Edge) Key() EdgeKey { return EdgeKey{e.From, e.Type, e.To} }

// Less orders edge keys bytewise element by element.
func (k EdgeKey) Less(o EdgeKey) bool {
	if k.From != o.From {
		return k.From < o.From
	}
	if k.Type != o.Type {
		return k.Type < o.Type
	}
	return k.To < o.To
}

// Checkpoint is a full state record (SPEC 4.2).
type Checkpoint struct {
	Reason       CheckpointReason
	Interval     Interval
	Resources    []Resource
	Edges        []Edge
	Scopes       map[string]ScopeStatus
	Capabilities []string
	StateHash    Hash
	PrevEpoch    *EpochID
	PrevHead     *uint64
}

// Delta flag bits.
const (
	FlagSynthetic   uint64 = 1 << 0
	FlagMetricFacts uint64 = 1 << 1
)

// Delta is a set of state operations (SPEC 4.3).
type Delta struct {
	Ops       []Op
	Flags     uint64
	Uncertain *Interval
}

// RangeFinding is a finding event preserved inside a range with its original sequence.
type RangeFinding struct {
	Seq     uint64
	Finding Finding
}

// Range replaces a coalesced run of records (SPEC 4.4).
type Range struct {
	Ops       []Op
	From, To  uint64
	Findings  []RangeFinding
	Flags     uint64
	Uncertain []Interval
}

// Encode validates r, encodes it deterministically, and records its bytes and hash.
func Encode(r *Record) ([]byte, error) {
	if err := normalizeRecord(r); err != nil {
		return nil, err
	}
	if err := validateRecord(r); err != nil {
		return nil, err
	}
	m := map[uint64]any{
		0: uint64(Version), 1: uint64(r.Type), 2: r.TargetID, 3: r.Epoch[:], 4: r.Seq,
		5: r.Writer[:], 6: r.Incarnation, 7: r.Parent, 8: r.Base, 9: r.Time, 10: r.Schema,
	}
	var body any
	switch r.Type {
	case TypeCheckpoint:
		body = r.Checkpoint.encode()
	case TypeDelta:
		body = r.Delta.encode()
	case TypeRange:
		body = r.Range.encode()
	case TypeFinding:
		body = r.Finding.encode()
	}
	m[11] = body
	for k, v := range r.Ext {
		if k < ExtensionKeyMin {
			return nil, fmt.Errorf("%w: extension key %d below %d", ErrUnsupportedField, k, ExtensionKeyMin)
		}
		m[k] = v
	}
	b, err := Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}
	if len(b) > MaxRecordBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(b))
	}
	r.raw = b
	r.hash = RecordHash(b)
	return b, nil
}

// Decode strictly decodes and validates one record (SPEC 3.2, 4).
func Decode(b []byte) (*Record, error) {
	v, err := decodeStrict(b)
	if err != nil {
		return nil, err
	}
	env, err := asIntKeyMap(v)
	if err != nil {
		return nil, err
	}
	ver, err := env.uint(0)
	if err != nil {
		return nil, err
	}
	if ver != Version {
		return nil, fmt.Errorf("%w: protocol version %d", ErrUnsupportedField, ver)
	}
	r := &Record{}
	t, err := env.uint(1)
	if err != nil {
		return nil, err
	}
	r.Type = RecordType(t)
	if r.TargetID, err = env.text(2); err != nil {
		return nil, err
	}
	ep, err := env.bytesN(3, 16)
	if err != nil {
		return nil, err
	}
	copy(r.Epoch[:], ep)
	if r.Seq, err = env.uint(4); err != nil {
		return nil, err
	}
	w, err := env.bytesN(5, 16)
	if err != nil {
		return nil, err
	}
	copy(r.Writer[:], w)
	for _, f := range []struct {
		k uint64
		p *uint64
	}{{6, &r.Incarnation}, {7, &r.Parent}, {8, &r.Base}, {9, &r.Time}, {10, &r.Schema}} {
		if *f.p, err = env.uint(f.k); err != nil {
			return nil, err
		}
	}
	bodyRaw, err := env.require(11)
	if err != nil {
		return nil, err
	}
	switch r.Type {
	case TypeCheckpoint:
		r.Checkpoint, err = decodeCheckpoint(bodyRaw)
	case TypeDelta:
		r.Delta, err = decodeDelta(bodyRaw)
	case TypeRange:
		r.Range, err = decodeRange(bodyRaw)
	case TypeFinding:
		r.Finding, err = decodeFinding(bodyRaw)
	default:
		return nil, fmt.Errorf("%w: record type %d", ErrUnsupportedField, t)
	}
	if err != nil {
		return nil, err
	}
	if err := env.unknown(); err != nil {
		return nil, err
	}
	r.Ext = env.extensions()
	if err := validateRecord(r); err != nil {
		return nil, err
	}
	r.raw = append([]byte(nil), b...)
	r.hash = RecordHash(r.raw)
	return r, nil
}

func normalizeRecord(r *Record) error {
	var err error
	switch {
	case r.Checkpoint != nil:
		for i := range r.Checkpoint.Resources {
			res := &r.Checkpoint.Resources[i]
			if res.Fields, err = NormalizeFields(res.Fields, false); err != nil {
				return fmt.Errorf("resource %s: %w", res.UID, err)
			}
		}
		for i := range r.Checkpoint.Edges {
			e := &r.Checkpoint.Edges[i]
			if e.Attrs, err = NormalizeFields(e.Attrs, false); err != nil {
				return fmt.Errorf("edge %v: %w", e.Key(), err)
			}
		}
	case r.Delta != nil:
		for i := range r.Delta.Ops {
			if err := r.Delta.Ops[i].normalize(); err != nil {
				return err
			}
		}
	case r.Range != nil:
		for i := range r.Range.Ops {
			if err := r.Range.Ops[i].normalize(); err != nil {
				return err
			}
		}
		for i := range r.Range.Findings {
			if err := r.Range.Findings[i].Finding.normalize(); err != nil {
				return err
			}
		}
	case r.Finding != nil:
		return r.Finding.normalize()
	}
	return nil
}

func validateRecord(r *Record) error {
	if !ValidTargetID(r.TargetID) {
		return fmt.Errorf("%w: invalid target_id", ErrMalformed)
	}
	if r.Incarnation < 1 {
		return fmt.Errorf("%w: incarnation must be at least 1", ErrInvalidChain)
	}
	if r.Seq < 1 {
		return fmt.Errorf("%w: seq must be at least 1", ErrInvalidChain)
	}
	set := 0
	for _, ok := range []bool{r.Checkpoint != nil, r.Delta != nil, r.Range != nil, r.Finding != nil} {
		if ok {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("%w: exactly one body required", ErrMalformed)
	}
	switch r.Type {
	case TypeCheckpoint:
		if r.Checkpoint == nil {
			return fmt.Errorf("%w: checkpoint body missing", ErrMalformed)
		}
		if r.Seq != r.Parent+1 || r.Base != r.Seq {
			return fmt.Errorf("%w: checkpoint requires seq = parent+1 and base = seq", ErrInvalidChain)
		}
		return r.Checkpoint.validate(r.Seq)
	case TypeDelta:
		if r.Delta == nil {
			return fmt.Errorf("%w: delta body missing", ErrMalformed)
		}
		if err := validateLinked(r); err != nil {
			return err
		}
		return r.Delta.validate()
	case TypeFinding:
		if r.Finding == nil {
			return fmt.Errorf("%w: finding body missing", ErrMalformed)
		}
		if err := validateLinked(r); err != nil {
			return err
		}
		return r.Finding.validate()
	case TypeRange:
		if r.Range == nil {
			return fmt.Errorf("%w: range body missing", ErrMalformed)
		}
		g := r.Range
		if !(1 < g.From && g.From <= g.To) || r.Seq != g.To || r.Parent != g.From-1 {
			return fmt.Errorf("%w: range span [%d,%d] inconsistent with seq %d parent %d", ErrInvalidChain, g.From, g.To, r.Seq, r.Parent)
		}
		if r.Base < 1 || r.Base > r.Parent {
			return fmt.Errorf("%w: base %d outside [1,%d]", ErrInvalidChain, r.Base, r.Parent)
		}
		return g.validate()
	default:
		return fmt.Errorf("%w: record type %d", ErrUnsupportedField, uint64(r.Type))
	}
}

func validateLinked(r *Record) error {
	if r.Seq != r.Parent+1 || r.Seq < 2 {
		return fmt.Errorf("%w: seq %d must equal parent+1 and follow a checkpoint", ErrInvalidChain, r.Seq)
	}
	if r.Base < 1 || r.Base > r.Parent {
		return fmt.Errorf("%w: base %d outside [1,%d]", ErrInvalidChain, r.Base, r.Parent)
	}
	return nil
}

func (c *Checkpoint) validate(seq uint64) error {
	if c.Reason < ReasonInitial || c.Reason > ReasonReplayAnchor {
		return fmt.Errorf("%w: checkpoint reason %d", ErrMalformed, c.Reason)
	}
	if c.Interval.Start > c.Interval.End {
		return fmt.Errorf("%w: interval start after end", ErrMalformed)
	}
	for i := 1; i < len(c.Resources); i++ {
		if !(c.Resources[i-1].UID < c.Resources[i].UID) {
			return fmt.Errorf("%w: resources not sorted by uid", ErrMalformed)
		}
	}
	for i := 1; i < len(c.Edges); i++ {
		if !c.Edges[i-1].Key().Less(c.Edges[i].Key()) {
			return fmt.Errorf("%w: edges not sorted", ErrMalformed)
		}
	}
	for i := 1; i < len(c.Capabilities); i++ {
		if !(c.Capabilities[i-1] < c.Capabilities[i]) {
			return fmt.Errorf("%w: capabilities not sorted and unique", ErrMalformed)
		}
	}
	for _, res := range c.Resources {
		if res.UID == "" || res.Kind == "" {
			return fmt.Errorf("%w: resource requires uid and kind", ErrMalformed)
		}
	}
	for k, s := range c.Scopes {
		if k == "" || s.State > ScopeUnavailable {
			return fmt.Errorf("%w: invalid scope %q", ErrMalformed, k)
		}
	}
	if (c.PrevEpoch != nil || c.PrevHead != nil) && seq != 1 {
		return fmt.Errorf("%w: previous epoch only on the first checkpoint", ErrMalformed)
	}
	if got := c.ContentHash(); got != c.StateHash {
		return fmt.Errorf("%w: content hashes to %s, declared %s", ErrInvalidStateHash, got, c.StateHash)
	}
	return nil
}

// ContentHash computes the state hash of the checkpoint content.
func (c *Checkpoint) ContentHash() Hash {
	return stateHash(c.Resources, c.Edges, c.Scopes)
}

func (d *Delta) validate() error {
	if len(d.Ops) == 0 {
		return fmt.Errorf("%w: delta without ops", ErrInvalidOp)
	}
	if d.Uncertain != nil && d.Uncertain.Start > d.Uncertain.End {
		return fmt.Errorf("%w: uncertainty interval", ErrMalformed)
	}
	return validateOps(d.Ops, false)
}

func (g *Range) validate() error {
	if err := validateOps(g.Ops, true); err != nil {
		return err
	}
	prev := uint64(0)
	for _, f := range g.Findings {
		if f.Seq < g.From || f.Seq > g.To || f.Seq <= prev {
			return fmt.Errorf("%w: range finding seq %d", ErrMalformed, f.Seq)
		}
		prev = f.Seq
		if err := f.Finding.validate(); err != nil {
			return err
		}
	}
	for _, iv := range g.Uncertain {
		if iv.Start > iv.End {
			return fmt.Errorf("%w: uncertainty interval", ErrMalformed)
		}
	}
	return nil
}

func validateOps(ops []Op, canonical bool) error {
	res := map[string]bool{}
	edges := map[EdgeKey]bool{}
	scopes := map[string]bool{}
	for i := range ops {
		op := &ops[i]
		if err := op.validate(); err != nil {
			return err
		}
		switch op.Kind {
		case OpCreate, OpUpdate, OpDelete:
			if res[op.UID] {
				return fmt.Errorf("%w: two ops for uid %s", ErrInvalidOp, op.UID)
			}
			res[op.UID] = true
		case OpEdgeAdd, OpEdgeRemove, OpEdgeReplace:
			k := op.EdgeKey()
			if edges[k] {
				return fmt.Errorf("%w: two ops for edge %v", ErrInvalidOp, k)
			}
			edges[k] = true
		case OpScopeSet:
			if scopes[op.ScopeKey] {
				return fmt.Errorf("%w: two ops for scope %s", ErrInvalidOp, op.ScopeKey)
			}
			scopes[op.ScopeKey] = true
		}
	}
	if canonical {
		for i := 1; i < len(ops); i++ {
			if !opLess(&ops[i-1], &ops[i]) {
				return fmt.Errorf("%w: range ops not in canonical order", ErrMalformed)
			}
		}
	}
	return nil
}

func (c *Checkpoint) encode() map[uint64]any {
	res := make([]any, len(c.Resources))
	for i, r := range c.Resources {
		res[i] = resourceArray(r)
	}
	edges := make([]any, len(c.Edges))
	for i, e := range c.Edges {
		edges[i] = edgeArray(e)
	}
	caps := c.Capabilities
	if caps == nil {
		caps = []string{}
	}
	m := map[uint64]any{
		0: uint64(c.Reason),
		1: []any{c.Interval.Start, c.Interval.End},
		2: res,
		3: edges,
		4: scopesMap(c.Scopes),
		5: caps,
		6: c.StateHash[:],
	}
	if c.PrevEpoch != nil {
		m[7] = c.PrevEpoch[:]
	}
	if c.PrevHead != nil {
		m[8] = *c.PrevHead
	}
	return m
}

func resourceArray(r Resource) []any {
	f := r.Fields
	if f == nil {
		f = map[string]any{}
	}
	return []any{r.UID, r.Kind, r.Namespace, r.Name, f}
}

func edgeArray(e Edge) []any {
	a := e.Attrs
	if a == nil {
		a = map[string]any{}
	}
	return []any{e.From, e.Type, e.To, a}
}

func scopesMap(s map[string]ScopeStatus) map[string]any {
	out := make(map[string]any, len(s))
	for k, v := range s {
		out[k] = v.encode()
	}
	return out
}

func (s ScopeStatus) encode() map[uint64]any {
	m := map[uint64]any{0: uint64(s.State)}
	if s.Reason != "" {
		m[1] = s.Reason
	}
	if s.Since != 0 {
		m[2] = s.Since
	}
	return m
}

func decodeScopeStatus(v any) (ScopeStatus, error) {
	var s ScopeStatus
	m, err := asIntKeyMap(v)
	if err != nil {
		return s, err
	}
	st, err := m.uint(0)
	if err != nil {
		return s, err
	}
	s.State = ScopeState(st)
	if m.has(1) {
		if s.Reason, err = m.text(1); err != nil {
			return s, err
		}
		if s.Reason == "" {
			return s, fmt.Errorf("%w: empty scope reason must be omitted", ErrMalformed)
		}
	}
	if u, ok, err := m.optUint(2); err != nil {
		return s, err
	} else if ok {
		if u == 0 {
			return s, fmt.Errorf("%w: zero scope since must be omitted", ErrMalformed)
		}
		s.Since = u
	}
	return s, m.unknown()
}

func decodeInterval(v any) (Interval, error) {
	a, ok := v.([]any)
	if !ok || len(a) != 2 {
		return Interval{}, fmt.Errorf("%w: interval", ErrMalformed)
	}
	s, ok1 := a[0].(uint64)
	e, ok2 := a[1].(uint64)
	if !ok1 || !ok2 {
		return Interval{}, fmt.Errorf("%w: interval bounds", ErrMalformed)
	}
	return Interval{s, e}, nil
}

func decodeResource(v any) (Resource, error) {
	a, ok := v.([]any)
	if !ok || len(a) != 5 {
		return Resource{}, fmt.Errorf("%w: resource: %v", ErrMalformed, errNotArray)
	}
	var r Resource
	var ok1, ok2, ok3, ok4 bool
	r.UID, ok1 = a[0].(string)
	r.Kind, ok2 = a[1].(string)
	r.Namespace, ok3 = a[2].(string)
	r.Name, ok4 = a[3].(string)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return r, fmt.Errorf("%w: resource identity", ErrMalformed)
	}
	f, err := fieldsFromDecoded(a[4], false)
	if err != nil {
		return r, err
	}
	r.Fields = f
	return r, nil
}

func decodeEdge(v any) (Edge, error) {
	a, ok := v.([]any)
	if !ok || len(a) != 4 {
		return Edge{}, fmt.Errorf("%w: edge: %v", ErrMalformed, errNotArray)
	}
	var e Edge
	var ok1, ok2, ok3 bool
	e.From, ok1 = a[0].(string)
	e.Type, ok2 = a[1].(string)
	e.To, ok3 = a[2].(string)
	if !ok1 || !ok2 || !ok3 {
		return e, fmt.Errorf("%w: edge key", ErrMalformed)
	}
	attrs, err := fieldsFromDecoded(a[3], false)
	if err != nil {
		return e, err
	}
	e.Attrs = attrs
	return e, nil
}

func decodeCheckpoint(v any) (*Checkpoint, error) {
	m, err := asIntKeyMap(v)
	if err != nil {
		return nil, err
	}
	c := &Checkpoint{}
	reason, err := m.uint(0)
	if err != nil {
		return nil, err
	}
	c.Reason = CheckpointReason(reason)
	iv, err := m.require(1)
	if err != nil {
		return nil, err
	}
	if c.Interval, err = decodeInterval(iv); err != nil {
		return nil, err
	}
	res, err := m.array(2)
	if err != nil {
		return nil, err
	}
	c.Resources = make([]Resource, len(res))
	for i, x := range res {
		if c.Resources[i], err = decodeResource(x); err != nil {
			return nil, err
		}
	}
	edges, err := m.array(3)
	if err != nil {
		return nil, err
	}
	c.Edges = make([]Edge, len(edges))
	for i, x := range edges {
		if c.Edges[i], err = decodeEdge(x); err != nil {
			return nil, err
		}
	}
	sc, err := m.require(4)
	if err != nil {
		return nil, err
	}
	scm, ok := sc.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: scopes", ErrMalformed)
	}
	c.Scopes = make(map[string]ScopeStatus, len(scm))
	for k, x := range scm {
		ks, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("%w: scope key", ErrMalformed)
		}
		if c.Scopes[ks], err = decodeScopeStatus(x); err != nil {
			return nil, err
		}
	}
	caps, err := m.array(5)
	if err != nil {
		return nil, err
	}
	c.Capabilities = make([]string, len(caps))
	for i, x := range caps {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("%w: capability", ErrMalformed)
		}
		c.Capabilities[i] = s
	}
	sh, err := m.bytesN(6, 32)
	if err != nil {
		return nil, err
	}
	copy(c.StateHash[:], sh)
	if m.has(7) {
		pe, err := m.bytesN(7, 16)
		if err != nil {
			return nil, err
		}
		var id EpochID
		copy(id[:], pe)
		c.PrevEpoch = &id
	}
	if u, ok, err := m.optUint(8); err != nil {
		return nil, err
	} else if ok {
		c.PrevHead = &u
	}
	return c, m.unknown()
}

func (d *Delta) encode() map[uint64]any {
	m := map[uint64]any{0: encodeOps(d.Ops)}
	if d.Flags != 0 {
		m[1] = d.Flags
	}
	if d.Uncertain != nil {
		m[2] = []any{d.Uncertain.Start, d.Uncertain.End}
	}
	return m
}

func decodeDelta(v any) (*Delta, error) {
	m, err := asIntKeyMap(v)
	if err != nil {
		return nil, err
	}
	d := &Delta{}
	ops, err := m.array(0)
	if err != nil {
		return nil, err
	}
	if d.Ops, err = decodeOps(ops); err != nil {
		return nil, err
	}
	if u, ok, err := m.optUint(1); err != nil {
		return nil, err
	} else if ok {
		if u == 0 {
			return nil, fmt.Errorf("%w: zero flags must be omitted", ErrMalformed)
		}
		d.Flags = u
	}
	if m.has(2) {
		x, _ := m.get(2)
		iv, err := decodeInterval(x)
		if err != nil {
			return nil, err
		}
		d.Uncertain = &iv
	}
	return d, m.unknown()
}

func (g *Range) encode() map[uint64]any {
	fs := make([]any, len(g.Findings))
	for i, f := range g.Findings {
		fs[i] = []any{f.Seq, f.Finding.encode()}
	}
	m := map[uint64]any{0: encodeOps(g.Ops), 1: []any{g.From, g.To}, 2: fs}
	if g.Flags != 0 {
		m[3] = g.Flags
	}
	if len(g.Uncertain) > 0 {
		ivs := make([]any, len(g.Uncertain))
		for i, iv := range g.Uncertain {
			ivs[i] = []any{iv.Start, iv.End}
		}
		m[4] = ivs
	}
	return m
}

func decodeRange(v any) (*Range, error) {
	m, err := asIntKeyMap(v)
	if err != nil {
		return nil, err
	}
	g := &Range{}
	ops, err := m.array(0)
	if err != nil {
		return nil, err
	}
	if g.Ops, err = decodeOps(ops); err != nil {
		return nil, err
	}
	sp, err := m.require(1)
	if err != nil {
		return nil, err
	}
	span, err := decodeInterval(sp)
	if err != nil {
		return nil, err
	}
	g.From, g.To = span.Start, span.End
	fs, err := m.array(2)
	if err != nil {
		return nil, err
	}
	for _, x := range fs {
		a, ok := x.([]any)
		if !ok || len(a) != 2 {
			return nil, fmt.Errorf("%w: range finding", ErrMalformed)
		}
		seq, ok := a[0].(uint64)
		if !ok {
			return nil, fmt.Errorf("%w: range finding seq", ErrMalformed)
		}
		f, err := decodeFinding(a[1])
		if err != nil {
			return nil, err
		}
		g.Findings = append(g.Findings, RangeFinding{Seq: seq, Finding: *f})
	}
	if u, ok, err := m.optUint(3); err != nil {
		return nil, err
	} else if ok {
		if u == 0 {
			return nil, fmt.Errorf("%w: zero flags must be omitted", ErrMalformed)
		}
		g.Flags = u
	}
	if m.has(4) {
		ivs, err := m.array(4)
		if err != nil {
			return nil, err
		}
		if len(ivs) == 0 {
			return nil, fmt.Errorf("%w: empty uncertainty list must be omitted", ErrMalformed)
		}
		for _, x := range ivs {
			iv, err := decodeInterval(x)
			if err != nil {
				return nil, err
			}
			g.Uncertain = append(g.Uncertain, iv)
		}
	}
	return g, m.unknown()
}

func sortResources(rs []Resource) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].UID < rs[j].UID })
}

func sortEdges(es []Edge) {
	sort.Slice(es, func(i, j int) bool { return es[i].Key().Less(es[j].Key()) })
}

// Equal reports whether two records have identical bytes.
func (r *Record) Equal(o *Record) bool { return bytes.Equal(r.raw, o.raw) }
