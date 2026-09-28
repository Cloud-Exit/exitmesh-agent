// Package findings turns rule and query observations into finding episodes and records (PRD 7.7).
package findings

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Kind is the observation type.
type Kind int

const (
	Firing Kind = iota + 1
	Resolved
	Stale
	Fresh
)

func (k Kind) String() string {
	switch k {
	case Firing:
		return "firing"
	case Resolved:
		return "resolved"
	case Stale:
		return "stale"
	case Fresh:
		return "fresh"
	}
	return "kind(" + strconv.Itoa(int(k)) + ")"
}

// Summary states.
const (
	StateFiring   = "firing"
	StateStale    = "stale"
	StateResolved = "resolved"
)

// Defaults.
const (
	DefaultUpdateInterval = time.Minute
	DefaultLateThreshold  = 15 * time.Minute
	DefaultMaxSamples     = 10
	DefaultMaxBytes       = 16 << 10
	DefaultMaxSampleBytes = 2 << 10
)

// QueryProvenance identifies a query-generated finding (PRD I8).
type QueryProvenance struct {
	Hash      protocol.Hash
	Requester string
}

// Observation is one rule or query result; Stale and Fresh without key or labels apply rule-wide.
type Observation struct {
	Kind          Kind
	RuleID        string
	RuleVersion   uint64
	BundleVersion string
	Query         *QueryProvenance
	// DedupKey overrides the derived key: rule id (or query hash) plus canonical sorted labels.
	DedupKey string
	// DedupLabels restricts the labels used for the derived key.
	DedupLabels []string
	Labels      map[string]string
	Category    string
	Severity    protocol.Severity
	EvalTime    time.Time
	// Count is the number of occurrences this observation represents (default 1).
	Count       uint64
	Resources   []string
	Facts       map[string]any
	Evidence    []protocol.Evidence
	MaxSamples  int
	MaxBytes    int
	Flags       uint64
	Node        string
	Summary     string
	Coverage    []string
	Suggestions []protocol.Suggestion
}

// Emit appends a finding inside the caller's spool transaction and returns its sequence.
type Emit func(protocol.Finding) (uint64, error)

// Options configure a Tracker.
type Options struct {
	TargetID       string
	Store          kv.Store
	UpdateInterval time.Duration
	LateThreshold  time.Duration
	MaxSamples     int
	MaxBytes       int
	MaxSampleBytes int
	// VolatileLabels are excluded from derived dedup keys in addition to "value".
	VolatileLabels []string
	Redactor       *redact.Redactor
	Clock          func() time.Time
}

type sample struct {
	Source    string            `cbor:"1,keyasint"`
	Text      string            `cbor:"2,keyasint"`
	Labels    map[string]string `cbor:"3,keyasint,omitempty"`
	Context   bool              `cbor:"4,keyasint,omitempty"`
	Truncated bool              `cbor:"5,keyasint,omitempty"`
	Count     uint64            `cbor:"6,keyasint"`
	FirstSeen uint64            `cbor:"7,keyasint"`
	LastSeen  uint64            `cbor:"8,keyasint"`
}

type transition struct {
	Seq           uint64              `cbor:"1,keyasint"`
	Transition    protocol.Transition `cbor:"2,keyasint"`
	EvalTime      uint64              `cbor:"3,keyasint"`
	BundleVersion string              `cbor:"4,keyasint,omitempty"`
	Severity      protocol.Severity   `cbor:"5,keyasint"`
}

type episode struct {
	ID          string                `cbor:"1,keyasint"`
	DedupKey    string                `cbor:"2,keyasint"`
	State       string                `cbor:"3,keyasint"`
	Provenance  protocol.Provenance   `cbor:"4,keyasint"`
	Category    string                `cbor:"5,keyasint"`
	Severity    protocol.Severity     `cbor:"6,keyasint"`
	FirstSeen   uint64                `cbor:"7,keyasint"`
	LastSeen    uint64                `cbor:"8,keyasint"`
	EvalTime    uint64                `cbor:"9,keyasint"`
	Count       uint64                `cbor:"10,keyasint"`
	Resources   []string              `cbor:"11,keyasint,omitempty"`
	Facts       map[string]any        `cbor:"12,keyasint,omitempty"`
	Labels      map[string]string     `cbor:"13,keyasint,omitempty"`
	Node        string                `cbor:"14,keyasint,omitempty"`
	Summary     string                `cbor:"15,keyasint,omitempty"`
	Coverage    []string              `cbor:"16,keyasint,omitempty"`
	Suggestions []protocol.Suggestion `cbor:"17,keyasint,omitempty"`
	Samples     []sample              `cbor:"18,keyasint,omitempty"`
	Flags       uint64                `cbor:"19,keyasint,omitempty"`
	Dropped     uint64                `cbor:"20,keyasint,omitempty"`
	Dirty       bool                  `cbor:"21,keyasint,omitempty"`
	EvDirty     bool                  `cbor:"22,keyasint,omitempty"`
	LastEmit    int64                 `cbor:"23,keyasint"`
	MaxSamples  int                   `cbor:"24,keyasint"`
	MaxBytes    int                   `cbor:"25,keyasint"`
	Transitions []transition          `cbor:"26,keyasint"`
}

func (e *episode) clone() *episode {
	c := *e
	c.Resources = append([]string(nil), e.Resources...)
	c.Samples = append([]sample(nil), e.Samples...)
	c.Transitions = append([]transition(nil), e.Transitions...)
	return &c
}

func (e *episode) last() transition { return e.Transitions[len(e.Transitions)-1] }

// Tracker holds finding episodes; Emit runs under its lock, so take the spool lock first, never after.
type Tracker struct {
	mu       sync.Mutex
	o        Options
	volatile map[string]bool
	byID     map[string]*episode
	open     map[string]string
}

const keyPrefix = "ep/"

var decMode, _ = cbor.DecOptions{DefaultMapType: reflect.TypeOf(map[string]any{})}.DecMode()

// NewTracker loads persisted episodes from o.Store.
func NewTracker(o Options) (*Tracker, error) {
	if o.TargetID == "" || o.Store == nil {
		return nil, errors.New("findings: target id and store are required")
	}
	if o.UpdateInterval <= 0 {
		o.UpdateInterval = DefaultUpdateInterval
	}
	if o.LateThreshold <= 0 {
		o.LateThreshold = DefaultLateThreshold
	}
	if o.MaxSamples <= 0 {
		o.MaxSamples = DefaultMaxSamples
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxSampleBytes <= 0 {
		o.MaxSampleBytes = DefaultMaxSampleBytes
	}
	if o.Redactor == nil {
		o.Redactor = redact.Default()
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	t := &Tracker{o: o, volatile: map[string]bool{"value": true}, byID: map[string]*episode{}, open: map[string]string{}}
	for _, l := range o.VolatileLabels {
		t.volatile[l] = true
	}
	err := o.Store.ForEach(keyPrefix, func(k string, v []byte) error {
		var e episode
		if err := decMode.Unmarshal(v, &e); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		if e.Facts != nil {
			f, err := protocol.NormalizeFields(e.Facts, false)
			if err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
			e.Facts = f
		}
		if len(e.Transitions) == 0 {
			return fmt.Errorf("%s: episode without transitions", k)
		}
		t.byID[e.ID] = &e
		if e.State != StateResolved {
			t.open[e.DedupKey] = e.ID
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("findings: load episodes: %w", err)
	}
	return t, nil
}

func ms(t time.Time) uint64 {
	if t.IsZero() || t.UnixMilli() <= 0 {
		return 0
	}
	return uint64(t.UnixMilli())
}

// DedupKey returns o.DedupKey or the rule id (or query hash) plus canonical non-volatile labels.
func (t *Tracker) DedupKey(o Observation) string {
	if o.DedupKey != "" {
		return o.DedupKey
	}
	base := o.RuleID
	if o.Query != nil {
		base = "query:" + hex.EncodeToString(o.Query.Hash[:])
	}
	return base + canonicalLabels(t.redactLabels(o.Labels), o.DedupLabels, t.volatile)
}

func canonicalLabels(labels map[string]string, only []string, volatile map[string]bool) string {
	keep := map[string]bool{}
	for _, l := range only {
		keep[l] = true
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if volatile[k] || (len(keep) > 0 && !keep[k]) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(labels[k]))
	}
	b.WriteByte('}')
	return b.String()
}

func (t *Tracker) redactLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = t.o.Redactor.KeyValue(k, v)
	}
	return out
}

// Observe applies an observation and emits the resulting transitions. It returns the number emitted.
func (t *Tracker) Observe(o Observation, emit Emit) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch o.Kind {
	case Firing:
		return t.firing(o, emit)
	case Resolved:
		return t.resolved(o, emit)
	case Stale, Fresh:
		return t.staleness(o, emit)
	}
	return 0, fmt.Errorf("findings: unknown observation kind %d", o.Kind)
}

// AddQueryFinding saves a query-generated observation as a finding with query provenance.
func (t *Tracker) AddQueryFinding(o Observation, emit Emit) (int, error) {
	if o.Query == nil || o.Query.Requester == "" {
		return 0, errors.New("findings: query findings need a query hash and requester")
	}
	o.Kind = Firing
	return t.Observe(o, emit)
}

func (t *Tracker) provenance(o Observation) (protocol.Provenance, error) {
	if o.Query != nil {
		if o.Query.Requester == "" {
			return protocol.Provenance{}, errors.New("findings: query provenance requires a requester")
		}
		return protocol.Provenance{Kind: protocol.ProvenanceQuery, QueryHash: o.Query.Hash, Requester: o.Query.Requester}, nil
	}
	if o.RuleID == "" || o.BundleVersion == "" {
		return protocol.Provenance{}, errors.New("findings: rule provenance requires rule id and bundle version")
	}
	return protocol.Provenance{Kind: protocol.ProvenanceRule, RuleID: o.RuleID, RuleVersion: o.RuleVersion, BundleVersion: o.BundleVersion}, nil
}

func (t *Tracker) firing(o Observation, emit Emit) (int, error) {
	prov, err := t.provenance(o)
	if err != nil {
		return 0, err
	}
	if o.Severity < protocol.SeverityInfo || o.Severity > protocol.SeverityCritical {
		return 0, fmt.Errorf("findings: invalid severity %d", o.Severity)
	}
	eval := ms(o.EvalTime)
	if eval == 0 {
		return 0, errors.New("findings: firing observation needs an evaluation time")
	}
	var facts map[string]any
	if len(o.Facts) > 0 {
		if facts, err = protocol.NormalizeFields(o.Facts, false); err != nil {
			return 0, fmt.Errorf("findings: facts: %w", err)
		}
	}
	key := t.DedupKey(o)
	n := max(o.Count, 1)
	id, isOpen := t.open[key]
	var e *episode
	if isOpen {
		e = t.byID[id].clone()
		e.Count += n
		e.Dirty = true
		e.LastSeen = max(e.LastSeen, eval)
		e.EvalTime = eval
	} else {
		first := eval
		for {
			id = protocol.FindingID(t.o.TargetID, key, first)
			if _, taken := t.byID[id]; !taken {
				break
			}
			first++
		}
		e = &episode{ID: id, DedupKey: key, FirstSeen: first, LastSeen: eval, EvalTime: eval, Count: n}
	}
	e.Provenance = prov
	e.Severity = o.Severity
	if o.Category != "" {
		e.Category = o.Category
	}
	if facts != nil {
		e.Facts = facts
	}
	if l := t.redactLabels(o.Labels); l != nil {
		e.Labels = l
	}
	if o.Node != "" {
		e.Node = o.Node
	}
	if o.Summary != "" {
		e.Summary = o.Summary
	}
	e.Coverage = append([]string(nil), o.Coverage...)
	if len(o.Suggestions) > 0 {
		e.Suggestions = append([]protocol.Suggestion(nil), o.Suggestions...)
	}
	e.Flags |= o.Flags &^ protocol.FindingLateAtWriter
	if mergeResources(e, o.Resources) {
		e.Dirty = true
	}
	e.MaxSamples, e.MaxBytes = capOr(o.MaxSamples, t.o.MaxSamples), capOr(o.MaxBytes, t.o.MaxBytes)
	if t.addEvidence(e, o.Evidence) {
		e.Dirty, e.EvDirty = true, true
	}
	switch {
	case !isOpen:
		e.EvDirty = true
		return 1, t.transition(e, protocol.TransitionFiring, eval, emit)
	case e.State == StateStale:
		return 1, t.transition(e, protocol.TransitionFresh, eval, emit)
	case t.o.Clock().UnixNano()-e.LastEmit >= int64(t.o.UpdateInterval):
		return 1, t.transition(e, protocol.TransitionUpdate, eval, emit)
	}
	return 0, t.persist(e)
}

func capOr(v, limit int) int {
	if v <= 0 {
		return limit
	}
	return min(v, limit)
}

func mergeResources(e *episode, add []string) bool {
	have := map[string]bool{}
	for _, r := range e.Resources {
		have[r] = true
	}
	changed := false
	for _, r := range add {
		if r != "" && !have[r] {
			have[r] = true
			e.Resources = append(e.Resources, r)
			changed = true
		}
	}
	sort.Strings(e.Resources)
	return changed
}

func (t *Tracker) addEvidence(e *episode, in []protocol.Evidence) bool {
	changed := false
	used := 0
	for _, s := range e.Samples {
		used += len(s.Text)
	}
	for _, ev := range in {
		text, truncated := truncateUTF8(t.o.Redactor.String(ev.Text), t.o.MaxSampleBytes)
		truncated = truncated || ev.Truncated
		labels := t.redactLabels(ev.Labels)
		n := max(ev.Count, 1)
		if truncated && e.Flags&protocol.FindingEvidenceTruncated == 0 {
			e.Flags |= protocol.FindingEvidenceTruncated
			changed = true
		}
		found := false
		for i := range e.Samples {
			s := &e.Samples[i]
			if s.Source == ev.Source && s.Text == text && s.Context == ev.Context && reflect.DeepEqual(s.Labels, labels) {
				s.Count += n
				s.FirstSeen = min(s.FirstSeen, ev.Time)
				s.LastSeen = max(s.LastSeen, ev.Time)
				s.Truncated = s.Truncated || truncated
				found, changed = true, true
				break
			}
		}
		if found {
			continue
		}
		if len(e.Samples) >= e.MaxSamples || used+len(text) > e.MaxBytes {
			e.Dropped += n
			if e.Flags&protocol.FindingEvidenceTruncated == 0 {
				e.Flags |= protocol.FindingEvidenceTruncated
				changed = true
			}
			continue
		}
		e.Samples = append(e.Samples, sample{Source: ev.Source, Text: text, Labels: labels, Context: ev.Context, Truncated: truncated, Count: n, FirstSeen: ev.Time, LastSeen: ev.Time})
		used += len(text)
		changed = true
	}
	return changed
}

func truncateUTF8(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s, true
}

func (t *Tracker) resolved(o Observation, emit Emit) (int, error) {
	id, ok := t.open[t.DedupKey(o)]
	if !ok {
		return 0, nil
	}
	e := t.byID[id].clone()
	return 1, t.transition(e, protocol.TransitionResolved, t.evalOrNow(o), emit)
}

func (t *Tracker) evalOrNow(o Observation) uint64 {
	if v := ms(o.EvalTime); v != 0 {
		return v
	}
	return ms(t.o.Clock())
}

func (t *Tracker) staleness(o Observation, emit Emit) (int, error) {
	var ids []string
	if o.DedupKey == "" && len(o.Labels) == 0 {
		if o.RuleID == "" {
			return 0, errors.New("findings: stale and fresh observations need a rule id or dedup key")
		}
		for _, id := range t.open {
			e := t.byID[id]
			if e.Provenance.Kind == protocol.ProvenanceRule && e.Provenance.RuleID == o.RuleID && (o.Node == "" || e.Node == o.Node) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
	} else if id, ok := t.open[t.DedupKey(o)]; ok {
		ids = []string{id}
	}
	from, tr := StateFiring, protocol.TransitionStale
	if o.Kind == Fresh {
		from, tr = StateStale, protocol.TransitionFresh
	}
	emitted := 0
	for _, id := range ids {
		e := t.byID[id]
		if e.State != from {
			continue
		}
		e = e.clone()
		if err := t.transition(e, tr, t.evalOrNow(o), emit); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, nil
}

func stateAfter(tr protocol.Transition) string {
	switch tr {
	case protocol.TransitionResolved:
		return StateResolved
	case protocol.TransitionStale:
		return StateStale
	}
	return StateFiring
}

func (t *Tracker) transition(e *episode, tr protocol.Transition, eval uint64, emit Emit) error {
	now := t.o.Clock()
	f := protocol.Finding{
		ID: e.ID, DedupKey: e.DedupKey, Transition: tr, Provenance: e.Provenance,
		Category: e.Category, Severity: e.Severity, EvalTime: eval,
		FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, Count: e.Count,
		Resources: append([]string(nil), e.Resources...), Node: e.Node, Summary: e.Summary,
		Coverage: append([]string(nil), e.Coverage...), Suggestions: append([]protocol.Suggestion(nil), e.Suggestions...),
		Flags: e.Flags,
	}
	if len(e.Facts) > 0 {
		f.Facts = protocol.CloneFields(e.Facts)
	}
	if len(e.Labels) > 0 {
		f.Labels = make(map[string]string, len(e.Labels))
		for k, v := range e.Labels {
			f.Labels[k] = v
		}
	}
	if len(f.Coverage) > 0 {
		f.Flags |= protocol.FindingIncompleteCoverage
	}
	if now.Sub(time.UnixMilli(int64(eval))) > t.o.LateThreshold {
		f.Flags |= protocol.FindingLateAtWriter
	}
	if e.EvDirty {
		for _, s := range e.Samples {
			ev := protocol.Evidence{Source: s.Source, Time: s.FirstSeen, Text: s.Text, Count: s.Count, Truncated: s.Truncated, Context: s.Context}
			if len(s.Labels) > 0 {
				ev.Labels = make(map[string]string, len(s.Labels))
				for k, v := range s.Labels {
					ev.Labels[k] = v
				}
			}
			f.Evidence = append(f.Evidence, ev)
		}
	}
	seq, err := emit(f)
	if err != nil {
		return fmt.Errorf("findings: emit %s %s: %w", tr, e.ID, err)
	}
	e.State = stateAfter(tr)
	e.EvalTime = eval
	e.Dirty, e.EvDirty = false, false
	e.LastEmit = now.UnixNano()
	e.Transitions = append(e.Transitions, transition{Seq: seq, Transition: tr, EvalTime: eval, BundleVersion: e.Provenance.BundleVersion, Severity: e.Severity})
	return t.persist(e)
}

func (t *Tracker) persist(e *episode) error {
	t.byID[e.ID] = e
	if e.State == StateResolved {
		if t.open[e.DedupKey] == e.ID {
			delete(t.open, e.DedupKey)
		}
	} else {
		t.open[e.DedupKey] = e.ID
	}
	b, err := cbor.Marshal(e)
	if err != nil {
		return fmt.Errorf("findings: encode episode: %w", err)
	}
	if err := t.o.Store.Put(keyPrefix+e.ID, b); err != nil {
		return fmt.Errorf("findings: persist episode: %w", err)
	}
	return nil
}

// Flush emits pending updates for firing episodes whose update interval has elapsed.
func (t *Tracker) Flush(emit Emit) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.o.Clock().UnixNano()
	ids := make([]string, 0, len(t.open))
	for _, id := range t.open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	emitted := 0
	for _, id := range ids {
		e := t.byID[id]
		if e.State != StateFiring || !e.Dirty || now-e.LastEmit < int64(t.o.UpdateInterval) {
			continue
		}
		if err := t.transition(e.clone(), protocol.TransitionUpdate, e.EvalTime, emit); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, nil
}

// Commit prunes resolved episodes and transition history at or below the committed seq.
func (t *Tracker) Commit(seq uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	ops := map[string][]byte{}
	for id, e := range t.byID {
		if e.State == StateResolved && e.last().Seq <= seq {
			delete(t.byID, id)
			ops[keyPrefix+id] = nil
			continue
		}
		keepFrom := 0
		for i, tr := range e.Transitions {
			if tr.Seq <= seq {
				keepFrom = i
			}
		}
		if keepFrom == 0 {
			continue
		}
		c := e.clone()
		c.Transitions = c.Transitions[keepFrom:]
		b, err := cbor.Marshal(c)
		if err != nil {
			return err
		}
		t.byID[id] = c
		ops[keyPrefix+id] = b
	}
	if len(ops) == 0 {
		return nil
	}
	if err := t.o.Store.Batch(ops); err != nil {
		return fmt.Errorf("findings: commit: %w", err)
	}
	return nil
}

// Summary returns, by finding id, the state at watermark of every finding touched in (fromSeq, watermark].
func (t *Tracker) Summary(fromSeq, watermark uint64) []protocol.SummaryEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []protocol.SummaryEntry{}
	for _, e := range t.byID {
		var last *transition
		touched := false
		for i := range e.Transitions {
			tr := &e.Transitions[i]
			if tr.Seq > watermark {
				break
			}
			last = tr
			touched = touched || tr.Seq > fromSeq
		}
		if !touched {
			continue
		}
		entry := protocol.SummaryEntry{
			FindingID: e.ID, DedupKey: e.DedupKey, State: stateAfter(last.Transition),
			FirstSeen: e.FirstSeen, LastTransition: last.Seq, EvalTime: last.EvalTime,
			BundleVersion: last.BundleVersion, Severity: last.Severity.String(),
		}
		if e.Provenance.Kind == protocol.ProvenanceRule {
			entry.RuleID = e.Provenance.RuleID
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	return out
}

// OpenCount returns the number of firing or stale episodes.
func (t *Tracker) OpenCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.open)
}
