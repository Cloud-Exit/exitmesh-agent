package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// Transition is finding body key 2.
type Transition uint64

const (
	TransitionFiring   Transition = 1
	TransitionUpdate   Transition = 2
	TransitionResolved Transition = 3
	TransitionStale    Transition = 4
	TransitionFresh    Transition = 5
)

func (t Transition) String() string {
	switch t {
	case TransitionFiring:
		return "firing"
	case TransitionUpdate:
		return "update"
	case TransitionResolved:
		return "resolved"
	case TransitionStale:
		return "stale"
	case TransitionFresh:
		return "fresh"
	}
	return fmt.Sprintf("transition(%d)", uint64(t))
}

// Severity is finding body key 5.
type Severity uint64

const (
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

// ParseSeverity maps a severity label to its value; unknown labels map to medium.
func ParseSeverity(s string) Severity {
	switch s {
	case "info", "informational", "none":
		return SeverityInfo
	case "low", "minor":
		return SeverityLow
	case "high", "major", "error":
		return SeverityHigh
	case "critical", "page", "fatal":
		return SeverityCritical
	default:
		return SeverityMedium
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// ProvenanceKind distinguishes rule- and query-generated findings.
type ProvenanceKind uint64

const (
	ProvenanceRule  ProvenanceKind = 1
	ProvenanceQuery ProvenanceKind = 2
)

// Provenance identifies what produced a finding.
type Provenance struct {
	Kind          ProvenanceKind
	RuleID        string
	RuleVersion   uint64
	BundleVersion string
	QueryHash     Hash
	Requester     string
}

// Finding flag bits.
const (
	FindingEvidenceTruncated  uint64 = 1 << 0
	FindingEvidenceLimited    uint64 = 1 << 1
	FindingIncompleteCoverage uint64 = 1 << 2
	FindingSamplesCompacted   uint64 = 1 << 3
	FindingLateAtWriter       uint64 = 1 << 4
)

// Evidence is one capped, redacted sample.
type Evidence struct {
	Source    string
	Time      uint64
	Text      string
	Count     uint64
	Labels    map[string]string
	Truncated bool
	Context   bool
}

// Suggestion is a bounded investigation option.
type Suggestion struct {
	Language string
	Query    string
	Source   string
}

// Finding is a finding event (SPEC 4.5).
type Finding struct {
	ID          string
	DedupKey    string
	Transition  Transition
	Provenance  Provenance
	Category    string
	Severity    Severity
	EvalTime    uint64
	FirstSeen   uint64
	LastSeen    uint64
	Count       uint64
	Resources   []string
	Facts       map[string]any
	Evidence    []Evidence
	Flags       uint64
	Node        string
	Labels      map[string]string
	Summary     string
	Suggestions []Suggestion
	Coverage    []string
}

// FindingID derives the deterministic finding id for an episode.
func FindingID(targetID, dedupKey string, firstSeen uint64) string {
	b, err := Marshal([]any{targetID, dedupKey, firstSeen})
	if err != nil {
		panic(err)
	}
	h := domainHash("EMHPv1/finding", b)
	return hex.EncodeToString(h[:16])
}

// QueryHash hashes a normalized investigation query.
func QueryHash(language, normalizedQuery, source string) Hash {
	b, err := Marshal([]any{language, normalizedQuery, source})
	if err != nil {
		panic(err)
	}
	return domainHash("EMHPv1/query", b)
}

func (f *Finding) normalize() error {
	if f.Facts != nil {
		n, err := NormalizeFields(f.Facts, false)
		if err != nil {
			return fmt.Errorf("finding facts: %w", err)
		}
		f.Facts = n
	}
	if len(f.Resources) > 1 {
		sort.Strings(f.Resources)
		out := f.Resources[:1]
		for _, r := range f.Resources[1:] {
			if r != out[len(out)-1] {
				out = append(out, r)
			}
		}
		f.Resources = out
	}
	return nil
}

func (f *Finding) validate() error {
	if f.ID == "" || f.DedupKey == "" {
		return fmt.Errorf("%w: finding requires id and dedup key", ErrMalformed)
	}
	if f.Transition < TransitionFiring || f.Transition > TransitionFresh {
		return fmt.Errorf("%w: transition %d", ErrMalformed, f.Transition)
	}
	if f.Severity < SeverityInfo || f.Severity > SeverityCritical {
		return fmt.Errorf("%w: severity %d", ErrMalformed, f.Severity)
	}
	switch f.Provenance.Kind {
	case ProvenanceRule:
		if f.Provenance.RuleID == "" || f.Provenance.BundleVersion == "" {
			return fmt.Errorf("%w: rule provenance requires rule id and bundle version", ErrMalformed)
		}
	case ProvenanceQuery:
		if f.Provenance.Requester == "" {
			return fmt.Errorf("%w: query provenance requires requester", ErrMalformed)
		}
	default:
		return fmt.Errorf("%w: provenance kind %d", ErrMalformed, f.Provenance.Kind)
	}
	for i := 1; i < len(f.Resources); i++ {
		if !(f.Resources[i-1] < f.Resources[i]) {
			return fmt.Errorf("%w: finding resources not sorted and unique", ErrMalformed)
		}
	}
	return nil
}

func (p Provenance) encode() map[uint64]any {
	if p.Kind == ProvenanceQuery {
		return map[uint64]any{0: uint64(p.Kind), 4: p.QueryHash[:], 5: p.Requester}
	}
	return map[uint64]any{0: uint64(p.Kind), 1: p.RuleID, 2: p.RuleVersion, 3: p.BundleVersion}
}

func stringMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (e Evidence) encode() map[uint64]any {
	m := map[uint64]any{0: e.Source, 1: e.Time, 2: e.Text}
	if e.Count != 0 {
		m[3] = e.Count
	}
	if len(e.Labels) > 0 {
		m[4] = stringMap(e.Labels)
	}
	if e.Truncated {
		m[5] = true
	}
	if e.Context {
		m[6] = true
	}
	return m
}

func (f *Finding) encode() map[uint64]any {
	res := f.Resources
	if res == nil {
		res = []string{}
	}
	m := map[uint64]any{
		0: f.ID, 1: f.DedupKey, 2: uint64(f.Transition), 3: f.Provenance.encode(),
		4: f.Category, 5: uint64(f.Severity), 6: f.EvalTime, 7: f.FirstSeen, 8: f.LastSeen,
		9: f.Count, 10: res,
	}
	if len(f.Facts) > 0 {
		m[11] = f.Facts
	}
	if len(f.Evidence) > 0 {
		ev := make([]any, len(f.Evidence))
		for i, e := range f.Evidence {
			ev[i] = e.encode()
		}
		m[12] = ev
	}
	if f.Flags != 0 {
		m[13] = f.Flags
	}
	if f.Node != "" {
		m[14] = f.Node
	}
	if len(f.Labels) > 0 {
		m[15] = stringMap(f.Labels)
	}
	if f.Summary != "" {
		m[16] = f.Summary
	}
	if len(f.Suggestions) > 0 {
		ss := make([]any, len(f.Suggestions))
		for i, s := range f.Suggestions {
			sm := map[uint64]any{0: s.Language, 1: s.Query}
			if s.Source != "" {
				sm[2] = s.Source
			}
			ss[i] = sm
		}
		m[17] = ss
	}
	if len(f.Coverage) > 0 {
		m[18] = f.Coverage
	}
	return m
}

func decodeStringMap(v any) (map[string]string, error) {
	raw, ok := v.(map[any]any)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("%w: expected non-empty text map", ErrMalformed)
	}
	out := make(map[string]string, len(raw))
	for k, x := range raw {
		ks, ok1 := k.(string)
		xs, ok2 := x.(string)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%w: expected text map", ErrMalformed)
		}
		out[ks] = xs
	}
	return out, nil
}

func decodeStrings(v any, nonEmpty bool) ([]string, error) {
	a, ok := v.([]any)
	if !ok || (nonEmpty && len(a) == 0) {
		return nil, fmt.Errorf("%w: expected text array", ErrMalformed)
	}
	out := make([]string, len(a))
	for i, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("%w: expected text", ErrMalformed)
		}
		out[i] = s
	}
	return out, nil
}

func decodeProvenance(v any) (Provenance, error) {
	var p Provenance
	m, err := asIntKeyMap(v)
	if err != nil {
		return p, err
	}
	k, err := m.uint(0)
	if err != nil {
		return p, err
	}
	p.Kind = ProvenanceKind(k)
	switch p.Kind {
	case ProvenanceRule:
		if p.RuleID, err = m.text(1); err != nil {
			return p, err
		}
		if p.RuleVersion, err = m.uint(2); err != nil {
			return p, err
		}
		if p.BundleVersion, err = m.text(3); err != nil {
			return p, err
		}
	case ProvenanceQuery:
		h, err := m.bytesN(4, 32)
		if err != nil {
			return p, err
		}
		copy(p.QueryHash[:], h)
		if p.Requester, err = m.text(5); err != nil {
			return p, err
		}
	default:
		return p, fmt.Errorf("%w: provenance kind %d", ErrMalformed, k)
	}
	return p, m.unknown()
}

func decodeEvidence(v any) (Evidence, error) {
	var e Evidence
	m, err := asIntKeyMap(v)
	if err != nil {
		return e, err
	}
	if e.Source, err = m.text(0); err != nil {
		return e, err
	}
	if e.Time, err = m.uint(1); err != nil {
		return e, err
	}
	if e.Text, err = m.text(2); err != nil {
		return e, err
	}
	if u, ok, err := m.optUint(3); err != nil {
		return e, err
	} else if ok {
		if u == 0 {
			return e, fmt.Errorf("%w: zero count must be omitted", ErrMalformed)
		}
		e.Count = u
	}
	if x, ok := m.get(4); ok {
		if e.Labels, err = decodeStringMap(x); err != nil {
			return e, err
		}
	}
	for _, f := range []struct {
		k uint64
		p *bool
	}{{5, &e.Truncated}, {6, &e.Context}} {
		if x, ok := m.get(f.k); ok {
			b, isBool := x.(bool)
			if !isBool || !b {
				return e, fmt.Errorf("%w: flag key %d must be true when present", ErrMalformed, f.k)
			}
			*f.p = true
		}
	}
	return e, m.unknown()
}

func decodeFinding(v any) (*Finding, error) {
	m, err := asIntKeyMap(v)
	if err != nil {
		return nil, err
	}
	f := &Finding{}
	if f.ID, err = m.text(0); err != nil {
		return nil, err
	}
	if f.DedupKey, err = m.text(1); err != nil {
		return nil, err
	}
	t, err := m.uint(2)
	if err != nil {
		return nil, err
	}
	f.Transition = Transition(t)
	pv, err := m.require(3)
	if err != nil {
		return nil, err
	}
	if f.Provenance, err = decodeProvenance(pv); err != nil {
		return nil, err
	}
	if f.Category, err = m.text(4); err != nil {
		return nil, err
	}
	sev, err := m.uint(5)
	if err != nil {
		return nil, err
	}
	f.Severity = Severity(sev)
	for _, x := range []struct {
		k uint64
		p *uint64
	}{{6, &f.EvalTime}, {7, &f.FirstSeen}, {8, &f.LastSeen}, {9, &f.Count}} {
		if *x.p, err = m.uint(x.k); err != nil {
			return nil, err
		}
	}
	rv, err := m.require(10)
	if err != nil {
		return nil, err
	}
	if f.Resources, err = decodeStrings(rv, false); err != nil {
		return nil, err
	}
	if x, ok := m.get(11); ok {
		if f.Facts, err = fieldsFromDecoded(x, false); err != nil {
			return nil, err
		}
		if len(f.Facts) == 0 {
			return nil, fmt.Errorf("%w: empty facts must be omitted", ErrMalformed)
		}
	}
	if m.has(12) {
		ev, err := m.array(12)
		if err != nil {
			return nil, err
		}
		if len(ev) == 0 {
			return nil, fmt.Errorf("%w: empty evidence must be omitted", ErrMalformed)
		}
		for _, x := range ev {
			e, err := decodeEvidence(x)
			if err != nil {
				return nil, err
			}
			f.Evidence = append(f.Evidence, e)
		}
	}
	if u, ok, err := m.optUint(13); err != nil {
		return nil, err
	} else if ok {
		if u == 0 {
			return nil, fmt.Errorf("%w: zero flags must be omitted", ErrMalformed)
		}
		f.Flags = u
	}
	for _, x := range []struct {
		k uint64
		p *string
	}{{14, &f.Node}, {16, &f.Summary}} {
		if m.has(x.k) {
			if *x.p, err = m.text(x.k); err != nil {
				return nil, err
			}
			if *x.p == "" {
				return nil, fmt.Errorf("%w: empty text key %d must be omitted", ErrMalformed, x.k)
			}
		}
	}
	if x, ok := m.get(15); ok {
		if f.Labels, err = decodeStringMap(x); err != nil {
			return nil, err
		}
	}
	if m.has(17) {
		ss, err := m.array(17)
		if err != nil {
			return nil, err
		}
		if len(ss) == 0 {
			return nil, fmt.Errorf("%w: empty suggestions must be omitted", ErrMalformed)
		}
		for _, x := range ss {
			sm, err := asIntKeyMap(x)
			if err != nil {
				return nil, err
			}
			var s Suggestion
			if s.Language, err = sm.text(0); err != nil {
				return nil, err
			}
			if s.Query, err = sm.text(1); err != nil {
				return nil, err
			}
			if sm.has(2) {
				if s.Source, err = sm.text(2); err != nil {
					return nil, err
				}
				if s.Source == "" {
					return nil, fmt.Errorf("%w: empty suggestion source must be omitted", ErrMalformed)
				}
			}
			if err := sm.unknown(); err != nil {
				return nil, err
			}
			f.Suggestions = append(f.Suggestions, s)
		}
	}
	if x, ok := m.get(18); ok {
		if f.Coverage, err = decodeStrings(x, true); err != nil {
			return nil, err
		}
	}
	return f, m.unknown()
}

// Clone deep-copies a finding.
func (f Finding) Clone() Finding {
	out := f
	out.Resources = append([]string(nil), f.Resources...)
	if f.Facts != nil {
		out.Facts = CloneFields(f.Facts)
	}
	out.Evidence = make([]Evidence, len(f.Evidence))
	for i, e := range f.Evidence {
		e.Labels = cloneStrMap(e.Labels)
		out.Evidence[i] = e
	}
	if f.Evidence == nil {
		out.Evidence = nil
	}
	out.Labels = cloneStrMap(f.Labels)
	out.Suggestions = append([]Suggestion(nil), f.Suggestions...)
	out.Coverage = append([]string(nil), f.Coverage...)
	return out
}

func cloneStrMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func domainHash(domain string, parts ...[]byte) Hash {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	for _, p := range parts {
		h.Write(p)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// EncodeFinding deterministically encodes a finding body outside a record (node agent queues).
func EncodeFinding(f *Finding) ([]byte, error) {
	c := f.Clone()
	if err := c.normalize(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return Marshal(c.encode())
}

// DecodeFinding strictly decodes a finding body produced by EncodeFinding.
func DecodeFinding(b []byte) (*Finding, error) {
	v, err := decodeStrict(b)
	if err != nil {
		return nil, err
	}
	f, err := decodeFinding(v)
	if err != nil {
		return nil, err
	}
	return f, f.validate()
}
