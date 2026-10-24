// Package evidence holds redacted matched lines under a per-node byte ceiling split into rule shares.
package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

// DefaultCeiling is the per-node ring size.
const DefaultCeiling = 16 << 20

const sampleOverhead = 64

// Sample is one matched line kept as evidence.
type Sample struct {
	Time   time.Time
	Labels map[string]string
	Text   string
}

// RuleStats describes one rule's share.
type RuleStats struct {
	Weight   float64
	Share    int64
	Bytes    int64
	Samples  int
	Evicted  uint64
	Rejected uint64
	// Limited is sticky while the rule is active: some of its evidence was evicted or rejected.
	Limited bool
}

// Stats describes the ring.
type Stats struct {
	Ceiling int64
	Bytes   int64
	Rules   map[string]RuleStats
}

type item struct {
	s    Sample
	size int64
}

type ruleRing struct {
	weight            float64
	share             int64
	items             []item
	head              int
	bytes             int64
	evicted, rejected uint64
	limited           bool
	limitedSinceTake  bool
}

func (rr *ruleRing) len() int { return len(rr.items) - rr.head }

func (rr *ruleRing) evictOldest() {
	rr.bytes -= rr.items[rr.head].size
	rr.items[rr.head] = item{}
	rr.head++
	rr.evicted++
	rr.limited, rr.limitedSinceTake = true, true
	if rr.head > 64 && rr.head*2 > len(rr.items) {
		rr.items = append([]item(nil), rr.items[rr.head:]...)
		rr.head = 0
	}
}

func (rr *ruleRing) fit(extra int64) {
	for rr.len() > 0 && rr.bytes+extra > rr.share {
		rr.evictOldest()
	}
}

// Ring is safe for concurrent use.
type Ring struct {
	mu         sync.Mutex
	ceiling    int64
	red        *redact.Redactor
	rules      map[string]*ruleRing
	bytes      int64
	labelHash  [32]byte
	labelCache map[string]string
	labelSize  int64
}

// New returns a ring with the given ceiling (DefaultCeiling when zero or negative).
func New(ceiling int64) *Ring {
	return NewWithRedactor(ceiling, nil)
}

// NewWithRedactor applies the agent's complete redaction policy at the evidence boundary.
func NewWithRedactor(ceiling int64, red *redact.Redactor) *Ring {
	if ceiling <= 0 {
		ceiling = DefaultCeiling
	}
	if red == nil {
		red = redact.Default()
	}
	return &Ring{ceiling: ceiling, red: red, rules: map[string]*ruleRing{}}
}

// SetRules sets active rules and weights (non-positive means 1) and drops samples of unlisted rules.
func (r *Ring) SetRules(weights map[string]float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, rr := range r.rules {
		if _, ok := weights[id]; !ok {
			r.bytes -= rr.bytes
			delete(r.rules, id)
		}
	}
	for id, w := range weights {
		if w <= 0 {
			w = 1
		}
		rr := r.rules[id]
		if rr == nil {
			rr = &ruleRing{}
			r.rules[id] = rr
		}
		rr.weight = w
	}
	r.reshare()
}

func (r *Ring) reshare() {
	var total float64
	for _, rr := range r.rules {
		total += rr.weight
	}
	for _, rr := range r.rules {
		rr.share = int64(float64(r.ceiling) * rr.weight / total)
		before := rr.bytes
		rr.fit(0)
		r.bytes -= before - rr.bytes
	}
}

func (r *Ring) clean(s Sample) (Sample, int64) {
	out := Sample{Time: s.Time, Text: r.red.String(s.Text)}
	size := int64(len(out.Text) + sampleOverhead)
	if len(s.Labels) > 0 {
		key := labelFingerprint(s.Labels)
		if r.labelCache != nil && key == r.labelHash {
			out.Labels = r.labelCache
			return out, size + r.labelSize
		}
		out.Labels = make(map[string]string, len(s.Labels))
		labelSize := int64(64 + 64*len(s.Labels))
		for k, v := range s.Labels {
			v = r.red.KeyValue(k, v)
			out.Labels[k] = v
			labelSize += int64(len(k) + len(v))
		}
		size += labelSize
		if labelSize <= 64<<10 {
			r.labelHash, r.labelCache, r.labelSize = key, out.Labels, labelSize
		}
	}
	return out, size
}

func labelFingerprint(labels map[string]string) [32]byte {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	var length [8]byte
	for _, k := range keys {
		for _, s := range []string{k, labels[k]} {
			binary.LittleEndian.PutUint64(length[:], uint64(len(s)))
			h.Write(length[:])
			h.Write([]byte(s))
		}
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Add redacts and stores a matched sample, activating unknown rules with weight 1.
func (r *Ring) Add(ruleID string, s Sample) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, size := r.clean(s)
	return r.add(ruleID, s, size)
}

// AddMany sanitizes one sample once and shares it across its matching rules.
func (r *Ring) AddMany(ruleIDs []string, s Sample) {
	if len(ruleIDs) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, size := r.clean(s)
	for _, id := range ruleIDs {
		r.add(id, s, size)
	}
}

func (r *Ring) add(ruleID string, s Sample, size int64) bool {
	rr := r.rules[ruleID]
	if rr == nil {
		rr = &ruleRing{weight: 1}
		r.rules[ruleID] = rr
		r.reshare()
	}
	if size > rr.share {
		rr.rejected++
		rr.limited, rr.limitedSinceTake = true, true
		return false
	}
	before := rr.bytes
	rr.fit(size)
	r.bytes -= before - rr.bytes
	rr.items = append(rr.items, item{s, size})
	rr.bytes += size
	r.bytes += size
	return true
}

// Take clears the rule and returns its newest n samples and whether any were lost since the last Take.
func (r *Ring) Take(ruleID string, n int) ([]Sample, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rr := r.rules[ruleID]
	if rr == nil {
		return nil, false
	}
	live := rr.items[rr.head:]
	n = max(n, 0)
	if len(live) > n {
		live = live[len(live)-n:]
	}
	out := make([]Sample, len(live))
	for i, it := range live {
		out[i] = it.s
		out[i].Labels = maps.Clone(it.s.Labels)
	}
	limited := rr.limitedSinceTake
	r.bytes -= rr.bytes
	rr.items, rr.head, rr.bytes, rr.limitedSinceTake = nil, 0, 0, false
	return out, limited
}

// Peek returns a rule's newest n samples without removing them (investigation reads, PRD I1).
func (r *Ring) Peek(ruleID string, n int) []Sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	rr := r.rules[ruleID]
	if rr == nil {
		return nil
	}
	live := rr.items[rr.head:]
	if n = max(n, 0); len(live) > n {
		live = live[len(live)-n:]
	}
	out := make([]Sample, len(live))
	for i, it := range live {
		s := it.s
		s.Labels = maps.Clone(it.s.Labels)
		out[i] = s
	}
	return out
}

// Limited reports whether a rule is evidence-limited.
func (r *Ring) Limited(ruleID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rr := r.rules[ruleID]
	return rr != nil && rr.limited
}

// LimitedRules lists evidence-limited rules in order.
func (r *Ring) LimitedRules() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for id, rr := range r.rules {
		if rr.limited {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Stats returns a snapshot.
func (r *Ring) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Stats{Ceiling: r.ceiling, Bytes: r.bytes, Rules: make(map[string]RuleStats, len(r.rules))}
	for id, rr := range r.rules {
		st.Rules[id] = RuleStats{Weight: rr.weight, Share: rr.share, Bytes: rr.bytes, Samples: rr.len(), Evicted: rr.evicted, Rejected: rr.rejected, Limited: rr.limited}
	}
	return st
}
