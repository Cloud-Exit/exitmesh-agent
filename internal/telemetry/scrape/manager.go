// Package scrape is the agent's own scrape loop with per-node budgets, staleness, and coverage status.
package scrape

import (
	"log/slog"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/prometheus/storage"
)

// Health of a target.
type Health string

const (
	HealthUnknown Health = "unknown"
	HealthUp      Health = "up"
	HealthDown    Health = "down"
	HealthDropped Health = "dropped"
)

// Reasons classify the last failure or drop of a target for coverage reporting.
const (
	ReasonTargetBudget = "target_budget"
	ReasonInvalid      = "invalid_target"
	ReasonUnreachable  = "unreachable"
	ReasonTimeout      = "timeout"
	ReasonTLS          = "tls"
	ReasonUnauthorized = "unauthorized"
	ReasonHTTPStatus   = "http_status"
	ReasonParse        = "parse"
	ReasonBodyLimit    = "body_limit"
	ReasonCredentials  = "credentials"
	ReasonError        = "error"
)

// Budgets bound the scrape work of one node. Zero means unlimited.
type Budgets struct {
	MaxTargets          int
	MaxSeriesPerTarget  int
	MaxSeries           int
	MaxSamplesPerSecond int
}

// Options configures a Manager.
type Options struct {
	Appendable      storage.Appendable
	Budgets         Budgets
	DefaultInterval time.Duration
	DefaultTimeout  time.Duration
	MaxBodyBytes    int64
	Logger          *slog.Logger
}

// TargetStatus reports one target for coverage.
type TargetStatus struct {
	Key            string
	URL            string
	Labels         map[string]string
	Health         Health
	Reason         string
	LastError      string
	LastScrape     time.Time
	LastDuration   time.Duration
	Samples        int
	Series         int
	SeriesDropped  uint64
	SamplesDropped uint64
	AppendErrors   uint64
}

// Manager runs one loop per accepted target.
type Manager struct {
	o       Options
	limiter *limiter
	active  atomic.Int64

	syncMu  sync.Mutex
	mu      sync.Mutex
	loops   map[string]*loop
	dropped []TargetStatus
}

// NewManager returns a Manager with defaults applied.
func NewManager(o Options) *Manager {
	if o.DefaultInterval <= 0 {
		o.DefaultInterval = 30 * time.Second
	}
	if o.DefaultTimeout <= 0 {
		o.DefaultTimeout = 10 * time.Second
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 32 << 20
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Manager{o: o, limiter: newLimiter(float64(o.Budgets.MaxSamplesPerSecond), time.Now), loops: map[string]*loop{}}
}

// Sync replaces the target set, admitting targets in order up to MaxTargets and staling removed ones.
func (m *Manager) Sync(targets []Target) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	seen := map[string]bool{}
	var accepted []Target
	var dropped []TargetStatus
	maxInterval := time.Second
	for _, t := range targets {
		k := t.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		if t.Interval <= 0 {
			t.Interval = m.o.DefaultInterval
		}
		if t.Timeout <= 0 {
			t.Timeout = m.o.DefaultTimeout
		}
		t.Timeout = min(t.Timeout, t.Interval)
		if _, err := t.targetLabels(); err != nil {
			dropped = append(dropped, TargetStatus{Key: k, URL: t.URL, Labels: copyMap(t.Labels), Health: HealthDropped, Reason: ReasonInvalid, LastError: err.Error()})
			continue
		}
		if b := m.o.Budgets.MaxTargets; b > 0 && len(accepted) >= b {
			dropped = append(dropped, TargetStatus{Key: k, URL: t.URL, Labels: copyMap(t.Labels), Health: HealthDropped, Reason: ReasonTargetBudget})
			continue
		}
		accepted = append(accepted, t)
		maxInterval = max(maxInterval, t.Interval)
	}
	m.limiter.setBurst(maxInterval)

	want := make(map[string]Target, len(accepted))
	for _, t := range accepted {
		want[t.Key()] = t
	}
	m.mu.Lock()
	var stop []*loop
	for k, l := range m.loops {
		if t, ok := want[k]; !ok || t.config() != l.t.config() {
			stop = append(stop, l)
			delete(m.loops, k)
		}
	}
	m.mu.Unlock()
	for _, l := range stop {
		l.stop()
	}
	m.mu.Lock()
	for _, t := range accepted {
		k := t.Key()
		if _, ok := m.loops[k]; ok {
			continue
		}
		l := newLoop(m, t)
		m.loops[k] = l
		go l.run()
	}
	m.dropped = dropped
	m.mu.Unlock()
}

// Status returns every known target, dropped ones included, ordered by key.
func (m *Manager) Status() []TargetStatus {
	m.mu.Lock()
	out := make([]TargetStatus, 0, len(m.loops)+len(m.dropped))
	for _, l := range m.loops {
		out = append(out, l.snapshot())
	}
	out = append(out, m.dropped...)
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ActiveSeries is the number of scraped series currently held against the node budget.
func (m *Manager) ActiveSeries() int { return int(m.active.Load()) }

// Stop ends every loop, writing staleness markers.
func (m *Manager) Stop() { m.Sync(nil) }

func (m *Manager) reserveSeries() bool {
	b := int64(m.o.Budgets.MaxSeries)
	for {
		cur := m.active.Load()
		if b > 0 && cur >= b {
			return false
		}
		if m.active.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (m *Manager) releaseSeries(n int) { m.active.Add(-int64(n)) }

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// limiter is a token bucket over samples; burst covers the longest scrape interval.
type limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newLimiter(rate float64, now func() time.Time) *limiter {
	l := &limiter{rate: rate, now: now, last: now()}
	l.burst, l.tokens = rate, rate
	return l
}

func (l *limiter) setBurst(interval time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	nb := l.rate * interval.Seconds()
	if nb > l.burst {
		l.tokens += nb - l.burst
	}
	l.burst = nb
	l.tokens = min(l.tokens, l.burst)
}

func (l *limiter) take(n int) int {
	if l.rate <= 0 {
		return n
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if el := now.Sub(l.last).Seconds(); el > 0 {
		l.tokens = min(l.burst, l.tokens+el*l.rate)
	}
	l.last = now
	g := min(n, int(math.Floor(l.tokens)))
	l.tokens -= float64(g)
	return g
}

func (l *limiter) giveBack(n int) {
	if l.rate <= 0 || n <= 0 {
		return
	}
	l.mu.Lock()
	l.tokens = min(l.burst, l.tokens+float64(n))
	l.mu.Unlock()
}
