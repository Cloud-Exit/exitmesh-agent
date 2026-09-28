package logql

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

const (
	// DefaultMaxSeries bounds rule counter cardinality when the budget sets none.
	DefaultMaxSeries = 1000
	// DefaultCounterBytes is the rule counter memory budget when the budget sets none.
	DefaultCounterBytes = 4 << 20
	// bucketBytes is the size of one counter bucket: bucket index, line count and byte count.
	bucketBytes     = 24
	bucketsPerRange = 60
	minBucketWidth  = time.Second
)

type bucket struct {
	idx   int64
	count uint64
	bytes uint64
}

type ring []bucket

func newRing(n int) ring {
	r := make(ring, n)
	for i := range r {
		r[i].idx = math.MinInt64
	}
	return r
}

func (r ring) add(b int64, n uint64) bool {
	s := &r[posMod(b, int64(len(r)))]
	switch {
	case s.idx == b:
	case s.idx < b:
		*s = bucket{idx: b}
	default:
		return false
	}
	s.count++
	s.bytes += n
	return true
}

func (r ring) sum(from, to int64) (count, bytes uint64) {
	for _, s := range r {
		if s.idx >= from && s.idx <= to {
			count += s.count
			bytes += s.bytes
		}
	}
	return count, bytes
}

func (r ring) newest() int64 {
	n := int64(math.MinInt64)
	for _, s := range r {
		if s.idx > n {
			n = s.idx
		}
	}
	return n
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func posMod(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}

type counterSeries struct {
	lbls labels.Labels
	key  string
	r    ring
}

// Program is a compiled LogQL rule evaluated over per-series time-bucketed counters; lines are never retained.
type Program struct {
	expr      Expr
	rng       *RangeAggregation
	pipe      *pipeline
	group     *Grouping
	preSum    bool
	window    int64
	width     int64
	nb        int
	maxSeries int
	reserved  int

	mu        sync.Mutex
	series    map[string]*counterSeries
	errs      ring
	lastErr   string
	maxT      int64
	lastSweep int64
	dropped   uint64
	late      uint64
	lastDrop  int64
	hasDrop   bool
}

// Status reports counter usage and budget-limited drops (PRD R9).
type Status struct {
	Series    int
	MaxSeries int
	// LiveBytes is the counter bucket memory in use; LabelBytes is the size of the series keys.
	LiveBytes  int
	LabelBytes int
	// DroppedLines counts matched lines not counted because their series exceeded MaxSeries.
	DroppedLines uint64
	// LateLines counts matched lines older than the counter window.
	LateLines uint64
	LastDrop  time.Time
	// BudgetLimited is true while a cardinality drop lies within the current window.
	BudgetLimited bool
}

// CompileRule validates a metric query against the subset and its counter budget.
func CompileRule(expr string, b bundle.Budget) (*Program, error) {
	e, err := ParseExpr(expr)
	if err != nil {
		return nil, err
	}
	if _, ok := e.(*LogExpr); ok {
		return nil, fmt.Errorf("logql: a rule must be a metric query such as count_over_time({...}[5m]) > 0, not a log query")
	}
	ra, g, preSum := findRange(e)
	if ra == nil {
		return nil, fmt.Errorf("logql: a rule needs a range aggregation")
	}
	if ra.Range < minBucketWidth {
		return nil, fmt.Errorf("logql: rule range %s is below the %s counter resolution", formatDuration(ra.Range), minBucketWidth)
	}
	if b.MaxComplexity > 0 {
		if n := countNodes(e); n > b.MaxComplexity {
			return nil, fmt.Errorf("logql: rule complexity %d exceeds the budget of %d", n, b.MaxComplexity)
		}
	}
	maxSeries := b.MaxSeries
	if maxSeries <= 0 {
		maxSeries = DefaultMaxSeries
	}
	budget := b.CounterBytes
	if budget <= 0 {
		budget = DefaultCounterBytes
	}
	width := max(ra.Range/bucketsPerRange, minBucketWidth)
	nb := int((ra.Range+width-1)/width) + 1
	req := nb * maxSeries * bucketBytes
	if req > budget {
		return nil, &BudgetError{Buckets: nb, MaxSeries: maxSeries, Required: req, CounterBytes: budget}
	}
	pipe, err := newPipeline(ra.Log)
	if err != nil {
		return nil, err
	}
	pipe.preserveErr = pipe.preserveErrors(g, preSum)
	return &Program{
		expr: e, rng: ra, pipe: pipe, group: g, preSum: preSum,
		window: int64(ra.Range), width: int64(width), nb: nb, maxSeries: maxSeries, reserved: req,
		series: map[string]*counterSeries{}, errs: newRing(nb), maxT: math.MinInt64, lastSweep: math.MinInt64,
	}, nil
}

// Expr returns the parsed rule expression.
func (p *Program) Expr() Expr { return p.expr }

// Matches reports whether a stream is selected by the rule, for the tailer's stream filter.
func (p *Program) Matches(streamLabels map[string]string) bool {
	return p.pipe.matchStream(streamLabels)
}

// Window is the counter window, the rule's range.
func (p *Program) Window() time.Duration { return time.Duration(p.window) }

// MemoryBytes is the counter memory reserved for the rule at its cardinality bound.
func (p *Program) MemoryBytes() int { return p.reserved }

// Observe applies the pipeline to one line and counts it; the line is never retained.
func (p *Program) Observe(streamLabels map[string]string, ts time.Time, line string) (matched bool) {
	if !p.pipe.matchStream(streamLabels) {
		return false
	}
	st, ok := p.pipe.process(streamLabels, line)
	if !ok {
		return false
	}
	isErr := st.err != "" && !p.pipe.preserveErr
	var lbls labels.Labels
	var key string
	if !isErr {
		lbls = projection(p.group, p.preSum, st.labels())
		key = lbls.String()
	}
	t := ts.UnixNano()
	b := floorDiv(t, p.width)
	p.mu.Lock()
	defer p.mu.Unlock()
	if t > p.maxT {
		p.maxT = t
	}
	oldest := floorDiv(p.maxT-p.window, p.width)
	if b < oldest {
		p.late++
		return true
	}
	if isErr {
		p.lastErr = st.err
		if !p.errs.add(b, uint64(len(line))) {
			p.late++
		}
		return true
	}
	s := p.series[key]
	if s == nil {
		if len(p.series) >= p.maxSeries && oldest > p.lastSweep {
			p.sweepLocked(oldest)
		}
		if len(p.series) >= p.maxSeries {
			p.dropped++
			p.lastDrop = t
			p.hasDrop = true
			return true
		}
		s = &counterSeries{lbls: lbls, key: key, r: newRing(p.nb)}
		p.series[key] = s
	}
	if !s.r.add(b, uint64(len(line))) {
		p.late++
	}
	return true
}

func (p *Program) sweepLocked(oldest int64) {
	p.lastSweep = oldest
	for k, s := range p.series {
		if s.r.newest() < oldest {
			delete(p.series, k)
		}
	}
}

// Eval computes the rule expression over the counters in the window ending at ts.
func (p *Program) Eval(ts time.Time) (promql.Vector, error) {
	t := ts.UnixNano()
	bEnd := floorDiv(t, p.width)
	bStart := floorDiv(t-p.window, p.width)
	p.mu.Lock()
	if t > p.maxT {
		p.maxT = t
	}
	if c, _ := p.errs.sum(bStart, bEnd); c > 0 {
		err := &PipelineError{Err: p.lastErr}
		p.mu.Unlock()
		return nil, err
	}
	p.sweepLocked(floorDiv(p.maxT-p.window, p.width))
	ms := ts.UnixMilli()
	var vec promql.Vector
	for _, s := range p.series {
		c, by := s.r.sum(bStart, bEnd)
		if c == 0 {
			continue
		}
		vec = append(vec, promql.Sample{T: ms, F: rangeValue(p.rng, c, by), Metric: s.lbls})
	}
	p.mu.Unlock()
	ev := &evaluator{t: ms, leaf: func(*RangeAggregation) (promql.Vector, error) { return vec, nil }}
	return ev.vector(p.expr)
}

func rangeValue(ra *RangeAggregation, count, bytes uint64) float64 {
	switch ra.Op {
	case RangeRate:
		return float64(count) / ra.Range.Seconds()
	case RangeBytes:
		return float64(bytes)
	}
	return float64(count)
}

// Status reports live counter usage and cardinality drops.
func (p *Program) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := Status{Series: len(p.series), MaxSeries: p.maxSeries, DroppedLines: p.dropped, LateLines: p.late}
	for _, s := range p.series {
		st.LiveBytes += p.nb * bucketBytes
		st.LabelBytes += len(s.key)
	}
	if p.hasDrop {
		st.LastDrop = time.Unix(0, p.lastDrop)
		st.BudgetLimited = p.lastDrop > p.maxT-p.window
	}
	return st
}
