package logql

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
)

// Default investigation limits, applied when a Limits field is zero.
const (
	DefaultMaxLines    = 1000
	DefaultMaxBytes    = 1 << 20
	DefaultQuerySeries = 500
	DefaultMaxSamples  = 50000
)

// Truncation reasons reported in Result.Limited.
const (
	LimitLines   = "max_lines"
	LimitBytes   = "max_bytes"
	LimitSeries  = "max_series"
	LimitSamples = "max_samples"
	LimitTimeout = "timeout"
)

// Direction orders log query results.
type Direction int

const (
	// Backward returns the newest lines first.
	Backward Direction = iota
	// Forward returns the oldest lines first.
	Forward
)

// Line is one log line with its stream labels.
type Line struct {
	Labels map[string]string
	Time   time.Time
	Text   string
}

// SourceRequest names the streams and the inclusive time range a query can use.
type SourceRequest struct {
	Matchers   []*labels.Matcher
	Start, End time.Time
}

// Match reports whether a stream is selected by the request matchers.
func (r SourceRequest) Match(streamLabels map[string]string) bool {
	for _, m := range r.Matchers {
		if !m.Matches(streamLabels[m.Name]) {
			return false
		}
	}
	return true
}

// LineSource streams candidate lines in any order; yield returning false stops the scan.
type LineSource interface {
	Scan(ctx context.Context, req SourceRequest, yield func(Line) bool) error
}

// LineSourceFunc adapts a function to LineSource.
type LineSourceFunc func(ctx context.Context, req SourceRequest, yield func(Line) bool) error

// Scan calls f.
func (f LineSourceFunc) Scan(ctx context.Context, req SourceRequest, yield func(Line) bool) error {
	return f(ctx, req, yield)
}

// Lines is an in-memory LineSource yielding lines in slice order.
type Lines []Line

// Scan yields the lines of selected streams within the request range.
func (ls Lines) Scan(ctx context.Context, req SourceRequest, yield func(Line) bool) error {
	for _, l := range ls {
		if err := ctx.Err(); err != nil {
			return err
		}
		if l.Time.Before(req.Start) || l.Time.After(req.End) || !req.Match(l.Labels) {
			continue
		}
		if !yield(l) {
			return nil
		}
	}
	return nil
}

// Limits bounds an investigation query (PRD I3). Start and End are required.
type Limits struct {
	Start, End time.Time
	// Step selects a range metric query; zero evaluates a metric query at End only.
	Step       time.Duration
	Direction  Direction
	MaxLines   int
	MaxBytes   int
	MaxSeries  int
	MaxSamples int
	Timeout    time.Duration
}

func (l Limits) withDefaults() Limits {
	if l.MaxLines <= 0 {
		l.MaxLines = DefaultMaxLines
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxSeries <= 0 {
		l.MaxSeries = DefaultQuerySeries
	}
	if l.MaxSamples <= 0 {
		l.MaxSamples = DefaultMaxSamples
	}
	return l
}

// ResultType is the shape of a query result.
type ResultType string

const (
	ResultStreams ResultType = "streams"
	ResultVector  ResultType = "vector"
	ResultMatrix  ResultType = "matrix"
)

// ResultLine is one matching line with its stream and extracted labels.
type ResultLine struct {
	Time   time.Time
	Labels labels.Labels
	Text   string
}

// Result is a bounded investigation result; Truncated is set with the limits that cut it.
type Result struct {
	Type         ResultType
	Lines        []ResultLine
	Vector       promql.Vector
	Matrix       promql.Matrix
	Start, End   time.Time
	Step         time.Duration
	Truncated    bool
	Limited      []string
	ScannedLines int64
	ScannedBytes int64
	ResultBytes  int
}

func (r *Result) limit(reason string) {
	r.Truncated = true
	for _, l := range r.Limited {
		if l == reason {
			return
		}
	}
	r.Limited = append(r.Limited, reason)
}

// RunQuery evaluates a query over src within lim, retaining nothing; a timeout returns a partial result marked LimitTimeout.
func RunQuery(ctx context.Context, query string, src LineSource, lim Limits) (*Result, error) {
	e, err := ParseExpr(query)
	if err != nil {
		return nil, err
	}
	if lim.Start.IsZero() || lim.End.IsZero() || lim.End.Before(lim.Start) {
		return nil, fmt.Errorf("logql: query window requires Start <= End")
	}
	if lim.Step < 0 {
		return nil, fmt.Errorf("logql: negative query step")
	}
	lim = lim.withDefaults()
	qctx := ctx
	if lim.Timeout > 0 {
		var cancel context.CancelFunc
		qctx, cancel = context.WithTimeout(ctx, lim.Timeout)
		defer cancel()
	}
	res := &Result{Start: lim.Start, End: lim.End, Step: lim.Step}
	var scanErr error
	if log, ok := e.(*LogExpr); ok {
		scanErr = runLogQuery(qctx, log, src, lim, res)
	} else {
		scanErr = runMetricQuery(qctx, e, src, lim, res)
	}
	if scanErr != nil {
		if ctx.Err() == nil && errors.Is(scanErr, context.DeadlineExceeded) {
			res.limit(LimitTimeout)
			return res, nil
		}
		return nil, scanErr
	}
	return res, nil
}

type heldLine struct {
	ResultLine
	seq int64
}

type lineHeap struct {
	items []heldLine
	// evictFirst orders the line to evict first at the root.
	evictFirst func(a, b heldLine) bool
}

func (h *lineHeap) Len() int           { return len(h.items) }
func (h *lineHeap) Less(i, j int) bool { return h.evictFirst(h.items[i], h.items[j]) }
func (h *lineHeap) Swap(i, j int)      { h.items[i], h.items[j] = h.items[j], h.items[i] }
func (h *lineHeap) Push(x any)         { h.items = append(h.items, x.(heldLine)) }
func (h *lineHeap) Pop() any {
	x := h.items[len(h.items)-1]
	h.items = h.items[:len(h.items)-1]
	return x
}

func older(a, b heldLine) bool {
	if !a.Time.Equal(b.Time) {
		return a.Time.Before(b.Time)
	}
	return a.seq < b.seq
}

func runLogQuery(ctx context.Context, log *LogExpr, src LineSource, lim Limits, res *Result) error {
	res.Type = ResultStreams
	pipe, err := newPipeline(log)
	if err != nil {
		return err
	}
	h := &lineHeap{evictFirst: older}
	if lim.Direction == Forward {
		h.evictFirst = func(a, b heldLine) bool { return older(b, a) }
	}
	bytes := 0
	var seq int64
	var ctxErr error
	req := SourceRequest{Matchers: log.Matchers, Start: lim.Start, End: lim.End}
	err = src.Scan(ctx, req, func(l Line) bool {
		if ctxErr = ctx.Err(); ctxErr != nil {
			return false
		}
		res.ScannedLines++
		res.ScannedBytes += int64(len(l.Text))
		if l.Time.Before(lim.Start) || !l.Time.Before(lim.End) || !pipe.matchStream(l.Labels) {
			return true
		}
		st, ok := pipe.process(l.Labels, l.Text)
		if !ok {
			return true
		}
		seq++
		heap.Push(h, heldLine{ResultLine: ResultLine{Time: l.Time, Labels: st.labels(), Text: l.Text}, seq: seq})
		bytes += len(l.Text)
		for h.Len() > lim.MaxLines || bytes > lim.MaxBytes {
			if h.Len() > lim.MaxLines {
				res.limit(LimitLines)
			} else {
				res.limit(LimitBytes)
			}
			x := heap.Pop(h).(heldLine)
			bytes -= len(x.Text)
		}
		return true
	})
	if err == nil {
		err = ctxErr
	}
	items := h.items
	sort.Slice(items, func(i, j int) bool {
		if lim.Direction == Forward {
			return older(items[i], items[j])
		}
		return older(items[j], items[i])
	})
	res.Lines = make([]ResultLine, len(items))
	for i, it := range items {
		res.Lines[i] = it.ResultLine
	}
	res.ResultBytes = bytes
	return err
}

type stepSeries struct {
	lbls   labels.Labels
	counts []uint64
	bytes  []uint64
}

func runMetricQuery(ctx context.Context, e Expr, src LineSource, lim Limits, res *Result) error {
	ra, g, preSum := findRange(e)
	pipe, err := newPipeline(ra.Log)
	if err != nil {
		return err
	}
	pipe.preserveErr = pipe.preserveErrors(g, preSum)
	steps := []int64{lim.End.UnixNano()}
	res.Type = ResultVector
	if lim.Step > 0 {
		res.Type = ResultMatrix
		n := int64(lim.End.Sub(lim.Start)/lim.Step) + 1
		if n > int64(lim.MaxSamples) {
			return fmt.Errorf("logql: %d steps exceed the sample limit of %d", n, lim.MaxSamples)
		}
		steps = make([]int64, n)
		for i := range steps {
			steps[i] = lim.Start.Add(time.Duration(i) * lim.Step).UnixNano()
		}
	}
	rng := int64(ra.Range)
	first, last := steps[0], steps[len(steps)-1]
	series := map[string]*stepSeries{}
	errSteps := make([]string, len(steps))
	cells := 0
	var ctxErr error
	req := SourceRequest{Matchers: ra.Log.Matchers, Start: time.Unix(0, first-rng+1), End: time.Unix(0, last)}
	err = src.Scan(ctx, req, func(l Line) bool {
		if ctxErr = ctx.Err(); ctxErr != nil {
			return false
		}
		res.ScannedLines++
		res.ScannedBytes += int64(len(l.Text))
		ts := l.Time.UnixNano()
		if ts <= first-rng || ts > last || !pipe.matchStream(l.Labels) {
			return true
		}
		lo, hi := stepRange(steps, ts, rng, lim.Step)
		if lo > hi {
			return true
		}
		st, ok := pipe.process(l.Labels, l.Text)
		if !ok {
			return true
		}
		if st.err != "" && !pipe.preserveErr {
			for k := lo; k <= hi; k++ {
				errSteps[k] = st.err
			}
			return true
		}
		lbls := projection(g, preSum, st.labels())
		key := lbls.String()
		s := series[key]
		if s == nil {
			if len(series) >= lim.MaxSeries {
				res.limit(LimitSeries)
				return true
			}
			if cells+len(steps) > lim.MaxSamples {
				res.limit(LimitSamples)
				return true
			}
			cells += len(steps)
			s = &stepSeries{lbls: lbls, counts: make([]uint64, len(steps)), bytes: make([]uint64, len(steps))}
			series[key] = s
		}
		for k := lo; k <= hi; k++ {
			s.counts[k]++
			s.bytes[k] += uint64(len(l.Text))
		}
		return true
	})
	if err == nil {
		err = ctxErr
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	matrix := map[string]*promql.Series{}
	points := 0
	for k, t := range steps {
		if errSteps[k] != "" {
			return &PipelineError{Err: errSteps[k]}
		}
		ms := time.Unix(0, t).UnixMilli()
		ev := &evaluator{t: ms, leaf: func(*RangeAggregation) (promql.Vector, error) {
			var v promql.Vector
			for _, s := range series {
				if s.counts[k] > 0 {
					v = append(v, promql.Sample{T: ms, F: rangeValue(ra, s.counts[k], s.bytes[k]), Metric: s.lbls})
				}
			}
			return v, nil
		}}
		vec, evErr := ev.vector(e)
		if evErr != nil {
			return evErr
		}
		if res.Type == ResultVector {
			res.Vector = vec
			continue
		}
		for _, smp := range vec {
			if points >= lim.MaxSamples {
				res.limit(LimitSamples)
				break
			}
			key := smp.Metric.String()
			sr := matrix[key]
			if sr == nil {
				sr = &promql.Series{Metric: smp.Metric}
				matrix[key] = sr
			}
			sr.Floats = append(sr.Floats, promql.FPoint{T: ms, F: smp.F})
			points++
		}
	}
	for _, sr := range matrix {
		res.Matrix = append(res.Matrix, *sr)
	}
	sort.Slice(res.Matrix, func(i, j int) bool { return labels.Compare(res.Matrix[i].Metric, res.Matrix[j].Metric) < 0 })
	return err
}

// stepRange returns the step indexes whose window (t-range, t] contains ts.
func stepRange(steps []int64, ts, rng int64, step time.Duration) (int, int) {
	if step <= 0 {
		if ts > steps[0]-rng && ts <= steps[0] {
			return 0, 0
		}
		return 1, 0
	}
	st := int64(step)
	lo := ceilDiv(ts-steps[0], st)
	hi := floorDiv(ts+rng-1-steps[0], st)
	lo = max(lo, 0)
	hi = min(hi, int64(len(steps)-1))
	return int(lo), int(hi)
}

func ceilDiv(a, b int64) int64 { return -floorDiv(-a, b) }
