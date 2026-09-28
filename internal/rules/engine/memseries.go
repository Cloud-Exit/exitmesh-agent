package engine

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/model/value"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/tsdb/chunks"
	"github.com/prometheus/prometheus/util/annotations"
)

// Sample is one float sample at a millisecond timestamp.
type Sample struct {
	T int64
	F float64
}

// Series is a labeled sequence of samples in ascending time order.
type Series struct {
	Labels  labels.Labels
	Samples []Sample
}

// MemSeries is an in-memory storage.Queryable fed per source; replaced-away series get staleness markers.
type MemSeries struct {
	mu        sync.RWMutex
	retention time.Duration
	clock     func() time.Time
	sources   map[string]map[string]*memSerie
}

type memSerie struct {
	lset    labels.Labels
	samples []Sample
}

// NewMemSeries returns an empty store keeping samples for retention (default 1h).
func NewMemSeries(retention time.Duration, clock func() time.Time) *MemSeries {
	if retention <= 0 {
		retention = time.Hour
	}
	if clock == nil {
		clock = time.Now
	}
	return &MemSeries{retention: retention, clock: clock, sources: map[string]map[string]*memSerie{}}
}

// Replace sets the current series of source. Series of source absent from series are marked stale.
func (m *MemSeries) Replace(source string, series []Series) {
	maxT := int64(math.MinInt64)
	for _, s := range series {
		for _, p := range s.Samples {
			if p.T > maxT {
				maxT = p.T
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if maxT == math.MinInt64 {
		maxT = timestamp.FromTime(m.clock())
	}
	cur := m.sources[source]
	if cur == nil {
		cur = map[string]*memSerie{}
		m.sources[source] = cur
	}
	seen := make(map[string]bool, len(series))
	for _, s := range series {
		key := s.Labels.String()
		seen[key] = true
		ms := cur[key]
		if ms == nil {
			ms = &memSerie{lset: s.Labels.Copy()}
			cur[key] = ms
		}
		pts := append([]Sample(nil), s.Samples...)
		sort.SliceStable(pts, func(i, j int) bool { return pts[i].T < pts[j].T })
		for _, p := range pts {
			if n := len(ms.samples); n == 0 || p.T > ms.samples[n-1].T {
				ms.samples = append(ms.samples, p)
			}
		}
	}
	for key, ms := range cur {
		if seen[key] {
			continue
		}
		n := len(ms.samples)
		if n > 0 && value.IsStaleNaN(ms.samples[n-1].F) {
			continue
		}
		t := maxT
		if n > 0 && t <= ms.samples[n-1].T {
			t = ms.samples[n-1].T + 1
		}
		ms.samples = append(ms.samples, Sample{T: t, F: math.Float64frombits(value.StaleNaN)})
	}
	cutoff := maxT - m.retention.Milliseconds()
	for key, ms := range cur {
		i := sort.Search(len(ms.samples), func(i int) bool { return ms.samples[i].T >= cutoff })
		if i == len(ms.samples) {
			delete(cur, key)
			continue
		}
		if i > 0 {
			ms.samples = append([]Sample(nil), ms.samples[i:]...)
		}
	}
	if len(cur) == 0 {
		delete(m.sources, source)
	}
}

// Sources returns the names of sources currently holding series, sorted.
func (m *MemSeries) Sources() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.sources))
	for s := range m.sources {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Querier implements storage.Queryable.
func (m *MemSeries) Querier(mint, maxt int64) (storage.Querier, error) {
	return &memQuerier{m: m, mint: mint, maxt: maxt}, nil
}

type memQuerier struct {
	m          *MemSeries
	mint, maxt int64
}

func matchAll(lset labels.Labels, ms []*labels.Matcher) bool {
	for _, m := range ms {
		if !m.Matches(lset.Get(m.Name)) {
			return false
		}
	}
	return true
}

type selected struct {
	lset    labels.Labels
	samples []Sample
	merged  bool
}

func (q *memQuerier) collect(start, end int64, ms []*labels.Matcher) []*selected {
	q.m.mu.RLock()
	byKey := map[string]*selected{}
	for _, src := range q.m.sources {
		for key, s := range src {
			if !matchAll(s.lset, ms) {
				continue
			}
			lo := sort.Search(len(s.samples), func(i int) bool { return s.samples[i].T >= start })
			hi := sort.Search(len(s.samples), func(i int) bool { return s.samples[i].T > end })
			if lo >= hi {
				continue
			}
			pts := append([]Sample(nil), s.samples[lo:hi]...)
			if cur, ok := byKey[key]; ok {
				cur.samples = append(cur.samples, pts...)
				cur.merged = true
				continue
			}
			byKey[key] = &selected{lset: s.lset, samples: pts}
		}
	}
	q.m.mu.RUnlock()
	out := make([]*selected, 0, len(byKey))
	for _, s := range byKey {
		if s.merged {
			sort.SliceStable(s.samples, func(i, j int) bool { return s.samples[i].T < s.samples[j].T })
			dedup := s.samples[:1]
			for _, p := range s.samples[1:] {
				if p.T != dedup[len(dedup)-1].T {
					dedup = append(dedup, p)
				}
			}
			s.samples = dedup
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return labels.Compare(out[i].lset, out[j].lset) < 0 })
	return out
}

func (q *memQuerier) Select(_ context.Context, _ bool, hints *storage.SelectHints, ms ...*labels.Matcher) storage.SeriesSet {
	start, end := q.mint, q.maxt
	if hints != nil {
		start, end = hints.Start, hints.End
	}
	sel := q.collect(start, end, ms)
	set := &sliceSet{series: make([]storage.Series, len(sel))}
	for i, s := range sel {
		pts := make([]chunks.Sample, len(s.samples))
		for j, p := range s.samples {
			pts[j] = memSample{t: p.T, f: p.F}
		}
		set.series[i] = storage.NewListSeries(s.lset, pts)
	}
	return set
}

func (q *memQuerier) LabelValues(_ context.Context, name string, _ *storage.LabelHints, ms ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	seen := map[string]bool{}
	for _, s := range q.collect(q.mint, q.maxt, ms) {
		if v := s.lset.Get(name); v != "" {
			seen[v] = true
		}
	}
	return sortedKeys(seen), nil, nil
}

func (q *memQuerier) LabelNames(_ context.Context, _ *storage.LabelHints, ms ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	seen := map[string]bool{}
	for _, s := range q.collect(q.mint, q.maxt, ms) {
		s.lset.Range(func(l labels.Label) { seen[l.Name] = true })
	}
	return sortedKeys(seen), nil, nil
}

func (q *memQuerier) Close() error { return nil }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type sliceSet struct {
	series []storage.Series
	i      int
}

func (s *sliceSet) Next() bool {
	if s.i >= len(s.series) {
		return false
	}
	s.i++
	return true
}
func (s *sliceSet) At() storage.Series                { return s.series[s.i-1] }
func (s *sliceSet) Err() error                        { return nil }
func (s *sliceSet) Warnings() annotations.Annotations { return nil }

type memSample struct {
	t int64
	f float64
}

func (s memSample) T() int64                      { return s.t }
func (s memSample) ST() int64                     { return 0 }
func (s memSample) F() float64                    { return s.f }
func (s memSample) H() *histogram.Histogram       { return nil }
func (s memSample) FH() *histogram.FloatHistogram { return nil }
func (s memSample) Type() chunkenc.ValueType      { return chunkenc.ValFloat }
func (s memSample) Copy() chunks.Sample           { return s }
