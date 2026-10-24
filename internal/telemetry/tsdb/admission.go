package tsdb

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunks"
)

// ErrSeriesLimit reports that a new series would exceed the retained head budget.
var ErrSeriesLimit = errors.New("tsdb: retained series limit reached")

type seriesBudget struct {
	limit     int64
	count     atomic.Int64
	enforcing atomic.Bool
}

func (b *seriesBudget) PreCreation(labels.Labels) error {
	if b.enforcing.Load() && b.count.Load() >= b.limit {
		return ErrSeriesLimit
	}
	return nil
}

func (b *seriesBudget) PostCreation(labels.Labels) { b.count.Add(1) }

func (b *seriesBudget) PostDeletion(deleted map[chunks.HeadSeriesRef]labels.Labels) {
	b.count.Add(-int64(len(deleted)))
}

type limitedAppender struct {
	storage.Appender
	mu *sync.Mutex
}

func (a *limitedAppender) Append(ref storage.SeriesRef, l labels.Labels, t int64, v float64) (storage.SeriesRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Appender.Append(ref, l, t, v)
}

func (a *limitedAppender) AppendHistogram(ref storage.SeriesRef, l labels.Labels, t int64, h *histogram.Histogram, fh *histogram.FloatHistogram) (storage.SeriesRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Appender.AppendHistogram(ref, l, t, h, fh)
}

func (a *limitedAppender) AppendHistogramSTZeroSample(ref storage.SeriesRef, l labels.Labels, t, st int64, h *histogram.Histogram, fh *histogram.FloatHistogram) (storage.SeriesRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Appender.AppendHistogramSTZeroSample(ref, l, t, st, h, fh)
}

func (a *limitedAppender) AppendSTZeroSample(ref storage.SeriesRef, l labels.Labels, t, st int64) (storage.SeriesRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Appender.AppendSTZeroSample(ref, l, t, st)
}
