package node

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
)

var errDiskCap = errors.New("node: disk cap reached, sample ingestion paused")

// gatedAppendable stops scrape ingestion while the state directory stays above its cap after shrinking.
type gatedAppendable struct {
	next    storage.Appendable
	paused  atomic.Bool
	dropped atomic.Uint64
}

func (g *gatedAppendable) Appender(ctx context.Context) storage.Appender {
	app := g.next.Appender(ctx)
	if !g.paused.Load() {
		return app
	}
	return &pausedAppender{Appender: app, g: g}
}

type pausedAppender struct {
	storage.Appender
	g *gatedAppendable
}

func (p *pausedAppender) reject() (storage.SeriesRef, error) {
	p.g.dropped.Add(1)
	return 0, errDiskCap
}

func (p *pausedAppender) Append(storage.SeriesRef, labels.Labels, int64, float64) (storage.SeriesRef, error) {
	return p.reject()
}

func (p *pausedAppender) AppendExemplar(storage.SeriesRef, labels.Labels, exemplar.Exemplar) (storage.SeriesRef, error) {
	return p.reject()
}

func (p *pausedAppender) AppendHistogram(storage.SeriesRef, labels.Labels, int64, *histogram.Histogram, *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return p.reject()
}

func (p *pausedAppender) AppendHistogramSTZeroSample(storage.SeriesRef, labels.Labels, int64, int64, *histogram.Histogram, *histogram.FloatHistogram) (storage.SeriesRef, error) {
	return p.reject()
}

func (p *pausedAppender) AppendSTZeroSample(storage.SeriesRef, labels.Labels, int64, int64) (storage.SeriesRef, error) {
	return p.reject()
}
