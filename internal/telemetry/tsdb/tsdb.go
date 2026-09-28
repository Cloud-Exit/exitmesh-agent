// Package tsdb wraps the Prometheus TSDB with rule-derived retention, a size ceiling, and pressure shrinking.
package tsdb

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/alecthomas/units"
	"github.com/prometheus/common/model"
	promcfg "github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/storage"
	ptsdb "github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/util/compression"
)

// HardCeiling bounds retention regardless of what rules request.
const HardCeiling = 6 * time.Hour

// Defaults.
const (
	DefaultBlockDuration   = 30 * time.Minute
	DefaultWALSegmentBytes = 8 << 20
	minShrinkSpan          = int64(time.Minute / time.Millisecond)
)

// Options configures Open.
type Options struct {
	// Retention is derived from rules; zero or anything above HardCeiling means HardCeiling.
	Retention time.Duration
	// MaxBytes bounds blocks, WAL, and head chunks together; zero disables the size bound.
	MaxBytes int64
	// BlockDuration is the head compaction granularity, which is also the retention granularity.
	BlockDuration time.Duration
	// WALSegmentBytes must be a multiple of 32 KiB.
	WALSegmentBytes int
	Logger          *slog.Logger
}

// DB is an open local TSDB. It implements storage.Queryable and storage.Appendable.
type DB struct {
	db *ptsdb.DB

	mu        sync.Mutex
	retention time.Duration
	maxBytes  int64
	limit     int64
}

var (
	_ storage.Queryable  = (*DB)(nil)
	_ storage.Appendable = (*DB)(nil)
)

// ClampRetention applies the hard ceiling.
func ClampRetention(r time.Duration) time.Duration {
	if r <= 0 || r > HardCeiling {
		return HardCeiling
	}
	return r
}

// Open opens or creates the TSDB in dir with a write-ahead log.
func Open(dir string, o Options) (*DB, error) {
	if o.BlockDuration <= 0 {
		o.BlockDuration = DefaultBlockDuration
	}
	if o.WALSegmentBytes <= 0 {
		o.WALSegmentBytes = DefaultWALSegmentBytes
	}
	if o.MaxBytes < 0 {
		return nil, errors.New("tsdb: negative MaxBytes")
	}
	ret := ClampRetention(o.Retention)
	opts := ptsdb.DefaultOptions()
	opts.RetentionDuration = ret.Milliseconds()
	opts.MaxBytes = o.MaxBytes
	opts.MinBlockDuration = o.BlockDuration.Milliseconds()
	// No block merging keeps retention and shrink granularity at one block.
	opts.MaxBlockDuration = opts.MinBlockDuration
	opts.WALSegmentSize = o.WALSegmentBytes
	opts.WALCompression = compression.Snappy
	opts.MaxBlockChunkSegmentSize = 8 << 20
	opts.BlockReloadInterval = 10 * time.Second
	db, err := ptsdb.Open(dir, o.Logger, nil, opts, nil)
	if err != nil {
		return nil, err
	}
	return &DB{db: db, retention: ret, maxBytes: o.MaxBytes}, nil
}

// Querier implements storage.Queryable.
func (d *DB) Querier(mint, maxt int64) (storage.Querier, error) { return d.db.Querier(mint, maxt) }

// Appender implements storage.Appendable.
func (d *DB) Appender(ctx context.Context) storage.Appender { return d.db.Appender(ctx) }

// Retention returns the effective retention.
func (d *DB) Retention() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.retention
}

// SetRetention applies a rule-derived retention (clamped) and returns the effective value.
func (d *DB) SetRetention(r time.Duration) (time.Duration, error) {
	d.mu.Lock()
	d.retention = ClampRetention(r)
	eff := d.retention
	err := d.applyLocked()
	d.mu.Unlock()
	if err != nil {
		return eff, err
	}
	return eff, d.reload()
}

// SetMaxBytes changes the configured size bound; zero disables it.
func (d *DB) SetMaxBytes(n int64) error {
	if n < 0 {
		return errors.New("tsdb: negative MaxBytes")
	}
	d.mu.Lock()
	d.maxBytes = n
	err := d.applyLocked()
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.reload()
}

// Relax removes a pressure limit installed by Shrink.
func (d *DB) Relax() error {
	d.mu.Lock()
	d.limit = 0
	err := d.applyLocked()
	d.mu.Unlock()
	return err
}

func (d *DB) effectiveBytesLocked() int64 {
	switch {
	case d.limit > 0 && (d.maxBytes == 0 || d.limit < d.maxBytes):
		return d.limit
	default:
		return d.maxBytes
	}
}

func (d *DB) applyLocked() error {
	return d.db.ApplyConfig(&promcfg.Config{StorageConfig: promcfg.StorageConfig{TSDBConfig: &promcfg.TSDBConfig{
		Retention: &promcfg.TSDBRetentionConfig{
			Time: model.Duration(d.retention),
			Size: units.Base2Bytes(d.effectiveBytesLocked()),
		},
	}}})
}

// reload makes retention settings take effect now by running an empty head compaction.
func (d *DB) reload() error {
	h := d.db.Head()
	mint := h.MinTime()
	if mint == math.MaxInt64 {
		return nil
	}
	return d.db.CompactHead(ptsdb.NewRangeHead(h, mint, mint-1))
}

// Size is the on-disk footprint: blocks, WAL, and head chunks.
func (d *DB) Size() int64 {
	n := d.db.Head().Size()
	for _, b := range d.db.Blocks() {
		n += b.Size()
	}
	return n
}

// Shrink drops the oldest data toward target and keeps target as a size limit until Relax.
func (d *DB) Shrink(ctx context.Context, target int64) (freed int64, err error) {
	if target < 0 {
		target = 0
	}
	before := d.Size()
	d.mu.Lock()
	d.limit = max(target, 1)
	err = d.applyLocked()
	d.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if err := d.reload(); err != nil {
		return 0, err
	}
	for i := 0; i < 16 && d.Size() > target; i++ {
		if err := ctx.Err(); err != nil {
			return max(before-d.Size(), 0), err
		}
		h := d.db.Head()
		mint, maxt := h.MinTime(), h.MaxTime()
		if mint == math.MaxInt64 || maxt-mint <= minShrinkSpan {
			break
		}
		cut := mint + (maxt-mint)/2
		if maxt-cut < minShrinkSpan {
			cut = maxt - minShrinkSpan
		}
		if err := d.db.CompactHead(ptsdb.NewRangeHead(h, mint, cut-1)); err != nil {
			return max(before-d.Size(), 0), err
		}
		if err := d.reload(); err != nil {
			return max(before-d.Size(), 0), err
		}
	}
	return max(before-d.Size(), 0), nil
}

// Stats describes the store.
type Stats struct {
	Series    uint64
	Bytes     int64
	Blocks    int
	MinTime   time.Time
	MaxTime   time.Time
	Retention time.Duration
	MaxBytes  int64
	Limit     int64
}

// Stats returns current counts and settings.
func (d *DB) Stats() Stats {
	h := d.db.Head()
	s := Stats{Series: h.NumSeries(), Bytes: d.Size(), Blocks: len(d.db.Blocks())}
	mint, maxt := h.MinTime(), h.MaxTime()
	if bs := d.db.Blocks(); len(bs) > 0 {
		mint = min(mint, bs[0].Meta().MinTime)
	}
	if mint != math.MaxInt64 {
		s.MinTime = time.UnixMilli(mint)
	}
	if maxt != math.MinInt64 {
		s.MaxTime = time.UnixMilli(maxt)
	}
	d.mu.Lock()
	s.Retention, s.MaxBytes, s.Limit = d.retention, d.maxBytes, d.limit
	d.mu.Unlock()
	return s
}

// Close flushes and closes the store.
func (d *DB) Close() error { return d.db.Close() }
