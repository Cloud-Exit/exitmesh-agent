package tsdb

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
)

func appendSeries(t *testing.T, d *DB, name string, start time.Time, span, step time.Duration, series int) {
	t.Helper()
	for ts := start; !ts.After(start.Add(span)); ts = ts.Add(step) {
		app := d.Appender(context.Background())
		for i := 0; i < series; i++ {
			l := labels.FromStrings("__name__", name, "i", string(rune('a'+i%26)), "n", time.Duration(i).String())
			if _, err := app.Append(0, l, ts.UnixMilli(), float64(ts.Unix())); err != nil {
				t.Fatal(err)
			}
		}
		if err := app.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func minSampleTime(t *testing.T, d *DB, name string) int64 {
	t.Helper()
	q, err := d.Querier(math.MinInt64, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ss := q.Select(context.Background(), false, nil, labels.MustNewMatcher(labels.MatchEqual, "__name__", name))
	minT := int64(math.MaxInt64)
	for ss.Next() {
		it := ss.At().Iterator(nil)
		if it.Next() != 0 {
			tt, _ := it.At()
			minT = min(minT, tt)
		}
	}
	if err := ss.Err(); err != nil {
		t.Fatal(err)
	}
	return minT
}

func TestAppendQueryAndReopen(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir, Options{Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var _ storage.Queryable = d
	start := time.Unix(1_700_000_000, 0)
	appendSeries(t, d, "m", start, 10*time.Minute, 30*time.Second, 3)
	if got := d.Stats().Series; got != 3 {
		t.Fatalf("series = %d", got)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dir, Options{Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := minSampleTime(t, d, "m"); got != start.UnixMilli() {
		t.Fatalf("WAL replay lost samples: min %d want %d", got, start.UnixMilli())
	}
}

func TestRetentionClampAndChange(t *testing.T) {
	if ClampRetention(0) != HardCeiling || ClampRetention(9*time.Hour) != HardCeiling || ClampRetention(time.Hour) != time.Hour {
		t.Fatal("clamp")
	}
	d, err := Open(t.TempDir(), Options{Retention: 10 * time.Hour, BlockDuration: 10 * time.Minute, WALSegmentBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Retention() != HardCeiling {
		t.Fatalf("retention %v", d.Retention())
	}
	start := time.Unix(1_700_000_000, 0).Truncate(time.Hour)
	appendSeries(t, d, "r", start, 4*time.Hour, time.Minute, 2)
	if err := d.db.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.Stats().Blocks == 0 {
		t.Fatal("expected persisted blocks")
	}
	if got := minSampleTime(t, d, "r"); got != start.UnixMilli() {
		t.Fatalf("data lost before retention change: %d", got)
	}
	eff, err := d.SetRetention(time.Hour)
	if err != nil || eff != time.Hour {
		t.Fatalf("SetRetention = %v, %v", eff, err)
	}
	got := minSampleTime(t, d, "r")
	oldest := start.Add(4 * time.Hour).Add(-time.Hour - 2*10*time.Minute - 15*time.Minute)
	if got < oldest.UnixMilli() {
		t.Fatalf("retention not applied: oldest sample %v, want after %v", time.UnixMilli(got), oldest)
	}
	if st := d.Stats(); st.Retention != time.Hour {
		t.Fatalf("stats retention %v", st.Retention)
	}
}

func TestShrinkUnderPressure(t *testing.T) {
	d, err := Open(t.TempDir(), Options{BlockDuration: 10 * time.Minute, WALSegmentBytes: 32 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	start := time.Unix(1_700_000_000, 0).Truncate(time.Hour)
	appendSeries(t, d, "s", start, 3*time.Hour, 15*time.Second, 40)
	before := d.Size()
	if before == 0 {
		t.Fatal("empty size")
	}
	target := before / 4
	freed, err := d.Shrink(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if freed <= 0 || d.Size() >= before {
		t.Fatalf("freed %d size %d before %d", freed, d.Size(), before)
	}
	if got := minSampleTime(t, d, "s"); got <= start.UnixMilli() {
		t.Fatalf("oldest data kept after shrink: %v", time.UnixMilli(got))
	}
	if d.Stats().Limit != target {
		t.Fatalf("limit %d", d.Stats().Limit)
	}
	app := d.Appender(context.Background())
	if _, err := app.Append(0, labels.FromStrings("__name__", "s", "i", "new"), start.Add(3*time.Hour+time.Minute).UnixMilli(), 1); err != nil {
		t.Fatalf("append after shrink: %v", err)
	}
	if err := app.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := d.Relax(); err != nil || d.Stats().Limit != 0 {
		t.Fatalf("relax: %v", err)
	}
	if err := d.SetMaxBytes(-1); err == nil {
		t.Fatal("negative max bytes accepted")
	}
	if err := d.SetMaxBytes(1 << 30); err != nil {
		t.Fatal(err)
	}
}
