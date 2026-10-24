package tsdb

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/value"
)

func TestRetainedSeriesLimitAndChurnRecovery(t *testing.T) {
	d, err := Open(t.TempDir(), Options{MaxSeries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now := time.Now().UnixMilli()
	write := func(name string, ts int64, v float64) error {
		app := d.Appender(context.Background())
		if _, err := app.Append(0, labels.FromStrings("__name__", name), ts, v); err != nil {
			_ = app.Rollback()
			return err
		}
		return app.Commit()
	}
	for _, name := range []string{"a", "b"} {
		if err := write(name, now, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := write("c", now, 1); !errors.Is(err, ErrSeriesLimit) {
		t.Fatalf("new series at capacity: %v", err)
	}
	if err := write("a", now+1, 2); err != nil {
		t.Fatalf("existing series rejected at capacity: %v", err)
	}
	for _, name := range []string{"a", "b"} {
		if err := write(name, now+2, math.Float64frombits(value.StaleNaN)); err != nil {
			t.Fatal(err)
		}
	}
	if err := write("c", now+3, 1); !errors.Is(err, ErrSeriesLimit) {
		t.Fatalf("stale retained series escaped the budget: %v", err)
	}
	if err := d.RelieveSeriesPressure(); err != nil {
		t.Fatal(err)
	}
	if err := write("c", now+3, 1); err != nil {
		t.Fatalf("series budget did not recover after compaction: %v", err)
	}
	if got := minSampleTime(t, d, "a"); got != now {
		t.Fatalf("pressure relief lost history: %d", got)
	}
}

func TestSeriesLimitPreservesReplayAndConcurrentAdmission(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	appendSeries(t, d, "existing", time.Now(), 0, time.Second, 3)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dir, Options{MaxSeries: 2})
	if err != nil {
		t.Fatalf("lower budget prevented WAL replay: %v", err)
	}
	if got := d.Stats().Series; got != 3 {
		t.Fatalf("replay lost series: %d", got)
	}
	app := d.Appender(context.Background())
	_, err = app.Append(0, labels.FromStrings("__name__", "new"), time.Now().UnixMilli(), 1)
	_ = app.Rollback()
	if !errors.Is(err, ErrSeriesLimit) {
		t.Fatalf("replayed series were not charged: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(t.TempDir(), Options{MaxSeries: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			app := d.Appender(context.Background())
			_, err := app.Append(0, labels.FromStrings("__name__", "m", "id", fmt.Sprint(i)), time.Now().UnixMilli(), 1)
			if err != nil && !errors.Is(err, ErrSeriesLimit) {
				t.Error(err)
			}
			if err := app.Commit(); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if got := d.Stats().Series; got != 8 {
		t.Fatalf("concurrent admission retained %d series", got)
	}
}
