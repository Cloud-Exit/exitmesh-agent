package disk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

var _ Shrinker = (*tsdb.DB)(nil)

type fakeTSDB struct {
	path    string
	shrinks []int64
	relaxed int
}

func (f *fakeTSDB) Size() int64 {
	fi, err := os.Stat(f.path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func (f *fakeTSDB) Shrink(_ context.Context, target int64) (int64, error) {
	before := f.Size()
	f.shrinks = append(f.shrinks, target)
	if before > target {
		if err := os.Truncate(f.path, target); err != nil {
			return 0, err
		}
	}
	return before - f.Size(), nil
}

func (f *fakeTSDB) Relax() error { f.relaxed++; return nil }

func write(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHostReserveProtectedAndTSDBShrunkFirst(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool", "seg")
	ts := &fakeTSDB{path: filepath.Join(dir, "tsdb", "wal")}
	write(t, spool, 300)
	write(t, ts.path, 100)
	write(t, filepath.Join(dir, "offsets.db"), 100)
	b := DiskBudget(dir, 1000, Options{TSDB: ts, TSDBDir: "tsdb", SpoolDir: "spool", SpoolReserve: 500})

	r, err := b.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Used != 500 || r.Spool != 300 || r.Reserved != 500 || r.TSDB != 100 || r.Other != 100 || r.Effective != 700 || r.Pressure || len(ts.shrinks) != 0 {
		t.Fatalf("baseline %+v", r)
	}

	write(t, ts.path, 400)
	r, err = b.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.TSDBTarget != 250 || r.Freed != 150 || r.TSDB != 250 || r.Pressure || r.Effective != 850 {
		t.Fatalf("shrink %+v", r)
	}

	write(t, filepath.Join(dir, "offsets.db"), 600)
	r, _ = b.Check(context.Background())
	if r.TSDBTarget != 0 || r.TSDB != 0 || !r.Pressure || r.Deficit != 100 || !b.Pressure() {
		t.Fatalf("pressure %+v", r)
	}
	if fi, _ := os.Stat(spool); fi.Size() != 300 {
		t.Fatal("spool touched")
	}

	write(t, filepath.Join(dir, "offsets.db"), 10)
	r, _ = b.Check(context.Background())
	if r.Pressure || ts.relaxed != 1 || b.Last().Effective != r.Effective {
		t.Fatalf("relax %+v relaxed %d", r, ts.relaxed)
	}
}

func TestNodeCapWithRealTSDB(t *testing.T) {
	dir := t.TempDir()
	db, err := tsdb.Open(filepath.Join(dir, "tsdb"), tsdb.Options{BlockDuration: 10 * time.Minute, WALSegmentBytes: 32 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	write(t, filepath.Join(dir, "queue", "q"), 1000)
	start := time.Unix(1_790_000_000, 0).Truncate(time.Hour)
	for el := time.Duration(0); el <= 3*time.Hour; el += 15 * time.Second {
		app := db.Appender(context.Background())
		for i := 0; i < 40; i++ {
			if _, err := app.Append(0, labelsFor(i), start.Add(el).UnixMilli(), float64(el)); err != nil {
				t.Fatal(err)
			}
		}
		if err := app.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	b := DiskBudget(dir, 0, Options{TSDB: db, TSDBDir: "tsdb", SpoolDir: "queue"})
	m := stable(t, b, filepath.Join(dir, "tsdb"))
	if m.TSDB == 0 || m.Spool != 1000 {
		t.Fatalf("measure %+v", m)
	}
	b = DiskBudget(dir, m.Effective/2, Options{TSDB: db, TSDBDir: "tsdb", SpoolDir: "queue"})
	r, err := b.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Freed <= 0 || r.TSDB >= m.TSDB || r.Spool != 1000 {
		t.Fatalf("real shrink %+v before %+v", r, m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	b.Run(ctx, time.Hour, func(Report, error) { calls++ })
	if calls != 1 {
		t.Fatalf("run calls %d", calls)
	}
}

// stable waits for background compaction, whose preallocated temporary blocks are transient.
func stable(t *testing.T, b *Budget, tsdbDir string) Report {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	prev := b.Measure()
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		cur := b.Measure()
		busy := false
		des, _ := os.ReadDir(tsdbDir)
		for _, de := range des {
			if strings.Contains(de.Name(), ".tmp") {
				busy = true
			}
		}
		if !busy && cur.Used == prev.Used {
			return cur
		}
		prev = cur
	}
	t.Fatal("tsdb never settled")
	return Report{}
}
