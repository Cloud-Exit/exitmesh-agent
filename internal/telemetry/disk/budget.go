// Package disk enforces the state directory cap by shrinking the TSDB first and reporting pressure.
package disk

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Shrinker is the TSDB side of the budget.
type Shrinker interface {
	Size() int64
	Shrink(ctx context.Context, target int64) (int64, error)
	Relax() error
}

// Options configures a Budget.
type Options struct {
	TSDB Shrinker
	// TSDBDir and SpoolDir are measured separately; relative paths are under the budget directory.
	TSDBDir  string
	SpoolDir string
	// SpoolReserve is always counted as used, so nothing else can grow into it (host mode).
	SpoolReserve int64
	HighWater    float64
	LowWater     float64
}

// Report is one measurement and the action taken.
type Report struct {
	Cap        int64
	Used       int64
	Spool      int64
	Reserved   int64
	TSDB       int64
	Other      int64
	Effective  int64
	TSDBTarget int64
	Freed      int64
	Pressure   bool
	Deficit    int64
}

// Budget enforces a byte cap over one directory.
type Budget struct {
	dir string
	cap int64
	o   Options

	mu     sync.Mutex
	last   Report
	shrunk bool
}

// DiskBudget returns a budget for dir with capBytes.
func DiskBudget(dir string, capBytes int64, o Options) *Budget {
	if o.HighWater <= 0 || o.HighWater > 1 {
		o.HighWater = 0.95
	}
	if o.LowWater <= 0 || o.LowWater >= o.HighWater {
		o.LowWater = o.HighWater - 0.10
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	o.TSDBDir, o.SpoolDir = abs(o.TSDBDir), abs(o.SpoolDir)
	return &Budget{dir: dir, cap: capBytes, o: o}
}

func du(root string) int64 {
	if root == "" {
		return 0
	}
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

func within(dir, p string) bool {
	if p == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Measure reports usage without acting.
func (b *Budget) Measure() Report {
	r := Report{Cap: b.cap, Used: du(b.dir), Spool: du(b.o.SpoolDir)}
	switch {
	case b.o.TSDBDir != "":
		r.TSDB = du(b.o.TSDBDir)
	case b.o.TSDB != nil:
		r.TSDB = b.o.TSDB.Size()
	}
	inside := r.Used
	if within(b.dir, b.o.SpoolDir) {
		inside -= r.Spool
	}
	if b.o.TSDBDir == "" || within(b.dir, b.o.TSDBDir) {
		inside -= r.TSDB
	}
	r.Other = max(inside, 0)
	r.Reserved = max(r.Spool, b.o.SpoolReserve)
	r.Effective = r.Other + r.TSDB + r.Reserved
	r.Deficit = max(r.Effective-b.cap, 0)
	r.Pressure = float64(r.Effective) > b.o.HighWater*float64(b.cap)
	return r
}

// Check shrinks the TSDB above the high water mark and relaxes it below the low water mark.
func (b *Budget) Check(ctx context.Context) (Report, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.Measure()
	low := int64(b.o.LowWater * float64(b.cap))
	var err error
	switch {
	case r.Pressure && b.o.TSDB != nil && r.TSDB > 0:
		target := max(low-r.Other-r.Reserved, 0)
		var freed int64
		freed, err = b.o.TSDB.Shrink(ctx, target)
		b.shrunk = true
		after := b.Measure()
		after.TSDBTarget, after.Freed = target, freed
		r = after
	case b.shrunk && r.Effective < low && b.o.TSDB != nil:
		err = b.o.TSDB.Relax()
		if err == nil {
			b.shrunk = false
		}
	}
	b.last = r
	return r, err
}

// Last returns the most recent report.
func (b *Budget) Last() Report {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

// Pressure reports whether the last check stayed above the high water mark.
func (b *Budget) Pressure() bool { return b.Last().Pressure }

// Run checks every interval until ctx ends, passing each report to fn.
func (b *Budget) Run(ctx context.Context, every time.Duration, fn func(Report, error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r, err := b.Check(ctx)
		if fn != nil {
			fn(r, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
