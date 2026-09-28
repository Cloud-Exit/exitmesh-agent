package logs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newFileTailer(t *testing.T, dir string, store kv.Store, c *collector, clk *fakeClock, only string) *FileTailer {
	t.Helper()
	ft, err := NewFileTailer(FileOptions{
		Paths:   []string{dir},
		Labels:  map[string]string{"host": "h1"},
		Store:   store,
		Sink:    c.sink,
		OnEvent: c.event,
		Filter:  func(l map[string]string) bool { return l["filename"] == only },
		Clock:   clk.Now, MaxLineBytes: 50, RotatedIdle: time.Minute, RescanInterval: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ft
}

func TestFileTailerRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "app.log")
	appendTo(t, a, "old history\n")
	appendTo(t, filepath.Join(dir, "other.log"), "not selected\n")
	appendTo(t, filepath.Join(dir, "app.log.1"), "rotated history\n")
	clk := &fakeClock{now: base}
	c := &collector{}
	ft := newFileTailer(t, dir, kv.NewMemory(), c, clk, a)
	poll(t, ft)
	appendTo(t, a, "one\n", "two\r\n", strings.Repeat("z", 80)+"\n")
	poll(t, ft)
	eq(t, c.texts(), []string{"one", "two", strings.Repeat("z", 50)})
	c.mu.Lock()
	l := c.lines[2]
	c.mu.Unlock()
	if !l.Truncated || l.Labels["filename"] != a || l.Labels["host"] != "h1" || !l.Time.Equal(base) {
		t.Fatalf("line %+v", l)
	}
	if err := os.Rename(a, a+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, a+".1", "late write\n")
	appendTo(t, a, "fresh file\n")
	poll(t, ft)
	eq(t, c.texts()[3:], []string{"late write", "fresh file"})
	if st := ft.Stats(); st.Files != 2 || st.Streams != 1 {
		t.Fatalf("stats %+v", st)
	}
	clk.Add(2 * time.Minute)
	poll(t, ft)
	if st := ft.Stats(); st.Files != 1 {
		t.Fatalf("rotated file not released: %+v", st)
	}
	if err := os.Truncate(a, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, a, "after truncate\n")
	poll(t, ft)
	eq(t, c.texts()[5:], []string{"after truncate"})
	if k := c.kinds(); len(k) != 1 || k[0] != GapTruncated {
		t.Fatalf("events %v", k)
	}
	created := filepath.Join(dir, "sub", "new.log")
	if err := os.MkdirAll(filepath.Dir(created), 0o755); err != nil {
		t.Fatal(err)
	}
	appendTo(t, created, "brand new\n")
	ft.SetFilter(func(l map[string]string) bool { return l["filename"] == created })
	poll(t, ft)
	eq(t, c.texts()[6:], []string{"brand new"})
	if err := ft.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileTailerRestartAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "svc.log")
	store := kv.NewMemory()
	clk := &fakeClock{now: base}
	c := &collector{}
	appendTo(t, a, strings.Repeat("header line\n", 10))
	ft := newFileTailer(t, dir, store, c, clk, a)
	poll(t, ft)
	appendTo(t, a, "body\n")
	poll(t, ft)
	eq(t, c.texts(), []string{"body"})
	if err := ft.Close(); err != nil {
		t.Fatal(err)
	}
	appendTo(t, a, "tail of rotated\n")
	if err := os.Rename(a, a+".1"); err != nil {
		t.Fatal(err)
	}
	gzipAndRemove(t, a+".1")
	appendTo(t, a, "new current\n")
	c.reset()
	ft2 := newFileTailer(t, dir, store, c, clk, a)
	poll(t, ft2)
	eq(t, c.texts(), []string{"tail of rotated", "new current"})
	if len(c.kinds()) != 0 {
		t.Fatalf("gaps %v", c.kinds())
	}
	if err := ft2.Close(); err != nil {
		t.Fatal(err)
	}

	appendTo(t, a, "renamed remainder\n")
	if err := os.Rename(a, a+"-20260901"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, a, "second current\n")
	c.reset()
	ft3 := newFileTailer(t, dir, store, c, clk, a)
	poll(t, ft3)
	eq(t, c.texts(), []string{"renamed remainder", "second current"})
	if err := ft3.Close(); err != nil {
		t.Fatal(err)
	}

	appendTo(t, a, "vanished\n")
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	appendTo(t, a, "third current\n")
	c.reset()
	ft4 := newFileTailer(t, dir, store, c, clk, a)
	poll(t, ft4)
	eq(t, c.texts(), []string{"third current"})
	if k := c.kinds(); len(k) != 1 || k[0] != GapMissedRotation {
		t.Fatalf("gaps %v", k)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ft4.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFileTailerExcludedFilesNeverOpened(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "auth.log")
	appendTo(t, secret, "x\n")
	if err := os.Chmod(secret, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(secret, 0o644)
	c := &collector{}
	ft := newFileTailer(t, dir, kv.NewMemory(), c, &fakeClock{now: base}, filepath.Join(dir, "missing.log"))
	poll(t, ft)
	if st := ft.Stats(); st.Streams != 0 || st.Files != 0 || st.Gaps != 0 {
		t.Fatalf("stats %+v", st)
	}
}
