package logs

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

var base = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func ts(i int) time.Time { return base.Add(time.Duration(i) * time.Second) }

func cri(i int, stream, tag, text string) string {
	return fmt.Sprintf("%s %s %s %s\n", ts(i).Format(time.RFC3339Nano), stream, tag, text)
}

func docker(i int, stream, log string) string {
	return fmt.Sprintf(`{"log":%q,"stream":%q,"time":%q}`+"\n", log, stream, ts(i).Format(time.RFC3339Nano))
}

type collector struct {
	mu     sync.Mutex
	lines  []Line
	events []Event
}

func (c *collector) sink(l Line) {
	c.mu.Lock()
	c.lines = append(c.lines, l)
	c.mu.Unlock()
}

func (c *collector) event(e Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *collector) texts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, l := range c.lines {
		out = append(out, l.Text)
	}
	return out
}

func (c *collector) kinds() []GapKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []GapKind
	for _, e := range c.events {
		out = append(out, e.Kind)
	}
	return out
}

func (c *collector) reset() {
	c.mu.Lock()
	c.lines, c.events = nil, nil
	c.mu.Unlock()
}

func acceptAll(map[string]string) bool { return true }

func containerDir(t *testing.T, root, ns, pod, uid, container string) string {
	t.Helper()
	d := filepath.Join(root, ns+"_"+pod+"_"+uid, container)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func appendTo(t *testing.T, path string, s ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(s, "")); err != nil {
		t.Fatal(err)
	}
}

func gzipAndRemove(t *testing.T, src string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(src + ".gz")
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
}

func newTailer(t *testing.T, root string, store kv.Store, c *collector, mod func(*Options)) *Tailer {
	t.Helper()
	o := Options{Root: root, Node: "n1", Store: store, Sink: c.sink, OnEvent: c.event, Filter: acceptAll}
	if mod != nil {
		mod(&o)
	}
	tl, err := NewTailer(o)
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

func poll(t *testing.T, tl interface{ Poll(context.Context) error }) {
	t.Helper()
	if err := tl.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestExistingContentSkippedNewPodReadFromStart(t *testing.T) {
	root := t.TempDir()
	old := containerDir(t, root, "ns", "old", "u0", "app")
	appendTo(t, filepath.Join(old, "0.log"), cri(1, "stdout", "F", "history"), cri(2, "stdout", "P", "half"))
	c := &collector{}
	tl := newTailer(t, root, kv.NewMemory(), c, nil)
	poll(t, tl)
	appendTo(t, filepath.Join(old, "0.log"), cri(3, "stdout", "F", " line"), cri(4, "stdout", "F", "live"))
	d := containerDir(t, root, "ns", "new", "u1", "app")
	appendTo(t, filepath.Join(d, "0.log"), cri(5, "stdout", "F", "first"))
	poll(t, tl)
	eq(t, c.texts(), []string{"first", " line", "live"})
}

func TestCRIPartialsAndLabels(t *testing.T) {
	root := t.TempDir()
	c := &collector{}
	tl := newTailer(t, root, kv.NewMemory(), c, func(o *Options) {
		o.MaxLineBytes = 16
		o.Enrich = func(ns, pod, uid, container string) map[string]string {
			return map[string]string{"workload": "web", "workload_kind": "Deployment", "namespace": "spoofed"}
		}
	})
	poll(t, tl)
	d := containerDir(t, root, "shop", "web-1", "uid-1", "nginx")
	appendTo(t, filepath.Join(d, "0.log"),
		cri(1, "stdout", "P", "hello "),
		cri(2, "stderr", "F", "err line"),
		cri(3, "stdout", "P", "wor"),
		cri(4, "stdout", "F", "ld"),
		cri(5, "stdout", "P", "0123456789"),
		cri(6, "stdout", "F", "abcdefghij"),
		cri(7, "stdout", "F", ""),
		"garbage line\n",
	)
	poll(t, tl)
	c.mu.Lock()
	lines := append([]Line(nil), c.lines...)
	c.mu.Unlock()
	if len(lines) != 4 {
		t.Fatalf("lines %+v", lines)
	}
	if lines[0].Text != "err line" || lines[0].Labels["stream"] != "stderr" {
		t.Fatalf("stderr %+v", lines[0])
	}
	l := lines[1]
	if l.Text != "hello world" || !l.Time.Equal(ts(1)) || l.Truncated {
		t.Fatalf("reassembled %+v", l)
	}
	want := map[string]string{"namespace": "shop", "pod": "web-1", "pod_uid": "uid-1", "container": "nginx", "stream": "stdout", "node": "n1", "workload": "web", "workload_kind": "Deployment"}
	if fmt.Sprint(l.Labels) != fmt.Sprint(want) {
		t.Fatalf("labels %v", l.Labels)
	}
	if lines[2].Text != "0123456789abcdef" || !lines[2].Truncated {
		t.Fatalf("capped partial %+v", lines[2])
	}
	if lines[3].Text != "" || lines[3].Truncated {
		t.Fatalf("empty line %+v", lines[3])
	}
	if st := tl.Stats(); st.Unparsed != 1 || st.TruncatedLines != 1 || st.Lines != 4 || st.Streams != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestDockerJSONAndOversizedLines(t *testing.T) {
	root := t.TempDir()
	c := &collector{}
	tl := newTailer(t, root, kv.NewMemory(), c, func(o *Options) { o.MaxLineBytes = 100 })
	poll(t, tl)
	d := containerDir(t, root, "ns", "p", "u", "c")
	big := strings.Repeat("x", 5000)
	appendTo(t, filepath.Join(d, "0.log"),
		docker(1, "stdout", "part one "),
		docker(2, "stdout", "part two\n"),
		docker(3, "stderr", "quoted \"value\"\n"),
		docker(4, "stderr", big+"\n"),
		cri(5, "stdout", "F", big),
		cri(6, "stdout", "F", "after"),
	)
	poll(t, tl)
	c.mu.Lock()
	lines := append([]Line(nil), c.lines...)
	c.mu.Unlock()
	if len(lines) != 5 {
		t.Fatalf("lines %d %+v", len(lines), c.texts())
	}
	if lines[0].Text != "part one part two" || lines[0].Labels["stream"] != "stdout" || !lines[0].Time.Equal(ts(1)) {
		t.Fatalf("docker partial %+v", lines[0])
	}
	if lines[1].Text != `quoted "value"` || lines[1].Labels["stream"] != "stderr" {
		t.Fatalf("docker escape %+v", lines[1])
	}
	if len(lines[2].Text) != 100 || !lines[2].Truncated || lines[2].Labels["stream"] != "stderr" || !lines[2].Time.Equal(ts(4)) {
		t.Fatalf("docker oversized %d %+v", len(lines[2].Text), lines[2].Labels)
	}
	if len(lines[3].Text) != 100 || !lines[3].Truncated {
		t.Fatalf("cri oversized %d", len(lines[3].Text))
	}
	if lines[4].Text != "after" || lines[4].Truncated {
		t.Fatalf("line after oversized %+v", lines[4])
	}
}

func TestRotationRenameAndCompress(t *testing.T) {
	root := t.TempDir()
	c := &collector{}
	tl := newTailer(t, root, kv.NewMemory(), c, nil)
	poll(t, tl)
	d := containerDir(t, root, "ns", "p", "u", "c")
	active := filepath.Join(d, "0.log")
	appendTo(t, active, cri(1, "stdout", "F", "a1"))
	poll(t, tl)
	appendTo(t, active, cri(2, "stdout", "F", "a2"))
	rotated := filepath.Join(d, "0.log.20260901-120010")
	if err := os.Rename(active, rotated); err != nil {
		t.Fatal(err)
	}
	appendTo(t, rotated, cri(3, "stdout", "F", "a3"))
	appendTo(t, active, cri(4, "stdout", "F", "b1"))
	poll(t, tl)
	appendTo(t, rotated, cri(5, "stdout", "F", "a4"))
	gzipAndRemove(t, rotated)
	appendTo(t, active, cri(6, "stdout", "F", "b2"))
	poll(t, tl)
	eq(t, c.texts(), []string{"a1", "a2", "a3", "b1", "a4", "b2"})
	if st := tl.Stats(); st.Files != 1 || st.Gaps != 0 {
		t.Fatalf("stats %+v events %v", st, c.kinds())
	}
	if err := os.WriteFile(filepath.Join(d, "1.log"), []byte(cri(7, "stdout", "F", "restarted")), 0o644); err != nil {
		t.Fatal(err)
	}
	poll(t, tl)
	eq(t, c.texts()[6:], []string{"restarted"})
}

func TestTruncationDetected(t *testing.T) {
	root := t.TempDir()
	c := &collector{}
	tl := newTailer(t, root, kv.NewMemory(), c, nil)
	poll(t, tl)
	d := containerDir(t, root, "ns", "p", "u", "c")
	f := filepath.Join(d, "0.log")
	appendTo(t, f, cri(1, "stdout", "F", "one"), cri(2, "stdout", "F", "two"))
	poll(t, tl)
	if err := os.Truncate(f, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, f, cri(3, "stdout", "F", "3"))
	poll(t, tl)
	eq(t, c.texts(), []string{"one", "two", "3"})
	if k := c.kinds(); len(k) != 1 || k[0] != GapTruncated {
		t.Fatalf("events %v", k)
	}
}

func TestRestartResumeNoDuplicatesNoLoss(t *testing.T) {
	root := t.TempDir()
	store := kv.NewMemory()
	c := &collector{}
	tl := newTailer(t, root, store, c, nil)
	poll(t, tl)
	d := containerDir(t, root, "ns", "p", "u", "c")
	f := filepath.Join(d, "0.log")
	appendTo(t, f, cri(1, "stdout", "F", "l1"), cri(2, "stdout", "F", "l2"))
	poll(t, tl)
	appendTo(t, f, cri(3, "stdout", "F", "l3"), cri(4, "stdout", "P", "part1-"), cri(5, "stderr", "F", "e1"))
	poll(t, tl)
	if err := tl.Close(); err != nil {
		t.Fatal(err)
	}
	eq(t, c.texts(), []string{"l1", "l2", "l3", "e1"})

	appendTo(t, f, cri(6, "stdout", "F", "part2"), cri(7, "stdout", "F", "l4"))
	c.reset()
	tl2 := newTailer(t, root, store, c, nil)
	poll(t, tl2)
	eq(t, c.texts(), []string{"part1-part2", "l4"})
	if len(c.kinds()) != 0 {
		t.Fatalf("unexpected gaps %v", c.kinds())
	}
	if !c.lines[0].Time.Equal(ts(4)) {
		t.Fatalf("group time %v", c.lines[0].Time)
	}

	appendTo(t, f, cri(8, "stdout", "F", "l5"))
	if err := tl2.Close(); err != nil {
		t.Fatal(err)
	}
	appendTo(t, f, cri(9, "stdout", "F", "l6"))
	rot := filepath.Join(d, "0.log.20260901-120100")
	if err := os.Rename(f, rot); err != nil {
		t.Fatal(err)
	}
	gzipAndRemove(t, rot)
	appendTo(t, f, cri(10, "stdout", "F", "n1"))
	c.reset()
	tl3 := newTailer(t, root, store, c, nil)
	poll(t, tl3)
	eq(t, c.texts(), []string{"l5", "l6", "n1"})
	if len(c.kinds()) != 0 {
		t.Fatalf("unexpected gaps %v", c.kinds())
	}
	if err := tl3.Close(); err != nil {
		t.Fatal(err)
	}

	appendTo(t, f, cri(11, "stdout", "F", "lost"))
	rot2 := filepath.Join(d, "0.log.20260901-120200")
	if err := os.Rename(f, rot2); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rot2); err != nil {
		t.Fatal(err)
	}
	unseen := filepath.Join(d, "0.log.20260901-120300")
	appendTo(t, unseen, cri(12, "stdout", "F", "never read"))
	gzipAndRemove(t, unseen)
	appendTo(t, filepath.Join(d, "0.log.20260901-120400"), cri(13, "stdout", "F", "plain rotated"))
	appendTo(t, f, cri(14, "stdout", "F", "current"))
	c.reset()
	tl4 := newTailer(t, root, store, c, nil)
	poll(t, tl4)
	eq(t, c.texts(), []string{"plain rotated", "current"})
	k := c.kinds()
	if len(k) != 2 || k[0] != GapMissedRotation || k[1] != GapMissedRotation {
		t.Fatalf("gaps %v", k)
	}
	if err := tl4.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOffsetBeyondSizeOnResume(t *testing.T) {
	root := t.TempDir()
	store := kv.NewMemory()
	c := &collector{}
	tl := newTailer(t, root, store, c, nil)
	poll(t, tl)
	d := containerDir(t, root, "ns", "p", "u", "c")
	f := filepath.Join(d, "0.log")
	for i := 0; i < 60; i++ {
		appendTo(t, f, cri(i, "stdout", "F", fmt.Sprintf("line-%02d", i)))
	}
	poll(t, tl)
	if err := tl.Close(); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(f)
	keep := int64(1100)
	if fi.Size() <= keep {
		t.Fatal("fixture too small")
	}
	if err := os.Truncate(f, keep); err != nil {
		t.Fatal(err)
	}
	c.reset()
	tl2 := newTailer(t, root, store, c, nil)
	poll(t, tl2)
	if k := c.kinds(); len(k) != 1 || k[0] != GapOffsetBeyondSize {
		t.Fatalf("gaps %v", k)
	}
	if got := c.texts(); len(got) == 0 || got[0] != "line-00" {
		t.Fatalf("reread from start: %v", got)
	}
}

func TestFilterExcludesStreamsEntirely(t *testing.T) {
	root := t.TempDir()
	store := kv.NewMemory()
	c := &collector{}
	onlyApp := func(l map[string]string) bool { return l["namespace"] == "app" && l["stream"] == "stdout" }
	tl := newTailer(t, root, store, c, func(o *Options) { o.Filter = nil })
	sys := containerDir(t, root, "kube-system", "dns", "u1", "coredns")
	app := containerDir(t, root, "app", "api", "u2", "api")
	sysLog := filepath.Join(sys, "0.log")
	appendTo(t, sysLog, cri(1, "stdout", "F", "secret system line"))
	if err := os.Chmod(sysLog, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(sysLog, 0o644)
	poll(t, tl)
	if st := tl.Stats(); st.Streams != 0 {
		t.Fatalf("tailing before a filter is set: %+v", st)
	}
	tl.SetFilter(onlyApp)
	poll(t, tl)
	appendTo(t, filepath.Join(app, "0.log"), cri(2, "stdout", "F", "keep"), cri(3, "stderr", "F", "drop stderr"))
	poll(t, tl)
	eq(t, c.texts(), []string{"keep"})
	if len(c.kinds()) != 0 || tl.Stats().Streams != 1 || tl.Stats().Files != 1 {
		t.Fatalf("excluded stream opened: %v %+v", c.kinds(), tl.Stats())
	}
	if err := tl.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Get(podStatePrefix + "app_api_u2/api"); !ok {
		t.Fatal("offsets not persisted")
	}
	tl.SetFilter(func(l map[string]string) bool { return l["namespace"] == "kube-system" })
	poll(t, tl)
	if err := tl.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Get(podStatePrefix + "app_api_u2/api"); ok {
		t.Fatal("offsets of excluded stream kept")
	}
	if fh, err := os.Open(sysLog); err == nil {
		fh.Close()
		return
	}
	if k := c.kinds(); len(k) != 1 || k[0] != GapReadError {
		t.Fatalf("newly included unreadable stream should report: %v", k)
	}
}

func TestEnrichmentDeferral(t *testing.T) {
	root := t.TempDir()
	c := &collector{}
	now := base
	var mu sync.Mutex
	known := false
	tl := newTailer(t, root, kv.NewMemory(), c, func(o *Options) {
		o.Clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
		o.Filter = func(l map[string]string) bool { return l["workload"] == "web" }
		o.Enrich = func(ns, pod, uid, container string) map[string]string {
			mu.Lock()
			defer mu.Unlock()
			if !known {
				return nil
			}
			return map[string]string{"workload": "web"}
		}
	})
	poll(t, tl)
	d := containerDir(t, root, "ns", "web-1", "u", "c")
	appendTo(t, filepath.Join(d, "0.log"), cri(1, "stdout", "F", "early"))
	poll(t, tl)
	if len(c.texts()) != 0 {
		t.Fatal("tailed before enrichment")
	}
	mu.Lock()
	known = true
	mu.Unlock()
	poll(t, tl)
	eq(t, c.texts(), []string{"early"})
	if c.lines[0].Labels["workload"] != "web" {
		t.Fatalf("labels %v", c.lines[0].Labels)
	}
}

func TestPartialGroupAcrossRotationAndRestart(t *testing.T) {
	root := t.TempDir()
	store := kv.NewMemory()
	c := &collector{}
	tl := newTailer(t, root, store, c, nil)
	poll(t, tl)
	d := containerDir(t, root, "ns", "p", "u", "c")
	f := filepath.Join(d, "0.log")
	appendTo(t, f, cri(1, "stdout", "P", "left-"))
	poll(t, tl)
	rot := filepath.Join(d, "0.log.20260901-120000")
	if err := os.Rename(f, rot); err != nil {
		t.Fatal(err)
	}
	appendTo(t, f, cri(2, "stdout", "P", "middle-"))
	poll(t, tl)
	if err := tl.Close(); err != nil {
		t.Fatal(err)
	}
	appendTo(t, f, cri(3, "stdout", "F", "right"))
	tl2 := newTailer(t, root, store, c, nil)
	poll(t, tl2)
	eq(t, c.texts(), []string{"left-middle-right"})
}

func TestRunCheckpointsAndStops(t *testing.T) {
	root := t.TempDir()
	store := kv.NewMemory()
	c := &collector{}
	tl := newTailer(t, root, store, c, func(o *Options) {
		o.PollInterval = 5 * time.Millisecond
		o.CheckpointInterval = 10 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tl.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	d := containerDir(t, root, "ns", "p", "u", "c")
	appendTo(t, filepath.Join(d, "0.log"), cri(1, "stdout", "F", "via run"))
	deadline := time.Now().Add(5 * time.Second)
	for len(c.texts()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no line")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Get(podStatePrefix + "ns_p_u/c"); !ok {
		t.Fatal("no checkpoint after run")
	}
}

func TestPartialGroupPrefixLostFlagged(t *testing.T) {
	root := t.TempDir()
	store := kv.NewMemory()
	c := &collector{}
	tl := newTailer(t, root, store, c, nil)
	poll(t, tl)
	d := containerDir(t, root, "ns", "p", "u", "c")
	f := filepath.Join(d, "0.log")
	appendTo(t, f, cri(1, "stdout", "P", "gone-"))
	poll(t, tl)
	if err := tl.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	appendTo(t, f, cri(2, "stdout", "F", "tail"), cri(3, "stdout", "F", "next"))
	tl2 := newTailer(t, root, store, c, nil)
	poll(t, tl2)
	eq(t, c.texts(), []string{"tail", "next"})
	if !c.lines[0].Truncated || c.lines[1].Truncated {
		t.Fatalf("flags %+v", c.lines)
	}
	if k := c.kinds(); len(k) != 1 || k[0] != GapMissedRotation {
		t.Fatalf("gaps %v", k)
	}
}
