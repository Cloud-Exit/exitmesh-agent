package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/metricfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

func factValue(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	case int:
		return float64(x)
	}
	return -1
}

func (h *harness) memFacts() (items int, p95 float64) {
	p95 = -1
	for _, it := range h.coord.received(nodeapi.KindMetricFacts) {
		for _, f := range it.Facts {
			if f.Pod == "web-1" && f.Container == "app" {
				items++
				if v, ok := f.Fields[metricfacts.MemP95]; ok {
					p95 = factValue(v)
				}
			}
		}
	}
	return items, p95
}

func TestMetricFactsOnlyOnThresholdChange(t *testing.T) {
	const every = 300 * time.Millisecond
	h := newHarness(t, options{caps: "metrics", realClock: true, facts: every})
	h.start()
	h.waitFor("first metric facts", func() bool { n, v := h.memFacts(); return n > 0 && v == 900 })
	stable := func(what string) int {
		deadline := time.Now().Add(20 * time.Second)
		for {
			n, _ := h.memFacts()
			time.Sleep(6 * every)
			if m, _ := h.memFacts(); m == n {
				return n
			}
			if time.Now().After(deadline) {
				t.Fatalf("metric facts never settled (%s)", what)
			}
		}
	}
	n := stable("unchanged usage")
	time.Sleep(6 * every)
	if m, _ := h.memFacts(); m != n {
		t.Fatalf("unchanged usage emitted facts: %d then %d", n, m)
	}
	h.kubelet.set(memFixture(5000))
	h.waitFor("changed facts", func() bool { _, v := h.memFacts(); return v >= 4000 })
	n = stable("new usage")
	if err := h.shutdown(); err != nil {
		t.Fatal(err)
	}
	h.start()
	time.Sleep(8 * every)
	if m, _ := h.memFacts(); m != n {
		t.Fatalf("restart re-sent unchanged facts: %d then %d", n, m)
	}
	for _, it := range h.coord.received(nodeapi.KindMetricFacts) {
		for _, f := range it.Facts {
			if f.Node != "" && f.Node != testNode {
				t.Fatalf("fact names node %q", f.Node)
			}
		}
	}
}

func TestInvestigationTasks(t *testing.T) {
	h := newHarness(t, options{realClock: true})
	h.coord.setBundle(h.trust.payload(t, logBundle("l1", []ruleSpec{oomRule}, oomGroup)))
	a := h.start()
	h.waitBundle("l1")
	h.waitScrapes(2)
	h.writeLog("other", "chatty-1", "uid-chatty-1", "main", "hello from chatty", "unrelated line")
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory password=hunter2secret")
	h.waitFor("matched line in the ring", func() bool { return a.ring.Stats().Rules["oom-logs"].Samples == 1 })
	now := time.Now()
	task := func(id string, kind nodeapi.TaskKind, q investigate.TaskQuery) {
		b, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		h.coord.addTask(nodeapi.Task{ID: id, Kind: kind, Payload: b, DeadlineMs: now.Add(time.Minute).UnixMilli()})
	}
	task("q-prom", nodeapi.TaskPromQLQuery, investigate.TaskQuery{Query: `container_memory_working_set_bytes{namespace="prod"}`,
		StartMs: now.Add(-time.Minute).UnixMilli(), EndMs: time.Now().UnixMilli(), Namespaces: []string{"prod"}})
	task("q-logs", nodeapi.TaskLogQLQuery, investigate.TaskQuery{Query: `{namespace="other"} |= "hello"`,
		StartMs: now.Add(-time.Minute).UnixMilli(), EndMs: time.Now().Add(time.Second).UnixMilli(), Namespaces: []string{"other"}})
	task("q-evidence", nodeapi.TaskEvidence, investigate.TaskQuery{Query: "oom-logs",
		StartMs: now.Add(-time.Minute).UnixMilli(), EndMs: time.Now().Add(time.Second).UnixMilli(), Namespaces: []string{"prod"}})
	get := func(id string) investigate.TaskResponse {
		var res nodeapi.TaskResult
		h.waitFor("task "+id, func() bool {
			var ok bool
			res, ok = h.coord.result(id)
			return ok
		})
		if res.Error != "" {
			t.Fatalf("task %s: %s", id, res.Error)
		}
		var out investigate.TaskResponse
		if err := json.Unmarshal(res.Payload, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	prom := get("q-prom")
	if len(prom.Data.Series) != 1 || prom.Data.Series[0].Metric["pod"] != "web-1" || len(prom.Data.Series[0].Points) == 0 || prom.Data.Series[0].Points[0].V != 900 {
		t.Fatalf("promql task %+v", prom.Data)
	}
	logs := get("q-logs")
	if len(logs.Data.Lines) != 1 || logs.Data.Lines[0].Text != "hello from chatty" || logs.Data.Lines[0].Labels["pod"] != "chatty-1" {
		t.Fatalf("logql task %+v", logs.Data)
	}
	ev := get("q-evidence")
	if len(ev.Data.Lines) != 1 || !strings.Contains(ev.Data.Lines[0].Text, "<redacted>") || strings.Contains(ev.Data.Lines[0].Text, "hunter2secret") {
		t.Fatalf("evidence task %+v", ev.Data)
	}
	if n := a.ring.Stats().Rules["oom-logs"].Samples; n != 1 {
		t.Fatalf("evidence read consumed the ring: %d samples left", n)
	}
	if hits := scanState(t, h.dir, "hello from chatty"); len(hits) > 0 {
		t.Fatalf("investigation retained lines in %v", hits)
	}
	if n := a.tailer.Stats().Lines; n != 1 {
		t.Fatalf("tailer read %d lines; the un-tailed stream must be read on demand only", n)
	}
}

func TestDiskCapUnderNoisyScrape(t *testing.T) {
	h := newHarness(t, options{caps: "metrics", realClock: true, diskCap: "1536Ki", disk: 100 * time.Millisecond,
		extraNode: "  maxSamplesPerSecond: 100000\n", tsdbBlock: 10 * time.Minute, tsdbWAL: 32 << 10})
	var noisy strings.Builder
	noisy.WriteString("# TYPE noisy_gauge gauge\n")
	for i := range 10000 {
		fmt.Fprintf(&noisy, "noisy_gauge{container=\"app\",namespace=\"prod\",pod=\"web-1\",series=\"s%04d\"} %d\n", i, i)
	}
	h.kubelet.set(noisy.String())
	a := h.start()
	h.waitScrapes(2)
	h.waitFor("disk pressure pauses ingestion", func() bool {
		return a.Status().Disk.Pressure && a.gate.paused.Load() && a.gate.dropped.Load() > 0
	})
	before := a.db.Size()
	time.Sleep(time.Second)
	if grown := a.db.Size() - before; grown > 64<<10 {
		t.Fatalf("tsdb grew %d bytes while ingestion was paused", grown)
	}
	if got := a.engineCoverage(); got != engine.CoverageUncovered {
		t.Fatalf("engine coverage under pressure %s", got)
	}
	h.waitFor("pressure disclosed to the coordinator", func() bool {
		reg, ok := h.coord.lastRegister()
		return ok && strings.HasPrefix(reg.Coverage["disk"], "pressure") && strings.Contains(reg.Coverage["metrics"], "disk cap reached")
	})
}

func TestGatedAppendable(t *testing.T) {
	db, err := tsdb.Open(t.TempDir(), tsdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	g := &gatedAppendable{next: db}
	l := labels.FromStrings("__name__", "x")
	app := g.Appender(context.Background())
	if _, err := app.Append(0, l, 1000, 1); err != nil {
		t.Fatal(err)
	}
	if err := app.Commit(); err != nil {
		t.Fatal(err)
	}
	g.paused.Store(true)
	app = g.Appender(context.Background())
	if _, err := app.Append(0, l, 2000, 2); !errors.Is(err, errDiskCap) {
		t.Fatalf("paused append: %v", err)
	}
	if _, err := app.AppendSTZeroSample(0, l, 3000, 2500); !errors.Is(err, errDiskCap) {
		t.Fatal("paused start timestamp append accepted")
	}
	if _, err := app.AppendHistogram(0, l, 3000, nil, nil); !errors.Is(err, errDiskCap) {
		t.Fatal("paused histogram append accepted")
	}
	if _, err := app.AppendHistogramSTZeroSample(0, l, 3000, 2500, nil, nil); !errors.Is(err, errDiskCap) {
		t.Fatal("paused histogram start timestamp append accepted")
	}
	if _, err := app.AppendExemplar(0, l, exemplar.Exemplar{}); !errors.Is(err, errDiskCap) {
		t.Fatal("paused exemplar append accepted")
	}
	if err := app.Commit(); err != nil {
		t.Fatal(err)
	}
	if g.dropped.Load() != 5 {
		t.Fatalf("dropped %d", g.dropped.Load())
	}
	g.paused.Store(false)
	app = g.Appender(context.Background())
	if _, err := app.Append(0, l, 4000, 4); err != nil {
		t.Fatalf("resumed append: %v", err)
	}
	if err := app.Commit(); err != nil {
		t.Fatal(err)
	}
	if st := db.Stats(); st.Series != 1 {
		t.Fatalf("series %d", st.Series)
	}
}

func TestNewRejectsIncompleteConfiguration(t *testing.T) {
	h := newHarness(t, options{})
	cfg := h.config()
	if _, err := New(nil, h.deps); err == nil {
		t.Fatal("nil config accepted")
	}
	d := h.deps
	d.Kube = nil
	if _, err := New(cfg, d); err == nil {
		t.Fatal("missing Kubernetes client accepted")
	}
	d = h.deps
	d.Roots = &bundle.Roots{}
	if _, err := New(cfg, d); !errors.Is(err, bundle.ErrNoRoots) {
		t.Fatalf("empty roots: %v", err)
	}
	d = h.deps
	d.KubeletURL, d.NodeIP = "", ""
	if _, err := New(cfg, d); err == nil || !strings.Contains(err.Error(), "NODE_IP") {
		t.Fatalf("metrics without a node address: %v", err)
	}
	d.KubeletURL = "https://host-without-port"
	if _, err := New(cfg, d); err == nil {
		t.Fatal("kubelet URL without port accepted")
	}
	c2 := h.config()
	c2.Node.Name = ""
	if _, err := New(c2, h.deps); err == nil {
		t.Fatal("missing node name accepted")
	}
	a, err := New(cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatalf("immediate stop: %v", err)
	}
	if err := a.Run(ctx); err == nil {
		t.Fatal("second Run accepted")
	}
}

func TestPromRange(t *testing.T) {
	for expr, want := range map[string]time.Duration{
		`up`:                                 0,
		`rate(x[5m])`:                        5 * time.Minute,
		`max_over_time(rate(x[1m])[10m:1m])`: 11 * time.Minute,
		`x offset 2m`:                        2 * time.Minute,
		`sum(rate(x[1m] offset 30s)) / y`:    90 * time.Second,
	} {
		if got := promRange(expr); got != want {
			t.Fatalf("%s: %s, want %s", expr, got, want)
		}
	}
	if promRange(`(`) != 0 {
		t.Fatal("invalid expression has a range")
	}
}

func TestQueueFullNeverBlocksEvaluationAndPoisonItemsAreDropped(t *testing.T) {
	h := newHarness(t, options{caps: "logs", diskCap: "256Ki"})
	h.coord.set(func(c *fakeCoord) { c.submitErr = errors.New("coordinator spool busy") })
	a := h.start()
	big := nodeapi.Part{RuleID: "filler", EvalTimeMs: 1}
	for i := range 200 {
		big.Samples = append(big.Samples, nodeapi.Sample{Labels: map[string]string{"i": fmt.Sprint(i), "pad": strings.Repeat("p", 64)}, Value: 1, TimestampMs: 1})
	}
	full := false
	for range 200 {
		if err := a.enqueue(nodeapi.Item{Kind: nodeapi.KindSeries, Part: &big}); errors.Is(err, spool.ErrFull) {
			full = true
			break
		}
	}
	if !full {
		t.Fatal("queue never filled")
	}
	n := a.cov.evaluatedCycles()
	h.waitFor("evaluation continues with a full queue", func() bool { return a.cov.evaluatedCycles() > n+3 })
	if d := a.Status().Coverage["queue.dropped"]; !strings.Contains(d, "series=1") {
		t.Fatalf("dropped items not reported: %q", d)
	}
	queued := a.queue.Usage().Items
	h.coord.set(func(c *fakeCoord) {
		c.submitErr = nil
		c.reject = func(it nodeapi.Item) bool { return it.Seq == 2 }
	})
	h.waitDelivered()
	if got := uint64(len(h.coord.received(nodeapi.KindSeries))); got != queued-1 {
		t.Fatalf("delivered %d of %d queued items", got, queued)
	}
	if d := a.Status().Dropped; !strings.Contains(d, "rejected=1") {
		t.Fatalf("poison item not reported: %q", d)
	}
}

func TestRunOutsideClusterFails(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	h := newHarness(t, options{})
	if err := Run(context.Background(), h.config(), slog.Default()); err == nil || !strings.Contains(err.Error(), "in-cluster") {
		t.Fatalf("Run outside a cluster: %v", err)
	}
}

func TestMetricFactsCarryObservedPodUID(t *testing.T) {
	const every = 300 * time.Millisecond
	h := newHarness(t, options{caps: "metrics", realClock: true, facts: every})
	h.start()
	uids := func() []string {
		var out []string
		for _, it := range h.coord.received(nodeapi.KindMetricFacts) {
			for _, f := range it.Facts {
				if f.Pod == "web-1" && f.Container == "app" {
					out = append(out, f.UID)
				}
			}
		}
		return out
	}
	h.waitFor("first metric facts", func() bool { return len(uids()) > 0 })
	if got := uids(); got[0] != "uid-web-1" {
		t.Fatalf("fact pod uid %q", got[0])
	}
	ctx := context.Background()
	if err := h.kube.CoreV1().Pods("prod").Delete(ctx, "web-1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.kube.CoreV1().Pods("prod").Create(ctx, pod("prod", "web-1", "uid-web-1b", testNode, "app", "sidecar"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.waitFor("unchanged usage of the replacement pod sent with its uid", func() bool {
		got := uids()
		return got[len(got)-1] == "uid-web-1b"
	})
	for _, u := range uids() {
		if u != "uid-web-1" && u != "uid-web-1b" {
			t.Fatalf("fact names pod uid %q", u)
		}
	}
}
