package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

var testNow = time.Now().Truncate(time.Second)

func openTSDB(t *testing.T, series ...labels.Labels) *tsdb.DB {
	t.Helper()
	db, err := tsdb.Open(t.TempDir(), tsdb.Options{Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := db.Appender(context.Background())
	for i := 0; i <= 80; i++ {
		ts := testNow.Add(-20 * time.Minute).Add(time.Duration(i) * 15 * time.Second)
		for j, l := range series {
			if _, err := app.Append(0, l, ts.UnixMilli(), float64(i*(j+1))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := app.Commit(); err != nil {
		t.Fatal(err)
	}
	return db
}

func criLine(ts time.Time, text string) string {
	return fmt.Sprintf("%s stdout F %s\n", ts.UTC().Format(time.RFC3339Nano), text)
}

func writePodLog(t *testing.T, root, ns, pod, uid, container string, lines []string) string {
	t.Helper()
	d := filepath.Join(root, ns+"_"+pod+"_"+uid, container)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i, l := range lines {
		b.WriteString(criLine(testNow.Add(-10*time.Minute).Add(time.Duration(i)*time.Second), l))
	}
	p := filepath.Join(d, "0.log")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, ns+"_"+pod+"_"+uid)
}

func podLogTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	var shop []string
	for i := range 20 {
		if i%4 == 0 {
			shop = append(shop, fmt.Sprintf("error %d password=hunter2", i))
		} else {
			shop = append(shop, fmt.Sprintf("ok %d", i))
		}
	}
	writePodLog(t, root, "shop", "api-1", "u1", "api", shop)
	writePodLog(t, root, "other", "db-1", "u2", "db", []string{"error other ns", "error again"})
	return root
}

func runTask(t *testing.T, e *Executor, kind nodeapi.TaskKind, q TaskQuery) (*TaskResponse, string) {
	t.Helper()
	b, _ := json.Marshal(q)
	res := e.Execute(context.Background(), nodeapi.Task{ID: "t1", Kind: kind, Payload: b})
	if res.ID != "t1" {
		t.Fatalf("result id %q", res.ID)
	}
	if res.Error != "" {
		return nil, res.Error
	}
	var resp TaskResponse
	if err := json.Unmarshal(res.Payload, &resp); err != nil {
		t.Fatal(err)
	}
	return &resp, ""
}

func mustInject(t *testing.T, f func(string, []*labels.Matcher) (string, error), q string, sc telemetryScope) string {
	t.Helper()
	out, err := f(q, sc.matchers())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExecutorPromQLRange(t *testing.T) {
	db := openTSDB(t,
		labels.FromStrings("__name__", "req_total", "namespace", "shop", "pod", "api-1", "node", "n1"),
		labels.FromStrings("__name__", "req_total", "namespace", "other", "pod", "db-1", "node", "n1"))
	e := NewExecutor(ExecOptions{Node: "n1", Queryable: db, Retention: db.Retention})
	q := TaskQuery{
		Query:   mustInject(t, InjectPromQL, `rate(req_total[5m])`, scopeA),
		StartMs: testNow.Add(-10 * time.Minute).UnixMilli(), EndMs: testNow.UnixMilli(), StepMs: 60_000,
		Namespaces: scopeA.namespaces,
	}
	resp, errStr := runTask(t, e, nodeapi.TaskPromQLQuery, q)
	if errStr != "" {
		t.Fatal(errStr)
	}
	if resp.Data.ResultType != TypeMatrix || len(resp.Data.Series) != 1 || resp.Data.Series[0].Metric["namespace"] != "shop" {
		t.Fatalf("series %+v", resp.Data)
	}
	if n := len(resp.Data.Series[0].Points); n != 11 {
		t.Fatalf("points %d", n)
	}
	if resp.RetentionMs != time.Hour.Milliseconds() {
		t.Fatalf("retention %d", resp.RetentionMs)
	}
	q.Query = `rate(req_total[5m])`
	if _, errStr := runTask(t, e, nodeapi.TaskPromQLQuery, q); !strings.Contains(errStr, "not bound to the task scope") {
		t.Fatalf("unscoped task must be rejected: %q", errStr)
	}
	q.Query = mustInject(t, InjectPromQL, `req_total`, scopeA)
	q.Limits = Limits{MaxSamples: 1}
	q.StepMs = 1000
	resp, errStr = runTask(t, e, nodeapi.TaskPromQLQuery, q)
	if errStr != "" || !resp.Truncated || !strings.Contains(strings.Join(resp.Limitations, ";"), "sample limit") {
		t.Fatalf("sample limit: %+v %q", resp, errStr)
	}
	if _, errStr := runTask(t, NewExecutor(ExecOptions{Node: "n2"}), nodeapi.TaskPromQLQuery, TaskQuery{Query: q.Query, StartMs: q.StartMs, EndMs: q.EndMs, Namespaces: q.Namespaces}); !strings.Contains(errStr, "not collected") {
		t.Fatalf("missing metrics must be reported: %q", errStr)
	}
}

// TestExecutorLogQLOnDemand is acceptance 17: no rule tails the stream, lines are bounded, nothing is retained.
func TestExecutorLogQLOnDemand(t *testing.T) {
	root := podLogTree(t)
	e := NewExecutor(ExecOptions{Node: "n1", PodLogRoot: root})
	q := TaskQuery{
		Query:   mustInject(t, InjectLogQL, `{container="api"} |= "error"`, scopeA),
		StartMs: testNow.Add(-15 * time.Minute).UnixMilli(), EndMs: testNow.UnixMilli(),
		Namespaces: scopeA.namespaces, Limits: Limits{MaxLines: 3},
	}
	resp, errStr := runTask(t, e, nodeapi.TaskLogQLQuery, q)
	if errStr != "" {
		t.Fatal(errStr)
	}
	if len(resp.Data.Lines) != 3 || !resp.Truncated {
		t.Fatalf("bounded lines: %d truncated=%v", len(resp.Data.Lines), resp.Truncated)
	}
	for _, l := range resp.Data.Lines {
		if l.Labels["namespace"] != "shop" || l.Labels["node"] != "n1" || !strings.HasPrefix(l.Text, "error") {
			t.Fatalf("line %+v", l)
		}
		if strings.Contains(l.Text, "hunter2") {
			t.Fatalf("line not redacted: %q", l.Text)
		}
	}
	if resp.Data.Lines[0].Text != "error 16 password=<redacted>" {
		t.Fatalf("newest first: %q", resp.Data.Lines[0].Text)
	}
	mq := q
	mq.Query = mustInject(t, InjectLogQL, `sum by (namespace) (count_over_time({container=~".+"} |= "error" [15m]))`, scopeA)
	mq.Limits = Limits{}
	resp, errStr = runTask(t, e, nodeapi.TaskLogQLQuery, mq)
	if errStr != "" || resp.Data.ResultType != TypeVector || len(resp.Data.Series) != 1 || resp.Data.Series[0].Points[0].V != 5 {
		t.Fatalf("metric query: %+v %q", resp, errStr)
	}
	if _, errStr := runTask(t, e, nodeapi.TaskLogRead, q); !strings.Contains(errStr, "stream selector") {
		t.Fatalf("log_read with a pipeline must be rejected: %q", errStr)
	}
	rq := q
	rq.Query = mustInject(t, InjectLogQL, `{pod="api-1"}`, scopeA)
	rq.Limits = Limits{}
	resp, errStr = runTask(t, e, nodeapi.TaskLogRead, rq)
	if errStr != "" || len(resp.Data.Lines) != 20 {
		t.Fatalf("log_read: %+v %q", resp, errStr)
	}
	if err := os.RemoveAll(filepath.Join(root, "shop_api-1_u1")); err != nil {
		t.Fatal(err)
	}
	resp, errStr = runTask(t, e, nodeapi.TaskLogRead, rq)
	if errStr != "" || len(resp.Data.Lines) != 0 {
		t.Fatalf("executor retained lines: %+v %q", resp, errStr)
	}
}

func TestExecutorReadBoundsAndNoSources(t *testing.T) {
	root := podLogTree(t)
	e := NewExecutor(ExecOptions{Node: "n1", PodLogRoot: root, ReadMaxLines: 5})
	q := TaskQuery{
		Query:   mustInject(t, InjectLogQL, `{pod="api-1"} |= "error"`, scopeA),
		StartMs: testNow.Add(-15 * time.Minute).UnixMilli(), EndMs: testNow.UnixMilli(), Namespaces: scopeA.namespaces,
	}
	resp, errStr := runTask(t, e, nodeapi.TaskLogQLQuery, q)
	if errStr != "" || !resp.Truncated || !strings.Contains(strings.Join(resp.Limitations, ";"), "older lines were not evaluated") {
		t.Fatalf("read bound: %+v %q", resp, errStr)
	}
	if _, errStr := runTask(t, NewExecutor(ExecOptions{Node: "n1"}), nodeapi.TaskLogQLQuery, q); !strings.Contains(errStr, "logs are not collected") {
		t.Fatalf("no sources: %q", errStr)
	}
	for _, bad := range []TaskQuery{{Query: q.Query, StartMs: 0, EndMs: 1}, {Query: q.Query, StartMs: q.StartMs, EndMs: q.StartMs + int64(7*time.Hour/time.Millisecond)}} {
		if _, errStr := runTask(t, e, nodeapi.TaskLogQLQuery, bad); errStr == "" {
			t.Fatalf("invalid window accepted: %+v", bad)
		}
	}
	b, _ := json.Marshal(q)
	if r := e.Execute(context.Background(), nodeapi.Task{ID: "x", Kind: "shell", Payload: b}); !strings.Contains(r.Error, "unknown task kind") {
		t.Fatalf("unknown kind: %q", r.Error)
	}
	if r := e.Execute(context.Background(), nodeapi.Task{ID: "x", Kind: nodeapi.TaskLogRead, Payload: []byte(`{"query":"x","bogus":1}`)}); r.Error == "" {
		t.Fatal("unknown payload fields must be rejected")
	}
}

func TestExecutorHostLogs(t *testing.T) {
	dir := t.TempDir()
	syslog := filepath.Join(dir, "syslog")
	var b strings.Builder
	for i := range 6 {
		ts := testNow.Add(-5 * time.Minute).Add(time.Duration(i) * time.Second)
		fmt.Fprintf(&b, "%s host app[1]: boom %d\n", ts.Format(time.RFC3339Nano), i)
		b.WriteString("  continuation without timestamp\n")
	}
	if err := os.WriteFile(syslog, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "old.log")
	if err := os.WriteFile(old, []byte(testNow.Add(-3*time.Hour).Format(time.RFC3339)+" boom old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(old, testNow.Add(-3*time.Hour), testNow.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rot.gz"), []byte("boom gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	journal := logql.LineSourceFunc(func(ctx context.Context, req logql.SourceRequest, yield func(logql.Line) bool) error {
		lbls := map[string]string{"unit": "ssh.service", "priority": "3"}
		if req.Match(lbls) {
			yield(logql.Line{Labels: lbls, Time: testNow.Add(-time.Minute), Text: "boom journal"})
		}
		return nil
	})
	e := NewExecutor(ExecOptions{Node: "h1", HostLogPaths: []string{dir}, Journal: journal})
	q := TaskQuery{Query: `{filename=~".+"} |= "boom"`, StartMs: testNow.Add(-time.Hour).UnixMilli(), EndMs: testNow.UnixMilli(), Forward: true}
	resp, errStr := runTask(t, e, nodeapi.TaskLogQLQuery, q)
	if errStr != "" || len(resp.Data.Lines) != 6 {
		t.Fatalf("host files: %+v %q", resp, errStr)
	}
	if !strings.HasSuffix(resp.Data.Lines[0].Text, "boom 0") || resp.Data.Lines[0].Labels["filename"] != syslog {
		t.Fatalf("forward order and filename label: %+v", resp.Data.Lines[0])
	}
	q.Query = `{unit="ssh.service"}`
	resp, errStr = runTask(t, e, nodeapi.TaskLogRead, q)
	if errStr != "" || len(resp.Data.Lines) != 1 || resp.Data.Lines[0].Text != "boom journal" {
		t.Fatalf("journal: %+v %q", resp, errStr)
	}
	small := NewExecutor(ExecOptions{Node: "h1", HostLogPaths: []string{syslog}, ReadMaxScanBytes: 200})
	q.Query = `{filename=~".+"}`
	resp, errStr = runTask(t, small, nodeapi.TaskLogRead, q)
	if errStr != "" || !resp.Truncated || len(resp.Data.Lines) == 0 || len(resp.Data.Lines) >= 12 {
		t.Fatalf("scan budget: %+v %q", resp, errStr)
	}
}

func TestLineTime(t *testing.T) {
	mtime := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	if ts, ok := lineTime("Jan  2 02:59:00 host x", mtime); !ok || !ts.Equal(time.Date(2026, 1, 2, 2, 59, 0, 0, time.UTC)) {
		t.Fatalf("syslog: %v %v", ts, ok)
	}
	if ts, ok := lineTime("Dec 31 23:00:00 host x", mtime); !ok || ts.Year() != 2025 {
		t.Fatalf("year rollover: %v %v", ts, ok)
	}
	if _, ok := lineTime("no time here", mtime); ok {
		t.Fatal("untimed line parsed")
	}
}

func TestExecutorConcurrencyBound(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{}, 4)
	journal := logql.LineSourceFunc(func(ctx context.Context, _ logql.SourceRequest, _ func(logql.Line) bool) error {
		started <- struct{}{}
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil
	})
	e := NewExecutor(ExecOptions{Node: "h1", Journal: journal, Limits: config.Investigation{MaxConcurrency: 1}})
	q := TaskQuery{Query: `{unit="a"}`, StartMs: testNow.Add(-time.Minute).UnixMilli(), EndMs: testNow.UnixMilli(), Limits: Limits{TimeoutMs: 10_000}}
	long, _ := json.Marshal(q)
	q.Limits.TimeoutMs = 100
	short, _ := json.Marshal(q)
	done := make(chan nodeapi.TaskResult)
	go func() {
		done <- e.Execute(context.Background(), nodeapi.Task{ID: "a", Kind: nodeapi.TaskLogRead, Payload: long})
	}()
	<-started
	r := e.Execute(context.Background(), nodeapi.Task{ID: "b", Kind: nodeapi.TaskLogRead, Payload: short})
	if !strings.Contains(r.Error, "busy") {
		t.Fatalf("second task must wait then fail busy: %q", r.Error)
	}
	close(block)
	<-done
}
