package scrape

import (
	"context"
	"encoding/pem"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/value"
	"github.com/prometheus/prometheus/storage"

	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

type rec struct {
	l labels.Labels
	t int64
	v float64
}

type memApp struct {
	mu      sync.Mutex
	samples []rec
}

func (m *memApp) Appender(context.Context) storage.Appender { return &memTx{m: m} }

func (m *memApp) find(name string, match map[string]string) []rec {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []rec
outer:
	for _, s := range m.samples {
		if s.l.Get("__name__") != name {
			continue
		}
		for k, v := range match {
			if s.l.Get(k) != v {
				continue outer
			}
		}
		out = append(out, s)
	}
	return out
}

func (m *memApp) last(t *testing.T, name string, match map[string]string) rec {
	t.Helper()
	r := m.find(name, match)
	if len(r) == 0 {
		t.Fatalf("no samples for %s %v", name, match)
	}
	return r[len(r)-1]
}

type memTx struct {
	storage.Appender
	m       *memApp
	pending []rec
}

func (a *memTx) Append(_ storage.SeriesRef, l labels.Labels, t int64, v float64) (storage.SeriesRef, error) {
	a.pending = append(a.pending, rec{l, t, v})
	return storage.SeriesRef(l.Hash()), nil
}
func (a *memTx) SetOptions(*storage.AppendOptions) {}
func (a *memTx) Rollback() error                   { a.pending = nil; return nil }
func (a *memTx) Commit() error {
	a.m.mu.Lock()
	a.m.samples = append(a.m.samples, a.pending...)
	a.m.mu.Unlock()
	a.pending = nil
	return nil
}

func isStale(v float64) bool { return value.IsStaleNaN(v) }

type exposition struct {
	mu    sync.Mutex
	body  string
	ctype string
	code  int
	auth  []string
	delay time.Duration
}

func (e *exposition) set(body, ctype string, code int) {
	e.mu.Lock()
	e.body, e.ctype, e.code = body, ctype, code
	e.mu.Unlock()
}

func (e *exposition) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	body, ctype, code, delay := e.body, e.ctype, e.code, e.delay
	e.auth = append(e.auth, r.Header.Get("Authorization"))
	e.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if code == 0 {
		code = 200
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

const textFixture = `# HELP http_requests_total Requests.
# TYPE http_requests_total counter
http_requests_total{code="200",job="app",instance="pod-a"} 10
http_requests_total{code="500"} 2
# TYPE latency_seconds histogram
latency_seconds_bucket{le="0.1"} 3
latency_seconds_bucket{le="+Inf"} 4
latency_seconds_sum 0.5
latency_seconds_count 4
`

const omFixture = `# TYPE build_info gauge
build_info{version="1.2.3"} 1
# TYPE jobs counter
jobs_total{queue="a"} 7
# EOF
`

func newTestManager(app storage.Appendable, b Budgets) *Manager {
	return NewManager(Options{Appendable: app, Budgets: b, DefaultInterval: time.Second, DefaultTimeout: time.Second})
}

func testLoop(m *Manager, t Target) *loop {
	if t.Interval == 0 {
		t.Interval = time.Second
	}
	if t.Timeout == 0 {
		t.Timeout = time.Second
	}
	return newLoop(m, t)
}

func TestTextHonorLabelsAndReportSeries(t *testing.T) {
	ex := &exposition{}
	ex.set(textFixture, "text/plain; version=0.0.4", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	app := &memApp{}
	m := newTestManager(app, Budgets{})
	l := testLoop(m, Target{URL: srv.URL + "/metrics", Labels: map[string]string{"job": "kubelet", "node": "n1"}})
	l.scrapeOnce(time.Now())

	host := strings.TrimPrefix(srv.URL, "http://")
	r := app.last(t, "http_requests_total", map[string]string{"code": "200"})
	if r.l.Get("job") != "kubelet" || r.l.Get("exported_job") != "app" || r.l.Get("exported_instance") != "pod-a" || r.l.Get("instance") != host || r.l.Get("node") != "n1" || r.v != 10 {
		t.Fatalf("labels %v v %v", r.l, r.v)
	}
	if r := app.last(t, "http_requests_total", map[string]string{"code": "500"}); r.l.Has("exported_job") || r.l.Get("job") != "kubelet" {
		t.Fatalf("unexpected rename %v", r.l)
	}
	if len(app.find("latency_seconds_bucket", nil)) != 2 {
		t.Fatal("histogram buckets missing")
	}
	if up := app.last(t, "up", map[string]string{"job": "kubelet", "instance": host}); up.v != 1 {
		t.Fatalf("up = %v", up.v)
	}
	if n := app.last(t, "scrape_samples_scraped", nil); n.v != 6 {
		t.Fatalf("samples scraped = %v", n.v)
	}
	if d := app.last(t, "scrape_duration_seconds", nil); d.v <= 0 {
		t.Fatalf("duration = %v", d.v)
	}
	st := l.snapshot()
	if st.Health != HealthUp || st.Series != 6 || st.Samples != 6 {
		t.Fatalf("status %+v", st)
	}
}

func TestOpenMetrics(t *testing.T) {
	ex := &exposition{}
	ex.set(omFixture, "application/openmetrics-text; version=1.0.0; charset=utf-8", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	app := &memApp{}
	l := testLoop(newTestManager(app, Budgets{}), Target{URL: srv.URL, Labels: map[string]string{"job": "om"}})
	l.scrapeOnce(time.Now())
	if r := app.last(t, "jobs_total", map[string]string{"queue": "a", "job": "om"}); r.v != 7 {
		t.Fatalf("jobs_total %v", r.v)
	}
	if r := app.last(t, "build_info", nil); r.l.Get("version") != "1.2.3" {
		t.Fatalf("build_info %v", r.l)
	}
	ex.set("jobs_total 1\n", "application/openmetrics-text; version=1.0.0", 200)
	l.scrapeOnce(time.Now())
	st := l.snapshot()
	if st.Health != HealthDown || st.Reason != ReasonParse {
		t.Fatalf("missing EOF should fail: %+v", st)
	}
	if r := app.last(t, "build_info", nil); !isStale(r.v) {
		t.Fatal("failed scrape did not mark series stale")
	}
	if up := app.last(t, "up", nil); up.v != 0 {
		t.Fatalf("up %v", up.v)
	}
}

func TestStalenessOnSeriesAndTargetDisappearance(t *testing.T) {
	ex := &exposition{}
	ex.set("a 1\nb 2\n", "text/plain", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	app := &memApp{}
	m := newTestManager(app, Budgets{})
	l := testLoop(m, Target{URL: srv.URL})
	now := time.Now()
	l.scrapeOnce(now)
	ex.set("a 1\n", "text/plain", 200)
	l.scrapeOnce(now.Add(time.Second))
	b := app.last(t, "b", nil)
	if !isStale(b.v) || b.t != now.Add(time.Second).UnixMilli() {
		t.Fatalf("b not stale at second scrape: %+v", b)
	}
	if a := app.last(t, "a", nil); isStale(a.v) {
		t.Fatal("a marked stale")
	}
	if m.ActiveSeries() != 1 {
		t.Fatalf("active series %d", m.ActiveSeries())
	}
	l.end()
	for _, n := range []string{"a", "up", "scrape_duration_seconds", "scrape_samples_scraped"} {
		if r := app.last(t, n, nil); !isStale(r.v) {
			t.Fatalf("%s not stale after target removal", n)
		}
	}
	if m.ActiveSeries() != 0 {
		t.Fatalf("active series %d after end", m.ActiveSeries())
	}
}

func TestSeriesAndRateBudgets(t *testing.T) {
	ex := &exposition{}
	ex.set("s1 1\ns2 1\ns3 1\ns4 1\ns5 1\n", "text/plain", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()

	app := &memApp{}
	m := newTestManager(app, Budgets{MaxSeriesPerTarget: 2})
	l := testLoop(m, Target{URL: srv.URL})
	l.scrapeOnce(time.Now())
	st := l.snapshot()
	if st.Series != 2 || st.SeriesDropped != 3 || len(app.find("s3", nil)) != 0 || len(app.find("s1", nil)) != 1 {
		t.Fatalf("per-target budget: %+v", st)
	}
	l.scrapeOnce(time.Now())
	if st := l.snapshot(); st.Series != 2 || st.SeriesDropped != 6 || len(app.find("s1", nil)) != 2 {
		t.Fatalf("known series must keep their slots: %+v", st)
	}

	app2 := &memApp{}
	m2 := newTestManager(app2, Budgets{MaxSeries: 3})
	la, lb := testLoop(m2, Target{URL: srv.URL + "/a"}), testLoop(m2, Target{URL: srv.URL + "/b"})
	la.scrapeOnce(time.Now())
	lb.scrapeOnce(time.Now())
	if la.snapshot().Series != 3 || lb.snapshot().Series != 0 || lb.snapshot().SeriesDropped != 5 || m2.ActiveSeries() != 3 {
		t.Fatalf("node budget: a=%+v b=%+v", la.snapshot(), lb.snapshot())
	}

	app3 := &memApp{}
	m3 := newTestManager(app3, Budgets{MaxSamplesPerSecond: 3})
	m3.limiter.setBurst(time.Second)
	l3 := testLoop(m3, Target{URL: srv.URL})
	l3.scrapeOnce(time.Now())
	st = l3.snapshot()
	if st.SamplesDropped != 2 || st.Series != 3 || len(app3.find("s4", nil)) != 0 {
		t.Fatalf("rate budget: %+v", st)
	}
	if up := app3.last(t, "up", nil); up.v != 1 {
		t.Fatal("rate limiting must not fail the scrape")
	}
}

func TestTargetBudgetAndSyncLifecycle(t *testing.T) {
	ex := &exposition{}
	ex.set("g 1\n", "text/plain", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	app := &memApp{}
	m := NewManager(Options{Appendable: app, Budgets: Budgets{MaxTargets: 1}, DefaultInterval: 20 * time.Millisecond})
	first := Target{URL: srv.URL + "/one", Labels: map[string]string{"job": "one"}}
	second := Target{URL: srv.URL + "/two", Labels: map[string]string{"job": "two"}}
	m.Sync([]Target{first, second, first, {URL: "ftp://x"}})
	st := m.Status()
	if len(st) != 3 {
		t.Fatalf("status %+v", st)
	}
	byJob := map[string]TargetStatus{}
	for _, s := range st {
		byJob[s.Labels["job"]+s.URL] = s
	}
	if s := byJob["two"+second.URL]; s.Health != HealthDropped || s.Reason != ReasonTargetBudget {
		t.Fatalf("second target not dropped: %+v", s)
	}
	if s := byJob["ftp://x"]; s.Reason != ReasonInvalid {
		t.Fatalf("invalid target: %+v", s)
	}
	waitFor(t, func() bool { return len(app.find("g", map[string]string{"job": "one"})) >= 2 })
	m.Sync([]Target{second})
	if r := app.last(t, "g", map[string]string{"job": "one"}); !isStale(r.v) {
		t.Fatal("removed target not marked stale")
	}
	waitFor(t, func() bool { return len(app.find("g", map[string]string{"job": "two"})) >= 1 })
	m.Stop()
	if r := app.last(t, "up", map[string]string{"job": "two"}); !isStale(r.v) {
		t.Fatal("stop did not mark stale")
	}
	if len(m.Status()) != 0 {
		t.Fatal("status after stop")
	}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBearerTokenFileReread(t *testing.T) {
	ex := &exposition{}
	ex.set("x 1\n", "text/plain", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := testLoop(newTestManager(&memApp{}, Budgets{}), Target{URL: srv.URL, BearerTokenFile: tok})
	l.scrapeOnce(time.Now())
	l.scrapeOnce(time.Now())
	next := tok + ".new"
	if err := os.WriteFile(next, []byte("second-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, tok); err != nil {
		t.Fatal(err)
	}
	l.scrapeOnce(time.Now())
	ex.mu.Lock()
	got := append([]string(nil), ex.auth...)
	ex.mu.Unlock()
	want := []string{"Bearer first-token", "Bearer first-token", "Bearer second-token"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("auth headers %v", got)
	}
	if err := os.Remove(tok); err != nil {
		t.Fatal(err)
	}
	l.scrapeOnce(time.Now())
	if st := l.snapshot(); st.Reason != ReasonCredentials {
		t.Fatalf("missing token: %+v", st)
	}
}

func TestTLSVerification(t *testing.T) {
	ex := &exposition{}
	ex.set("x 1\n", "text/plain", 200)
	srv := httptest.NewTLSServer(ex)
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newTestManager(&memApp{}, Budgets{})
	cases := []struct {
		tls  TLSConfig
		want Health
		why  string
	}{
		{TLSConfig{CAFile: ca}, HealthUp, ""},
		{TLSConfig{}, HealthDown, ReasonTLS},
		{TLSConfig{InsecureSkipVerify: true}, HealthUp, ""},
		{TLSConfig{CAFile: filepath.Join(t.TempDir(), "missing")}, HealthDown, ReasonTLS},
	}
	for i, c := range cases {
		l := testLoop(m, Target{URL: srv.URL, TLS: c.tls})
		l.scrapeOnce(time.Now())
		if st := l.snapshot(); st.Health != c.want || st.Reason != c.why {
			t.Fatalf("case %d: %+v", i, st)
		}
	}
}

func TestFailureClassification(t *testing.T) {
	ex := &exposition{}
	srv := httptest.NewServer(ex)
	defer srv.Close()
	m := NewManager(Options{Appendable: &memApp{}, MaxBodyBytes: 64})
	check := func(tg Target, want string) {
		t.Helper()
		l := testLoop(m, tg)
		l.scrapeOnce(time.Now())
		if st := l.snapshot(); st.Health != HealthDown || st.Reason != want {
			t.Fatalf("want %s got %+v", want, st)
		}
	}
	ex.set("", "text/plain", 403)
	check(Target{URL: srv.URL}, ReasonUnauthorized)
	ex.set("", "text/plain", 503)
	check(Target{URL: srv.URL}, ReasonHTTPStatus)
	ex.set(strings.Repeat("m 1\n", 40), "text/plain", 200)
	check(Target{URL: srv.URL}, ReasonBodyLimit)
	ex.set("m{ 1\n", "text/plain", 200)
	check(Target{URL: srv.URL}, ReasonParse)
	ex.set("m 1\n", "text/plain", 200)
	ex.mu.Lock()
	ex.delay = time.Second
	ex.mu.Unlock()
	check(Target{URL: srv.URL, Timeout: 50 * time.Millisecond}, ReasonTimeout)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	check(Target{URL: "http://" + addr + "/metrics"}, ReasonUnreachable)
}

func TestIntoTSDB(t *testing.T) {
	db, err := tsdb.Open(t.TempDir(), tsdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ex := &exposition{}
	ex.set(textFixture, "text/plain", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	m := newTestManager(db, Budgets{})
	l := testLoop(m, Target{URL: srv.URL, Labels: map[string]string{"job": "j"}})
	now := time.Now()
	l.scrapeOnce(now)
	ex.set("latency_seconds_count 5\n", "text/plain", 200)
	l.scrapeOnce(now.Add(time.Second))
	if st := l.snapshot(); st.Health != HealthUp || st.AppendErrors != 0 {
		t.Fatalf("status %+v", st)
	}
	q, err := db.Querier(math.MinInt64, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ss := q.Select(context.Background(), false, nil, labels.MustNewMatcher(labels.MatchEqual, "__name__", "latency_seconds_sum"))
	if !ss.Next() {
		t.Fatal("series missing")
	}
	it := ss.At().Iterator(nil)
	var vals []float64
	for it.Next() != 0 {
		_, v := it.At()
		vals = append(vals, v)
	}
	if len(vals) != 2 || vals[0] != 0.5 || !isStale(vals[1]) {
		t.Fatalf("values %v", vals)
	}
}

func TestDiscovery(t *testing.T) {
	kt := KubeletTargets("10.0.0.5", 10250, KubeletOptions{Node: "n1"})
	if len(kt) != 2 || kt[0].URL != "https://10.0.0.5:10250/metrics" || kt[1].URL != "https://10.0.0.5:10250/metrics/cadvisor" {
		t.Fatalf("kubelet targets %+v", kt)
	}
	if kt[1].BearerTokenFile != ServiceAccountTokenFile || kt[1].TLS.CAFile != ServiceAccountCAFile || kt[1].Labels["node"] != "n1" || kt[1].Labels["metrics_path"] != "/metrics/cadvisor" {
		t.Fatalf("kubelet auth %+v", kt[1])
	}
	if v6 := KubeletTargets("fd00::1", 10250, KubeletOptions{InsecureSkipVerify: true}); v6[0].URL != "https://[fd00::1]:10250/metrics" || v6[0].TLS.CAFile != "" {
		t.Fatalf("ipv6 %+v", v6[0])
	}
	pods := []Pod{
		{Namespace: "a", Name: "p1", IP: "10.1.0.1", Phase: "Running", Node: "n1", Annotations: map[string]string{AnnotationScrape: "true", AnnotationPort: "9100", AnnotationPath: "stats", AnnotationScheme: "https"}, Ports: []PodPort{{Container: "exp", Port: 9100}}},
		{Namespace: "a", Name: "p2", IP: "10.1.0.2", Phase: "Running", Annotations: map[string]string{AnnotationScrape: "true"}, Ports: []PodPort{{Container: "c", Port: 8080}, {Container: "c", Port: 53, Protocol: "UDP"}}},
		{Namespace: "a", Name: "p3", IP: "10.1.0.3", Phase: "Running", Annotations: map[string]string{AnnotationScrape: "false"}, Ports: []PodPort{{Port: 1}}},
		{Namespace: "a", Name: "p4", IP: "", Phase: "Pending", Annotations: map[string]string{AnnotationScrape: "true", AnnotationPort: "1"}},
		{Namespace: "a", Name: "p5", IP: "10.1.0.5", Phase: "Running", Annotations: map[string]string{AnnotationScrape: "true", AnnotationPort: "x"}},
		{Namespace: "a", Name: "p6", IP: "10.1.0.6", Phase: "Running", Annotations: map[string]string{AnnotationScrape: "true", AnnotationPort: "80", AnnotationScheme: "gopher"}},
	}
	pt := PodTargets(pods)
	if len(pt) != 2 {
		t.Fatalf("pod targets %+v", pt)
	}
	if pt[0].URL != "https://10.1.0.1:9100/stats" || pt[0].Labels["container"] != "exp" || pt[0].Labels["namespace"] != "a" || pt[0].Labels["node"] != "n1" {
		t.Fatalf("p1 %+v", pt[0])
	}
	if pt[1].URL != "http://10.1.0.2:8080/metrics" || pt[1].Labels["pod"] != "p2" {
		t.Fatalf("p2 %+v", pt[1])
	}
	if tl, _ := pt[1].targetLabels(); tl["instance"] != "10.1.0.2:8080" || tl["job"] != "kubernetes-pods" {
		t.Fatalf("target labels %v", tl)
	}
}

func TestLimiterRefill(t *testing.T) {
	var now atomic.Int64
	base := time.Unix(1000, 0)
	l := newLimiter(10, func() time.Time { return base.Add(time.Duration(now.Load())) })
	l.setBurst(2 * time.Second)
	if g := l.take(25); g != 20 {
		t.Fatalf("burst grant %d", g)
	}
	if g := l.take(5); g != 0 {
		t.Fatalf("empty grant %d", g)
	}
	now.Store(int64(500 * time.Millisecond))
	if g := l.take(10); g != 5 {
		t.Fatalf("refill grant %d", g)
	}
	l.giveBack(3)
	if g := l.take(10); g != 3 {
		t.Fatalf("give back %d", g)
	}
}
