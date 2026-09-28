package investigate

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
)

const (
	secretToken = "s3cret-token-value"
	secretUser  = "lookback-user"
	secretPass  = "lookback-pass-value"
)

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (s *seen) add(r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r)
	s.mu.Unlock()
}

func (s *seen) last(path string) *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.reqs) - 1; i >= 0; i-- {
		if s.reqs[i].URL.Path == path {
			return s.reqs[i]
		}
	}
	return nil
}

func secretFiles(t *testing.T) (token, user, pass string) {
	t.Helper()
	d := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write("token", secretToken), write("user", secretUser), write("pass", secretPass)
}

const matrixBody = `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"up","namespace":"shop"},"values":[[1700000000,"1"],[1700000060.5,"NaN"]]}]}}`
const vectorBody = `{"status":"success","warnings":["partial response"],"data":{"resultType":"vector","result":[{"metric":{"namespace":"shop"},"value":[1700000000,"42"]}]}}`

func upstream(t *testing.T, s *seen, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func lookbackHarness(t *testing.T, sources ...config.Lookback) *harness {
	t.Helper()
	return newHarness(t, func(o *Options) { o.Lookback = sources })
}

func lbArgs(t *testing.T, source, lang, query string, extra map[string]any) json.RawMessage {
	a := map[string]any{"source": source, "language": lang, "query": query, "window": win(10*time.Minute, 0)}
	for k, v := range extra {
		a[k] = v
	}
	return args(t, a)
}

func TestPrometheusAdapter(t *testing.T) {
	s := &seen{}
	srv := upstream(t, s, map[string]string{
		"/api/v1/query_range":  matrixBody,
		"/api/v1/query":        vectorBody,
		"/api/v1/status/flags": `{"status":"success","data":{"storage.tsdb.retention.time":"15d"}}`,
	})
	tok, _, _ := secretFiles(t)
	h := lookbackHarness(t, config.Lookback{Name: "prom", Type: config.SourcePrometheus, URL: srv.URL, BearerTokenFile: tok})
	r := h.mustCall(t, ToolLookback, lbArgs(t, "prom", LangPromQL, `rate(up{job="a"}[5m])`, map[string]any{"step_ms": 60_000}))
	req := s.last("/api/v1/query_range")
	if req == nil || req.Header.Get("Authorization") != "Bearer "+secretToken {
		t.Fatalf("auth header missing: %+v", req)
	}
	if q := req.URL.Query(); q.Get("query") != `rate(up{job="a",namespace="shop"}[5m])` || q.Get("step") != "60s" || q.Get("start") == "" || q.Get("timeout") != "30s" {
		t.Fatalf("params %v", q)
	}
	if r.RetentionMs != (15*24*time.Hour).Milliseconds() || r.Source != "prom" || r.QueryHash == "" {
		t.Fatalf("result %+v", r)
	}
	d := r.Data.(Telemetry)
	if d.ResultType != TypeMatrix || len(d.Series) != 1 || d.Series[0].Points[1].T != 1700000060500 || d.Series[0].Source != "prom" {
		t.Fatalf("data %+v", d)
	}
	r = h.mustCall(t, ToolLookback, lbArgs(t, "prom", LangPromQL, `up`, nil))
	if s.last("/api/v1/query").URL.Query().Get("time") == "" || !strings.Contains(joined(r), "source warning: partial response") {
		t.Fatalf("instant %v", r.Limitations)
	}
	n := 0
	for _, rq := range s.reqs {
		if rq.URL.Path == "/api/v1/status/flags" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("retention discovered %d times, want once", n)
	}
	r = h.mustCall(t, ToolLookback, lbArgs(t, "prom", LangPromQL, `up`, map[string]any{"window": win(5*time.Hour, 4*time.Hour)}))
	if strings.Contains(joined(r), "expired") {
		t.Fatalf("within retention flagged: %v", r.Limitations)
	}
	if _, err := h.call(t, ToolLookback, lbArgs(t, "prom", LangMetricsQL, `up`, nil)); errClass(err) != ClassInvalid {
		t.Fatalf("metricsql on prometheus: %v", err)
	}
	if _, err := h.call(t, ToolLookback, lbArgs(t, "prom", LangLogQL, `{a="b"}`, nil)); errClass(err) != ClassInvalid {
		t.Fatalf("logql on prometheus: %v", err)
	}
}

func TestMimirAndVictoriaMetricsAdapters(t *testing.T) {
	s := &seen{}
	srv := upstream(t, s, map[string]string{
		"/base/prometheus/api/v1/query":       vectorBody,
		"/api/v1/query":                       vectorBody,
		"/flags":                              "-retentionPeriod=\"1\"\n-search.maxQueryLen=\"16384\"\n",
		"/select/7:3/prometheus/api/v1/query": vectorBody,
		"/select/9/prometheus/api/v1/query":   vectorBody,
	})
	_, user, pass := secretFiles(t)
	h := lookbackHarness(t,
		config.Lookback{Name: "mimir", Type: config.SourceMimir, URL: srv.URL + "/base/", Tenant: "team-a", BasicUsernameFile: user, BasicPasswordFile: pass},
		config.Lookback{Name: "vm", Type: config.SourceVictoriaMetrics, URL: srv.URL},
		config.Lookback{Name: "vmc", Type: config.SourceVictoriaMetrics, URL: srv.URL, AccountID: "7", ProjectID: "3"},
		config.Lookback{Name: "vmc2", Type: config.SourceVictoriaMetrics, URL: srv.URL, AccountID: "9", Retention: config.Duration(time.Hour)},
	)
	r := h.mustCall(t, ToolLookback, lbArgs(t, "mimir", LangPromQL, `up`, nil))
	req := s.last("/base/prometheus/api/v1/query")
	u, p, ok := req.BasicAuth()
	if req.Header.Get("X-Scope-OrgID") != "team-a" || !ok || u != secretUser || p != secretPass || req.URL.Query().Get("query") != `up{namespace="shop"}` {
		t.Fatalf("mimir request %v %v", req.Header, req.URL)
	}
	if !strings.Contains(joined(r), "retention of lookback source mimir is unknown") {
		t.Fatalf("unknown retention not reported: %v", r.Limitations)
	}
	r = h.mustCall(t, ToolLookback, lbArgs(t, "vm", LangMetricsQL, `foo{a="b" or c="d"}`, nil))
	if q := s.last("/api/v1/query").URL.Query().Get("query"); q != `foo{a="b",namespace="shop" or c="d",namespace="shop"}` {
		t.Fatalf("metricsql injection %q", q)
	}
	if r.RetentionMs != vmMonth.Milliseconds() {
		t.Fatalf("vm retention %d", r.RetentionMs)
	}
	h.mustCall(t, ToolLookback, lbArgs(t, "vmc", LangPromQL, `up`, nil))
	if s.last("/select/7:3/prometheus/api/v1/query") == nil || s.last("/select/7:3/prometheus/api/v1/query").Header.Get("X-Scope-OrgID") != "" {
		t.Fatal("vm cluster tenant path")
	}
	r = h.mustCall(t, ToolLookback, lbArgs(t, "vmc2", LangMetricsQL, `up`, map[string]any{"window": win(3*time.Hour, 2*time.Hour)}))
	if s.last("/select/9/prometheus/api/v1/query") == nil || r.RetentionMs != time.Hour.Milliseconds() || !strings.Contains(joined(r), "older data has expired") {
		t.Fatalf("vm cluster account only / expired retention: %v", r.Limitations)
	}
}

func TestLokiAdapter(t *testing.T) {
	s := &seen{}
	srv := upstream(t, s, map[string]string{
		"/loki/api/v1/query_range": `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"namespace":"shop","app":"api"},"values":[["1700000000000000000","token=abc123 boom"],["1700000001000000000","boom 2"]]}]}}`,
		"/loki/api/v1/query":       vectorBody,
	})
	h := lookbackHarness(t, config.Lookback{Name: "loki", Type: config.SourceLoki, URL: srv.URL, Tenant: "t1", Retention: config.Duration(24 * time.Hour)})
	r := h.mustCall(t, ToolLookback, lbArgs(t, "loki", LangLogQL, `{app="api"} |= "boom"`, map[string]any{"limits": map[string]any{"max_lines": 1}}))
	req := s.last("/loki/api/v1/query_range")
	if req.Header.Get("X-Scope-OrgID") != "t1" || req.URL.Query().Get("query") != `{app="api", namespace="shop"} |= "boom"` || req.URL.Query().Get("limit") != "2" || req.URL.Query().Get("direction") != "backward" {
		t.Fatalf("loki request %v %v", req.Header, req.URL.Query())
	}
	d := r.Data.(Telemetry)
	if len(d.Lines) != 1 || !r.Truncated || d.Lines[0].Text != "boom 2" {
		t.Fatalf("loki lines %+v", d)
	}
	h.mustCall(t, ToolLookback, lbArgs(t, "loki", LangLogQL, `{app="api"} |= "token"`, nil))
	h.mustCall(t, ToolLookback, lbArgs(t, "loki", LangLogQL, `sum(count_over_time({app="api"}[5m]))`, nil))
	if q := s.last("/loki/api/v1/query").URL.Query(); q.Get("time") == "" || !strings.Contains(q.Get("query"), `namespace="shop"`) {
		t.Fatalf("loki instant %v", q)
	}
	r = h.mustCall(t, ToolLookback, lbArgs(t, "loki", LangLogQL, `{app="api"}`, nil))
	for _, l := range r.Data.(Telemetry).Lines {
		if strings.Contains(l.Text, "abc123") {
			t.Fatalf("lookback line not redacted: %q", l.Text)
		}
	}
}

// TestVictoriaLogsAdapter covers acceptance 34: translation fixtures, rejection with a reason, and native LogsQL injection.
func TestVictoriaLogsAdapter(t *testing.T) {
	s := &seen{}
	srv := upstream(t, s, map[string]string{
		"/select/logsql/query":             `{"_time":"2023-11-14T22:13:20Z","_msg":"err one","_stream":"{app=\"api\"}","app":"api","level":"error"}` + "\n" + `{"_time":"2023-11-14T22:13:21Z","_msg":"err two","app":"api"}` + "\n",
		"/select/logsql/stats_query":       vectorBody,
		"/select/logsql/stats_query_range": matrixBody,
		"/flags":                           "-retentionPeriod=\"7d\"\n",
	})
	h := lookbackHarness(t, config.Lookback{Name: "vl", Type: config.SourceVictoriaLogs, URL: srv.URL, AccountID: "12", ProjectID: "34"})
	fixtures := []struct {
		logql string
		want  []string
	}{
		{`{app="api"} |= "err"`, []string{`app="api"`, `namespace="shop"`, `*err*`}},
		{`{app="api"} != "debug" |~ "a+b"`, []string{`!*debug*`, `~"(?-s:a+b)"`}},
		{`{app="api"} | json | level="error"`, []string{`unpack_json`, `filter level:=error`}},
		{`{app="api"} | regexp "(?P<code>\\d+)"`, []string{`extract_regexp`}},
		{`{app="api"} | pattern "<ip> <_>"`, []string{`extract "<plain:ip>`}},
	}
	for _, f := range fixtures {
		r := h.mustCall(t, ToolLookback, lbArgs(t, "vl", LangLogQL, f.logql, nil))
		req := s.last("/select/logsql/query")
		q := req.URL.Query().Get("query")
		for _, w := range f.want {
			if !strings.Contains(q, w) || !strings.Contains(r.Executed, w) {
				t.Fatalf("%s: %q missing in %q", f.logql, w, q)
			}
		}
		if req.Header.Get("AccountID") != "12" || req.Header.Get("ProjectID") != "34" || !strings.Contains(q, "_time:[") {
			t.Fatalf("tenant headers or window %v %q", req.Header, q)
		}
		if !strings.Contains(r.Query, `namespace="shop"`) || r.Language != LangLogQL {
			t.Fatalf("hashed query %q", r.Query)
		}
	}
	r := h.mustCall(t, ToolLookback, lbArgs(t, "vl", LangLogQL, `{app="api"}`, nil))
	d := r.Data.(Telemetry)
	if len(d.Lines) != 2 || d.Lines[0].Text != "err two" || d.Lines[1].Labels["level"] != "error" || r.RetentionMs != (7*24*time.Hour).Milliseconds() {
		t.Fatalf("rows %+v", r)
	}
	h.mustCall(t, ToolLookback, lbArgs(t, "vl", LangLogQL, `sum by (app) (count_over_time({app="api"}[5m]))`, nil))
	if q := s.last("/select/logsql/stats_query").URL.Query(); !strings.Contains(q.Get("query"), "stats by (app) count(*) as value") || q.Get("time") == "" {
		t.Fatalf("stats %v", q)
	}
	for _, bad := range []struct{ q, reason string }{
		{`topk(3, count_over_time({app="api"}[5m]))`, "cannot translate topk"},
		{`{app="api"} | logfmt | d > 5s`, "cannot translate duration label filter"},
		{`{app="api"} | json x="y.z"`, "json extraction parameters"},
	} {
		_, err := h.call(t, ToolLookback, lbArgs(t, "vl", LangLogQL, bad.q, nil))
		if errClass(err) != ClassInvalid || !strings.Contains(err.Error(), bad.reason) {
			t.Fatalf("%s: %v", bad.q, err)
		}
	}
	if _, err := h.call(t, ToolLookback, lbArgs(t, "vl", LangLogQL, `sum(count_over_time({app="api"}[5m]))`, map[string]any{"step_ms": 60_000})); errClass(err) != ClassInvalid || !strings.Contains(err.Error(), "range metric queries") {
		t.Fatalf("range metric: %v", err)
	}
	r = h.mustCall(t, ToolLogsQL, args(t, map[string]any{"source": "vl", "query": `error or warn | union (panic)`, "window": win(10*time.Minute, 0)}))
	q := s.last("/select/logsql/query").URL.Query().Get("query")
	if strings.Count(q, `namespace=~"shop"`) != 2 || r.Language != LangLogsQL || strings.Contains(r.Query, "_time") {
		t.Fatalf("native logsql injection %q / %q", q, r.Query)
	}
	h.mustCall(t, ToolLogsQL, args(t, map[string]any{"source": "vl", "query": `* | stats by (level) count() c`, "window": win(10*time.Minute, 0), "step_ms": 60_000}))
	if q := s.last("/select/logsql/stats_query_range").URL.Query(); q.Get("step") != "60s" || !strings.Contains(q.Get("query"), `namespace=~"shop"`) {
		t.Fatalf("stats range %v", q)
	}
	for _, bad := range []map[string]any{
		{"source": "vl", "query": `error |`, "window": win(time.Minute, 0)},
		{"source": "vl", "query": `error`, "window": win(time.Minute, 0), "step_ms": 1000},
	} {
		if _, err := h.call(t, ToolLogsQL, args(t, bad)); errClass(err) != ClassInvalid {
			t.Fatalf("%v: %v", bad, err)
		}
	}
}

func TestLookbackLimitations(t *testing.T) {
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		switch r.Header.Get("X-Scope-OrgID") {
		case "denied":
			http.Error(w, "no", http.StatusForbidden)
		case "broken":
			http.Error(w, "boom", http.StatusBadGateway)
		case "bad":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"status":"error","errorType":"bad_data","error":"parse error at char 3"}`)
		case "redirect":
			http.Redirect(w, r, "http://elsewhere.invalid/steal", http.StatusFound)
		case "huge":
			fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"x":"%s"},"value":[1,"1"]}]}}`, strings.Repeat("a", 5<<20))
		}
	}))
	t.Cleanup(srv.Close)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	mk := func(name, tenant string) config.Lookback {
		return config.Lookback{Name: name, Type: config.SourceMimir, URL: srv.URL, Tenant: tenant, Retention: config.Duration(time.Hour)}
	}
	h := lookbackHarness(t, mk("denied", "denied"), mk("broken", "broken"), mk("bad", "bad"), mk("redirect", "redirect"), mk("huge", "huge"),
		config.Lookback{Name: "dead", Type: config.SourcePrometheus, URL: deadURL, Retention: config.Duration(time.Hour)})
	for name, want := range map[string]string{
		"denied":   "insufficient authorization (HTTP 403)",
		"broken":   "endpoint unavailable (HTTP 502)",
		"bad":      "query rejected (HTTP 400): parse error at char 3",
		"redirect": "redirect (HTTP 302) not followed",
		"dead":     "endpoint unreachable",
		"huge":     "exceeded the 4194304 byte cap",
	} {
		r := h.mustCall(t, ToolLookback, lbArgs(t, name, LangPromQL, `up`, map[string]any{"limits": map[string]any{"max_bytes": 1 << 20}}))
		if !strings.Contains(joined(r), want) {
			t.Fatalf("%s: %v", name, r.Limitations)
		}
		if a := h.audit[len(h.audit)-1]; a.Outcome != OutcomeLimited || (name != "huge" && a.ErrorClass == "") {
			t.Fatalf("%s audit %+v", name, a)
		}
	}
	for _, rq := range s.reqs {
		if rq.Host != strings.TrimPrefix(srv.URL, "http://") {
			t.Fatalf("request left the configured endpoint: %s", rq.Host)
		}
	}
	none := newHarness(t, nil)
	r := none.mustCall(t, ToolLookback, lbArgs(t, "", LangPromQL, `up`, nil))
	if !strings.Contains(joined(r), "no lookback source is configured; "+LimitationNoLookback) || r.Data != nil {
		t.Fatalf("missing source %+v", r)
	}
	if _, err := none.call(t, ToolLookback, lbArgs(t, "prom", LangPromQL, `up`, nil)); errClass(err) != ClassUnauthorized {
		t.Fatalf("unconfigured source: %v", err)
	}
}

func TestLookbackTLSAndConcurrency(t *testing.T) {
	var mu sync.Mutex
	inflight, peak := 0, 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inflight++
		peak = max(peak, inflight)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
		fmt.Fprint(w, vectorBody)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	h := lookbackHarness(t,
		config.Lookback{Name: "tls", Type: config.SourceVictoriaMetrics, URL: srv.URL, AccountID: "1", CAFile: ca},
		config.Lookback{Name: "untrusted", Type: config.SourceVictoriaMetrics, URL: srv.URL, AccountID: "1"})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := h.svc.Call(context.Background(), ToolLookback, lbArgs(t, "tls", LangPromQL, `up`, nil))
			if err != nil || len(v.(*Result).Data.(Telemetry).Series) != 1 {
				t.Errorf("tls call: %v", err)
			}
		}()
	}
	wg.Wait()
	if peak > SourceConcurrency {
		t.Fatalf("per-source concurrency %d exceeds %d", peak, SourceConcurrency)
	}
	r := h.mustCall(t, ToolLookback, lbArgs(t, "untrusted", LangPromQL, `up`, nil))
	if !strings.Contains(joined(r), "endpoint unreachable") {
		t.Fatalf("untrusted CA accepted: %v", r.Limitations)
	}
	for _, bad := range []config.Lookback{
		{Name: "x", Type: "graphite", URL: "http://a"},
		{Name: "x", Type: config.SourcePrometheus, URL: "ftp://a"},
		{Name: "x", Type: config.SourcePrometheus, URL: "http://u:p@a"},
		{Name: "x", Type: config.SourceVictoriaMetrics, URL: "http://a", AccountID: "../x"},
		{Name: "x", Type: config.SourceVictoriaMetrics, URL: "http://a", ProjectID: "1"},
		{Name: "x", Type: config.SourcePrometheus, URL: "http://a", CAFile: "/nonexistent"},
	} {
		if _, err := NewService(Options{Role: RoleCoordinator, Lookback: []config.Lookback{bad}}); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
}

func TestAuditHasNoSecrets(t *testing.T) {
	s := &seen{}
	srv := upstream(t, s, map[string]string{"/api/v1/query": vectorBody, "/loki/api/v1/query_range": `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"a":"b"},"values":[["1","response-body-line"]]}]}}`})
	tok, user, pass := secretFiles(t)
	h := lookbackHarness(t,
		config.Lookback{Name: "prom", Type: config.SourcePrometheus, URL: srv.URL, BearerTokenFile: tok, Retention: config.Duration(time.Hour)},
		config.Lookback{Name: "loki", Type: config.SourceLoki, URL: srv.URL, BasicUsernameFile: user, BasicPasswordFile: pass, Tenant: "t"})
	h.mustCall(t, ToolLookback, lbArgs(t, "prom", LangPromQL, `up`, nil))
	h.mustCall(t, ToolLookback, lbArgs(t, "loki", LangLogQL, `{a="b"}`, nil))
	h.mustCall(t, ToolLogQL, args(t, map[string]any{"query": `{container="api"}`, "window": win(15*time.Minute, 0)}))
	_, _ = h.call(t, ToolLookback, lbArgs(t, "nope", LangPromQL, `up`, nil))
	if len(h.audit) != 4 {
		t.Fatalf("audit records %d", len(h.audit))
	}
	b, _ := json.Marshal(h.audit)
	for _, secret := range []string{secretToken, secretUser, secretPass, "response-body-line", "hunter2", "error 0", tok} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("audit leaks %q: %s", secret, b)
		}
	}
	for _, a := range h.audit[:3] {
		if a.RequestID == "" || a.Requester != "user:alice" || a.Purpose != "incident 42" || a.QueryHash == "" || a.Language == "" || a.Source == "" || a.Window == nil || a.Limits.MaxLines == 0 {
			t.Fatalf("audit metadata %+v", a)
		}
	}
}

func TestDecoders(t *testing.T) {
	for in, want := range map[string]time.Duration{"1": vmMonth, "7d": 7 * 24 * time.Hour, "12h": 12 * time.Hour, "2w": 14 * 24 * time.Hour, "1y": 365 * 24 * time.Hour, "1.5d": 36 * time.Hour} {
		if got, ok := parseVMRetention(in); !ok || got != want {
			t.Fatalf("%s: %s", in, got)
		}
	}
	for _, in := range []string{"", "0", "xd", "-1"} {
		if _, ok := parseVMRetention(in); ok {
			t.Fatalf("%q parsed", in)
		}
	}
	body := []byte(`{"_time":"2023-11-14T22:13:20Z","_msg":"a"}` + "\n" + `{"_time":"2023-11-14T22:13:21Z","_m`)
	resp, err := decodeVictoriaLogsLines(body, true, Limits{MaxBytes: 1})
	if err != nil || len(resp.Data.Lines) != 1 || !resp.Truncated {
		t.Fatalf("partial rows %+v %v", resp, err)
	}
	if _, err := decodeVictoriaLogsLines([]byte("not json\n"), false, Limits{}); err == nil {
		t.Fatal("malformed rows accepted")
	}
	if _, err := decodePromEnvelope([]byte(`{"status":"success","data":{"resultType":"string","result":[1,"x"]}}`), false, Limits{}); err == nil {
		t.Fatal("string result accepted")
	}
	resp, err = decodePromEnvelope([]byte(`{"status":"success","data":{"resultType":"scalar","result":[1.5,"+Inf"]}}`), false, Limits{})
	if err != nil || resp.Data.Series[0].Points[0].T != 1500 {
		t.Fatalf("scalar %+v %v", resp, err)
	}
	b, err := json.Marshal(resp.Data.Series[0].Points[0])
	var p Point
	if err != nil || string(b) != `[1500,"+Inf"]` || json.Unmarshal(b, &p) != nil || p.T != 1500 || p.V < 1e308 {
		t.Fatalf("point json %s %v %+v", b, err, p)
	}
}
