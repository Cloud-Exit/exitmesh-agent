package investigate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// workloadState has owned, selected, and mounting pods beside unmappable resources and another namespace.
func workloadState() *protocol.State {
	st := protocol.NewState()
	for _, r := range []protocol.Resource{
		{UID: "p1", Kind: "Pod", Namespace: "shop", Name: "api-1", Fields: map[string]any{"nodeName": "n1"}},
		{UID: "p2", Kind: "Pod", Namespace: "shop", Name: "api-2", Fields: map[string]any{"nodeName": "n2"}},
		{UID: "p3", Kind: "Pod", Namespace: "shop", Name: "web-1", Fields: map[string]any{"nodeName": "n1"}},
		{UID: "p4", Kind: "Pod", Namespace: "other", Name: "db-1", Fields: map[string]any{"nodeName": "n1"}},
		{UID: "d1", Kind: "apps/Deployment", Namespace: "shop", Name: "api"},
		{UID: "rs1", Kind: "apps/ReplicaSet", Namespace: "shop", Name: "api-7c9"},
		{UID: "d2", Kind: "apps/Deployment", Namespace: "shop", Name: "idle"},
		{UID: "svc", Kind: "Service", Namespace: "shop", Name: "web"},
		{UID: "pvc", Kind: "PersistentVolumeClaim", Namespace: "shop", Name: "data"},
		{UID: "cm", Kind: "ConfigMap", Namespace: "shop", Name: "cfg"},
		{UID: "ns", Kind: "Namespace", Name: "shop"},
		{UID: "n1", Kind: "Node", Name: "n1"},
	} {
		st.Resources[r.UID] = &r
	}
	for _, e := range [][3]string{{"d1", "owns", "rs1"}, {"rs1", "owns", "p1"}, {"rs1", "owns", "p2"}, {"svc", "selects", "p3"}, {"p2", "mounts", "pvc"}, {"p1", "runs-on", "n1"}} {
		st.Edges[protocol.EdgeKey{From: e[0], Type: e[1], To: e[2]}] = map[string]any{}
	}
	return st
}

func req(ns, pod, node string) labels.Labels {
	return labels.FromStrings("__name__", "req_total", "namespace", ns, "pod", pod, "node", node)
}

// workloadHarness serves workloadState with sibling pods in the same namespace on both nodes.
func workloadHarness(t *testing.T, sources ...config.Lookback) *harness {
	t.Helper()
	st := workloadState()
	coord := openTSDB(t,
		labels.FromStrings("__name__", "kube_pod_info", "namespace", "shop", "pod", "api-1"),
		labels.FromStrings("__name__", "kube_pod_info", "namespace", "shop", "pod", "api-2"),
		labels.FromStrings("__name__", "kube_pod_info", "namespace", "shop", "pod", "web-1"))
	h := newHarness(t, func(o *Options) {
		o.State = func() *protocol.State { return st }
		o.Coordinator = coord
		o.Lookback = sources
	})
	root1, root2 := t.TempDir(), t.TempDir()
	writePodLog(t, root1, "shop", "api-1", "p1", "api", []string{"error api-1"})
	writePodLog(t, root1, "shop", "web-1", "p3", "web", []string{"error web-1"})
	writePodLog(t, root1, "other", "db-1", "p4", "db", []string{"error db-1"})
	writePodLog(t, root2, "shop", "api-2", "p2", "api", []string{"error api-2"})
	ring := evidence.New(1 << 20)
	ring.SetRules(map[string]float64{"r1": 1})
	for _, pod := range []string{"api-1", "web-1"} {
		ring.Add("r1", evidence.Sample{Time: testNow.Add(-time.Minute), Labels: map[string]string{"namespace": "shop", "pod": pod}, Text: "evidence " + pod})
	}
	n1 := openTSDB(t, req("shop", "api-1", "n1"), req("shop", "web-1", "n1"), req("other", "db-1", "n1"))
	n2 := openTSDB(t, req("shop", "api-2", "n2"))
	h.router.execs = map[string]*Executor{
		"n1": NewExecutor(ExecOptions{Node: "n1", Queryable: n1, PodLogRoot: root1, Evidence: ring}),
		"n2": NewExecutor(ExecOptions{Node: "n2", Queryable: n2, PodLogRoot: root2}),
	}
	h.router.fail = nil
	return h
}

func scoped(t *testing.T, sc map[string]any, kv map[string]any) json.RawMessage {
	t.Helper()
	a := map[string]any{"scope": sc, "window": win(15*time.Minute, 0)}
	for k, v := range kv {
		a[k] = v
	}
	return args(t, a)
}

func resources(refs ...map[string]any) map[string]any { return map[string]any{"resources": refs} }

func uid(u string) map[string]any { return map[string]any{"uid": u} }

func podsOfSeries(d Telemetry) []string {
	var out []string
	for _, s := range d.Series {
		out = append(out, s.Metric["pod"])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func podsOfLines(d Telemetry) []string {
	var out []string
	for _, l := range d.Lines {
		out = append(out, l.Labels["pod"])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func assertPromBound(t *testing.T, q string, want ...*labels.Matcher) {
	t.Helper()
	for _, sel := range promSelectors(t, q) {
		if !hasAllMatchers(sel, want) {
			t.Fatalf("selector %v in %q lacks %v", sel, q, want)
		}
	}
}

func TestPodScopeNeverWidens(t *testing.T) {
	h := workloadHarness(t)
	sc := resources(uid("p1"))
	pod := labels.MustNewMatcher(labels.MatchEqual, "pod", "api-1")
	ns := labels.MustNewMatcher(labels.MatchEqual, "namespace", "shop")
	for _, c := range []struct {
		q    string
		want []string
	}{
		{`req_total`, []string{"api-1"}},
		{`req_total{pod=~".+"} or on() kube_pod_info{pod="api-2"}`, []string{"api-1"}},
		{`sum by (pod) ({__name__=~"req_total|kube_pod_info", pod=~"api-.*|web-.*"})`, []string{"api-1"}},
		{`label_replace(req_total{pod="web-1"}, "pod", "api-1", "", "")`, nil},
	} {
		r := h.mustCall(t, ToolPromQL, scoped(t, sc, map[string]any{"query": c.q}))
		if got := podsOfSeries(r.Data.(Telemetry)); !slices.Equal(got, c.want) {
			t.Fatalf("%s: pods %v, want %v", c.q, got, c.want)
		}
		assertPromBound(t, r.Query, ns, pod)
	}
	for _, q := range []string{`{namespace="shop"}`, `{pod=~".+"} |= "error"`} {
		r := h.mustCall(t, ToolLogQL, scoped(t, sc, map[string]any{"query": q}))
		if got := podsOfLines(r.Data.(Telemetry)); !slices.Equal(got, []string{"api-1"}) {
			t.Fatalf("%s: log pods %v", q, got)
		}
	}
	r := h.mustCall(t, ToolLogQL, scoped(t, sc, map[string]any{"query": `sum by (pod) (count_over_time({pod=~"web-1|api-.*"} |~ "web|api" [15m])) > 0`}))
	if got := podsOfSeries(r.Data.(Telemetry)); !slices.Equal(got, []string{"api-1"}) {
		t.Fatalf("logql regex selector: pods %v", got)
	}
	e, err := logql.ParseExpr(r.Query)
	if err != nil {
		t.Fatal(err)
	}
	walkLogQL(e, func(le *logql.LogExpr, _ time.Duration) {
		if !hasAllMatchers(le.Matchers, []*labels.Matcher{ns, pod}) {
			t.Fatalf("stream selector %v lacks the pod bound", le.Matchers)
		}
	})
	r = h.mustCall(t, ToolEvidence, scoped(t, sc, map[string]any{"rule_id": "r1"}))
	if got := podsOfLines(r.Data.(Telemetry)); !slices.Equal(got, []string{"api-1"}) {
		t.Fatalf("evidence pods %v", got)
	}
}

func TestRelatedResourceScopeBoundToPods(t *testing.T) {
	h := workloadHarness(t)
	for _, c := range []struct {
		sc   map[string]any
		want []string
		re   string
	}{
		{resources(map[string]any{"kind": "apps/Deployment", "namespace": "shop", "name": "api"}), []string{"api-1", "api-2"}, `pod=~"api-1|api-2"`},
		{resources(uid("rs1")), []string{"api-1", "api-2"}, `pod=~"api-1|api-2"`},
		{resources(uid("svc")), []string{"web-1"}, `pod="web-1"`},
		{resources(uid("pvc")), []string{"api-2"}, `pod="api-2"`},
		{resources(uid("p1"), uid("svc")), []string{"api-1", "web-1"}, `pod=~"api-1|web-1"`},
		{map[string]any{"namespaces": []string{"shop"}, "resources": []map[string]any{uid("d1")}}, []string{"api-1", "api-2"}, `pod=~"api-1|api-2"`},
		{resources(uid("ns"), uid("p1")), []string{"api-1"}, `pod="api-1"`},
		{resources(uid("n1"), uid("p1")), []string{"api-1"}, `node="n1"`},
	} {
		r := h.mustCall(t, ToolPromQL, scoped(t, c.sc, map[string]any{"query": `req_total or kube_pod_info`}))
		if got := podsOfSeries(r.Data.(Telemetry)); !slices.Equal(got, c.want) {
			t.Fatalf("%v: pods %v, want %v", c.sc, got, c.want)
		}
		if !strings.Contains(r.Query, c.re) || !strings.Contains(r.Query, `namespace="shop"`) {
			t.Fatalf("%v: query %q lacks %s", c.sc, r.Query, c.re)
		}
		l := h.mustCall(t, ToolLogQL, scoped(t, c.sc, map[string]any{"query": `{namespace="shop"}`}))
		if got := podsOfLines(l.Data.(Telemetry)); len(got) == 0 || !isSubset(got, c.want) {
			t.Fatalf("%v: log pods %v, want within %v", c.sc, got, c.want)
		}
	}
}

func isSubset(got, want []string) bool {
	for _, g := range got {
		if !slices.Contains(want, g) {
			return false
		}
	}
	return true
}

func TestUnmappableResourceScopeRejected(t *testing.T) {
	s := &seen{}
	srv := upstream(t, s, map[string]string{"/api/v1/query": vectorBody})
	h := workloadHarness(t, config.Lookback{Name: "prom", Type: config.SourcePrometheus, URL: srv.URL, Retention: config.Duration(time.Hour)})
	for _, sc := range []map[string]any{
		resources(uid("cm")),
		resources(uid("d2")),
		resources(uid("p1"), uid("p4")),
		resources(uid("p1"), uid("cm")),
		{"namespaces": []string{"shop"}, "resources": []map[string]any{uid("p4")}},
		{"cluster": true, "resources": []map[string]any{uid("cm")}},
	} {
		for _, tc := range []struct {
			tool string
			kv   map[string]any
		}{
			{ToolPromQL, map[string]any{"query": "req_total"}},
			{ToolLogQL, map[string]any{"query": `{namespace="shop"}`}},
			{ToolLookback, map[string]any{"source": "prom", "language": LangPromQL, "query": "req_total"}},
			{ToolEvidence, map[string]any{"rule_id": "r1"}},
		} {
			_, err := h.call(t, tc.tool, scoped(t, sc, tc.kv))
			if errClass(err) != ClassUnauthorized {
				t.Fatalf("%s %v: want unauthorized, got %v", tc.tool, sc, err)
			}
		}
	}
	if len(s.reqs) != 0 {
		t.Fatalf("a rejected scope reached the lookback source: %d requests", len(s.reqs))
	}
	r := h.mustCall(t, ToolState, scoped(t, resources(uid("cm")), nil))
	if got := r.Data.(map[string]any)["resources"].([]StateResource); len(got) != 1 || got[0].UID != "cm" {
		t.Fatalf("state.query keeps exact resource filtering: %+v", got)
	}
}

// promUpstream evaluates received PromQL against db, standing in for a lookback Prometheus.
func promUpstream(t *testing.T, s *seen, db storage.Queryable) *httptest.Server {
	t.Helper()
	eng := promql.NewEngine(promql.EngineOpts{MaxSamples: 1 << 20, Timeout: 10 * time.Second, LookbackDelta: 5 * time.Minute})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		sec, err := strconv.ParseFloat(r.URL.Query().Get("time"), 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q, err := eng.NewInstantQuery(r.Context(), db, nil, r.URL.Query().Get("query"), time.UnixMilli(int64(sec*1000)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer q.Close()
		vec, err := q.Exec(r.Context()).Vector()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out := []map[string]any{}
		for _, smp := range vec {
			out = append(out, map[string]any{"metric": smp.Metric.Map(), "value": []any{float64(smp.T) / 1000, strconv.FormatFloat(smp.F, 'f', -1, 64)}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": out}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLookbackResourceScope(t *testing.T) {
	s := &seen{}
	store := openTSDB(t, req("shop", "api-1", "n1"), req("shop", "api-2", "n2"), req("shop", "web-1", "n1"))
	prom := promUpstream(t, s, store)
	logs := upstream(t, s, map[string]string{
		"/api/v1/query":            vectorBody,
		"/loki/api/v1/query_range": `{"status":"success","data":{"resultType":"streams","result":[]}}`,
		"/select/logsql/query":     "",
	})
	ret := config.Duration(time.Hour)
	h := workloadHarness(t,
		config.Lookback{Name: "prom", Type: config.SourcePrometheus, URL: prom.URL, Retention: ret},
		config.Lookback{Name: "vm", Type: config.SourceVictoriaMetrics, URL: logs.URL, Retention: ret},
		config.Lookback{Name: "loki", Type: config.SourceLoki, URL: logs.URL, Retention: ret},
		config.Lookback{Name: "vl", Type: config.SourceVictoriaLogs, URL: logs.URL, Retention: ret},
	)
	for _, c := range []struct {
		sc   map[string]any
		want []string
		pod  string
	}{
		{resources(uid("p1")), []string{"api-1"}, `pod="api-1"`},
		{resources(uid("d1")), []string{"api-1", "api-2"}, `pod=~"api-1|api-2"`},
	} {
		for _, q := range []string{`req_total`, `req_total or on() req_total{pod="web-1"}`, `{__name__=~"req.*", pod=~".*"}`} {
			r := h.mustCall(t, ToolLookback, scoped(t, c.sc, map[string]any{"source": "prom", "language": LangPromQL, "query": q}))
			if got := podsOfSeries(r.Data.(Telemetry)); !slices.Equal(got, c.want) {
				t.Fatalf("%v %s: lookback pods %v, want %v", c.sc, q, got, c.want)
			}
			if sent := s.last("/api/v1/query").URL.Query().Get("query"); strings.Count(sent, c.pod) != len(promSelectors(t, sent)) {
				t.Fatalf("%v: sent %q does not bind every selector to %s", c.sc, sent, c.pod)
			}
		}
		h.mustCall(t, ToolLookback, scoped(t, c.sc, map[string]any{"source": "vm", "language": LangMetricsQL, "query": `foo{a="b" or pod="web-1"}`}))
		if sent := s.last("/api/v1/query").URL.Query().Get("query"); strings.Count(sent, c.pod) != 2 {
			t.Fatalf("metricsql or-groups %q lack %s", sent, c.pod)
		}
		h.mustCall(t, ToolLookback, scoped(t, c.sc, map[string]any{"source": "loki", "language": LangLogQL, "query": `{app="api"} |= "x"`}))
		if sent := s.last("/loki/api/v1/query_range").URL.Query().Get("query"); !strings.Contains(sent, c.pod) {
			t.Fatalf("loki %q lacks %s", sent, c.pod)
		}
		stream := strings.Replace(c.pod, `pod="`, `pod=~"`, 1)
		h.mustCall(t, ToolLookback, scoped(t, c.sc, map[string]any{"source": "vl", "language": LangLogQL, "query": `{app="api"} |= "x"`}))
		if sent := s.last("/select/logsql/query").URL.Query().Get("query"); !strings.Contains(sent, stream) {
			t.Fatalf("victorialogs translated %q lacks %s", sent, stream)
		}
		h.mustCall(t, ToolLogsQL, scoped(t, c.sc, map[string]any{"source": "vl", "query": `error or _stream:{pod="web-1"} | union (panic)`}))
		if sent := s.last("/select/logsql/query").URL.Query().Get("query"); strings.Count(sent, stream) != 2 {
			t.Fatalf("victorialogs native %q lacks %s on the query and its subquery", sent, stream)
		}
	}
}

func TestTelemetryBindingMapping(t *testing.T) {
	st := workloadState()
	for _, r := range []protocol.Resource{
		{UID: "cj", Kind: "batch/CronJob", Namespace: "shop", Name: "nightly"},
		{UID: "job", Kind: "batch/Job", Namespace: "shop", Name: "nightly-1"},
		{UID: "p5", Kind: "Pod", Namespace: "shop", Name: "nightly-1-x"},
		{UID: "ing", Kind: "networking.k8s.io/Ingress", Namespace: "shop", Name: "web"},
		{UID: "hpa", Kind: "autoscaling/HorizontalPodAutoscaler", Namespace: "shop", Name: "api"},
		{UID: "pv", Kind: "PersistentVolume", Name: "pv-1"},
		{UID: "np", Kind: "networking.k8s.io/NetworkPolicy", Namespace: "shop", Name: "deny"},
		{UID: "sc", Kind: "storage.k8s.io/StorageClass", Name: "fast"},
		{UID: "orphan", Kind: "apps/ReplicaSet", Namespace: "shop", Name: "orphan"},
	} {
		st.Resources[r.UID] = &r
	}
	for _, e := range [][3]string{{"cj", "owns", "job"}, {"job", "owns", "p5"}, {"ing", "routes", "svc"}, {"hpa", "scales", "d1"}, {"pvc", "binds", "pv"}, {"np", "targets", "p1"}, {"orphan", "runs-on", "n1"}, {"p1", "owns", "p3"}} {
		st.Edges[protocol.EdgeKey{From: e[0], Type: e[1], To: e[2]}] = map[string]any{}
	}
	for _, c := range []struct {
		sc    Scope
		ns    []string
		pods  []string
		nodes []string
		class string
	}{
		{sc: Scope{Resources: []ResourceRef{{UID: "p1"}}}, ns: []string{"shop"}, pods: []string{"api-1"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "n1"}}}, nodes: []string{"n1"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "ns"}}}, ns: []string{"shop"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "cj"}}}, ns: []string{"shop"}, pods: []string{"nightly-1-x"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "ing"}}}, ns: []string{"shop"}, pods: []string{"web-1"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "hpa"}}}, ns: []string{"shop"}, pods: []string{"api-1", "api-2"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "pv"}}}, ns: []string{"shop"}, pods: []string{"api-2"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "np"}}}, ns: []string{"shop"}, pods: []string{"api-1"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "p1"}, {UID: "p2"}, {UID: "d1"}}}, ns: []string{"shop"}, pods: []string{"api-1", "api-2"}},
		{sc: Scope{Namespaces: []string{"shop"}, Nodes: []string{"n2"}, Resources: []ResourceRef{{UID: "p1"}, {UID: "p4"}}}, ns: []string{"shop"}, pods: []string{"api-1"}, nodes: []string{"n2"}},
		{sc: Scope{Namespaces: []string{"shop", "other"}, Resources: []ResourceRef{{UID: "n1"}}}, ns: []string{"other", "shop"}, nodes: []string{"n1"}},
		{sc: Scope{Resources: []ResourceRef{{UID: "sc"}}}, class: ClassUnauthorized},
		{sc: Scope{Resources: []ResourceRef{{UID: "orphan"}}}, class: ClassUnauthorized},
		{sc: Scope{Resources: []ResourceRef{{UID: "cm"}}}, class: ClassUnauthorized},
		{sc: Scope{Resources: []ResourceRef{{UID: "p4"}, {UID: "d1"}}}, class: ClassUnauthorized},
		{sc: Scope{Namespaces: []string{"other"}, Resources: []ResourceRef{{UID: "svc"}}}, class: ClassUnauthorized},
	} {
		rs, err := resolveScope(c.sc, st)
		if err != nil {
			t.Fatal(err)
		}
		got, err := rs.telemetryBinding(st)
		if c.class != "" {
			if errClass(err) != c.class {
				t.Fatalf("%+v: want %s, got %v (%+v)", c.sc, c.class, err, got)
			}
			continue
		}
		if err != nil || !slices.Equal(got.namespaces, c.ns) || !slices.Equal(got.pods, c.pods) || !slices.Equal(got.nodes, c.nodes) {
			t.Fatalf("%+v: binding %+v %v", c.sc, got, err)
		}
	}
	many := protocol.NewState()
	many.Resources["svc"] = &protocol.Resource{UID: "svc", Kind: "Service", Namespace: "shop", Name: "big"}
	for i := range maxScopeEntries + 1 {
		u := "pod" + strconv.Itoa(i)
		many.Resources[u] = &protocol.Resource{UID: u, Kind: "Pod", Namespace: "shop", Name: u}
		many.Edges[protocol.EdgeKey{From: "svc", Type: "selects", To: u}] = nil
	}
	rs, _ := resolveScope(Scope{Resources: []ResourceRef{{UID: "svc"}}}, many)
	if _, err := rs.telemetryBinding(many); errClass(err) != ClassInvalid {
		t.Fatalf("unbounded pod set: %v", err)
	}
}

func TestExecutorEnforcesPodScope(t *testing.T) {
	db := openTSDB(t, req("shop", "api-1", "n1"), req("shop", "web-1", "n1"))
	e := NewExecutor(ExecOptions{Node: "n1", Queryable: db})
	base := TaskQuery{StartMs: testNow.Add(-time.Minute).UnixMilli(), EndMs: testNow.UnixMilli(), Namespaces: []string{"shop"}, Pods: []string{"api-1"}}
	q := base
	q.Query = `req_total{namespace="shop"}`
	if _, errStr := runTask(t, e, "promql_query", q); !strings.Contains(errStr, "not bound to the task scope") {
		t.Fatalf("task without the pod matcher: %q", errStr)
	}
	q.Query = `req_total{namespace="shop",pod="api-1"}`
	resp, errStr := runTask(t, e, "promql_query", q)
	if errStr != "" || len(resp.Data.Series) != 1 || resp.Data.Series[0].Metric["pod"] != "api-1" {
		t.Fatalf("scoped task %+v %s", resp, errStr)
	}
	q.Namespaces = []string{"shop", "other"}
	if _, errStr := runTask(t, e, "promql_query", q); !strings.Contains(errStr, "exactly one namespace") {
		t.Fatalf("pods across namespaces: %q", errStr)
	}
	ring := evidence.New(1 << 20)
	ring.SetRules(map[string]float64{"r1": 1})
	for _, pod := range []string{"api-1", "web-1", ""} {
		ring.Add("r1", evidence.Sample{Time: testNow, Labels: map[string]string{"namespace": "shop", "pod": pod}, Text: pod})
	}
	q = base
	q.Query, q.EndMs = "r1", testNow.Add(time.Minute).UnixMilli()
	resp, errStr = runTask(t, NewExecutor(ExecOptions{Node: "n1", Evidence: ring}), "evidence_read", q)
	if errStr != "" || len(resp.Data.Lines) != 1 || resp.Data.Lines[0].Text != "api-1" {
		t.Fatalf("evidence pod filter %+v %s", resp, errStr)
	}
}
