package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type fakeRouter struct {
	execs map[string]*Executor
	fail  map[string]error
	block chan struct{}
	mu    sync.Mutex
	runs  []string
}

func (f *fakeRouter) Nodes() []string {
	var out []string
	for n := range f.execs {
		out = append(out, n)
	}
	for n := range f.fail {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func (f *fakeRouter) Run(ctx context.Context, node string, t nodeapi.Task) (nodeapi.TaskResult, error) {
	f.mu.Lock()
	f.runs = append(f.runs, node+" "+string(t.Kind)+" "+t.ID)
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nodeapi.TaskResult{}, ctx.Err()
		}
	}
	if err := f.fail[node]; err != nil {
		return nodeapi.TaskResult{}, err
	}
	return f.execs[node].Execute(ctx, t), nil
}

func testState() *protocol.State {
	st := protocol.NewState()
	for _, r := range []protocol.Resource{
		{UID: "u1", Kind: "Pod", Namespace: "shop", Name: "api-1", Fields: map[string]any{"nodeName": "n1", "phase": "Running", "status": map[string]any{"ready": true}}},
		{UID: "u2", Kind: "Pod", Namespace: "other", Name: "db-1", Fields: map[string]any{"nodeName": "n1", "phase": "Running"}},
		{UID: "u3", Kind: "apps/Deployment", Namespace: "shop", Name: "api"},
		{UID: "u4", Kind: "Node", Name: "n1"},
		{UID: "u5", Kind: "Namespace", Name: "shop"},
	} {
		st.Resources[r.UID] = &r
	}
	st.Edges[protocol.EdgeKey{From: "u3", Type: "owns", To: "u1"}] = nil
	st.Edges[protocol.EdgeKey{From: "u1", Type: "scheduled_on", To: "u4"}] = nil
	st.Edges[protocol.EdgeKey{From: "u1", Type: "talks_to", To: "u2"}] = map[string]any{"port": int64(5432)}
	st.Scopes["Pod|shop"] = protocol.ScopeStatus{State: protocol.ScopePartial, Reason: "list forbidden"}
	st.Scopes["Pod|other"] = protocol.ScopeStatus{State: protocol.ScopeUnavailable, Reason: "hidden"}
	return st
}

type harness struct {
	svc    *Service
	router *fakeRouter
	audit  []AuditRecord
	saved  []findings.Observation
	mu     sync.Mutex
}

func newHarness(t *testing.T, mut func(*Options)) *harness {
	t.Helper()
	root := podLogTree(t)
	n1db := openTSDB(t,
		labels.FromStrings("__name__", "req_total", "namespace", "shop", "pod", "api-1", "node", "n1"),
		labels.FromStrings("__name__", "req_total", "namespace", "other", "pod", "db-1", "node", "n1"))
	n2db := openTSDB(t, labels.FromStrings("__name__", "req_total", "namespace", "shop", "pod", "api-2", "node", "n2"))
	coord := openTSDB(t,
		labels.FromStrings("__name__", "kube_pod_info", "namespace", "shop", "pod", "api-1"),
		labels.FromStrings("__name__", "kube_pod_info", "namespace", "other", "pod", "db-1"))
	h := &harness{router: &fakeRouter{
		execs: map[string]*Executor{
			"n1": NewExecutor(ExecOptions{Node: "n1", Queryable: n1db, Retention: n1db.Retention, PodLogRoot: root}),
			"n2": NewExecutor(ExecOptions{Node: "n2", Queryable: n2db, Retention: n2db.Retention}),
		},
		fail: map[string]error{"n3": errors.New("connection reset")},
	}}
	st := testState()
	o := Options{
		Role: RoleCoordinator, State: func() *protocol.State { return st }, Nodes: h.router, Coordinator: coord,
		Audit:       func(r AuditRecord) { h.mu.Lock(); h.audit = append(h.audit, r); h.mu.Unlock() },
		SaveFinding: func(ob findings.Observation) error { h.saved = append(h.saved, ob); return nil },
	}
	if mut != nil {
		mut(&o)
	}
	svc, err := NewService(o)
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h
}

func args(t *testing.T, kv map[string]any) json.RawMessage {
	t.Helper()
	base := map[string]any{"requester": "user:alice", "purpose": "incident 42", "scope": map[string]any{"namespaces": []string{"shop"}}}
	for k, v := range kv {
		base[k] = v
	}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func win(from, to time.Duration) map[string]any {
	return map[string]any{"start": testNow.Add(-from).UnixMilli(), "end": testNow.Add(-to).UnixMilli()}
}

func (h *harness) call(t *testing.T, tool string, a json.RawMessage) (*Result, error) {
	t.Helper()
	v, err := h.svc.Call(context.Background(), tool, a)
	if err != nil {
		return nil, err
	}
	return v.(*Result), nil
}

func (h *harness) mustCall(t *testing.T, tool string, a json.RawMessage) *Result {
	t.Helper()
	r, err := h.call(t, tool, a)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return r
}

func joined(r *Result) string { return strings.Join(r.Limitations, "\n") }

func TestPromQLFanout(t *testing.T) {
	h := newHarness(t, nil)
	r := h.mustCall(t, ToolPromQL, args(t, map[string]any{"query": `req_total or kube_pod_info`, "window": win(5*time.Minute, 0)}))
	d := r.Data.(Telemetry)
	var sources []string
	for _, s := range d.Series {
		if s.Metric["namespace"] != "shop" {
			t.Fatalf("series outside scope: %+v", s)
		}
		sources = append(sources, s.Source)
	}
	slices.Sort(sources)
	if !slices.Equal(sources, []string{"coordinator", "node/n1", "node/n2"}) {
		t.Fatalf("sources %v", sources)
	}
	if !strings.Contains(joined(r), "node/n3: query failed: connection reset") {
		t.Fatalf("partial failure not reported: %v", r.Limitations)
	}
	if len(d.Nodes) != 3 || d.Nodes[2].Node != "n3" || d.Nodes[2].Status != NodeFailed {
		t.Fatalf("node statuses %+v", d.Nodes)
	}
	if r.Source != sourceLive || r.Query != `req_total{namespace="shop"} or kube_pod_info{namespace="shop"}` || r.QueryHash != protocol.QueryHash(LangPromQL, r.Query, sourceLive).String() {
		t.Fatalf("provenance %+v", r)
	}
	if r.Limits.MaxSeries != 1000 || r.Limits.TimeoutMs != 30_000 || r.RetentionMs != time.Hour.Milliseconds() {
		t.Fatalf("limits %+v retention %d", r.Limits, r.RetentionMs)
	}

	h.router.runs = nil
	r = h.mustCall(t, ToolPromQL, args(t, map[string]any{"query": `sum(req_total)`, "window": win(5*time.Minute, 0),
		"scope": map[string]any{"namespaces": []string{"shop"}, "nodes": []string{"n1", "n2", "n9"}}, "step_ms": 60_000}))
	if len(h.router.runs) != 2 || !strings.Contains(joined(r), "node n9 is not covered") || !strings.Contains(joined(r), limitationPerSource) {
		t.Fatalf("runs %v limitations %v", h.router.runs, r.Limitations)
	}
	if !strings.Contains(r.Query, `node=~"n1|n2|n9"`) {
		t.Fatalf("node scope not injected: %s", r.Query)
	}
	d = r.Data.(Telemetry)
	if d.ResultType != TypeMatrix || len(d.Series) != 2 {
		t.Fatalf("range fan-out %+v", d)
	}
}

func TestPromQLHistoryLimitation(t *testing.T) {
	h := newHarness(t, nil)
	r := h.mustCall(t, ToolPromQL, args(t, map[string]any{"query": `rate(req_total[5m])`, "window": win(3*time.Hour, 2*time.Hour)}))
	if !strings.Contains(joined(r), LimitationNoLookback) || !strings.Contains(joined(r), "retention 1h0m0s") {
		t.Fatalf("I7 limitation missing: %v", r.Limitations)
	}
	h = newHarness(t, func(o *Options) {
		o.Lookback = []config.Lookback{{Name: "prom", Type: config.SourcePrometheus, URL: "http://prom:9090"}, {Name: "loki", Type: config.SourceLoki, URL: "http://loki:3100"}}
	})
	r = h.mustCall(t, ToolPromQL, args(t, map[string]any{"query": `rate(req_total[5m])`, "window": win(3*time.Hour, 2*time.Hour)}))
	if !strings.Contains(joined(r), "extend it with lookback.query against [prom]") {
		t.Fatalf("lookback hint missing: %v", r.Limitations)
	}
	r = h.mustCall(t, ToolPromQL, args(t, map[string]any{"query": `rate(req_total[5m])`, "window": win(10*time.Minute, 0)}))
	if strings.Contains(joined(r), "in-cluster window") {
		t.Fatalf("in-window query flagged: %v", r.Limitations)
	}
}

func TestLogQLFanout(t *testing.T) {
	h := newHarness(t, nil)
	r := h.mustCall(t, ToolLogQL, args(t, map[string]any{"query": `{container=~".+"} |= "error"`, "window": win(15*time.Minute, 0), "limits": map[string]any{"max_lines": 2}}))
	d := r.Data.(Telemetry)
	if d.ResultType != TypeStreams || len(d.Lines) != 2 || !r.Truncated {
		t.Fatalf("lines %+v truncated=%v", d, r.Truncated)
	}
	for _, l := range d.Lines {
		if l.Source != "node/n1" || l.Labels["namespace"] != "shop" || strings.Contains(l.Text, "hunter2") {
			t.Fatalf("line %+v", l)
		}
	}
	if !strings.Contains(joined(r), "node/n2: query failed: investigate: logs are not collected on node n2") {
		t.Fatalf("n2 failure: %v", r.Limitations)
	}
	h.router.runs = nil
	h.mustCall(t, ToolLogQL, args(t, map[string]any{"query": `{pod="api-1"}`, "window": win(15*time.Minute, 0), "direction": "forward"}))
	if !strings.Contains(strings.Join(h.router.runs, ","), "log_read") {
		t.Fatalf("bare selector should use log_read: %v", h.router.runs)
	}
	if _, err := h.call(t, ToolLogQL, args(t, map[string]any{"query": `{pod="api-1"}`, "window": win(15*time.Minute, 0), "step_ms": 1000})); errClass(err) != ClassInvalid {
		t.Fatalf("step on log query: %v", err)
	}
}

// TestAuthorization is acceptance 35 for namespaces and endpoints.
func TestAuthorization(t *testing.T) {
	h := newHarness(t, nil)
	r := h.mustCall(t, ToolPromQL, args(t, map[string]any{"query": `req_total{namespace="other"}`, "window": win(5*time.Minute, 0)}))
	if d := r.Data.(Telemetry); len(d.Series) != 0 || !strings.Contains(r.Query, `namespace="other",namespace="shop"`) {
		t.Fatalf("other namespace reached: %+v %s", d.Series, r.Query)
	}
	r = h.mustCall(t, ToolLogQL, args(t, map[string]any{"query": `{namespace="other"}`, "window": win(15*time.Minute, 0)}))
	if d := r.Data.(Telemetry); len(d.Lines) != 0 {
		t.Fatalf("other namespace logs reached: %+v", d.Lines)
	}
	cases := []struct {
		tool string
		a    map[string]any
	}{
		{ToolState, map[string]any{"namespace": "other"}},
		{ToolPromQL, map[string]any{"query": "up", "window": win(time.Minute, 0), "scope": map[string]any{}}},
		{ToolPromQL, map[string]any{"query": "up", "window": win(time.Minute, 0), "scope": map[string]any{"resources": []map[string]any{{"uid": "nope"}}}}},
		{ToolLookback, map[string]any{"source": "evil", "language": "promql", "query": "up", "window": win(time.Minute, 0)}},
		{ToolGraph, map[string]any{"from": []map[string]any{{"uid": "u2"}}}},
		{ToolPromQL, map[string]any{"query": "up", "window": win(time.Minute, 0), "scope": map[string]any{"resources": []map[string]any{{"uid": "u5"}, {"kind": "Node", "name": "n1"}}}}},
	}
	for i, c := range cases {
		_, err := h.call(t, c.tool, args(t, c.a))
		if i == len(cases)-1 {
			if err != nil {
				t.Fatalf("resource scope should bind namespace and node: %v", err)
			}
			continue
		}
		if errClass(err) != ClassUnauthorized {
			t.Fatalf("case %d: want unauthorized, got %v", i, err)
		}
	}
	last := h.audit[len(h.audit)-2]
	if last.Outcome != OutcomeRejected || last.ErrorClass != ClassUnauthorized || last.Tool != ToolGraph {
		t.Fatalf("audit of rejection %+v", last)
	}
	for _, bad := range []map[string]any{
		{"query": "up"},
		{"query": "up", "window": win(7*time.Hour, 0)},
		{"query": "up", "window": map[string]any{"start": testNow.UnixMilli(), "end": testNow.Add(time.Hour).UnixMilli()}},
		{"query": "rate(up[7h])", "window": win(time.Minute, 0)},
		{"query": "up @ 100", "window": win(time.Minute, 0)},
		{"query": "sum(", "window": win(time.Minute, 0)},
		{"query": "up", "window": win(time.Minute, 0), "limits": map[string]any{"max_lines": -1}},
		{"query": "up", "window": win(time.Minute, 0), "unknown": true},
		{"query": "up", "window": win(time.Minute, 0), "requester": ""},
		{"query": "up", "window": win(time.Minute, 0), "scope": map[string]any{"namespaces": []string{"Bad_NS"}}},
		{"query": "up", "window": win(time.Hour, 0), "step_ms": 1},
	} {
		if _, err := h.call(t, ToolPromQL, args(t, bad)); errClass(err) != ClassInvalid {
			t.Fatalf("%v: want invalid, got %v", bad, err)
		}
	}
	if _, err := h.call(t, "shell.exec", args(t, nil)); errClass(err) != ClassInvalid {
		t.Fatalf("unknown tool: %v", err)
	}
}

func TestLimitsClamped(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.Limits = config.Investigation{MaxLines: 10, MaxSeries: 1, MaxBytes: 1 << 20} })
	r := h.mustCall(t, ToolPromQL, args(t, map[string]any{"query": `req_total`, "window": win(time.Minute, 0), "limits": map[string]any{"max_series": 999, "max_lines": 5}}))
	if r.Limits.MaxSeries != 1 || r.Limits.MaxLines != 5 || !r.Truncated || !strings.Contains(joined(r), "series limit 1 reached") {
		t.Fatalf("clamp %+v %v", r.Limits, r.Limitations)
	}
}

func TestStateQuery(t *testing.T) {
	h := newHarness(t, nil)
	r := h.mustCall(t, ToolState, args(t, map[string]any{"kind": "Pod"}))
	res := r.Data.(map[string]any)["resources"].([]StateResource)
	if len(res) != 1 || res[0].UID != "u1" {
		t.Fatalf("pods %+v", res)
	}
	if j := joined(r); !strings.Contains(j, "Pod|shop is partial: list forbidden") || strings.Contains(j, "Pod|other") {
		t.Fatalf("scope limitations %v", r.Limitations)
	}
	r = h.mustCall(t, ToolState, args(t, map[string]any{"fields": map[string]any{"status.ready": true, "phase": "Running"}}))
	if res := r.Data.(map[string]any)["resources"].([]StateResource); len(res) != 1 || res[0].Name != "api-1" {
		t.Fatalf("field filter %+v", res)
	}
	r = h.mustCall(t, ToolState, args(t, map[string]any{"limits": map[string]any{"max_lines": 1}}))
	if res := r.Data.(map[string]any)["resources"].([]StateResource); len(res) != 1 || !r.Truncated {
		t.Fatalf("limit %+v", r)
	}
	r = h.mustCall(t, ToolState, args(t, map[string]any{"scope": map[string]any{"cluster": true}, "kind": "Pod"}))
	if res := r.Data.(map[string]any)["resources"].([]StateResource); len(res) != 2 {
		t.Fatalf("cluster scope %+v", res)
	}
	r = h.mustCall(t, ToolState, args(t, map[string]any{"scope": map[string]any{"nodes": []string{"n1"}}}))
	if res := r.Data.(map[string]any)["resources"].([]StateResource); len(res) != 3 {
		t.Fatalf("node scope %+v", res)
	}
	r = h.mustCall(t, ToolState, args(t, map[string]any{"window": win(time.Hour, 30*time.Minute)}))
	if !strings.Contains(joined(r), "not reconstructed") {
		t.Fatalf("historical window not disclosed: %v", r.Limitations)
	}
}

func TestGraphQuery(t *testing.T) {
	h := newHarness(t, nil)
	r := h.mustCall(t, ToolGraph, args(t, map[string]any{"from": []map[string]any{{"kind": "Pod", "namespace": "shop", "name": "api-1"}}, "depth": 2}))
	d := r.Data.(map[string]any)
	edges := d["edges"].([]GraphEdge)
	if len(edges) != 1 || edges[0].From != "u3" || edges[0].Type != "owns" {
		t.Fatalf("edges %+v", edges)
	}
	if !strings.Contains(joined(r), "2 edges lead outside the request scope") {
		t.Fatalf("omitted edges %v", r.Limitations)
	}
	r = h.mustCall(t, ToolGraph, args(t, map[string]any{"scope": map[string]any{"cluster": true}, "from": []map[string]any{{"uid": "u1"}}, "edge_types": []string{"talks_to"}, "direction": "out"}))
	edges = r.Data.(map[string]any)["edges"].([]GraphEdge)
	if len(edges) != 1 || edges[0].To != "u2" || edges[0].Attrs["port"] != int64(5432) {
		t.Fatalf("typed edges %+v", edges)
	}
	if _, err := h.call(t, ToolGraph, args(t, map[string]any{"from": []map[string]any{{"uid": "u1"}}, "depth": 9})); errClass(err) != ClassInvalid {
		t.Fatalf("depth: %v", err)
	}
}

func TestFindingSaveProvenance(t *testing.T) {
	h := newHarness(t, nil)
	var emitted []protocol.Finding
	tr, err := findings.NewTracker(findings.Options{TargetID: "t1", Store: kv.NewMemory(), Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.o.SaveFinding = func(o findings.Observation) error {
		h.saved = append(h.saved, o)
		_, err := tr.AddQueryFinding(o, func(f protocol.Finding) (uint64, error) {
			emitted = append(emitted, f)
			return uint64(len(emitted)), nil
		})
		return err
	}
	r := h.mustCall(t, ToolFindingSave, args(t, map[string]any{
		"tool": ToolLogQL, "query": `{container="api"} |= "error"`, "window": win(15*time.Minute, 0),
		"severity": "high", "summary": "api errors", "labels": map[string]string{"app": "api"},
		"scope": map[string]any{"namespaces": []string{"shop"}, "resources": []map[string]any{{"uid": "u1"}}},
	}))
	if len(h.saved) != 1 || len(emitted) != 1 {
		t.Fatalf("saved %d emitted %d", len(h.saved), len(emitted))
	}
	o, f := h.saved[0], emitted[0]
	if o.Query == nil || o.Query.Requester != "user:alice" || o.Query.Hash.String() != r.QueryHash || o.Kind != findings.Firing {
		t.Fatalf("observation provenance %+v", o)
	}
	if f.Provenance.Kind != protocol.ProvenanceQuery || f.Provenance.QueryHash.String() != r.QueryHash || f.Provenance.Requester != "user:alice" {
		t.Fatalf("finding provenance %+v", f.Provenance)
	}
	if len(o.Evidence) != 5 || !slices.Equal(o.Resources, []string{"u1"}) || o.Category != defaultCategory || strings.Contains(o.Evidence[0].Text, "hunter2") {
		t.Fatalf("observation %+v", o)
	}
	if a := h.audit[len(h.audit)-1]; !a.RetainedFinding || a.Tool != ToolFindingSave || a.QueryHash != r.QueryHash {
		t.Fatalf("audit %+v", a)
	}
	for _, bad := range []map[string]any{
		{"tool": ToolLogQL, "query": `{container="api"} |= "nomatch"`, "window": win(15*time.Minute, 0), "severity": "high", "summary": "x"},
		{"tool": ToolLogQL, "query": `{container="api"}`, "window": win(15*time.Minute, 0), "severity": "urgent", "summary": "x"},
		{"tool": ToolState, "query": `x`, "window": win(15*time.Minute, 0), "severity": "high", "summary": "x"},
	} {
		if _, err := h.call(t, ToolFindingSave, args(t, bad)); errClass(err) != ClassInvalid {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	r = h.mustCall(t, ToolFindingSave, args(t, map[string]any{"tool": ToolPromQL, "query": `req_total`, "window": win(time.Minute, 0), "severity": "low", "summary": "req"}))
	if len(h.saved) != 2 || h.saved[1].Query == nil || h.saved[1].Query.Hash.String() != r.QueryHash || h.saved[1].Evidence[0].Labels["namespace"] != "shop" {
		t.Fatalf("metric save %+v", h.saved[1])
	}
}

func TestServiceConcurrencyAndTools(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.Limits = config.Investigation{MaxConcurrency: 1} })
	h.router.block = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := h.call(t, ToolPromQL, args(t, map[string]any{"query": "up", "window": win(time.Minute, 0)}))
		done <- err
	}()
	for {
		h.router.mu.Lock()
		n := len(h.router.runs)
		h.router.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := h.call(t, ToolPromQL, args(t, map[string]any{"query": "up", "window": win(time.Minute, 0), "limits": map[string]any{"timeout_ms": 50}})); errClass(err) != ClassBusy {
		t.Fatalf("want busy, got %v", err)
	}
	close(h.router.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	tools := h.svc.Tools()
	if len(tools) != 8 {
		t.Fatalf("tools %d", len(tools))
	}
	for _, tl := range tools {
		var sch struct {
			Required   []string       `json:"required"`
			Properties map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(tl.InputSchema, &sch); err != nil || !slices.Contains(sch.Required, "scope") || sch.Properties["limits"] == nil {
			t.Fatalf("%s schema %s", tl.Name, tl.InputSchema)
		}
	}
}

func TestHostService(t *testing.T) {
	db := openTSDB(t, labels.FromStrings("__name__", "node_load1"))
	local := NewExecutor(ExecOptions{Node: "h1", Queryable: db, Retention: db.Retention})
	var audit []AuditRecord
	svc, err := NewService(Options{Role: RoleHost, Local: local, Audit: func(r AuditRecord) { audit = append(audit, r) }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(scope map[string]any) (*Result, error) {
		v, err := svc.Call(context.Background(), ToolPromQL, args(t, map[string]any{"query": "node_load1", "window": win(time.Minute, 0), "scope": scope}))
		if err != nil {
			return nil, err
		}
		return v.(*Result), nil
	}
	for _, sc := range []map[string]any{{"cluster": true}, {"nodes": []string{"h1"}}} {
		r, err := call(sc)
		if err != nil || r.Source != sourceHost || len(r.Data.(Telemetry).Series) != 1 || r.Query != "node_load1" {
			t.Fatalf("%v: %+v %v", sc, r, err)
		}
	}
	for _, sc := range []map[string]any{{"nodes": []string{"h2"}}, {"namespaces": []string{"shop"}}} {
		if _, err := call(sc); errClass(err) != ClassUnauthorized {
			t.Fatalf("%v: %v", sc, err)
		}
	}
	if len(audit) != 4 || audit[0].Outcome != OutcomeOK || audit[3].Outcome != OutcomeRejected {
		t.Fatalf("audit %+v", audit)
	}
	if _, err := NewService(Options{Role: RoleHost}); err == nil {
		t.Fatal("host without executor")
	}
	if _, err := NewService(Options{Role: "node"}); err == nil {
		t.Fatal("unknown role")
	}
}

func TestLogQLPerSourceAggregation(t *testing.T) {
	r1, r2 := podLogTree(t), podLogTree(t)
	router := &fakeRouter{execs: map[string]*Executor{
		"n1": NewExecutor(ExecOptions{Node: "n1", PodLogRoot: r1}),
		"n2": NewExecutor(ExecOptions{Node: "n2", PodLogRoot: r2}),
	}}
	svc, err := NewService(Options{Role: RoleCoordinator, Nodes: router})
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.Call(context.Background(), ToolLogQL, args(t, map[string]any{"query": `sum(count_over_time({pod="api-1"} |= "error" [15m]))`, "window": win(15*time.Minute, 0)}))
	if err != nil {
		t.Fatal(err)
	}
	r := v.(*Result)
	d := r.Data.(Telemetry)
	if len(d.Series) != 2 || d.Series[0].Points[0].V != 5 || !strings.Contains(joined(r), limitationPerSource) {
		t.Fatalf("per-source %+v %v", d.Series, r.Limitations)
	}
	v, _ = svc.Call(context.Background(), ToolLogQL, args(t, map[string]any{"query": `count_over_time({pod="api-1"}[15m]) > 1`, "window": win(15*time.Minute, 0)}))
	if strings.Contains(joined(v.(*Result)), limitationPerSource) {
		t.Fatal("per-stream query flagged as aggregating")
	}
	empty, _ := NewService(Options{Role: RoleCoordinator})
	v, err = empty.Call(context.Background(), ToolPromQL, args(t, map[string]any{"query": "up", "window": win(time.Minute, 0)}))
	if err != nil || !strings.Contains(joined(v.(*Result)), "no node agents are connected") {
		t.Fatalf("no sources: %v %v", v, err)
	}
	if _, err := empty.Call(context.Background(), ToolState, args(t, nil)); errClass(err) != ClassUnavailable {
		t.Fatalf("no state: %v", err)
	}
	if _, err := empty.Call(context.Background(), ToolFindingSave, args(t, map[string]any{"tool": ToolPromQL, "query": "up", "window": win(time.Minute, 0), "severity": "low", "summary": "x"})); errClass(err) != ClassUnavailable {
		t.Fatalf("no finding sink: %v", err)
	}
}
