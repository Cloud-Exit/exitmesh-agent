package engine

import (
	"context"
	"github.com/prometheus/prometheus/promql/parser"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/util/annotations"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

func TestNodeLocalJoinAgainstNodeScopedKubeSeries(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute,
		sp(repeat(950, 10), "__name__", "container_memory_working_set_bytes", "namespace", "shop", "pod", "cart-1", "container", "app", "id", "/kubepods/x"),
		sp(repeat(400, 10), "__name__", "container_memory_working_set_bytes", "namespace", "shop", "pod", "cart-2", "container", "app", "id", "/kubepods/y"),
	)
	load(m, "kube", time.Minute,
		sp(repeat(1000, 10), "__name__", "kube_pod_container_resource_limits", "namespace", "shop", "pod", "cart-1", "container", "app", "resource", "memory", "unit", "byte"),
		sp(repeat(1000, 10), "__name__", "kube_pod_container_resource_limits", "namespace", "shop", "pod", "cart-2", "container", "app", "resource", "memory", "unit", "byte"),
	)
	r := promRule("mem-near-limit", `container_memory_working_set_bytes / on(namespace, pod, container) kube_pod_container_resource_limits > 0.9`, 2*time.Minute, 0)
	r.Labels = map[string]string{"severity": "warning"}
	r.Annotations = map[string]string{"description": "{{ $labels.pod }} uses {{ $value }} of its limit"}
	r.Meta.ResourceLabels = &bundle.ResourceRef{Kind: "Pod", Namespace: "namespace", Name: "pod"}
	resolve := func(kind, ns, name string) (string, bool) {
		if kind == "Pod" && ns == "shop" && name == "cart-1" {
			return "uid-cart-1", true
		}
		return "", false
	}
	e, s := newTestEngine(t, Options{Role: RoleNode, Queryable: m, KubeSubset: subset, ResolveResource: resolve},
		mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
	var evs []AlertEvent
	for i := range 3 {
		eval(t, e, at(time.Duration(i)*time.Minute))
		evs = append(evs, s.take()...)
	}
	if len(evs) != 1 || evs[0].Transition != TransitionFiring {
		t.Fatalf("events %+v", evs)
	}
	ev := evs[0]
	if ev.Labels["pod"] != "cart-1" || ev.Labels["severity"] != "warning" || ev.Value != 0.95 || !slices.Equal(ev.ResourceUIDs, []string{"uid-cart-1"}) {
		t.Fatalf("event %+v", ev)
	}
	if ev.Annotations["description"] != "cart-1 uses 0.95 of its limit" || ev.Summary != "" || ev.Severity != "warning" || ev.Scope != bundle.ScopeNode {
		t.Fatalf("annotations %+v", ev)
	}
}

func TestSummaryFromMetaAndAnnotation(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp([]float64{5}, "__name__", "x", "pod", "p"))
	a := promRule("a", `x > 1`, 0, 0)
	a.Annotations = map[string]string{"summary": "pod {{ $labels.pod }} at {{ $value }}"}
	b := promRule("b", `x > 1`, 0, 0)
	b.Meta.Summary = "meta {{ $labels.pod }}"
	b.Annotations = map[string]string{"summary": "ignored"}
	e, s := newTestEngine(t, Options{Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{a, b}, nil))
	eval(t, e, at(0))
	evs := s.take()
	if only(evs, "a")[0].Summary != "pod p at 5" || only(evs, "b")[0].Summary != "meta p" {
		t.Fatalf("summaries %+v", evs)
	}
}

// slowQueryable blocks selects of slow_metric until the query context ends.
type slowQueryable struct{ storage.Queryable }

func (s slowQueryable) Querier(mint, maxt int64) (storage.Querier, error) {
	q, err := s.Queryable.Querier(mint, maxt)
	return slowQuerier{q}, err
}

type slowQuerier struct{ storage.Querier }

func (s slowQuerier) Select(ctx context.Context, sort bool, h *storage.SelectHints, ms ...*labels.Matcher) storage.SeriesSet {
	for _, m := range ms {
		if m.Name == labels.MetricName && m.Value == "slow_metric" {
			<-ctx.Done()
			return storage.ErrSeriesSet(ctx.Err())
		}
	}
	return s.Querier.Select(ctx, sort, h, ms...)
}

func (s slowQuerier) LabelValues(ctx context.Context, n string, h *storage.LabelHints, ms ...*labels.Matcher) ([]string, annotations.Annotations, error) {
	return s.Querier.LabelValues(ctx, n, h, ms...)
}

func TestBudgetIsolation(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	var specs []spec
	for i := range 50 {
		specs = append(specs, sp(repeat(1, 20), "__name__", "big_metric", "i", strings.Repeat("x", i+1)))
	}
	specs = append(specs, sp(repeat(1, 20), "__name__", "slow_metric"), sp(repeat(9, 20), "__name__", "good_metric"))
	load(m, "tsdb", time.Minute, specs...)
	heavy := promRule("heavy", `count(big_metric) > 0`, 0, 0)
	heavy.Meta.Budget.MaxSamples = 10
	slow := promRule("slow", `slow_metric > 0`, 0, 0)
	slow.Meta.Budget.MaxEvalTime = 30 * time.Millisecond
	wide := promRule("wide", `big_metric > 0`, 0, 0)
	wide.Meta.Budget.MaxSeries = 5
	good := promRule("good", `good_metric > 5`, 0, 0)
	e, s := newTestEngine(t, Options{Queryable: slowQueryable{m}, BudgetBackoff: 3 * time.Minute},
		mkBundle("v1", nil, []bundle.AlertRule{heavy, slow, wide, good}, nil))
	eval(t, e, at(0))
	evs := s.take()
	if len(evs) != 1 || evs[0].RuleID != "good" || evs[0].Transition != TransitionFiring {
		t.Fatalf("events %+v", evs)
	}
	for id, wants := range map[string]string{"heavy": "too many samples", "slow": "", "wide": "exceed max_series 5"} {
		st := stateOf(e, id)
		if st.State != StateBudgetLimited || !strings.Contains(st.Reason, wants) || !st.BackoffUntil.Equal(at(3*time.Minute)) {
			t.Fatalf("%s: %+v", id, st)
		}
	}
	if st := stateOf(e, "good"); st.State != StateActive || st.Firing != 1 {
		t.Fatalf("good: %+v", st)
	}
	eval(t, e, at(time.Minute))
	if st := stateOf(e, "heavy"); !st.LastEval.Equal(at(0)) || st.State != StateBudgetLimited {
		t.Fatalf("heavy evaluated during backoff: %+v", st)
	}
	if st := stateOf(e, "good"); !st.LastEval.Equal(at(time.Minute)) {
		t.Fatalf("good not evaluated: %+v", st)
	}
	eval(t, e, at(3*time.Minute))
	if st := stateOf(e, "heavy"); !st.LastEval.Equal(at(3*time.Minute)) || !st.BackoffUntil.Equal(at(6*time.Minute)) {
		t.Fatalf("heavy not retried after backoff: %+v", st)
	}
}

func TestBudgetExceededMarksFiringStale(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "a", "k", "1"), sp(cat(repeat(0, 1), repeat(1, 4)), "__name__", "b", "k", "2"))
	r := promRule("r", `a > 0 unless on() (b > 0)`, 0, 0)
	r.Meta.Budget.MaxSeries = 1
	e, s := newTestEngine(t, Options{Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
	eval(t, e, at(0))
	if got := transitions(s.take()); !slices.Equal(got, []string{TransitionFiring}) {
		t.Fatalf("got %v", got)
	}
	r2 := promRule("r", `a > 0 or b > 0`, 0, 0)
	r2.Meta.Budget.MaxSeries = 1
	if err := e.SetBundle(mkBundle("v2", nil, []bundle.AlertRule{r2}, nil), BundleResult{}); err != nil {
		t.Fatal(err)
	}
	eval(t, e, at(time.Minute))
	evs := s.take()
	if len(evs) != 1 || evs[0].Transition != TransitionStale || !evs[0].Incomplete || evs[0].BundleVersion != "v2" {
		t.Fatalf("got %+v", evs)
	}
}

func TestFailedRuleReportsAndStaysIsolated(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 3), "__name__", "x", "a", "1"), sp(repeat(1, 3), "__name__", "x", "a", "2"), sp(repeat(1, 3), "__name__", "y"))
	dup := promRule("dup", `label_replace(x, "a", "same", "", "") > 0`, 0, 0)
	ok := promRule("ok", `y > 0`, 0, 0)
	e, s := newTestEngine(t, Options{Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{dup, ok}, nil))
	eval(t, e, at(0))
	if evs := s.take(); len(evs) != 1 || evs[0].RuleID != "ok" {
		t.Fatalf("events %+v", evs)
	}
	st := stateOf(e, "dup")
	if st.State != StateFailed || st.Reason == "" {
		t.Fatalf("dup: %+v", st)
	}
	eval(t, e, at(time.Minute))
	if st := stateOf(e, "dup"); !st.LastEval.Equal(at(time.Minute)) {
		t.Fatalf("failed rule must keep its interval: %+v", st)
	}
	noq, _ := newTestEngine(t, Options{}, mkBundle("v1", nil, []bundle.AlertRule{ok}, nil))
	eval(t, noq, at(0))
	if st := stateOf(noq, "ok"); st.State != StateFailed || !strings.Contains(st.Reason, "no metrics queryable") {
		t.Fatalf("no queryable: %+v", st)
	}
}

func TestAbsentIsIncompleteWhileCoverageWarms(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 10), "__name__", "present"), sp([]float64{3, 3, 3}, "__name__", "gauge"))
	var mu sync.Mutex
	cov := CoverageWarming
	coverage := func() Coverage { mu.Lock(); defer mu.Unlock(); return cov }
	set := func(c Coverage) { mu.Lock(); cov = c; mu.Unlock() }
	abs := promRule("abs", `absent(up{job="kubelet"})`, 0, 0)
	g := promRule("g", `gauge > 2`, 0, 0)
	e, s := newTestEngine(t, Options{Role: RoleNode, Queryable: m, Coverage: coverage}, mkBundle("v1", nil, []bundle.AlertRule{abs, g}, nil))
	eval(t, e, at(0))
	evs := s.take()
	if len(only(evs, "abs")) != 0 {
		t.Fatalf("absent matched while warming: %+v", evs)
	}
	if ge := only(evs, "g"); len(ge) != 1 || ge[0].Transition != TransitionFiring || !ge[0].Incomplete {
		t.Fatalf("gauge events %+v", ge)
	}
	if st := stateOf(e, "abs"); st.State != StateStale || !strings.Contains(st.Reason, "warming") {
		t.Fatalf("abs state %+v", st)
	}
	set(CoverageCovered)
	eval(t, e, at(time.Minute))
	evs = s.take()
	if ae := only(evs, "abs"); len(ae) != 1 || ae[0].Transition != TransitionFiring {
		t.Fatalf("absent after coverage: %+v", evs)
	}
	if ge := only(evs, "g"); len(ge) != 1 || ge[0].Transition != TransitionUpdate || ge[0].Incomplete {
		t.Fatalf("coverage completion update: %+v", ge)
	}
	set(CoverageUncovered)
	eval(t, e, at(10*time.Minute))
	evs = s.take()
	if got := transitions(evs); !slices.Equal(got, []string{TransitionStale, TransitionStale}) {
		t.Fatalf("uncovered node must mark stale, got %+v", evs)
	}
	set(CoverageCovered)
	m.Replace("recovered", []Series{{Labels: labels.FromStrings("__name__", "gauge"), Samples: []Sample{{T: timestamp.FromTime(at(11 * time.Minute)), F: 1}}}})
	eval(t, e, at(11*time.Minute))
	if got := transitions(only(s.take(), "g")); !slices.Equal(got, []string{TransitionResolved}) {
		t.Fatalf("recovery after coverage returns: %v", got)
	}
}

func TestClusterRuleEndToEnd(t *testing.T) {
	nodes, _ := cluster(t)
	rule := clusterRule("ns-rate", `sum by (namespace) (rate(reqs_total[5m])) > 50`, 2*time.Minute)
	var coordMu sync.Mutex
	coordMem := NewMemSeries(time.Hour, func() time.Time { return t0 })
	var nodeEngines []*Engine
	for _, n := range nodes {
		name := n.name
		push := func(p Part) {
			coordMu.Lock()
			defer coordMu.Unlock()
			coordMem.Replace(name+"/"+p.RuleID, PartSeries(name, p))
		}
		ne, _ := newTestEngine(t, Options{Role: RoleNode, Queryable: n.m, Push: push}, mkBundle("v1", nil, []bundle.AlertRule{rule}, nil))
		nodeEngines = append(nodeEngines, ne)
	}
	var covMu sync.Mutex
	cov := CoverageCovered
	clusterCov := func(id string, v int) Coverage {
		covMu.Lock()
		defer covMu.Unlock()
		if id != "ns-rate" || v != 1 {
			t.Errorf("coverage asked for %s v%d", id, v)
		}
		return cov
	}
	ce, s := newTestEngine(t, Options{Role: RoleCoordinator, Queryable: coordMem, ClusterCoverage: clusterCov}, mkBundle("v1", nil, []bundle.AlertRule{rule}, nil))
	var fired []AlertEvent
	for i := 5; i <= 7; i++ {
		ts := at(time.Duration(i) * time.Minute)
		for _, ne := range nodeEngines {
			eval(t, ne, ts)
		}
		eval(t, ce, ts)
		fired = append(fired, s.take()...)
	}
	if len(fired) != 2 || fired[0].Labels["namespace"] != "a" || fired[1].Labels["namespace"] != "b" || fired[0].Value != 60 || fired[1].Value != 74 {
		t.Fatalf("fired %+v", fired)
	}
	if !fired[0].ActiveAt.Equal(at(5*time.Minute)) || fired[0].Scope != bundle.ScopeCluster {
		t.Fatalf("fired %+v", fired[0])
	}
	if st := stateOf(nodeEngines[0], "ns-rate"); st.State != StateActive || st.Firing != 0 {
		t.Fatalf("node part state %+v", st)
	}
	covMu.Lock()
	cov = CoverageConverging
	covMu.Unlock()
	coordMem.Replace("n3/ns-rate", nil)
	ts := at(8 * time.Minute)
	for _, ne := range nodeEngines[:2] {
		eval(t, ne, ts)
	}
	eval(t, ce, ts)
	evs := s.take()
	if st := stateOf(ce, "ns-rate"); st.State != StateConverging {
		t.Fatalf("coordinator state %+v", st)
	}
	if len(evs) != 2 {
		t.Fatalf("want two stale events, got %+v", evs)
	}
	for _, ev := range evs {
		if ev.Transition != TransitionStale || !ev.Incomplete {
			t.Fatalf("missing node contribution resolved or was complete: %+v", ev)
		}
	}
}

func TestKubeOnlyClusterRuleSkippedOnNodes(t *testing.T) {
	r := clusterRule("rollout", `kube_deployment_spec_replicas != kube_deployment_status_replicas_available`, 0)
	pushed := 0
	ne, _ := newTestEngine(t, Options{Role: RoleNode, KubeSubset: subset, Push: func(Part) { pushed++ }}, mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
	eval(t, ne, at(0))
	if pushed != 0 || len(ne.RuleStates()) != 0 {
		t.Fatalf("node evaluated a coordinator-only rule: %d %+v", pushed, ne.RuleStates())
	}
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "kube", time.Minute,
		sp([]float64{3}, "__name__", "kube_deployment_spec_replicas", "namespace", "a", "deployment", "web"),
		sp([]float64{1}, "__name__", "kube_deployment_status_replicas_available", "namespace", "a", "deployment", "web"))
	ce, s := newTestEngine(t, Options{Role: RoleCoordinator, KubeSubset: subset, Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
	eval(t, ce, at(0))
	if evs := s.take(); len(evs) != 1 || evs[0].Labels["deployment"] != "web" {
		t.Fatalf("events %+v", evs)
	}
	nl := promRule("local", `up == 0`, 0, 0)
	ce2, _ := newTestEngine(t, Options{Role: RoleCoordinator, Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{nl}, nil))
	eval(t, ce2, at(0))
	if len(ce2.RuleStates()) != 0 {
		t.Fatalf("coordinator reported a node-local rule: %+v", ce2.RuleStates())
	}
	nop, _ := newTestEngine(t, Options{Role: RoleNode}, mkBundle("v1", nil, []bundle.AlertRule{clusterRule("c", `sum(rate(x[5m]))`, 0)}, nil))
	eval(t, nop, at(0))
	if st := stateOf(nop, "c"); st.State != StateUnsupported || !strings.Contains(st.Reason, "push sink") {
		t.Fatalf("no push: %+v", st)
	}
}

func TestMissingInputIsStaleNotResolved(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp([]float64{5, 5, 5}, "__name__", "node_timex_offset_seconds"))
	h := promRule("plain", `node_timex_offset_seconds > 1`, 0, 0)
	e, s := newTestEngine(t, Options{Role: RoleHost, Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{h}, nil))
	eval(t, e, at(0))
	if got := transitions(only(s.take(), "plain")); !slices.Equal(got, []string{TransitionFiring}) {
		t.Fatalf("plain rule should fire: %v", got)
	}
	eval(t, e, at(20*time.Minute))
	evs := s.take()
	if got := transitions(only(evs, "plain")); !slices.Equal(got, []string{TransitionStale}) {
		t.Fatalf("telemetry loss must mark stale, never resolve: %v", got)
	}
	if st := stateOf(e, "plain"); st.State != StateStale || !strings.Contains(st.Reason, "no input series for node_timex_offset_seconds") {
		t.Fatalf("state %+v", st)
	}
	if got := promInputs(mustParse(t, `abs(node_timex_offset_seconds) > 1 and on() kube_node_info unless absent(up)`)); !slices.Equal(got, []string{"node_timex_offset_seconds"}) {
		t.Fatalf("inputs %v", got)
	}
}

func mustParse(t *testing.T, q string) parser.Expr {
	t.Helper()
	x, err := promParser.ParseExpr(q)
	if err != nil {
		t.Fatal(err)
	}
	return x
}
