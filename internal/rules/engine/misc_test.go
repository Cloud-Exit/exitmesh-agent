package engine

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestStateLabelValueFormatting(t *testing.T) {
	st := protocol.NewState()
	st.Resources["u1"] = &protocol.Resource{UID: "u1", Kind: "Pod", Namespace: "ns", Name: "p", Fields: map[string]any{
		"ratio": 0.25, "count": int64(3), "ok": true, "items": []any{"a"}, "status": "Running",
	}}
	r := bundle.StateRule{Kinds: []string{"Pod"}, Expr: `field(r, "status.phase.deep", "d") == "d" && field(r, "ratio.x", 1) == 1`, Meta: meta("fmt", bundle.ClassState, "")}
	r.Labels = map[string]string{
		"ratio": `=field(r, "ratio", 0.0)`, "count": `=field(r, "count", 0)`, "ok": `=field(r, "ok", false)`,
		"ts": `=timestamp("2026-01-01T00:00:00Z")`, "dur": `=duration("90s")`, "items": `=field(r, "items", [])`,
		"age": `=string(now - timestamp("2025-12-31T23:00:00Z"))`,
	}
	e, s := newTestEngine(t, Options{Role: RoleCoordinator, StateSource: func() *protocol.State { return st }}, mkBundle("v1", []bundle.StateRule{r}, nil, nil))
	eval(t, e, at(0))
	evs := s.take()
	if len(evs) != 1 {
		t.Fatalf("events %+v", evs)
	}
	want := map[string]string{"ratio": "0.25", "count": "3", "ok": "true", "ts": "2026-01-01T00:00:00Z", "dur": "1m30s", "items": "[a]", "age": "3600s"}
	for k, v := range want {
		if evs[0].Labels[k] != v {
			t.Fatalf("%s = %q, want %q (%v)", k, evs[0].Labels[k], v, evs[0].Labels)
		}
	}
	if evs[0].RuleID != "fmt" || evs[0].RuleVersion != 1 || evs[0].Scope != bundle.ScopeCluster {
		t.Fatalf("identity %+v", evs[0])
	}
}

func TestStateRuleVersionFallsBackToRule(t *testing.T) {
	r := stateRule("v", `true`, "Pod")
	r.Meta.Version, r.Version = 0, 7
	e, _ := newTestEngine(t, Options{Role: RoleCoordinator, StateSource: protocol.NewState}, mkBundle("v1", []bundle.StateRule{r}, nil, nil))
	eval(t, e, at(0))
	if st := stateOf(e, "v"); st.Version != 7 || st.State != StateActive {
		t.Fatalf("state %+v", st)
	}
	node, _ := newTestEngine(t, Options{Role: RoleNode}, mkBundle("v1", []bundle.StateRule{r}, nil, nil))
	eval(t, node, at(0))
	if len(node.RuleStates()) != 0 {
		t.Fatalf("node reports state rules: %+v", node.RuleStates())
	}
}

func TestScalarResultAndDefaultInterval(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(4, 10), "__name__", "x"))
	r := promRule("sc", `scalar(x) * 2`, 0, 0)
	r.GroupInterval = 0
	e, s := newTestEngine(t, Options{Queryable: m, DefaultInterval: 2 * time.Minute}, mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
	eval(t, e, at(0))
	evs := s.take()
	if len(evs) != 1 || evs[0].Value != 8 || len(evs[0].Labels) != 1 || evs[0].Labels["alertname"] != "sc" {
		t.Fatalf("scalar result %+v", evs)
	}
	eval(t, e, at(time.Minute))
	if st := stateOf(e, "sc"); !st.LastEval.Equal(at(0)) {
		t.Fatalf("evaluated before its interval: %+v", st)
	}
	eval(t, e, at(2*time.Minute))
	if st := stateOf(e, "sc"); !st.LastEval.Equal(at(2 * time.Minute)) {
		t.Fatalf("not evaluated at its interval: %+v", st)
	}
}

func TestNodePartFailuresAreIsolated(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	var specs []spec
	for _, p := range []string{"a", "b", "c"} {
		specs = append(specs, sp([]float64{0, 60, 120, 180, 240, 300}, "__name__", "reqs_total", "pod", p))
	}
	load(m, "tsdb", time.Minute, specs...)
	wide := clusterRule("wide", `sum by (pod) (rate(reqs_total[5m]))`, 0)
	wide.Meta.Budget.MaxSeries = 2
	ok := clusterRule("ok", `sum(rate(reqs_total[5m]))`, 0)
	var parts []Part
	e, _ := newTestEngine(t, Options{Role: RoleNode, Queryable: m, Push: func(p Part) { parts = append(parts, p) }}, mkBundle("v7", nil, []bundle.AlertRule{ok, wide}, nil))
	eval(t, e, at(5*time.Minute))
	if len(parts) != 1 || parts[0].RuleID != "ok" || parts[0].BundleVersion != "v7" || len(parts[0].Vector) != 1 || parts[0].Vector[0].F != 3 {
		t.Fatalf("parts %+v", parts)
	}
	if st := stateOf(e, "wide"); st.State != StateBudgetLimited {
		t.Fatalf("wide %+v", st)
	}
	noq, _ := newTestEngine(t, Options{Role: RoleNode, Push: func(Part) {}}, mkBundle("v1", nil, []bundle.AlertRule{ok}, nil))
	eval(t, noq, at(0))
	if st := stateOf(noq, "ok"); st.State != StateFailed {
		t.Fatalf("no queryable %+v", st)
	}
}

func TestResolveResourceVariants(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp([]float64{1}, "__name__", "node_down", "node", "n1"), sp([]float64{1}, "__name__", "node_down", "node", "n2"), sp([]float64{1}, "__name__", "node_down", "other", "x"))
	r := promRule("nd", `node_down > 0`, 0, 0)
	r.Meta.ResourceLabels = &bundle.ResourceRef{Kind: "Node", Name: "node"}
	resolve := func(kind, ns, name string) (string, bool) {
		if kind == "Node" && ns == "" && name == "n1" {
			return "uid-n1", true
		}
		return "", false
	}
	e, s := newTestEngine(t, Options{Queryable: m, ResolveResource: resolve}, mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
	eval(t, e, at(0))
	got := map[string]int{}
	for _, ev := range s.take() {
		got[ev.Labels["node"]] = len(ev.ResourceUIDs)
	}
	if got["n1"] != 1 || got["n2"] != 0 || got[""] != 0 || len(got) != 3 {
		t.Fatalf("resources %v", got)
	}
}

func TestSelectorAndGroupingForms(t *testing.T) {
	s, err := SplitPromQL(clusterRule("r", `sum by ("odd.label", ns) (((rate({__name__="reqs_total"}[5m]))))`, 0), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.NodeExpr, `sum by ("odd.label", ns) (rate(`) || !strings.Contains(s.CoordExpr, `sum by ("odd.label", ns)`) {
		t.Fatalf("split %+v", s)
	}
	if _, err := SplitPromQL(clusterRule("r", `sum(`, 0), Options{}); err == nil {
		t.Fatal("parse error not propagated")
	}
	if _, err := SplitPromQL(clusterRule("r", `sum(rate(x[5m])) + 1`, 0), Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := SplitPromQL(clusterRule("r", `sum(rate(x[5m])) + 1 > 2`, 0), Options{}); err != nil {
		t.Fatal(err)
	}
	r := promRule("n", `up`, 0, 0)
	r.Meta.Scope = ""
	if err := ValidatePromQL(r, Options{}); err != nil {
		t.Fatal(err)
	}
	if CoverageCovered.String() != "covered" || CoverageConverging.String() != "converging" || Coverage(9).String() != "unknown" {
		t.Fatal("coverage names")
	}
}

func TestNonFiniteValuesPersist(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(0, 5), "__name__", "x", "k", "nan"), sp(repeat(1, 5), "__name__", "x", "k", "inf"), sp(repeat(0, 5), "__name__", "y"))
	store := kv.NewMemory()
	b := mkBundle("v1", nil, []bundle.AlertRule{promRule("div", `x / on() group_left y`, 0, 0)}, nil)
	e1, s1 := newTestEngine(t, Options{Queryable: m, Store: store}, b)
	eval(t, e1, at(0))
	evs := s1.take()
	if len(evs) != 2 || !math.IsInf(evs[0].Value, 1) || !math.IsNaN(evs[1].Value) {
		t.Fatalf("events %+v", evs)
	}
	e2, s2 := newTestEngine(t, Options{Queryable: m, Store: store}, b)
	eval(t, e2, at(time.Minute))
	if st := stateOf(e2, "div"); st.Firing != 2 {
		t.Fatalf("restored %+v", st)
	}
	if evs := s2.take(); len(evs) != 0 {
		t.Fatalf("restart re-announced %+v", evs)
	}
	var f jsonFloat
	if err := f.UnmarshalJSON([]byte(`1`)); err == nil {
		t.Fatal("numeric encoding accepted")
	}
}

func TestAtModifierAndNegativeOffsetRejected(t *testing.T) {
	for expr, wants := range map[string]string{
		`x @ 100 > 1`:                                  "@ modifier",
		`rate(x[5m] @ end()) > 1`:                      "@ modifier",
		`max_over_time(x[5m:1m] @ 5)`:                  "@ modifier",
		`x offset -5m > 1`:                             "negative offsets",
		`max_over_time(rate(x[1m])[5m:1m] offset -1m)`: "negative offsets",
	} {
		if err := ValidatePromQL(promRule("a", expr, 0, 0), Options{}); err == nil || !strings.Contains(err.Error(), wants) {
			t.Fatalf("%s: %v", expr, err)
		}
	}
	if err := ValidatePromQL(promRule("a", `x offset 5m > 1`, 0, 0), Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentedStateRuleExamplesCompile(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "state-rules.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, _ := strings.Cut(string(doc), "```cel\n")
	block, _, _ := strings.Cut(rest, "```")
	n := 0
	for _, line := range strings.Split(block, "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if err := ValidateCEL(stateRule("doc", line, "Pod")); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		n++
	}
	if n != 7 {
		t.Fatalf("found %d examples", n)
	}
}

func TestStateRuleIDFromRuleHonorsPolicy(t *testing.T) {
	r := stateRule("by-rule-id", `true`, "Pod")
	r.Meta.ID = ""
	u := stateRule("unsup", `true`, "Pod")
	u.Meta.ID = ""
	e, _ := newTestEngine(t, Options{Role: RoleCoordinator, Policy: Policy{DisabledRules: []string{"by-rule-id"}}}, nil)
	if err := e.SetBundle(mkBundle("v1", []bundle.StateRule{r, u}, nil, nil), BundleResult{Unsupported: map[string]string{"unsup": "no"}}); err != nil {
		t.Fatal(err)
	}
	eval(t, e, at(0))
	if st := stateOf(e, "by-rule-id"); st.State != StateDisabled {
		t.Fatalf("got %+v", st)
	}
	if st := stateOf(e, "unsup"); st.State != StateUnsupported {
		t.Fatalf("got %+v", st)
	}
}
