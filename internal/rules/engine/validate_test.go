package engine

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

var subset = map[string]bool{
	"kube_pod_container_resource_limits":        true,
	"kube_pod_status_phase":                     true,
	"kube_node_status_condition":                true,
	"kube_deployment_spec_replicas":             true,
	"kube_deployment_status_replicas_available": true,
}

func TestValidatePromQLRejections(t *testing.T) {
	cases := []struct {
		name  string
		rule  bundle.AlertRule
		wants string
	}{
		{"parse", promRule("p", `sum(`, 0, 0), "parse error"},
		{"string result", promRule("p", `"x"`, 0, 0), "want a vector or scalar"},
		{"unknown scope", func() bundle.AlertRule { r := promRule("p", `up`, 0, 0); r.Meta.Scope = "galaxy"; return r }(), `unknown scope "galaxy"`},
		{"quantile", clusterRule("q", `quantile by (namespace) (0.9, rate(x[5m]))`, 0), "quantile is not decomposable across nodes"},
		{"topk", clusterRule("q", `topk(3, rate(x[5m]))`, 0), "topk over raw series is not decomposable"},
		{"stddev", clusterRule("q", `stddev(rate(x[5m]))`, 0), "stddev is not decomposable"},
		{"stdvar", clusterRule("q", `stdvar by (a) (rate(x[5m]))`, 0), "stdvar is not decomposable"},
		{"group", clusterRule("q", `group(rate(x[5m]))`, 0), "aggregation group is not decomposable"},
		{"absent", clusterRule("q", `absent(up{job="x"})`, 0), "absent and absent_over_time are not allowed in cluster rules"},
		{"absent over time", clusterRule("q", `sum(rate(x[5m])) > 0 or absent_over_time(x[5m])`, 0), "not allowed in cluster rules"},
		{"unpublished kube", promRule("k", `kube_deployment_status_observed_generation > 1`, 0, 0), "kube_deployment_status_observed_generation is not in the published kube_* subset; express it as a state rule with kinds: [Deployment]"},
		{"unpublished kube cluster", clusterRule("k", `sum(kube_cronjob_next_schedule_time)`, 0), "kinds: [CronJob]"},
		{"unknown kube kind", clusterRule("k", `sum(kube_widget_info)`, 0), "express it as a state rule over the normalized fields"},
		{"non node-scoped kube in node rule", promRule("k", `kube_deployment_spec_replicas > 0`, 0, 0), "kube_deployment_spec_replicas is not node-scoped"},
		{"mixed join", clusterRule("k", `sum by (namespace) (rate(x[5m])) / on (namespace) kube_deployment_spec_replicas`, 0), "joins node series (x) with kube_* series (kube_deployment_spec_replicas)"},
		{"vector binop", clusterRule("b", `sum(rate(x[5m])) / sum(rate(y[5m]))`, 0), "between two vectors is not decomposable"},
		{"set op", clusterRule("b", `sum(rate(x[5m])) and 1`, 0), "parse error"},
		{"scalar selects", clusterRule("b", `sum(rate(x[5m])) > scalar(y)`, 0), "scalar operand scalar(y) must not select series"},
		{"raw", clusterRule("r", `x > 5`, 0), "raw series x cannot be evaluated across nodes"},
		{"bad inner", clusterRule("r", `sum(x)`, 0), "inner expression x must be a per-node rate"},
		{"irate inner", clusterRule("r", `sum(irate(x[5m]))`, 0), "inner function irate is not per-node decomposable"},
		{"subquery inner", clusterRule("r", `sum(max_over_time(rate(x[1m])[5m:1m]))`, 0), "must take a range selector"},
		{"nested agg", clusterRule("r", `max(sum by (a) (rate(x[5m])))`, 0), "inner expression"},
		{"function outer", clusterRule("r", `abs(sum(rate(x[5m])))`, 0), "function abs is not decomposable"},
		{"histogram without le", clusterRule("h", `histogram_quantile(0.9, sum by (namespace) (rate(x_bucket[5m])))`, 0), "must keep the le label"},
		{"histogram max", clusterRule("h", `histogram_quantile(0.9, max by (le) (rate(x_bucket[5m])))`, 0), "must apply to sum by (le, ...)"},
		{"histogram without drops le", clusterRule("h", `histogram_quantile(0.9, sum without (le) (rate(x_bucket[5m])))`, 0), "must keep the le label"},
		{"regex name", promRule("n", `{__name__=~"kube_.*"}`, 0, 0), "must name its metric literally"},
		{"literal only", clusterRule("n", `1 > bool 0`, 0), "cluster rule selects no series"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePromQL(c.rule, Options{KubeSubset: subset})
			if err == nil || !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("got %v, want %q", err, c.wants)
			}
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.RuleID != c.rule.Meta.ID {
				t.Fatalf("not a ValidationError for the rule: %v", err)
			}
		})
	}
}

func TestValidatePromQLComplexityBudget(t *testing.T) {
	r := promRule("c", `a + b + c + d + e`, 0, 0)
	r.Meta.Budget.MaxComplexity = 5
	if err := ValidatePromQL(r, Options{}); err == nil || !strings.Contains(err.Error(), "complexity 9 exceeds the budget of 5") {
		t.Fatalf("got %v", err)
	}
	r.Meta.Budget.MaxComplexity = 0
	if err := ValidatePromQL(r, Options{Policy: Policy{MaxComplexity: 4}}); err == nil || !strings.Contains(err.Error(), "budget of 4") {
		t.Fatalf("policy cap not applied: %v", err)
	}
	if err := ValidatePromQL(r, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePromQLAccepts(t *testing.T) {
	for _, r := range []bundle.AlertRule{
		promRule("join", `container_memory_working_set_bytes / on(namespace, pod, container) kube_pod_container_resource_limits > 0.9`, 0, 0),
		promRule("absent", `absent(up{job="kubelet"})`, 0, 0),
		promRule("node", `kube_node_status_condition{condition="Ready",status="true"} == 0`, 0, 0),
		clusterRule("kube-only", `kube_deployment_spec_replicas != kube_deployment_status_replicas_available`, 0),
	} {
		if err := ValidatePromQL(r, Options{KubeSubset: subset}); err != nil {
			t.Fatalf("%s: %v", r.Meta.ID, err)
		}
	}
	if _, err := SplitPromQL(promRule("join", `up`, 0, 0), Options{}); err == nil || !strings.Contains(err.Error(), "node-local") {
		t.Fatalf("node rule split: %v", err)
	}
	s, err := SplitPromQL(clusterRule("kube-only", `kube_deployment_spec_replicas != kube_deployment_status_replicas_available`, 0), Options{KubeSubset: subset})
	if err != nil || s.NodeExpr != "" || s.CoordExpr != `kube_deployment_spec_replicas != kube_deployment_status_replicas_available` {
		t.Fatalf("kube-only split %+v %v", s, err)
	}
}

func TestSplitShapes(t *testing.T) {
	sel := func(part string) string {
		s := `exitmesh_split{__exitmesh_rule__="r",__exitmesh_rule_version__="1"`
		if part != "" {
			s += `,__exitmesh_part__="` + part + `"`
		}
		return s + "}"
	}
	helpers := "__exitmesh_node__, __exitmesh_rule__, __exitmesh_rule_version__, __exitmesh_part__"
	cases := []struct {
		expr, node, coord, outer string
		grouping                 []string
		without                  bool
	}{
		{`sum by (namespace) (rate(x[5m])) > 10`, `sum by (namespace) (rate(x[5m]))`, `(sum by (namespace) (` + sel("") + `)) > (10)`, "sum", []string{"namespace"}, false},
		{`count without (pod) (increase(x[10m]))`, `count without (pod) (increase(x[10m]))`, `sum without (pod, ` + helpers + `) (` + sel("") + `)`, "count", []string{"pod"}, true},
		{`min(min_over_time(x[5m]))`, `min (min_over_time(x[5m]))`, `min (` + sel("") + `)`, "min", nil, false},
		{`2 < bool max by (a) (max_over_time(x[5m]))`, `max by (a) (max_over_time(x[5m]))`, `(2) < bool (max by (a) (` + sel("") + `))`, "max", []string{"a"}, false},
		{`avg by (a) (rate(x[5m]))`, `label_replace(sum by (a) (rate(x[5m])), "__exitmesh_part__", "sum", "", "") or label_replace(count by (a) (rate(x[5m])), "__exitmesh_part__", "count", "", "")`, `(sum by (a) (` + sel("sum") + `) / sum by (a) (` + sel("count") + `))`, "avg", []string{"a"}, false},
		{`histogram_quantile(0.99, sum by (le, a) (rate(x_bucket[5m]))) > 0.5`, `sum by (le, a) (rate(x_bucket[5m]))`, `(histogram_quantile(0.99, sum by (le, a) (` + sel("") + `))) > (0.5)`, "sum", []string{"le", "a"}, false},
		{`(sum(quantile_over_time(0.9, x[5m])) * 100)`, `sum (quantile_over_time(0.9, x[5m]))`, `((sum (` + sel("") + `)) * (100))`, "sum", nil, false},
	}
	for _, c := range cases {
		s, err := SplitPromQL(clusterRule("r", c.expr, 0), Options{})
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if s.NodeExpr != c.node || s.CoordExpr != c.coord || s.Outer != c.outer || fmt.Sprint(s.Grouping) != fmt.Sprint(c.grouping) || s.Without != c.without {
			t.Fatalf("%s:\n got %+v\nwant node=%s coord=%s", c.expr, s, c.node, c.coord)
		}
	}
}

type node struct {
	name string
	m    *MemSeries
}

// cluster builds three nodes with disjoint series and returns them with the union.
func cluster(t *testing.T) ([]node, *MemSeries) {
	t.Helper()
	union := NewMemSeries(time.Hour, nil)
	var nodes []node
	pods := map[string][]string{"n1": {"a/p1", "b/p2"}, "n2": {"a/p3", "c/p4"}, "n3": {"a/p5", "b/p6", "b/p7"}}
	names := []string{"n1", "n2", "n3"}
	for ni, name := range names {
		m := NewMemSeries(time.Hour, nil)
		var specs []spec
		for pi, p := range pods[name] {
			ns, pod, _ := strings.Cut(p, "/")
			rate := float64((ni+1)*10 + pi)
			var vals []float64
			for i := range 16 {
				vals = append(vals, rate*60*float64(i))
			}
			specs = append(specs, sp(vals, "__name__", "reqs_total", "namespace", ns, "pod", pod, "node", name))
			for bi, le := range []string{"0.1", "1", "+Inf"} {
				var bv []float64
				for i := range 16 {
					bv = append(bv, float64((bi+1)*(ni+pi+1))*60*float64(i))
				}
				specs = append(specs, sp(bv, "__name__", "lat_bucket", "namespace", ns, "pod", pod, "le", le))
			}
		}
		load(m, "tsdb", time.Minute, specs...)
		load(union, name, time.Minute, specs...)
		nodes = append(nodes, node{name: name, m: m})
	}
	return nodes, union
}

func canon(v promql.Vector) []string {
	out := make([]string, 0, len(v))
	for _, s := range v {
		lb := labels.NewBuilder(s.Metric)
		lb.Del(labels.MetricName)
		out = append(out, fmt.Sprintf("%s=%.6f", lb.Labels().String(), s.F))
	}
	sort.Strings(out)
	return out
}

func TestClusterDecompositionMatchesDirectEvaluation(t *testing.T) {
	nodes, union := cluster(t)
	ts := at(15 * time.Minute)
	for _, expr := range []string{
		`sum by (namespace) (rate(reqs_total[5m]))`,
		`sum by (namespace) (rate(reqs_total[5m])) > 50`,
		`count by (namespace) (rate(reqs_total[5m]))`,
		`avg by (namespace) (rate(reqs_total[5m]))`,
		`avg without (pod, node) (rate(reqs_total[5m]))`,
		`max by (namespace) (increase(reqs_total[5m]))`,
		`min(max_over_time(reqs_total[5m]))`,
		`sum without (pod, node) (rate(reqs_total[5m]))`,
		`histogram_quantile(0.5, sum by (le, namespace) (rate(lat_bucket[5m])))`,
	} {
		rule := clusterRule("r", expr, 0)
		s, err := SplitPromQL(rule, Options{})
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		coord := NewMemSeries(time.Hour, nil)
		for _, n := range nodes {
			part := Part{RuleID: "r", RuleVersion: 1, EvalTime: ts, Vector: instant(t, n.m, s.NodeExpr, ts)}
			coord.Replace(n.name+"/r", PartSeries(n.name, part))
		}
		got, want := canon(instant(t, coord, s.CoordExpr, ts)), canon(instant(t, union, expr, ts))
		if len(want) == 0 || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s:\n split %v\ndirect %v", expr, got, want)
		}
	}
}

func TestPartSeriesLabelsAndSkipsHistograms(t *testing.T) {
	v := promql.Vector{{Metric: labels.FromStrings("namespace", "a"), F: 2}, {Metric: labels.FromStrings("namespace", "h"), H: &histogram.FloatHistogram{}}, {Metric: labels.FromStrings("namespace", "b"), F: math.NaN()}}
	ss := PartSeries("n1", Part{RuleID: "r", RuleVersion: 3, EvalTime: at(0), Vector: v})
	if len(ss) != 2 || ss[0].Labels.String() != `{__exitmesh_node__="n1", __exitmesh_rule__="r", __exitmesh_rule_version__="3", __name__="exitmesh_split", namespace="a"}` || ss[0].Samples[0].T != ms(at(0)) {
		t.Fatalf("got %v", ss)
	}
}

func TestValidateCEL(t *testing.T) {
	ok := stateRule("ok", `field(r, "status.phase", "") == "Pending" && in(r, "owns").size() == 0`, "Pod")
	ok.Labels = map[string]string{"phase": `=field(r, "status.phase", "")`, "team": "x"}
	if err := ValidateCEL(ok); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rule  bundle.StateRule
		wants string
	}{
		{stateRule("k", `true`), "lists no kinds"},
		{stateRule("s", `r.kind ==`, "Pod"), "CEL compile error"},
		{stateRule("t", `1 + 1`, "Pod"), "want bool"},
		{stateRule("u", `nope(r)`, "Pod"), "undeclared reference"},
		{func() bundle.StateRule { r := stateRule("f", `true`, "Pod"); r.For = -time.Second; return r }(), "must not be negative"},
		{func() bundle.StateRule {
			r := stateRule("c", `r.name == "a" || r.name == "b" || r.name == "c"`, "Pod")
			r.Meta.Budget.MaxComplexity = 4
			return r
		}(), "complexity"},
		{func() bundle.StateRule {
			r := stateRule("l", `true`, "Pod")
			r.Labels = map[string]string{"x": `=r.`}
			return r
		}(), "CEL compile error"},
		{func() bundle.StateRule {
			r := stateRule("lc", `r.name == "a"`, "Pod")
			r.Meta.Budget.MaxComplexity = 5
			r.Labels = map[string]string{"x": `=r.name`}
			return r
		}(), "including label expressions"},
	}
	for _, c := range cases {
		if err := ValidateCEL(c.rule); err == nil || !strings.Contains(err.Error(), c.wants) {
			t.Fatalf("%s: got %v, want %q", c.rule.ID, err, c.wants)
		}
	}
}

func TestRewriteIn(t *testing.T) {
	cases := map[string]string{
		`in(r, "owns")`:                    `_in(r, "owns")`,
		`size(in (r, 'x')) > 0`:            `size(_in (r, 'x')) > 0`,
		`"a" in ["a"] && in(r, "t") != []`: `"a" in ["a"] && _in(r, "t") != []`,
		`x in (y)`:                         `x in (y)`,
		`f(x) in(y)`:                       `f(x) in(y)`,
		`"in(r)" + r'in(' + """in(""" `:    `"in(r)" + r'in(' + """in(""" `,
		`r.in("x")`:                        `r.in("x")`,
		`1.5 in(l)`:                        `1.5 in(l)`,
		`[in(r,"a")][0]`:                   `[_in(r,"a")][0]`,
		`"esc\"in(" + in(r, "t")[0].name`:  `"esc\"in(" + _in(r, "t")[0].name`,
	}
	for in, want := range cases {
		if got := rewriteIn(in); got != want {
			t.Fatalf("rewriteIn(%s) = %s, want %s", in, got, want)
		}
	}
}
