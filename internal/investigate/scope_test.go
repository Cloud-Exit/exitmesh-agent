package investigate

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/logstorage"
	"github.com/VictoriaMetrics/metricsql"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

var (
	scopeA  = telemetryScope{namespaces: []string{"shop"}}
	scopeAB = telemetryScope{namespaces: []string{"shop", "pay"}, nodes: []string{"n1.example"}}
)

func promSelectors(t *testing.T, q string) [][]*labels.Matcher {
	t.Helper()
	e, err := promParser.ParseExpr(q)
	if err != nil {
		t.Fatalf("re-parse %q: %v", q, err)
	}
	var out [][]*labels.Matcher
	parser.Inspect(e, func(n parser.Node, _ []parser.Node) error {
		if vs, ok := n.(*parser.VectorSelector); ok {
			out = append(out, vs.LabelMatchers)
		}
		return nil
	})
	return out
}

func TestInjectPromQL(t *testing.T) {
	cases := []struct {
		q         string
		selectors int
	}{
		{`up`, 1},
		{`rate(http_requests_total{job="api"}[5m])`, 1},
		{`sum by (pod) (rate(a[5m])) / on(pod) group_left sum by (pod) (b)`, 2},
		{`max_over_time(rate(x[1m])[30m:1m])`, 1},
		{`a or b unless c`, 3},
		{`x{namespace="other"}`, 1},
		{`x{namespace=~".*"}`, 1},
		{`x{namespace!="shop"} and on() vector(1)`, 1},
		{`{__name__=~"kube_.+"} offset 10m`, 1},
		{`label_replace(up, "namespace", "other", "", "")`, 1},
		{`absent(nothing{pod="p"})`, 1},
		{`vector(1) + time()`, 0},
		{`histogram_quantile(0.9, sum by (le) (rate(h_bucket[5m])))`, 1},
	}
	for _, sc := range []telemetryScope{scopeA, scopeAB} {
		want := sc.matchers()
		for _, c := range cases {
			out, err := InjectPromQL(c.q, want)
			if err != nil {
				t.Fatalf("%q: %v", c.q, err)
			}
			sels := promSelectors(t, out)
			if len(sels) != c.selectors {
				t.Fatalf("%q: %d selectors in %q", c.q, len(sels), out)
			}
			for _, m := range sels {
				if !hasAllMatchers(m, want) {
					t.Fatalf("%q: selector without scope in %q", c.q, out)
				}
			}
		}
	}
	out, err := InjectPromQL(`x{namespace="other"}`, scopeA.matchers())
	if err != nil || out != `x{namespace="other",namespace="shop"}` {
		t.Fatalf("conflicting matcher must AND: %q %v", out, err)
	}
	out, _ = InjectPromQL(`up`, scopeAB.matchers())
	if out != `up{namespace=~"shop|pay",node="n1.example"}` {
		t.Fatalf("regex scope not quoted: %q", out)
	}
	for _, bad := range []string{`sum(`, `x{`, `{}`, `rate(x)`, `x @ 1000`} {
		if _, err := InjectPromQL(bad, scopeA.matchers()); err == nil && !strings.Contains(bad, "@") {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestPromReach(t *testing.T) {
	cases := map[string]time.Duration{
		`up`:                                  0,
		`rate(x[5m])`:                         5 * time.Minute,
		`rate(x[5m] offset 1h)`:               time.Hour + 5*time.Minute,
		`max_over_time(rate(x[5m])[2h:1m])`:   2*time.Hour + 5*time.Minute,
		`a offset 3h + rate(b[10m])`:          3 * time.Hour,
		`max_over_time(x[1h:] offset 30m)`:    90 * time.Minute,
		`sum(rate(y[1d]))`:                    24 * time.Hour,
		`count_over_time(z{a="b"}[15m]) > 1`:  15 * time.Minute,
		`avg_over_time(q[10m:1m] offset 20m)`: 30 * time.Minute,
	}
	for q, want := range cases {
		got, err := promReach(q)
		if err != nil || got != want {
			t.Fatalf("%q: reach %s, want %s (%v)", q, got, want, err)
		}
	}
	for _, q := range []string{`x @ 100`, `rate(x[5m] @ end())`, `max_over_time(x[1h:1m] @ start())`} {
		if _, err := promReach(q); err == nil {
			t.Fatalf("%q: @ must be rejected", q)
		}
	}
}

func TestInjectMetricsQL(t *testing.T) {
	sc := scopeAB
	want := metricsqlFilters(sc.matchers())
	cases := []string{
		`up`,
		`foo{a="b" or c="d"}`,
		`rate(x{namespace="other"}[5m]) + on(a) y`,
		`with (f(m) = m{a="1"}) f(z)`,
		`sum(rate({__name__=~"a.*"}[1m:30s]))`,
		`topk_max(3, a) or b`,
		`label_set(time(), "namespace", "other")`,
		`histogram_quantile(0.9, sum(rate(h_bucket[5m])) by (vmrange))`,
	}
	for _, q := range cases {
		out, err := InjectMetricsQL(q, sc.matchers())
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		e, err := metricsql.Parse(out)
		if err != nil {
			t.Fatalf("re-parse %q: %v", out, err)
		}
		metricsql.VisitAll(e, func(x metricsql.Expr) {
			me, ok := x.(*metricsql.MetricExpr)
			if !ok {
				return
			}
			for _, g := range me.LabelFilterss {
				for _, w := range want {
					if !slices.Contains(g, w) {
						t.Fatalf("%q: group %v lacks %v in %q", q, g, w, out)
					}
				}
			}
		})
	}
	out, err := InjectMetricsQL(`foo{a="b" or namespace="other"}`, scopeA.matchers())
	if err != nil || out != `foo{a="b",namespace="shop" or namespace="other",namespace="shop"}` {
		t.Fatalf("or groups must each AND the scope: %q %v", out, err)
	}
	if _, err := InjectMetricsQL(`sum(`, scopeA.matchers()); err == nil {
		t.Fatal("parse error must be rejected")
	}
	if r, err := metricsqlReach(`rate(x[5m] offset 1h)`); err != nil || r != time.Hour+5*time.Minute {
		t.Fatalf("metricsql reach %s %v", r, err)
	}
	if _, err := metricsqlReach(`x @ 100`); err == nil {
		t.Fatal("@ must be rejected in metricsql")
	}
}

func TestInjectLogQL(t *testing.T) {
	cases := []string{
		`{app="api"}`,
		`{app="api"} |= "error" | json | level="error" or level="warn"`,
		`{namespace="other"} |~ "a|b"`,
		`{namespace=~".+"}`,
		`sum by (pod) (count_over_time({app="api"} |= "x" [5m]))`,
		`sum(rate({a="1"}[1m])) > 3`,
		`topk(3, sum by (app) (bytes_over_time({app=~"a|b"}[10m])))`,
	}
	want := scopeAB.matchers()
	for _, q := range cases {
		out, err := InjectLogQL(q, want)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		e, err := logql.ParseExpr(out)
		if err != nil {
			t.Fatalf("re-parse %q: %v", out, err)
		}
		n := 0
		walkLogQL(e, func(le *logql.LogExpr, _ time.Duration) {
			n++
			if !hasAllMatchers(le.Matchers, want) {
				t.Fatalf("%q: selector lacks scope in %q", q, out)
			}
		})
		if n == 0 {
			t.Fatalf("%q: no selectors", q)
		}
		if err := verifyLogQLScope(out, want); err != nil {
			t.Fatal(err)
		}
	}
	out, err := InjectLogQL(`{namespace="other"}`, scopeA.matchers())
	if err != nil || !strings.Contains(out, `namespace="other"`) || !strings.Contains(out, `namespace="shop"`) {
		t.Fatalf("conflicting matcher must AND: %q %v", out, err)
	}
	if _, err := InjectLogQL(`{app="x"`, scopeA.matchers()); err == nil {
		t.Fatal("parse error must be rejected")
	}
	if _, _, r, err := logqlShape(`sum(rate({a="1"}[2h]))`); err != nil || r != 2*time.Hour {
		t.Fatalf("logql reach %s %v", r, err)
	}
	if err := verifyLogQLScope(`{app="x"}`, want); err == nil {
		t.Fatal("unscoped selector must fail verification")
	}
}

func TestInjectLogsQL(t *testing.T) {
	cases := []string{
		`error`,
		`error or warn`,
		`_stream:{namespace="other"} error`,
		`* | stats by (level) count() c`,
		`x | union (y)`,
		`x:in(y | fields x)`,
		`"a" AND NOT "b" | filter level:=error`,
	}
	start, end := time.UnixMilli(1_700_000_000_000), time.UnixMilli(1_700_000_600_000)
	for _, q := range cases {
		out, err := InjectLogsQL(q, scopeAB.namespaces, scopeAB.nodes, start, end)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		for _, f := range []string{`namespace=~"shop|pay"`, `node=~"n1\\.example"`} {
			if !strings.Contains(out, f) {
				t.Fatalf("%q: %s missing in %q", q, f, out)
			}
		}
		re, err := logstorage.ParseQuery(out)
		if err != nil || re.String() != out {
			t.Fatalf("%q: unstable %q %v", q, out, err)
		}
		if s, e := re.GetFilterTimeRange(); s != start.UnixNano() || e != end.UnixNano() {
			t.Fatalf("%q: time range %d..%d", q, s, e)
		}
	}
	out, _ := InjectLogsQL(`x | union (y)`, scopeA.namespaces, scopeA.nodes, time.Time{}, time.Time{})
	if strings.Count(out, `{namespace=~"shop"}`) != 2 {
		t.Fatalf("union subquery must be scoped: %q", out)
	}
	out, _ = InjectLogsQL(`_stream:{namespace="other"} error`, scopeA.namespaces, scopeA.nodes, time.Time{}, time.Time{})
	if !strings.Contains(out, `namespace=~"shop"`) || !strings.Contains(out, `namespace="other"`) {
		t.Fatalf("conflicting stream filter must AND: %q", out)
	}
	if _, err := InjectLogsQL(`error |`, scopeA.namespaces, scopeA.nodes, time.Time{}, time.Time{}); err == nil {
		t.Fatal("parse error must be rejected")
	}
	if !isLogsQLStats(`* | stats count()`, end) || isLogsQLStats(`error`, end) {
		t.Fatal("stats detection")
	}
}
