package logql

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func vectorMap(v promql.Vector) map[string]float64 {
	m := map[string]float64{}
	for _, s := range v {
		m[s.Metric.String()] = s.F
	}
	return m
}

func mustRule(t *testing.T, expr string, b bundle.Budget) *Program {
	t.Helper()
	p, err := CompileRule(expr, b)
	if err != nil {
		t.Fatalf("CompileRule(%q): %v", expr, err)
	}
	return p
}

func TestRuleMixedFixture(t *testing.T) {
	p := mustRule(t, `sum by (pod) (count_over_time({namespace="shop", container="api"} |= "level=error" != "healthz" [5m])) > 1`, bundle.Budget{})
	type in struct {
		pod, ns, ctr, line string
		match              bool
	}
	fixture := []in{
		{"a", "shop", "api", "level=error msg=db timeout", true},
		{"a", "shop", "api", "level=info msg=ok secret=hunter2", false},
		{"a", "shop", "api", "level=error msg=pool exhausted", true},
		{"a", "shop", "api", "level=error path=/healthz", false},
		{"b", "shop", "api", "level=error msg=once", true},
		{"a", "shop", "sidecar", "level=error msg=other container", false},
		{"a", "other", "api", "level=error msg=other namespace", false},
		{"c", "shop", "api", "level=warn msg=slow token=abc123", false},
	}
	for i, f := range fixture {
		stream := map[string]string{"namespace": f.ns, "pod": f.pod, "container": f.ctr}
		if got := p.Observe(stream, t0.Add(time.Duration(i)*time.Second), f.line); got != f.match {
			t.Fatalf("line %d %q matched=%v want %v", i, f.line, got, f.match)
		}
	}
	v, err := p.Eval(t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := vectorMap(v); !reflect.DeepEqual(got, map[string]float64{`{pod="a"}`: 2}) {
		t.Fatalf("got %v", got)
	}
	if !p.Matches(map[string]string{"namespace": "shop", "container": "api"}) || p.Matches(map[string]string{"namespace": "shop", "container": "sidecar"}) {
		t.Fatal("Matches must apply the stream selector")
	}
	state := fmt.Sprintf("%v %v", p.series, p.errs)
	for _, f := range fixture {
		if strings.Contains(state, f.line) || strings.Contains(state, "hunter2") || strings.Contains(state, "abc123") {
			t.Fatalf("counter state retains line content: %s", state)
		}
	}
}

func TestRuleCountRateBytesAndWindow(t *testing.T) {
	cases := []struct {
		expr string
		want float64
	}{
		{`count_over_time({app="x"}[1m])`, 3},
		{`rate({app="x"}[1m])`, 3.0 / 60},
		{`bytes_over_time({app="x"}[1m])`, 3 + 4 + 5},
	}
	for _, tc := range cases {
		p := mustRule(t, tc.expr, bundle.Budget{})
		for i, l := range []string{"abc", "abcd", "abcde"} {
			p.Observe(map[string]string{"app": "x"}, t0.Add(time.Duration(i*10)*time.Second), l)
		}
		v, err := p.Eval(t0.Add(30 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if len(v) != 1 || v[0].F != tc.want || v[0].T != t0.Add(30*time.Second).UnixMilli() || v[0].Metric.String() != `{app="x"}` {
			t.Fatalf("%s: got %v want %v", tc.expr, v, tc.want)
		}
		if p.Window() != time.Minute {
			t.Fatalf("window %v", p.Window())
		}
	}
}

func TestRuleWindowExpiry(t *testing.T) {
	p := mustRule(t, `count_over_time({app="x"}[1m])`, bundle.Budget{MaxSeries: 2})
	p.Observe(map[string]string{"app": "x", "pod": "a"}, t0, "l")
	p.Observe(map[string]string{"app": "x", "pod": "b"}, t0.Add(30*time.Second), "l")
	v, _ := p.Eval(t0.Add(61 * time.Second))
	if got := vectorMap(v); !reflect.DeepEqual(got, map[string]float64{`{app="x", pod="b"}`: 1}) {
		t.Fatalf("expired bucket still counted: %v", got)
	}
	if st := p.Status(); st.Series != 1 {
		t.Fatalf("expired series not removed: %+v", st)
	}
	if !p.Observe(map[string]string{"app": "x", "pod": "c"}, t0, "old") {
		t.Fatal("late line must still report its match")
	}
	if st := p.Status(); st.LateLines != 1 || st.Series != 1 {
		t.Fatalf("late line must not create a series: %+v", st)
	}
	p.Observe(map[string]string{"app": "x", "pod": "c"}, t0.Add(62*time.Second), "new")
	if st := p.Status(); st.Series != 2 || st.BudgetLimited {
		t.Fatalf("expiry must free cardinality: %+v", st)
	}
	v, _ = p.Eval(t0.Add(200 * time.Second))
	if len(v) != 0 {
		t.Fatalf("got %v after the window passed", v)
	}
}

func TestRuleMatchAllBudget(t *testing.T) {
	p := mustRule(t, `sum by (pod) (count_over_time({namespace=~".+"}[5m]))`, bundle.Budget{MaxSeries: 10})
	for i := 0; i < 100; i++ {
		for j := 0; j < 3; j++ {
			if !p.Observe(map[string]string{"namespace": "ns", "pod": fmt.Sprintf("p%03d", i)}, t0.Add(time.Duration(i)*time.Second), "any line") {
				t.Fatal("match-all rule must match")
			}
		}
	}
	st := p.Status()
	if st.Series != 10 || st.DroppedLines != 270 || !st.BudgetLimited || st.MaxSeries != 10 {
		t.Fatalf("status %+v", st)
	}
	if st.LiveBytes > p.MemoryBytes() {
		t.Fatalf("live counters %d exceed reservation %d", st.LiveBytes, p.MemoryBytes())
	}
	v, err := p.Eval(t0.Add(100 * time.Second))
	if err != nil || len(v) != 10 {
		t.Fatalf("got %d samples, %v", len(v), err)
	}
	if st := p.Status(); !st.BudgetLimited || st.LastDrop.IsZero() {
		t.Fatalf("status %+v", st)
	}
	p.Eval(t0.Add(20 * time.Minute))
	if st := p.Status(); st.BudgetLimited {
		t.Fatalf("budget-limited must clear once drops leave the window: %+v", st)
	}
}

func TestRulePreAggregationBoundsCardinality(t *testing.T) {
	p := mustRule(t, `sum(count_over_time({namespace=~".+"}[5m]))`, bundle.Budget{MaxSeries: 1})
	for i := 0; i < 50; i++ {
		p.Observe(map[string]string{"namespace": "ns", "pod": fmt.Sprintf("p%d", i)}, t0, "x")
	}
	v, err := p.Eval(t0.Add(time.Second))
	if err != nil || len(v) != 1 || v[0].F != 50 || p.Status().DroppedLines != 0 {
		t.Fatalf("got %v %v %+v", v, err, p.Status())
	}
}

func TestRuleBudgetRejection(t *testing.T) {
	_, err := CompileRule(`count_over_time({app="x"}[1h])`, bundle.Budget{MaxSeries: 100000})
	var be *BudgetError
	if !errors.As(err, &be) || be.Buckets != 61 || be.Required != 61*100000*bucketBytes || be.CounterBytes != DefaultCounterBytes {
		t.Fatalf("got %v", err)
	}
	_, err = CompileRule(`count_over_time({app="x"}[10s])`, bundle.Budget{MaxSeries: 10, CounterBytes: 11*10*bucketBytes - 1})
	if !errors.As(err, &be) || be.Buckets != 11 {
		t.Fatalf("got %v", err)
	}
	p, err := CompileRule(`count_over_time({app="x"}[10s])`, bundle.Budget{MaxSeries: 10, CounterBytes: 11 * 10 * bucketBytes})
	if err != nil || p.MemoryBytes() != 11*10*bucketBytes {
		t.Fatalf("got %v", err)
	}
	p, err = CompileRule(`count_over_time({app="x"}[5m])`, bundle.Budget{})
	if err != nil || p.MemoryBytes() != 61*DefaultMaxSeries*bucketBytes {
		t.Fatalf("default budget: %v", err)
	}
}

func TestRuleCompileRejections(t *testing.T) {
	cases := map[string]string{
		`{app="x"} |= "error"`:                                           "must be a metric query",
		`count_over_time({app="x"}[500ms])`:                              "below the 1s counter resolution",
		`count_over_time({app="x"} | line_format "x" [1m])`:              "unsupported construct",
		`sum(count_over_time({app="x"} | logfmt | a="1" or b="2" [1m]))`: "complexity",
	}
	for expr, msg := range cases {
		_, err := CompileRule(expr, bundle.Budget{MaxComplexity: 6})
		if err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("CompileRule(%q) = %v, want %q", expr, err, msg)
		}
	}
}

func TestRulePipelineError(t *testing.T) {
	p := mustRule(t, `sum by (level) (count_over_time({app="x"} | json [1m]))`, bundle.Budget{})
	p.Observe(map[string]string{"app": "x"}, t0, `{"level":"error"}`)
	p.Observe(map[string]string{"app": "x"}, t0, `not json`)
	_, err := p.Eval(t0.Add(time.Second))
	var pe *PipelineError
	if !errors.As(err, &pe) || pe.Err != "JSONParserErr" {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "not json") {
		t.Fatal("pipeline errors must not echo line content")
	}
	if _, err := p.Eval(t0.Add(2 * time.Minute)); err != nil {
		t.Fatalf("error must expire with the window: %v", err)
	}

	p = mustRule(t, `sum by (level) (count_over_time({app="x"} | json | __error__="" [1m]))`, bundle.Budget{})
	p.Observe(map[string]string{"app": "x"}, t0, `{"level":"error"}`)
	p.Observe(map[string]string{"app": "x"}, t0, `not json`)
	v, err := p.Eval(t0.Add(time.Second))
	if err != nil || !reflect.DeepEqual(vectorMap(v), map[string]float64{`{level="error"}`: 1}) {
		t.Fatalf("got %v %v", v, err)
	}

	for _, expr := range []string{
		`count_over_time({app="x"} | json | __error__!="" [1m])`,
		`max by (__error__) (count_over_time({app="x"} | json [1m]))`,
		`sum without (level) (count_over_time({app="x"} | json | __error__!="" [1m]))`,
	} {
		p = mustRule(t, expr, bundle.Budget{})
		p.Observe(map[string]string{"app": "x"}, t0, `not json`)
		if _, err := p.Eval(t0.Add(time.Second)); !errors.As(err, &pe) {
			t.Fatalf("%s: Loki keeps error samples only under sum by or sum, got %v", expr, err)
		}
	}
	for expr, want := range map[string]map[string]float64{
		`sum by (__error__) (count_over_time({app="x"} | json [1m]))`:               {`{}`: 1, `{__error__="JSONParserErr"}`: 1},
		`sum(count_over_time({app="x"} | json | __error__!="" [1m]))`:               {`{}`: 1},
		`sum by (level) (count_over_time({app="x"} | json | __error__=~".*" [1m]))`: {`{level="error"}`: 1, `{}`: 1},
	} {
		p = mustRule(t, expr, bundle.Budget{})
		p.Observe(map[string]string{"app": "x"}, t0, `{"level":"error"}`)
		p.Observe(map[string]string{"app": "x"}, t0, `not json`)
		v, err := p.Eval(t0.Add(time.Second))
		if err != nil || !reflect.DeepEqual(vectorMap(v), want) {
			t.Fatalf("%s: got %v %v", expr, vectorMap(v), err)
		}
	}

	p = mustRule(t, `sum by (__error__) (count_over_time({app="x"} | json | __error__!="" [1m]))`, bundle.Budget{})
	p.Observe(map[string]string{"app": "x"}, t0, `{"level":"error"}`)
	p.Observe(map[string]string{"app": "x"}, t0, `not json`)
	v, err = p.Eval(t0.Add(time.Second))
	if err != nil || !reflect.DeepEqual(vectorMap(v), map[string]float64{`{__error__="JSONParserErr"}`: 1}) {
		t.Fatalf("got %v %v", v, err)
	}
}

func TestRuleThresholdAndAggregations(t *testing.T) {
	obs := func(p *Program) {
		for pod, n := range map[string]int{"a": 1, "b": 3, "c": 5} {
			for i := 0; i < n; i++ {
				p.Observe(map[string]string{"app": "x", "pod": pod, "ns": "n1"}, t0, "l")
			}
		}
	}
	cases := []struct {
		expr string
		want map[string]float64
	}{
		{`sum(count_over_time({app="x"}[1m])) > 8`, map[string]float64{`{}`: 9}},
		{`sum(count_over_time({app="x"}[1m])) > 10`, map[string]float64{}},
		{`sum(count_over_time({app="x"}[1m])) > bool 10`, map[string]float64{`{}`: 0}},
		{`count_over_time({app="x"}[1m]) >= 3`, map[string]float64{`{app="x", ns="n1", pod="b"}`: 3, `{app="x", ns="n1", pod="c"}`: 5}},
		{`4 < count_over_time({app="x"}[1m])`, map[string]float64{`{app="x", ns="n1", pod="c"}`: 5}},
		{`max by (ns) (count_over_time({app="x"}[1m]))`, map[string]float64{`{ns="n1"}`: 5}},
		{`min(count_over_time({app="x"}[1m]))`, map[string]float64{`{}`: 1}},
		{`avg(count_over_time({app="x"}[1m])) * 2`, map[string]float64{`{}`: 6}},
		{`count(count_over_time({app="x"}[1m]))`, map[string]float64{`{}`: 3}},
		{`topk(2, count_over_time({app="x"}[1m]))`, map[string]float64{`{app="x", ns="n1", pod="b"}`: 3, `{app="x", ns="n1", pod="c"}`: 5}},
		{`sum without (pod) (count_over_time({app="x"}[1m]))`, map[string]float64{`{app="x", ns="n1"}`: 9}},
		{`sum by (pod) (rate({app="x"}[1m])) * 60 - 1`, map[string]float64{`{pod="a"}`: 0, `{pod="b"}`: 2, `{pod="c"}`: 4}},
	}
	for _, tc := range cases {
		p := mustRule(t, tc.expr, bundle.Budget{})
		obs(p)
		v, err := p.Eval(t0.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if got := vectorMap(v); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.expr, got, tc.want)
		}
	}
}

func TestRuleConcurrentObserveEval(t *testing.T) {
	p := mustRule(t, `sum by (pod) (rate({app="x"} | logfmt | level="error" [1m]))`, bundle.Budget{MaxSeries: 5})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				p.Observe(map[string]string{"app": "x", "pod": fmt.Sprintf("p%d", i%8)}, t0.Add(time.Duration(i)*time.Millisecond), "level=error n="+fmt.Sprint(w))
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if _, err := p.Eval(t0.Add(time.Second)); err != nil {
				t.Error(err)
			}
			_ = p.Status()
		}
	}()
	wg.Wait()
	st := p.Status()
	if st.Series != 5 || st.DroppedLines == 0 {
		t.Fatalf("status %+v", st)
	}
}
