package metricfacts

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

const gib = float64(1 << 30)

func loadDrift(t *testing.T, db *tsdb.DB, start time.Time) {
	t.Helper()
	span := 6 * time.Hour
	type ser struct {
		l labels.Labels
		v func(el time.Duration) float64
	}
	api := func(name string, extra ...string) labels.Labels {
		return labels.FromStrings(append([]string{"__name__", name, "namespace", "shop", "pod", "api-1", "container", "api"}, extra...)...)
	}
	side := func(name string, extra ...string) labels.Labels {
		return labels.FromStrings(append([]string{"__name__", name, "namespace", "shop", "pod", "api-1", "container", "sidecar"}, extra...)...)
	}
	series := []ser{
		{api("container_memory_working_set_bytes", "node", "n1", "job", "kubelet"), func(el time.Duration) float64 { return gib * (0.4 + 0.55*float64(el)/float64(span)) }},
		{api("container_cpu_usage_seconds_total", "node", "n1", "job", "kubelet"), func(el time.Duration) float64 { return 0.25 * el.Seconds() }},
		{side("container_memory_working_set_bytes"), func(time.Duration) float64 { return 100 << 20 }},
		{side("container_cpu_usage_seconds_total"), func(el time.Duration) float64 { return 0.02 * el.Seconds() }},
		{labels.FromStrings("__name__", "container_memory_working_set_bytes", "namespace", "shop", "pod", "api-1", "container", "POD"), func(time.Duration) float64 { return 1 }},
		{labels.FromStrings("__name__", "container_memory_working_set_bytes", "namespace", "shop", "pod", "api-1", "container", ""), func(time.Duration) float64 { return 5 * gib }},
		{api("kube_pod_container_resource_limits", "resource", "memory", "unit", "byte"), func(time.Duration) float64 { return gib }},
		{api("kube_pod_container_resource_requests", "resource", "memory", "unit", "byte"), func(time.Duration) float64 { return gib / 2 }},
		{api("kube_pod_container_resource_limits", "resource", "cpu", "unit", "core"), func(time.Duration) float64 { return 0.5 }},
		{api("kube_pod_container_resource_requests", "resource", "cpu", "unit", "core"), func(time.Duration) float64 { return 0.25 }},
		{api("kube_pod_container_status_restarts_total"), func(el time.Duration) float64 {
			if el >= 5*time.Hour+30*time.Minute {
				return 2
			}
			return 0
		}},
		{labels.FromStrings("__name__", "kube_pod_info", "namespace", "shop", "pod", "api-1", "node", "n1"), func(time.Duration) float64 { return 1 }},
		{labels.FromStrings("__name__", "kube_node_status_condition", "node", "n1", "condition", "MemoryPressure", "status", "true"), func(el time.Duration) float64 {
			if el > 5*time.Hour {
				return 1
			}
			return 0
		}},
		{labels.FromStrings("__name__", "kube_node_status_condition", "node", "n1", "condition", "DiskPressure", "status", "true"), func(time.Duration) float64 { return 0 }},
	}
	for el := time.Duration(0); el <= span; el += 30 * time.Second {
		app := db.Appender(context.Background())
		for _, s := range series {
			if _, err := app.Append(0, s.l, start.Add(el).UnixMilli(), s.v(el)); err != nil {
				t.Fatal(err)
			}
		}
		if err := app.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func byKey(fs []Fact) map[string]Fact {
	m := map[string]Fact{}
	for _, f := range fs {
		m[f.Key()] = f
	}
	return m
}

func TestMemoryDriftVisibleFromSnapshots(t *testing.T) {
	db, err := tsdb.Open(t.TempDir(), tsdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	start := time.Unix(1_790_000_000, 0).Truncate(time.Hour)
	loadDrift(t, db, start)
	engine := promql.NewEngine(promql.EngineOpts{MaxSamples: 50_000_000, Timeout: time.Minute})
	th := DefaultThresholds()

	var prevAPI, prevSide map[string]any
	var ratios []float64
	var deltas, sideDeltas int
	var last map[string]Fact
	for h := 1; h <= 6; h++ {
		facts, err := Compute(context.Background(), db, engine, start.Add(time.Duration(h)*time.Hour), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		m := byKey(facts)
		if len(m) != 3 {
			t.Fatalf("hour %d facts %+v", h, facts)
		}
		a := m["container/shop/api-1/api"]
		ratios = append(ratios, a.Fields[MemLimitRatio].(float64))
		if th.Changed(prevAPI, a.Fields) {
			deltas++
		}
		s := m["container/shop/api-1/sidecar"]
		if th.Changed(prevSide, s.Fields) {
			sideDeltas++
		}
		prevAPI, prevSide, last = a.Fields, s.Fields, m
		if h == 1 {
			if a.Fields[MemSaturated] != false || a.Fields[CPUSaturated] != false || a.Fields[RestartsCount] != 0.0 {
				t.Fatalf("first hour %+v", a.Fields)
			}
			if n := m["node/n1"]; n.Fields[NodeMemPressure] != false || n.Fields[NodeDiskPressure] != false {
				t.Fatalf("node %+v", n)
			}
		}
	}
	if ratios[0] < 0.47 || ratios[0] > 0.50 || ratios[5] < 0.93 || ratios[5] > 0.95 {
		t.Fatalf("ratios %v", ratios)
	}
	for i := 1; i < len(ratios); i++ {
		if ratios[i] <= ratios[i-1] {
			t.Fatalf("drift not monotonic %v", ratios)
		}
	}
	a := last["container/shop/api-1/api"]
	f := a.Fields
	if a.Node != "n1" || f[MemSaturated] != true || f[MemLimit] != gib || f[MemRequest] != gib/2 || f[CPULimit] != 0.5 || f[CPURequest] != 0.25 {
		t.Fatalf("last api fact %+v", a)
	}
	if p := f[CPUP95].(float64); math.Abs(p-0.25) > 0.001 || f[CPULimitRatio].(float64) != 0.5 || f[CPUSaturated] != false {
		t.Fatalf("cpu %+v", f)
	}
	if f[RestartsCount] != 2.0 || f[RestartsPerHour] != 2.0 {
		t.Fatalf("restarts %+v", f)
	}
	if n := last["node/n1"]; n.Fields[NodeMemPressure] != true || n.Fields[NodeDiskPressure] != false {
		t.Fatalf("node pressure %+v", n)
	}
	s := last["container/shop/api-1/sidecar"]
	if s.Node != "n1" || s.Fields[MemP95] != float64(100<<20) || s.Fields[MemLimitRatio] != nil {
		t.Fatalf("sidecar %+v", s)
	}
	if deltas != 6 || sideDeltas != 1 {
		t.Fatalf("deltas api %d sidecar %d", deltas, sideDeltas)
	}
	if _, err := Compute(context.Background(), db, engine, start, 0); err == nil {
		t.Fatal("zero interval accepted")
	}
}

func TestThresholds(t *testing.T) {
	th := DefaultThresholds()
	cases := []struct {
		name      string
		prev, cur map[string]any
		want      bool
	}{
		{"first", nil, map[string]any{MemP95: 1.0}, true},
		{"none", nil, nil, false},
		{"same", map[string]any{MemP95: 100e6}, map[string]any{MemP95: 100e6}, false},
		{"small relative", map[string]any{MemP95: 100e6}, map[string]any{MemP95: 109e6}, false},
		{"over ten percent", map[string]any{MemP95: 100e6}, map[string]any{MemP95: 111e6}, true},
		{"below floor", map[string]any{MemP95: 1e6}, map[string]any{MemP95: 3e6}, false},
		{"cpu near zero", map[string]any{CPUP95: 0.001}, map[string]any{CPUP95: 0.005}, false},
		{"cpu real change", map[string]any{CPUP95: 0.1}, map[string]any{CPUP95: 0.2}, true},
		{"flag flip", map[string]any{MemSaturated: false}, map[string]any{MemSaturated: true}, true},
		{"field added", map[string]any{MemP95: 1.0}, map[string]any{MemP95: 1.0, MemLimit: 2.0}, true},
		{"field swapped", map[string]any{MemP95: 1.0}, map[string]any{MemLimit: 1.0}, true},
		{"type change", map[string]any{MemSaturated: false}, map[string]any{MemSaturated: 1.0}, true},
		{"int values", map[string]any{RestartsCount: 1}, map[string]any{RestartsCount: int64(3)}, true},
		{"restart below floor", map[string]any{RestartsCount: 0.0}, map[string]any{RestartsCount: 0.5}, false},
	}
	for _, c := range cases {
		if got := th.Changed(c.prev, c.cur); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	strict := Thresholds{Relative: 0.5}
	if strict.Changed(map[string]any{"x": 10.0}, map[string]any{"x": 14.0}) || !strict.Changed(map[string]any{"x": 10.0}, map[string]any{"x": 16.0}) {
		t.Fatal("configured relative threshold")
	}
}
