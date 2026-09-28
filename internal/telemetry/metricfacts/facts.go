// Package metricfacts summarizes local series into per-resource facts and change thresholds.
package metricfacts

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
)

// Field names.
const (
	CPUP50           = "metric.cpu.p50_cores"
	CPUP95           = "metric.cpu.p95_cores"
	CPURequest       = "metric.cpu.request_cores"
	CPULimit         = "metric.cpu.limit_cores"
	CPULimitRatio    = "metric.cpu.limit_ratio_p95"
	CPUSaturated     = "metric.cpu.saturated"
	MemP50           = "metric.memory.p50_bytes"
	MemP95           = "metric.memory.p95_bytes"
	MemRequest       = "metric.memory.request_bytes"
	MemLimit         = "metric.memory.limit_bytes"
	MemLimitRatio    = "metric.memory.limit_ratio_p95"
	MemSaturated     = "metric.memory.saturated"
	RestartsCount    = "metric.restarts.count"
	RestartsPerHour  = "metric.restarts.per_hour"
	NodeMemPressure  = "metric.node.memory_pressure"
	NodeDiskPressure = "metric.node.disk_pressure"
	NodePIDPressure  = "metric.node.pid_pressure"
)

// SaturationRatio is the fraction of a limit at which usage p95 counts as saturated.
const SaturationRatio = 0.9

// Fact is one resource summary: a container (Namespace, Pod, Container set) or a node (only Node set).
type Fact struct {
	Namespace string
	Pod       string
	Container string
	Node      string
	Fields    map[string]any
	// UID is the pod the node agent observed under Namespace and Pod when it computed the fact.
	UID string `cbor:",omitempty"`
}

// Key identifies the resource.
func (f Fact) Key() string {
	if f.Pod == "" {
		return "node/" + f.Node
	}
	return "container/" + f.Namespace + "/" + f.Pod + "/" + f.Container
}

const containerSel = `{container!="",container!="POD"}`

func promDur(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) + "ms" }

type query struct {
	expr string
	set  func(c *Fact, v float64, lbl func(string) string)
}

// Compute evaluates the summaries over (now-interval, now].
func Compute(ctx context.Context, q storage.Queryable, engine *promql.Engine, now time.Time, interval time.Duration) ([]Fact, error) {
	if interval <= 0 {
		return nil, errors.New("metricfacts: interval must be positive")
	}
	step := min(30*time.Second, interval/4)
	rateWin := max(2*time.Minute, 4*step)
	iv, st := promDur(interval), promDur(step)
	by := "namespace, pod, container"
	cpu := fmt.Sprintf(`sum by (%s, node) (rate(container_cpu_usage_seconds_total%s[%s]))`, by, containerSel, promDur(rateWin))
	mem := fmt.Sprintf(`sum by (%s, node) (container_memory_working_set_bytes%s)`, by, containerSel)
	kube := func(metric, resource string) string {
		return fmt.Sprintf(`max by (%s) (last_over_time(%s{resource=%q}[%s]))`, by, metric, resource, iv)
	}
	num := func(k string) func(*Fact, float64, func(string) string) {
		return func(c *Fact, v float64, _ func(string) string) { c.Fields[k] = v }
	}
	withNode := func(k string) func(*Fact, float64, func(string) string) {
		return func(c *Fact, v float64, lbl func(string) string) {
			c.Fields[k] = v
			if n := lbl("node"); n != "" && c.Node == "" {
				c.Node = n
			}
		}
	}
	queries := []query{
		{fmt.Sprintf(`quantile_over_time(0.5, (%s)[%s:%s])`, cpu, iv, st), withNode(CPUP50)},
		{fmt.Sprintf(`quantile_over_time(0.95, (%s)[%s:%s])`, cpu, iv, st), withNode(CPUP95)},
		{fmt.Sprintf(`quantile_over_time(0.5, (%s)[%s:%s])`, mem, iv, st), withNode(MemP50)},
		{fmt.Sprintf(`quantile_over_time(0.95, (%s)[%s:%s])`, mem, iv, st), withNode(MemP95)},
		{kube("kube_pod_container_resource_requests", "cpu"), num(CPURequest)},
		{kube("kube_pod_container_resource_limits", "cpu"), num(CPULimit)},
		{kube("kube_pod_container_resource_requests", "memory"), num(MemRequest)},
		{kube("kube_pod_container_resource_limits", "memory"), num(MemLimit)},
		{fmt.Sprintf(`max by (%s) (max_over_time(kube_pod_container_status_restarts_total[%s]) - min_over_time(kube_pod_container_status_restarts_total[%s]))`, by, iv, iv), num(RestartsCount)},
	}
	facts := map[string]*Fact{}
	for _, qu := range queries {
		vec, err := instant(ctx, engine, q, qu.expr, now)
		if err != nil {
			return nil, err
		}
		for _, s := range vec {
			if math.IsNaN(s.F) || math.IsInf(s.F, 0) || s.H != nil {
				continue
			}
			f := Fact{Namespace: s.Metric.Get("namespace"), Pod: s.Metric.Get("pod"), Container: s.Metric.Get("container")}
			if f.Pod == "" || f.Container == "" {
				continue
			}
			c := facts[f.Key()]
			if c == nil {
				f.Fields = map[string]any{}
				c = &f
				facts[f.Key()] = c
			}
			qu.set(c, s.F, s.Metric.Get)
		}
	}
	podNodes, err := instant(ctx, engine, q, fmt.Sprintf(`max by (namespace, pod, node) (last_over_time(kube_pod_info[%s]))`, iv), now)
	if err != nil {
		return nil, err
	}
	nodeOf := map[string]string{}
	for _, s := range podNodes {
		nodeOf[s.Metric.Get("namespace")+"/"+s.Metric.Get("pod")] = s.Metric.Get("node")
	}
	out := make([]Fact, 0, len(facts))
	for _, c := range facts {
		if c.Node == "" {
			c.Node = nodeOf[c.Namespace+"/"+c.Pod]
		}
		derive(c, interval)
		out = append(out, *c)
	}
	nodes, err := nodeFacts(ctx, q, engine, now, iv)
	if err != nil {
		return nil, err
	}
	out = append(out, nodes...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

func derive(c *Fact, interval time.Duration) {
	f := c.Fields
	for _, k := range []string{CPUP50, CPUP95, CPURequest, CPULimit} {
		if v, ok := f[k].(float64); ok {
			f[k] = round(v, 4)
		}
	}
	for _, k := range []string{MemP50, MemP95, MemRequest, MemLimit, RestartsCount} {
		if v, ok := f[k].(float64); ok {
			f[k] = math.Round(v)
		}
	}
	if n, ok := f[RestartsCount].(float64); ok {
		f[RestartsPerHour] = round(n/interval.Hours(), 4)
	}
	ratio := func(p95Key, limitKey, ratioKey, satKey string) {
		p, ok1 := f[p95Key].(float64)
		l, ok2 := f[limitKey].(float64)
		if !ok1 || !ok2 || l <= 0 {
			return
		}
		f[ratioKey] = round(p/l, 4)
		f[satKey] = p > SaturationRatio*l
	}
	ratio(MemP95, MemLimit, MemLimitRatio, MemSaturated)
	ratio(CPUP95, CPULimit, CPULimitRatio, CPUSaturated)
}

func round(v float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.Round(v*p) / p
}

func nodeFacts(ctx context.Context, q storage.Queryable, engine *promql.Engine, now time.Time, iv string) ([]Fact, error) {
	vec, err := instant(ctx, engine, q, fmt.Sprintf(`max by (node, condition) (last_over_time(kube_node_status_condition{condition=~"MemoryPressure|DiskPressure|PIDPressure",status="true"}[%s]))`, iv), now)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{"MemoryPressure": NodeMemPressure, "DiskPressure": NodeDiskPressure, "PIDPressure": NodePIDPressure}
	byNode := map[string]*Fact{}
	for _, s := range vec {
		n := s.Metric.Get("node")
		if n == "" {
			continue
		}
		f := byNode[n]
		if f == nil {
			f = &Fact{Node: n, Fields: map[string]any{}}
			byNode[n] = f
		}
		f.Fields[fields[s.Metric.Get("condition")]] = s.F == 1
	}
	out := make([]Fact, 0, len(byNode))
	for _, f := range byNode {
		out = append(out, *f)
	}
	return out, nil
}

func instant(ctx context.Context, engine *promql.Engine, q storage.Queryable, expr string, now time.Time) (promql.Vector, error) {
	qry, err := engine.NewInstantQuery(ctx, q, nil, expr, now)
	if err != nil {
		return nil, err
	}
	defer qry.Close()
	res := qry.Exec(ctx)
	if res.Err != nil {
		return nil, res.Err
	}
	return res.Vector()
}

// Thresholds decide whether a summary changed enough to emit a delta.
type Thresholds struct {
	// Relative is the minimum relative change of a numeric field, exclusive.
	Relative float64
	// Floors are minimum absolute changes by field-name suffix, so values near zero do not flap.
	Floors map[string]float64
}

// DefaultThresholds returns a 10 percent relative threshold with unit floors.
func DefaultThresholds() Thresholds {
	return Thresholds{Relative: 0.10, Floors: map[string]float64{
		"_cores":     0.01,
		"_bytes":     4 << 20,
		"_ratio_p95": 0.02,
		".count":     1,
		".per_hour":  0.5,
	}}
}

func (t Thresholds) floor(key string) float64 {
	best, fl := -1, 0.0
	for suf, v := range t.Floors {
		if strings.HasSuffix(key, suf) && len(suf) > best {
			best, fl = len(suf), v
		}
	}
	return fl
}

// Changed reports a field set change, a non-numeric flip, or a numeric move above both bounds.
func (t Thresholds) Changed(prev, cur map[string]any) bool {
	if prev == nil {
		return cur != nil
	}
	if len(prev) != len(cur) {
		return true
	}
	for k, nv := range cur {
		ov, ok := prev[k]
		if !ok {
			return true
		}
		of, ook := toFloat(ov)
		nf, nok := toFloat(nv)
		if ook != nok {
			return true
		}
		if !ook {
			if ov != nv {
				return true
			}
			continue
		}
		d := math.Abs(nf - of)
		if d > t.Relative*math.Abs(of) && d >= t.floor(k) && d > 0 {
			return true
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	}
	return 0, false
}
