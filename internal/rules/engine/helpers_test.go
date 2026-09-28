package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func at(d time.Duration) time.Time { return t0.Add(d) }

type sinkRec struct {
	mu  sync.Mutex
	evs []AlertEvent
}

func (s *sinkRec) add(ev AlertEvent) {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
}

func (s *sinkRec) take() []AlertEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.evs
	s.evs = nil
	return out
}

func only(evs []AlertEvent, rule string) []AlertEvent {
	var out []AlertEvent
	for _, e := range evs {
		if e.RuleID == rule {
			out = append(out, e)
		}
	}
	return out
}

func transitions(evs []AlertEvent) []string {
	out := []string{}
	for _, e := range evs {
		out = append(out, e.Transition)
	}
	return out
}

type spec struct {
	lset   labels.Labels
	values []float64
}

func sp(values []float64, kv ...string) spec {
	return spec{lset: labels.FromStrings(kv...), values: values}
}

func repeat(v float64, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func cat(parts ...[]float64) []float64 {
	var out []float64
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// load writes each spec's values at t0 + i*step into source.
func load(m *MemSeries, source string, step time.Duration, specs ...spec) {
	var ss []Series
	for _, s := range specs {
		se := Series{Labels: s.lset}
		for i, v := range s.values {
			se.Samples = append(se.Samples, Sample{T: timestamp.FromTime(at(time.Duration(i) * step)), F: v})
		}
		ss = append(ss, se)
	}
	m.Replace(source, ss)
}

func meta(id, class, scope string) bundle.RuleMeta {
	return bundle.RuleMeta{ID: id, Version: 1, Class: class, Scope: scope, Severity: "warning", Category: "test"}
}

func promRule(id, expr string, forD, keep time.Duration) bundle.AlertRule {
	return bundle.AlertRule{
		Meta: meta(id, bundle.ClassPromQL, bundle.ScopeNode), Alert: id, Expr: expr,
		For: forD, KeepFiringFor: keep, GroupInterval: time.Minute,
	}
}

func clusterRule(id, expr string, forD time.Duration) bundle.AlertRule {
	r := promRule(id, expr, forD, 0)
	r.Meta.Scope = bundle.ScopeCluster
	return r
}

func stateRule(id, expr string, kinds ...string) bundle.StateRule {
	return bundle.StateRule{ID: id, Version: 1, Kinds: kinds, Expr: expr, Interval: time.Minute, Meta: meta(id, bundle.ClassState, bundle.ScopeCluster)}
}

func mkBundle(version string, state []bundle.StateRule, prom, logq []bundle.AlertRule) *bundle.Bundle {
	return &bundle.Bundle{Manifest: bundle.Manifest{Version: version, EngineVersion: bundle.EngineVersion}, State: state, PromQL: prom, LogQL: logq}
}

func newTestEngine(t *testing.T, opts Options, b *bundle.Bundle) (*Engine, *sinkRec) {
	t.Helper()
	s := &sinkRec{}
	if opts.Sink == nil {
		opts.Sink = s.add
	}
	if opts.Clock == nil {
		opts.Clock = func() time.Time { return t0 }
	}
	e, err := NewEngine(opts)
	if err != nil {
		t.Fatal(err)
	}
	if b != nil {
		if err := e.SetBundle(b, BundleResult{}); err != nil {
			t.Fatal(err)
		}
	}
	return e, s
}

func eval(t *testing.T, e *Engine, ts time.Time) {
	t.Helper()
	if err := e.Evaluate(context.Background(), ts); err != nil {
		t.Fatal(err)
	}
}

func stateOf(e *Engine, id string) RuleState {
	for _, s := range e.RuleStates() {
		if s.RuleID == id {
			return s
		}
	}
	return RuleState{}
}
