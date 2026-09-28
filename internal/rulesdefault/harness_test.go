package rulesdefault

import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

var t0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

const (
	step       = 10 * time.Second
	sampleStep = 30 * time.Second
	fixtureMiB = 1 << 20
	fixtureGiB = 1 << 30
)

// window is the bad phase of a fixture timeline; the zero window is never active.
type window struct{ start, end time.Duration }

func (w window) active(t time.Duration) bool { return w.end > w.start && t >= w.start && t < w.end }

func (w window) after(t time.Duration) bool { return w.end > w.start && t >= w.end }

func (w window) overlap(t time.Duration) time.Duration {
	if w.end <= w.start || t <= w.start {
		return 0
	}
	return min(t, w.end) - w.start
}

type timeline struct {
	w   window
	end time.Duration
}

type line struct {
	labels map[string]string
	text   string
}

// fixture makes one rule fire in its bad phase and resolve after it; the same fixture without a bad phase must never fire.
type fixture struct {
	id      string
	target  string
	bad     *protocol.State
	good    *protocol.State
	series  func(tl timeline) []engine.Series
	kube    []*corev1.Pod
	lines   func(t time.Duration, bad bool) []line
	warmup  time.Duration
	badFor  time.Duration
	recover time.Duration
	firing  int
	labels  map[string]string
}

type valueFn func(t time.Duration, w window) float64

func gauge(good, bad float64) valueFn {
	return func(t time.Duration, w window) float64 {
		if w.active(t) {
			return bad
		}
		return good
	}
}

// counter integrates a per-second rate that is badRate inside the window.
func counter(goodRate, badRate float64) valueFn {
	return func(t time.Duration, w window) float64 {
		return goodRate*t.Seconds() + (badRate-goodRate)*w.overlap(t).Seconds()
	}
}

func series(tl timeline, fn valueFn, kv ...string) engine.Series {
	return seriesOf(tl, fn, labels.FromStrings(kv...))
}

func seriesOf(tl timeline, fn valueFn, lset labels.Labels) engine.Series {
	s := engine.Series{Labels: lset}
	for d := time.Duration(0); d <= tl.end; d += sampleStep {
		s.Samples = append(s.Samples, engine.Sample{T: timestamp.FromTime(t0.Add(d)), F: fn(d, tl.w)})
	}
	return s
}

// kubeSeries synthesizes the node-scoped kube_* series of pods through the real normalizer and synthesis.
func kubeSeries(t *testing.T, tl timeline, node string, pods ...*corev1.Pod) []engine.Series {
	t.Helper()
	st := protocol.NewState()
	for _, p := range pods {
		m, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(p)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{Object: m}
		u.SetAPIVersion("v1")
		u.SetKind("Pod")
		res, _, err := state.Normalize(u)
		if err != nil {
			t.Fatal(err)
		}
		st.Resources[res.UID] = &res
	}
	var out []engine.Series
	for _, s := range state.NodeScoped(state.KubeSeries(st, 0), node) {
		v := s.Value
		out = append(out, seriesOf(tl, func(time.Duration, window) float64 { return v }, s.Labels))
	}
	if len(out) == 0 {
		t.Fatal("no kube series synthesized")
	}
	return out
}

func ruleTiming(t *testing.T, b *bundle.Bundle) (bundle.RuleMeta, time.Duration, time.Duration) {
	t.Helper()
	switch {
	case len(b.State) == 1:
		return b.State[0].Meta, b.State[0].For, b.State[0].KeepFiringFor
	case len(b.PromQL) == 1:
		return b.PromQL[0].Meta, b.PromQL[0].For, b.PromQL[0].KeepFiringFor
	case len(b.LogQL) == 1:
		return b.LogQL[0].Meta, b.LogQL[0].For, b.LogQL[0].KeepFiringFor
	}
	t.Fatalf("bundle holds %d state, %d promql, %d logql rules", len(b.State), len(b.PromQL), len(b.LogQL))
	return bundle.RuleMeta{}, 0, 0
}

type sink struct {
	mu  sync.Mutex
	evs []engine.AlertEvent
}

func (s *sink) add(ev engine.AlertEvent) {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
}

// drive runs the fixture through a real engine and returns the rule's alert events.
func drive(t *testing.T, f fixture, b *bundle.Bundle, meta bundle.RuleMeta, tl timeline) []engine.AlertEvent {
	t.Helper()
	now := t0
	clock := func() time.Time { return now }
	var prog *logql.Program
	mem := engine.NewMemSeries(tl.end+time.Hour, clock)
	cur := f.good
	sk := &sink{}
	opts := engine.Options{
		Clock:       clock,
		Sink:        sk.add,
		Queryable:   mem,
		KubeSubset:  state.PublishedSubset(),
		StateSource: func() *protocol.State { return cur },
		CompileLogQL: func(expr string, bg bundle.Budget) (engine.LogProgram, error) {
			p, err := logql.CompileRule(expr, bg)
			if err != nil {
				return nil, err
			}
			prog = p
			return p, nil
		},
	}
	switch {
	case f.target == bundle.TargetHost:
		opts.Role = engine.RoleHost
	case meta.Class == bundle.ClassState:
		opts.Role = engine.RoleCoordinator
	default:
		opts.Role = engine.RoleNode
	}
	e, err := engine.NewEngine(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetBundle(b, engine.BundleResult{}); err != nil {
		t.Fatal(err)
	}
	if f.series != nil {
		mem.Replace("fixture", f.series(tl))
	}
	if len(f.kube) > 0 {
		mem.Replace("kube", kubeSeries(t, tl, "node-a", f.kube...))
	}
	if f.lines != nil && prog == nil {
		t.Fatal("LogQL program was not compiled")
	}
	evaluated := false
	for d := time.Duration(0); d <= tl.end; d += step {
		now = t0.Add(d)
		if f.bad != nil && tl.w.active(d) {
			cur = f.bad
		} else {
			cur = f.good
		}
		if f.lines != nil && d > 0 {
			ls := f.lines(d, tl.w.active(d-step))
			for i, l := range ls {
				ts := now.Add(-step + step*time.Duration(i+1)/time.Duration(len(ls)+1))
				prog.Observe(l.labels, ts, l.text)
			}
		}
		if err := e.Evaluate(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		for _, s := range e.RuleStates() {
			if s.RuleID != f.id {
				continue
			}
			evaluated = evaluated || !s.LastEval.IsZero()
			switch s.State {
			case engine.StateFailed, engine.StateBudgetLimited, engine.StateUnsupported, engine.StateDisabled, engine.StateStale:
				t.Fatalf("rule %s is %s at %s: %s", f.id, s.State, d, s.Reason)
			}
		}
	}
	if !evaluated {
		t.Fatalf("rule %s was never evaluated", f.id)
	}
	sk.mu.Lock()
	defer sk.mu.Unlock()
	var out []engine.AlertEvent
	for _, ev := range sk.evs {
		if ev.RuleID == f.id {
			out = append(out, ev)
		}
	}
	return out
}

func TestFixtures(t *testing.T) {
	for _, f := range fixtures() {
		t.Run(f.id, func(t *testing.T) {
			t.Parallel()
			full, _ := loadBundle(t, f.target)
			b := full.Only([]string{f.id})
			meta, forD, keep := ruleTiming(t, b)
			if meta.Class == bundle.ClassState {
				if f.badFor == 0 {
					f.badFor = forD + 5*time.Minute
				}
				if f.recover == 0 {
					f.recover = keep + 10*time.Minute
				}
			}
			if f.recover == 0 {
				f.recover = keep + 20*time.Minute
			}
			want := max(f.firing, 1)
			tl := timeline{w: window{f.warmup, f.warmup + f.badFor}, end: f.warmup + f.badFor + f.recover}

			evs := drive(t, f, b, meta, tl)
			fired := map[string]engine.AlertEvent{}
			resolved := map[string]engine.AlertEvent{}
			for _, ev := range evs {
				switch ev.Transition {
				case engine.TransitionFiring:
					if _, ok := fired[ev.InstanceKey]; ok {
						t.Fatalf("instance %s fired twice", ev.InstanceKey)
					}
					fired[ev.InstanceKey] = ev
				case engine.TransitionResolved:
					if _, ok := fired[ev.InstanceKey]; ok {
						resolved[ev.InstanceKey] = ev
					}
				case engine.TransitionStale:
					t.Fatalf("instance %s went stale", ev.InstanceKey)
				}
			}
			if len(fired) != want {
				t.Fatalf("%d instances fired, want %d: %v", len(fired), want, evs)
			}
			earliest, latest := t0.Add(tl.w.start+forD), t0.Add(tl.w.end)
			labelled := len(f.labels) == 0
			for key, ev := range fired {
				if ev.EvalTime.Before(earliest) || ev.EvalTime.After(latest) {
					t.Fatalf("instance %s fired at %s, want within [%s, %s] (for %s)", key, ev.EvalTime, earliest, latest, forD)
				}
				r, ok := resolved[key]
				if !ok {
					t.Fatalf("instance %s never resolved", key)
				}
				if r.EvalTime.Before(t0.Add(tl.w.end + keep)) {
					t.Fatalf("instance %s resolved at %s, before recovery plus keep_firing_for %s", key, r.EvalTime, keep)
				}
				t.Logf("instance %s fired at +%s, resolved at +%s", key, ev.EvalTime.Sub(t0), r.EvalTime.Sub(t0))
				if ev.Severity != meta.Severity || ev.Category != meta.Category {
					t.Fatalf("event severity %q category %q, want %q %q", ev.Severity, ev.Category, meta.Severity, meta.Category)
				}
				sub := maps.Clone(ev.Labels)
				maps.DeleteFunc(sub, func(k, _ string) bool { _, ok := f.labels[k]; return !ok })
				labelled = labelled || maps.Equal(sub, f.labels)
			}
			if !labelled {
				var got []map[string]string
				for _, ev := range fired {
					got = append(got, ev.Labels)
				}
				t.Fatalf("no firing instance carries labels %v: %v", f.labels, got)
			}

			healthy := drive(t, f, b, meta, timeline{end: tl.end})
			if i := slices.IndexFunc(healthy, func(ev engine.AlertEvent) bool { return ev.Transition == engine.TransitionFiring }); i >= 0 {
				t.Fatalf("healthy fixture fired: %v", healthy[i])
			}
		})
	}
}

func TestNewReasonUpdatesWhenAReasonAppears(t *testing.T) {
	full, _ := loadBundle(t, k8s)
	b := full.Only([]string{"event.new_reason"})
	one := st(res("c1", "PersistentVolumeClaim", "shop", "data", map[string]any{"phase": "Pending", "events.warning.ProvisioningFailed": int64(1)}))
	two := st(res("c1", "PersistentVolumeClaim", "shop", "data", map[string]any{"phase": "Pending", "events.warning.ProvisioningFailed": int64(2), "events.warning.FailedBinding": int64(1)}))
	cur := one
	sk := &sink{}
	e, err := engine.NewEngine(engine.Options{Role: engine.RoleCoordinator, Clock: func() time.Time { return t0 }, Sink: sk.add, StateSource: func() *protocol.State { return cur }})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetBundle(b, engine.BundleResult{}); err != nil {
		t.Fatal(err)
	}
	for i, s := range []*protocol.State{one, one, two} {
		cur = s
		if err := e.Evaluate(context.Background(), t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, ev := range sk.evs {
		got = append(got, ev.Transition+":"+ev.Labels["reason_count"])
	}
	if !slices.Equal(got, []string{"firing:1", "update:2"}) {
		t.Fatalf("transitions %v, want a firing then an update carrying the new reason count", got)
	}
}
