package engine

import (
	"slices"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

type step struct {
	pending, firing int
	trans           []string
}

func runTimeline(t *testing.T, values []float64, expr string, forD, keep time.Duration, want []step) []AlertEvent {
	t.Helper()
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(values, "__name__", "http_requests", "job", "app-server", "instance", "0"))
	e, s := newTestEngine(t, Options{Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{promRule("r", expr, forD, keep)}, nil))
	var all []AlertEvent
	for i, w := range want {
		eval(t, e, at(time.Duration(i)*time.Minute))
		evs := s.take()
		all = append(all, evs...)
		st := stateOf(e, "r")
		if st.Pending != w.pending || st.Firing != w.firing || !slices.Equal(transitions(evs), append([]string{}, w.trans...)) {
			t.Fatalf("eval %d: pending=%d firing=%d transitions=%v, want %+v", i, st.Pending, st.Firing, transitions(evs), w)
		}
	}
	return all
}

func TestKeepFiringForMatchesPrometheus(t *testing.T) {
	values := cat([]float64{75, 85, 70, 70}, repeat(10, 6))
	evs := runTimeline(t, values, `http_requests > 50`, time.Minute, time.Minute, []step{
		{pending: 1},
		{firing: 1, trans: []string{TransitionFiring}},
		{firing: 1},
		{firing: 1},
		{firing: 1},
		{trans: []string{TransitionResolved}},
		{},
	})
	fired, resolved := evs[0], evs[1]
	if !fired.ActiveAt.Equal(at(0)) || !fired.FiredAt.Equal(at(time.Minute)) || fired.Value != 85 {
		t.Fatalf("firing event %+v", fired)
	}
	if !resolved.ResolvedAt.Equal(at(5*time.Minute)) || !resolved.FiredAt.Equal(at(time.Minute)) {
		t.Fatalf("resolved event %+v", resolved)
	}
	if fired.Labels["alertname"] != "r" || fired.Labels["job"] != "app-server" || fired.Labels["__name__"] != "" {
		t.Fatalf("labels %v", fired.Labels)
	}
}

func TestPendingIsNotKeptFiring(t *testing.T) {
	runTimeline(t, cat([]float64{75}, repeat(10, 5)), `http_requests > 50`, time.Minute, time.Minute, []step{
		{pending: 1},
		{},
		{},
	})
}

func TestZeroForFiresImmediatelyAndResolvesWithoutKeep(t *testing.T) {
	runTimeline(t, []float64{75, 75, 10, 75}, `http_requests > 50`, 0, 0, []step{
		{firing: 1, trans: []string{TransitionFiring}},
		{firing: 1},
		{trans: []string{TransitionResolved}},
		{firing: 1, trans: []string{TransitionFiring}},
	})
}

func TestKeepFiringRearmsWhenConditionReturns(t *testing.T) {
	runTimeline(t, []float64{75, 10, 75, 10, 10, 10}, `http_requests > 50`, 0, 2*time.Minute, []step{
		{firing: 1, trans: []string{TransitionFiring}},
		{firing: 1},
		{firing: 1},
		{firing: 1},
		{firing: 1},
		{trans: []string{TransitionResolved}},
	})
}

func TestForResetsWhenConditionBreaks(t *testing.T) {
	runTimeline(t, []float64{75, 75, 10, 75, 75, 75}, `http_requests > 50`, 2*time.Minute, 0, []step{
		{pending: 1},
		{pending: 1},
		{},
		{pending: 1},
		{pending: 1},
		{firing: 1, trans: []string{TransitionFiring}},
	})
}

func TestAlertSetDemotesWhenForGrows(t *testing.T) {
	a := newAlertSet()
	obs := evalInput{observed: []observation{{key: "k", labels: map[string]string{"a": "1"}, value: 1}}}
	if tr, _ := a.eval(at(0), 0, 0, obs); len(tr) != 1 || tr[0].kind != TransitionFiring {
		t.Fatalf("got %+v", tr)
	}
	tr, _ := a.eval(at(time.Minute), 5*time.Minute, 0, obs)
	if len(tr) != 1 || tr[0].kind != TransitionResolved || a.active["k"].Firing {
		t.Fatalf("got %+v", tr)
	}
	if tr, _ := a.eval(at(5*time.Minute), 5*time.Minute, 0, obs); len(tr) != 1 || tr[0].kind != TransitionFiring {
		t.Fatalf("got %+v", tr)
	}
}

func TestAlertSetIncompleteMarksStaleNeverResolves(t *testing.T) {
	a := newAlertSet()
	obs := func(sum string) evalInput {
		return evalInput{observed: []observation{{key: "k", summary: sum, value: 1}}}
	}
	a.eval(at(0), 0, 0, obs("s"))
	tr, _ := a.eval(at(time.Minute), 0, 0, evalInput{incompleteRest: true})
	if len(tr) != 1 || tr[0].kind != TransitionStale || !tr[0].incomplete {
		t.Fatalf("got %+v", tr)
	}
	if tr, _ := a.eval(at(2*time.Minute), 0, 0, evalInput{incomplete: map[string]bool{"k": true}}); len(tr) != 0 {
		t.Fatalf("second incomplete eval emitted %+v", tr)
	}
	tr, _ = a.eval(at(3*time.Minute), 0, 0, obs("s"))
	if len(tr) != 1 || tr[0].kind != TransitionUpdate || tr[0].incomplete {
		t.Fatalf("recovery from stale: %+v", tr)
	}
	tr, _ = a.eval(at(4*time.Minute), 0, 0, obs("changed"))
	if len(tr) != 1 || tr[0].kind != TransitionUpdate || tr[0].inst.Summary != "changed" {
		t.Fatalf("summary change: %+v", tr)
	}
	if tr, _ := a.eval(at(5*time.Minute), 0, 0, obs("changed")); len(tr) != 0 {
		t.Fatalf("unchanged emitted %+v", tr)
	}
	a.eval(at(6*time.Minute), 0, 0, evalInput{observed: []observation{{key: "p", value: 1}}})
	if _, ok := a.active["k"]; ok {
		t.Fatal("confirmed false did not resolve")
	}
	pend := newAlertSet()
	pend.eval(at(0), time.Hour, 0, obs("s"))
	if tr, _ := pend.eval(at(time.Minute), time.Hour, 0, evalInput{incompleteRest: true}); len(tr) != 0 || len(pend.active) != 1 {
		t.Fatalf("pending instance changed on incomplete: %+v", tr)
	}
}

func TestAlertSetRejectsDuplicateLabelSets(t *testing.T) {
	a := newAlertSet()
	_, err := a.eval(at(0), 0, 0, evalInput{observed: []observation{{key: "k"}, {key: "k"}}})
	if err == nil {
		t.Fatal("duplicate label sets accepted")
	}
}

func TestExpandTemplates(t *testing.T) {
	got := expand("{{ $labels.pod }} in {{$labels.namespace}} at {{ $value }} ({{ .Labels.pod }}, {{ .Value }}) {{ $labels.missing }}|{{ humanize $value }}",
		map[string]string{"pod": "p1", "namespace": "ns"}, 0.95)
	want := "p1 in ns at 0.95 (p1, 0.95) |{{ humanize $value }}"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
