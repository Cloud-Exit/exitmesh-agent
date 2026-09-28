package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// hookQueryable runs hook on every querier creation.
type hookQueryable struct {
	storage.Queryable
	hook func()
}

func (h hookQueryable) Querier(mint, maxt int64) (storage.Querier, error) {
	h.hook()
	return h.Queryable.Querier(mint, maxt)
}

func TestBundleSwitchesOnlyBetweenCycles(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	v1 := mkBundle("v1", nil, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0), promRule("b", `x > 0`, 0, 0)}, nil)
	v2 := mkBundle("v2", nil, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0), promRule("b", `x > 0`, 0, 0), promRule("c", `x > 0`, 0, 0)}, nil)
	var once sync.Once
	var e *Engine
	var setErr error
	q := hookQueryable{Queryable: m, hook: func() { once.Do(func() { setErr = e.SetBundle(v2, BundleResult{}) }) }}
	e, s := newTestEngine(t, Options{Queryable: q}, v1)
	if e.BundleVersion() != "" {
		t.Fatal("bundle active before the first cycle")
	}
	eval(t, e, at(0))
	if setErr != nil {
		t.Fatal(setErr)
	}
	evs := s.take()
	if len(evs) != 2 || evs[0].BundleVersion != "v1" || evs[1].BundleVersion != "v1" || e.BundleVersion() != "v1" {
		t.Fatalf("mid-cycle switch: %+v", evs)
	}
	if len(e.RuleStates()) != 2 {
		t.Fatalf("states %+v", e.RuleStates())
	}
	eval(t, e, at(time.Minute))
	evs = s.take()
	if len(evs) != 1 || evs[0].RuleID != "c" || evs[0].BundleVersion != "v2" || e.BundleVersion() != "v2" {
		t.Fatalf("after switch: %+v", evs)
	}
	eval(t, e, at(2*time.Minute))
	if len(s.take()) != 0 || len(e.RuleStates()) != 3 {
		t.Fatal("unexpected events after switch")
	}
}

func TestInvalidBundleKeepsActiveBundle(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	e, s := newTestEngine(t, Options{Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0)}, nil))
	eval(t, e, at(0))
	s.take()
	bad := []*bundle.Bundle{
		mkBundle("v2", nil, []bundle.AlertRule{promRule("a", `x >`, 0, 0)}, nil),
		mkBundle("v2", []bundle.StateRule{stateRule("s", `r.`, "Pod")}, nil, nil),
		mkBundle("v2", nil, []bundle.AlertRule{promRule("a", `x`, 0, 0), promRule("a", `x`, 0, 0)}, nil),
		mkBundle("v2", nil, []bundle.AlertRule{promRule("", `x`, 0, 0)}, nil),
		nil,
	}
	for i, b := range bad {
		if err := e.SetBundle(b, BundleResult{}); err == nil {
			t.Fatalf("bundle %d accepted", i)
		}
	}
	eval(t, e, at(time.Minute))
	if e.BundleVersion() != "v1" || stateOf(e, "a").State != StateActive {
		t.Fatalf("active bundle changed: %s %+v", e.BundleVersion(), e.RuleStates())
	}
}

func TestPolicyDisabledUnsupportedAndCapabilities(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	dis := promRule("dis", `x > 0`, 0, 0)
	metaDis := promRule("meta-dis", `x > 0`, 0, 0)
	metaDis.Meta.Disabled = true
	newer := promRule("newer", `x >`, 0, 0)
	newer.Meta.MinEngine = bundle.EngineVersion + 1
	flagged := promRule("flagged", `x > 0`, 0, 0)
	logs := promRule("logs", `x > 0`, 0, 0)
	logs.Meta.Capabilities = []string{bundle.CapLogs}
	state := stateRule("inv", `true`, "Pod")
	b := mkBundle("v1", []bundle.StateRule{state}, []bundle.AlertRule{dis, metaDis, newer, flagged, logs}, []bundle.AlertRule{{Meta: meta("lq", bundle.ClassLogQL, bundle.ScopeNode), Alert: "lq", Expr: `x`}})
	s := &sinkRec{}
	e, err := NewEngine(Options{Queryable: m, Sink: s.add, Clock: func() time.Time { return t0 },
		Policy: Policy{DisabledRules: []string{"dis"}, Capabilities: []string{bundle.CapMetrics}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetBundle(b, BundleResult{Unsupported: map[string]string{"flagged": "uses a construct this agent lacks"}}); err != nil {
		t.Fatal(err)
	}
	eval(t, e, at(0))
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("inactive rules evaluated: %+v", evs)
	}
	want := map[string][2]string{
		"dis":      {StateDisabled, ""},
		"meta-dis": {StateDisabled, ""},
		"newer":    {StateUnsupported, "requires engine version 2"},
		"flagged":  {StateUnsupported, "construct this agent lacks"},
		"logs":     {StateUnsupported, "capability logs is unavailable"},
		"inv":      {StateUnsupported, "capability inventory is unavailable"},
		"lq":       {StateUnsupported, "capability logs is unavailable"},
	}
	states := e.RuleStates()
	if len(states) != len(want) {
		t.Fatalf("states %+v", states)
	}
	for _, st := range states {
		w := want[st.RuleID]
		if st.State != w[0] || !strings.Contains(st.Reason, w[1]) || !st.LastEval.IsZero() {
			t.Fatalf("%s: %+v", st.RuleID, st)
		}
	}
	if !slices.IsSortedFunc(states, func(a, b RuleState) int { return strings.Compare(a.RuleID, b.RuleID) }) {
		t.Fatal("states not sorted")
	}
}

func TestDisablingFiringRuleMarksStale(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	store := kv.NewMemory()
	e, s := newTestEngine(t, Options{Queryable: m, Store: store}, mkBundle("v1", nil, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0), promRule("b", `x > 0`, 0, 0)}, nil))
	eval(t, e, at(0))
	s.take()
	off := promRule("a", `x > 0`, 0, 0)
	off.Meta.Disabled = true
	if err := e.SetBundle(mkBundle("v2", nil, []bundle.AlertRule{off}, nil), BundleResult{}); err != nil {
		t.Fatal(err)
	}
	eval(t, e, at(time.Minute))
	evs := s.take()
	if got := transitions(evs); !slices.Equal(got, []string{TransitionStale, TransitionStale}) || evs[0].RuleID != "a" || evs[1].RuleID != "b" || evs[0].BundleVersion != "v1" {
		t.Fatalf("got %+v", evs)
	}
	if _, ok, _ := store.Get(alertKeyPrefix + "a"); ok {
		t.Fatal("disabled rule state kept")
	}
	if _, ok, _ := store.Get(alertKeyPrefix + "b"); ok {
		t.Fatal("removed rule state kept")
	}
}

func TestRuleVersionChangeCarriesState(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	e, s := newTestEngine(t, Options{Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0)}, nil))
	eval(t, e, at(0))
	s.take()
	v2 := promRule("a", `x >= 1`, 0, 0)
	v2.Meta.Version = 2
	if err := e.SetBundle(mkBundle("v2", nil, []bundle.AlertRule{v2}, nil), BundleResult{}); err != nil {
		t.Fatal(err)
	}
	eval(t, e, at(time.Minute))
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("version bump flapped: %+v", evs)
	}
	if st := stateOf(e, "a"); st.Version != 2 || st.Firing != 1 {
		t.Fatalf("state %+v", st)
	}
	cls := mkBundle("v3", []bundle.StateRule{stateRule("a", `true`, "Pod")}, nil, nil)
	if err := e.SetBundle(cls, BundleResult{}); err != nil {
		t.Fatal(err)
	}
	eval(t, e, at(2*time.Minute))
	evs := s.take()
	if len(evs) != 1 || evs[0].Transition != TransitionStale || evs[0].Class != bundle.ClassPromQL || evs[0].RuleVersion != 2 {
		t.Fatalf("class change: %+v", evs)
	}
}

func TestPersistenceResumesForStateAndWarmingUp(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(cat(repeat(1, 20), repeat(0, 10)), "__name__", "x"))
	store := kv.NewMemory()
	rule := promRule("slow-burn", `x > 0`, 10*time.Minute, 0)
	b := mkBundle("v1", nil, []bundle.AlertRule{rule}, nil)
	e1, _ := newTestEngine(t, Options{Queryable: m, Store: store}, b)
	for i := 0; i <= 5; i++ {
		eval(t, e1, at(time.Duration(i)*time.Minute))
	}
	if st := stateOf(e1, "slow-burn"); st.State != StateWarmingUp || st.Pending != 1 {
		t.Fatalf("before restart %+v", st)
	}

	e2, s2 := newTestEngine(t, Options{Queryable: m, Store: store, Clock: func() time.Time { return at(6 * time.Minute) }}, b)
	eval(t, e2, at(6*time.Minute))
	if st := stateOf(e2, "slow-burn"); st.State != StateActive || st.Pending != 1 {
		t.Fatalf("resumed state %+v", st)
	}
	var fired []AlertEvent
	for i := 7; i <= 12; i++ {
		eval(t, e2, at(time.Duration(i)*time.Minute))
		fired = append(fired, s2.take()...)
	}
	if len(fired) != 1 || fired[0].Transition != TransitionFiring || !fired[0].FiredAt.Equal(at(11*time.Minute)) || !fired[0].ActiveAt.Equal(at(time.Minute)) {
		t.Fatalf("resumed for: %+v", fired)
	}

	e3, s3 := newTestEngine(t, Options{Queryable: m, Store: store, Clock: func() time.Time { return at(20 * time.Minute) }}, b)
	eval(t, e3, at(20*time.Minute))
	if evs := s3.take(); len(evs) != 1 || evs[0].Transition != TransitionResolved || !evs[0].FiredAt.Equal(at(11*time.Minute)) {
		t.Fatalf("firing state not resumed: %+v", evs)
	}

	fresh, _ := newTestEngine(t, Options{Queryable: m, Store: kv.NewMemory()}, b)
	eval(t, fresh, at(0))
	if st := stateOf(fresh, "slow-burn"); st.State != StateWarmingUp || !strings.Contains(st.Reason, "10m0s") {
		t.Fatalf("fresh %+v", st)
	}
	eval(t, fresh, at(10*time.Minute))
	if st := stateOf(fresh, "slow-burn"); st.State != StateActive {
		t.Fatalf("fresh after for %+v", st)
	}
}

func TestPersistenceOutageBeyondTolerance(t *testing.T) {
	m := NewMemSeries(3*time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 180), "__name__", "x"), sp(repeat(1, 180), "__name__", "y"))
	store := kv.NewMemory()
	b := mkBundle("v1", nil, []bundle.AlertRule{promRule("p", `x > 0`, 30*time.Minute, 0), promRule("f", `y > 0`, 0, 0)}, nil)
	e1, _ := newTestEngine(t, Options{Queryable: m, Store: store}, b)
	eval(t, e1, at(0))
	e2, s2 := newTestEngine(t, Options{Queryable: m, Store: store, Clock: func() time.Time { return at(2 * time.Hour) }}, b)
	eval(t, e2, at(2*time.Hour))
	if st := stateOf(e2, "p"); st.State != StateWarmingUp || st.Pending != 1 {
		t.Fatalf("pending after long outage %+v", st)
	}
	if st := stateOf(e2, "f"); st.Firing != 1 {
		t.Fatalf("firing lost %+v", st)
	}
	if evs := s2.take(); len(evs) != 0 {
		t.Fatalf("restored firing re-announced: %+v", evs)
	}
}

func TestRestoredRulesAbsentFromBundleGoStale(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	store := kv.NewMemory()
	e1, _ := newTestEngine(t, Options{Queryable: m, Store: store}, mkBundle("v1", nil, []bundle.AlertRule{promRule("gone", `x > 0`, 0, 0), promRule("moved", `x > 0`, 0, 0)}, nil))
	eval(t, e1, at(0))
	e2, s2 := newTestEngine(t, Options{Queryable: m, Store: store}, mkBundle("v2", []bundle.StateRule{stateRule("moved", `false`, "Pod")}, nil, nil))
	eval(t, e2, at(time.Minute))
	evs := s2.take()
	if len(evs) != 2 || evs[0].RuleID != "moved" || evs[1].RuleID != "gone" || evs[0].Transition != TransitionStale || evs[1].BundleVersion != "v1" {
		t.Fatalf("got %+v", evs)
	}
	if _, ok, _ := store.Get(alertKeyPrefix + "gone"); ok {
		t.Fatal("orphaned state kept")
	}
	if err := store.Put(alertKeyPrefix+"bad", []byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(Options{Store: store}); err == nil {
		t.Fatal("corrupt alert state accepted")
	}
	if _, err := NewEngine(Options{Role: "gateway"}); err == nil {
		t.Fatal("unknown role accepted")
	}
}

type fakeLog struct {
	mu  sync.Mutex
	vec promql.Vector
	err error
}

func (f *fakeLog) Eval(time.Time) (promql.Vector, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vec, f.err
}

func (f *fakeLog) set(v promql.Vector, err error) {
	f.mu.Lock()
	f.vec, f.err = v, err
	f.mu.Unlock()
}

func TestLogQLRules(t *testing.T) {
	progs := map[string]*fakeLog{}
	var budgets []bundle.Budget
	compile := func(expr string, b bundle.Budget) (LogProgram, error) {
		if strings.Contains(expr, "invalid") {
			return nil, errors.New("unsupported stage")
		}
		budgets = append(budgets, b)
		p := &fakeLog{}
		progs[expr] = p
		return p, nil
	}
	errs := logRule("errs", `sum by (pod) (count_over_time({app="web"} |= "absent_over_time(" [5m])) > 5`, time.Minute)
	errs.Meta.Budget.CounterBytes = 1 << 20
	gone := logRule("gone", `absent_over_time({app="web"}[10m])`, 0)
	var mu sync.Mutex
	cov := CoverageCovered
	e, s := newTestEngine(t, Options{Role: RoleNode, CompileLogQL: compile, Policy: Policy{MaxCounterBytes: 1 << 16},
		Coverage: func() Coverage { mu.Lock(); defer mu.Unlock(); return cov }}, mkBundle("v1", nil, nil, []bundle.AlertRule{errs, gone}))
	if len(budgets) != 2 || budgets[0].CounterBytes != 1<<16 || budgets[1].CounterBytes != 1<<16 {
		t.Fatalf("budgets %+v", budgets)
	}
	pe, pg := progs[errs.Expr], progs[gone.Expr]
	pe.set(promql.Vector{{Metric: labels.FromStrings("pod", "web-1"), F: 12}}, nil)
	pg.set(promql.Vector{{Metric: labels.EmptyLabels(), F: 1}}, nil)
	eval(t, e, at(0))
	evs := s.take()
	if len(evs) != 1 || evs[0].RuleID != "gone" || evs[0].Class != bundle.ClassLogQL {
		t.Fatalf("got %+v", evs)
	}
	eval(t, e, at(time.Minute))
	evs = s.take()
	if len(evs) != 1 || evs[0].RuleID != "errs" || evs[0].Labels["pod"] != "web-1" || evs[0].Value != 12 || evs[0].Labels["alertname"] != "errs" {
		t.Fatalf("got %+v", evs)
	}
	mu.Lock()
	cov = CoverageWarming
	mu.Unlock()
	pe.set(nil, nil)
	eval(t, e, at(2*time.Minute))
	if got := transitions(s.take()); !slices.Equal(got, []string{TransitionStale, TransitionStale}) {
		t.Fatalf("warming node: %v", got)
	}
	mu.Lock()
	cov = CoverageCovered
	mu.Unlock()
	pe.set(nil, errors.New("counter overflow"))
	eval(t, e, at(3*time.Minute))
	if st := stateOf(e, "errs"); st.State != StateFailed || st.Reason != "counter overflow" {
		t.Fatalf("errs %+v", st)
	}
	if _, err := NewEngine(Options{}); err != nil {
		t.Fatal(err)
	}
	bad, _ := newTestEngine(t, Options{CompileLogQL: compile}, nil)
	if err := bad.SetBundle(mkBundle("v2", nil, nil, []bundle.AlertRule{logRule("x", `invalid`, 0)}), BundleResult{}); err == nil || !strings.Contains(err.Error(), "unsupported stage") {
		t.Fatalf("got %v", err)
	}
	noc, _ := newTestEngine(t, Options{}, mkBundle("v1", nil, nil, []bundle.AlertRule{logRule("x", `{a="b"}`, 0)}))
	cl := logRule("cl", `sum(count_over_time({a="b"}[5m]))`, 0)
	cl.Meta.Scope = bundle.ScopeCluster
	cle, _ := newTestEngine(t, Options{CompileLogQL: compile}, mkBundle("v1", nil, nil, []bundle.AlertRule{cl}))
	coord, _ := newTestEngine(t, Options{Role: RoleCoordinator}, mkBundle("v1", nil, nil, []bundle.AlertRule{logRule("x", `{a="b"}`, 0)}))
	eval(t, noc, at(0))
	eval(t, cle, at(0))
	eval(t, coord, at(0))
	if st := stateOf(noc, "x"); st.State != StateUnsupported || !strings.Contains(st.Reason, "no LogQL compiler") {
		t.Fatalf("no compiler %+v", st)
	}
	if st := stateOf(cle, "cl"); st.State != StateUnsupported || !strings.Contains(st.Reason, "cluster-scoped LogQL") {
		t.Fatalf("cluster %+v", st)
	}
	if len(coord.RuleStates()) != 0 {
		t.Fatalf("coordinator evaluates LogQL: %+v", coord.RuleStates())
	}
}

func logRule(id, expr string, forD time.Duration) bundle.AlertRule {
	r := promRule(id, expr, forD, 0)
	r.Meta.Class = bundle.ClassLogQL
	return r
}

func TestLogQLEvalTimeBudget(t *testing.T) {
	slow := LogProgramFunc(func(time.Time) (promql.Vector, error) {
		time.Sleep(20 * time.Millisecond)
		return nil, nil
	})
	r := logRule("slow", `{a="b"}`, 0)
	r.Meta.Budget.MaxEvalTime = time.Millisecond
	e, _ := newTestEngine(t, Options{CompileLogQL: func(string, bundle.Budget) (LogProgram, error) { return slow, nil }}, mkBundle("v1", nil, nil, []bundle.AlertRule{r}))
	eval(t, e, at(0))
	if st := stateOf(e, "slow"); st.State != StateBudgetLimited || !strings.Contains(st.Reason, "max_eval_time") {
		t.Fatalf("got %+v", st)
	}
}

func TestLogUsesAbsent(t *testing.T) {
	for expr, want := range map[string]bool{
		`absent_over_time({a="b"}[5m])`:                            true,
		`count_over_time({a="b"} |= "absent_over_time(" [5m])`:     false,
		"count_over_time({a=\"b\"} |= `absent_over_time(` [5m])":   false,
		`sum(rate({a="b"}[1m])) or absent_over_time ({a="b"}[1m])`: true,
	} {
		if got := logUsesAbsent(expr); got != want {
			t.Fatalf("%s: %v", expr, got)
		}
	}
}

func TestEvidenceLimitedAndCancelledCycle(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	e, _ := newTestEngine(t, Options{Queryable: m, EvidenceLimited: func(id string) bool { return id == "ev" }},
		mkBundle("v1", nil, []bundle.AlertRule{promRule("ev", `x > 0`, 0, 0), promRule("other", `x > 0`, 0, 0)}, nil))
	eval(t, e, at(0))
	if st := stateOf(e, "ev"); st.State != StateEvidenceLimited {
		t.Fatalf("ev %+v", st)
	}
	if st := stateOf(e, "other"); st.State != StateActive {
		t.Fatalf("other %+v", st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Evaluate(ctx, at(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if st := stateOf(e, "ev"); !st.LastEval.Equal(at(0)) {
		t.Fatalf("cancelled cycle evaluated: %+v", st)
	}
}

type failingStore struct{ kv.Store }

func (failingStore) Batch(map[string][]byte) error { return errors.New("disk full") }

func TestPersistFailureIsReportedAfterEmitting(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 5), "__name__", "x"))
	e, s := newTestEngine(t, Options{Queryable: m, Store: failingStore{kv.NewMemory()}}, mkBundle("v1", nil, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0)}, nil))
	if err := e.Evaluate(context.Background(), at(0)); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("got %v", err)
	}
	if len(s.take()) != 1 {
		t.Fatal("events dropped on persist failure")
	}
}

func TestConcurrentSetBundleAndReads(t *testing.T) {
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	load(m, "tsdb", time.Minute, sp(repeat(1, 40), "__name__", "x"))
	st := clusterState()
	dup := stateRule("dup-kinds", `r.name == "cart-a"`, "Pod", "Pod")
	e, s := newTestEngine(t, Options{Queryable: m, StateSource: func() *protocol.State { return st }},
		mkBundle("v0", []bundle.StateRule{dup}, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0)}, nil))
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			v := "v" + strings.Repeat("x", i%3)
			if err := e.SetBundle(mkBundle(v, []bundle.StateRule{dup}, []bundle.AlertRule{promRule("a", `x > 0`, 0, 0)}, nil), BundleResult{}); err != nil {
				t.Error(err)
				return
			}
			_ = e.RuleStates()
			_ = e.BundleVersion()
		}
	}()
	for i := range 30 {
		eval(t, e, at(time.Duration(i)*time.Minute))
	}
	close(done)
	wg.Wait()
	fired := firingKeys(s.take())
	if !slices.Equal(fired["a"], []string{`{alertname="a"}`}) || !slices.Equal(fired["dup-kinds"], []string{"pod-a"}) {
		t.Fatalf("fired %v", fired)
	}
}
