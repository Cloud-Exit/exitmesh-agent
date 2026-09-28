package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/common/types"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/value"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Options configures an Engine. Only Store, Clock, and Sink are needed by every role.
type Options struct {
	// Role is RoleNode, RoleCoordinator, or RoleHost (the default, which evaluates everything locally).
	Role  string
	Store kv.Store
	Clock func() time.Time
	Sink  func(AlertEvent)
	// Push receives node contributions to cluster rules (node role).
	Push       func(Part)
	KubeSubset map[string]bool
	// CompileLogQL compiles LogQL rule expressions; it may register the program with the log tailer.
	CompileLogQL func(expr string, b bundle.Budget) (LogProgram, error)
	Queryable    storage.Queryable
	// StateSource returns a state snapshot that is not mutated while the cycle runs.
	StateSource func() *protocol.State
	// ScopeMatch reports whether a state scope key covers resources of kind in namespace.
	ScopeMatch      func(scopeKey, kind, namespace string) bool
	ResolveResource func(kind, namespace, name string) (uid string, ok bool)
	// Coverage reports local telemetry coverage for node-local rules.
	Coverage func() Coverage
	// ClusterCoverage reports whether every node contributes to a cluster rule on a compatible version.
	ClusterCoverage func(ruleID string, ruleVersion int) Coverage
	EvidenceLimited func(ruleID string) bool
	Policy          Policy
	DefaultInterval time.Duration
	BudgetBackoff   time.Duration
	// OutageTolerance bounds the downtime after which persisted pending state is not resumed.
	OutageTolerance time.Duration
	LookbackDelta   time.Duration
}

// Engine evaluates the rules of the active bundle in cycles.
type Engine struct {
	opts  Options
	start time.Time

	stageMu sync.Mutex
	staged  *compiledBundle

	mu        sync.Mutex
	cur       *compiledBundle
	rt        map[string]*ruleRuntime
	restored  map[string]*persistedRule
	activated bool
	engines   map[engineKey]*promql.Engine

	viewMu  sync.RWMutex
	version string
	states  []RuleState
}

type ruleRuntime struct {
	info        ruleInfo
	alerts      *alertSet
	loadedAt    time.Time
	resumed     bool
	lastEval    time.Time
	lastDur     time.Duration
	lastErr     string
	budgetErr   string
	backoff     time.Time
	stale       string
	coverage    Coverage
	evaluations int
}

type persistedRule struct {
	ruleInfo
	LastEval  time.Time   `json:"last_eval"`
	Instances []*instance `json:"instances"`
}

type engineKey struct {
	samples int
	timeout time.Duration
}

const alertKeyPrefix = "alerts/"

// NewEngine returns an engine and loads persisted alert state from opts.Store.
func NewEngine(opts Options) (*Engine, error) {
	if opts.Store == nil {
		opts.Store = kv.NewMemory()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	switch opts.Role {
	case "":
		opts.Role = RoleHost
	case RoleNode, RoleCoordinator, RoleHost:
	default:
		return nil, fmt.Errorf("engine: unknown role %q", opts.Role)
	}
	if opts.DefaultInterval <= 0 {
		opts.DefaultInterval = time.Minute
	}
	if opts.BudgetBackoff <= 0 {
		opts.BudgetBackoff = 5 * time.Minute
	}
	if opts.OutageTolerance <= 0 {
		opts.OutageTolerance = time.Hour
	}
	if opts.LookbackDelta <= 0 {
		opts.LookbackDelta = 5 * time.Minute
	}
	e := &Engine{
		opts:     opts,
		start:    opts.Clock(),
		rt:       map[string]*ruleRuntime{},
		restored: map[string]*persistedRule{},
		engines:  map[engineKey]*promql.Engine{},
	}
	err := opts.Store.ForEach(alertKeyPrefix, func(k string, v []byte) error {
		var p persistedRule
		if err := json.Unmarshal(v, &p); err != nil {
			return fmt.Errorf("engine: alert state %s: %w", k, err)
		}
		e.restored[strings.TrimPrefix(k, alertKeyPrefix)] = &p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

// SetBundle compiles and stages b for the next cycle; an invalid bundle changes nothing.
func (e *Engine) SetBundle(b *bundle.Bundle, res BundleResult) error {
	if b == nil {
		return errors.New("engine: nil bundle")
	}
	cb, err := e.compile(b, res)
	if err != nil {
		return err
	}
	e.stageMu.Lock()
	e.staged = cb
	e.stageMu.Unlock()
	return nil
}

// BundleVersion returns the version of the active bundle.
func (e *Engine) BundleVersion() string {
	e.viewMu.RLock()
	defer e.viewMu.RUnlock()
	return e.version
}

// RuleStates returns the per-rule states as of the last cycle, ordered by rule ID.
func (e *Engine) RuleStates() []RuleState {
	e.viewMu.RLock()
	defer e.viewMu.RUnlock()
	return slices.Clone(e.states)
}

// Evaluate runs one cycle at now over every rule whose interval is due.
func (e *Engine) Evaluate(ctx context.Context, now time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	writes := map[string][]byte{}
	events := e.activate(now, writes)
	var cycleErr error
	if e.cur != nil {
		var sc *stateCycle
		for _, cr := range e.cur.rules {
			if !cr.evaluated() {
				continue
			}
			rt := e.rt[cr.ID]
			if now.Before(rt.backoff) || (!rt.lastEval.IsZero() && now.Sub(rt.lastEval) < e.interval(cr)) {
				continue
			}
			if err := ctx.Err(); err != nil {
				cycleErr = errors.Join(cycleErr, err)
				break
			}
			evs, err := e.evalRule(ctx, cr, rt, now, &sc)
			if err != nil {
				cycleErr = errors.Join(cycleErr, err)
				break
			}
			events = append(events, evs...)
			b, err := e.persisted(rt)
			if err != nil {
				cycleErr = errors.Join(cycleErr, fmt.Errorf("engine: persist %s: %w", cr.ID, err))
				continue
			}
			writes[alertKeyPrefix+cr.ID] = b
		}
	}
	var perr error
	if len(writes) > 0 {
		perr = e.opts.Store.Batch(writes)
	}
	e.publish(now)
	if e.opts.Sink != nil {
		for _, ev := range events {
			e.opts.Sink(ev)
		}
	}
	return errors.Join(cycleErr, perr)
}

func (e *Engine) interval(cr *compiledRule) time.Duration {
	if cr.interval > 0 {
		return cr.interval
	}
	return e.opts.DefaultInterval
}

func (e *Engine) persisted(rt *ruleRuntime) ([]byte, error) {
	p := persistedRule{ruleInfo: rt.info, LastEval: rt.lastEval}
	for _, k := range rt.alerts.sortedKeys() {
		p.Instances = append(p.Instances, rt.alerts.active[k])
	}
	return json.Marshal(p)
}

// activate switches to the staged bundle; rules no longer evaluated mark firing instances stale.
func (e *Engine) activate(now time.Time, writes map[string][]byte) []AlertEvent {
	e.stageMu.Lock()
	nb := e.staged
	e.staged = nil
	e.stageMu.Unlock()
	if nb == nil {
		return nil
	}
	var evs []AlertEvent
	ids := make([]string, 0, len(e.rt))
	for id := range e.rt {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rt := e.rt[id]
		if cr := nb.byID[id]; cr != nil && cr.evaluated() && cr.Class == rt.info.Class {
			continue
		}
		evs = append(evs, e.events(rt.info, rt.alerts.staleAll(), now)...)
		delete(e.rt, id)
		writes[alertKeyPrefix+id] = nil
	}
	for _, cr := range nb.rules {
		if !cr.evaluated() {
			continue
		}
		rt := e.rt[cr.ID]
		if rt == nil {
			rt = &ruleRuntime{alerts: newAlertSet(), loadedAt: now}
			if rec := e.restored[cr.ID]; rec != nil {
				delete(e.restored, cr.ID)
				if rec.Class == cr.Class {
					downtime := max(e.start.Sub(rec.LastEval), 0)
					rt.resumed = rt.alerts.restore(rec.Instances, downtime, e.opts.OutageTolerance)
				} else {
					evs = append(evs, e.staleRestored(rec, now)...)
					writes[alertKeyPrefix+cr.ID] = nil
				}
			}
			e.rt[cr.ID] = rt
		}
		rt.info = cr.ruleInfo
	}
	if !e.activated {
		ids = ids[:0]
		for id := range e.restored {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			evs = append(evs, e.staleRestored(e.restored[id], now)...)
			writes[alertKeyPrefix+id] = nil
		}
		e.restored, e.activated = nil, true
	}
	e.cur = nb
	return evs
}

func (e *Engine) staleRestored(rec *persistedRule, now time.Time) []AlertEvent {
	a := newAlertSet()
	a.restore(rec.Instances, 0, e.opts.OutageTolerance)
	return e.events(rec.ruleInfo, a.staleAll(), now)
}

func (e *Engine) events(info ruleInfo, trans []transition, now time.Time) []AlertEvent {
	out := make([]AlertEvent, 0, len(trans))
	for _, t := range trans {
		out = append(out, AlertEvent{
			RuleID: info.ID, RuleVersion: info.Version, BundleVersion: info.BundleVersion,
			Class: info.Class, Scope: info.Scope, Transition: t.kind, InstanceKey: t.inst.Key,
			Labels: maps.Clone(t.inst.Labels), Annotations: maps.Clone(t.inst.Annotations), Value: float64(t.inst.Value),
			ActiveAt: t.inst.ActiveAt, FiredAt: t.inst.FiredAt, ResolvedAt: t.resolvedAt, EvalTime: now,
			ResourceUIDs: slices.Clone(t.inst.Resources), Severity: info.Severity, Category: info.Category,
			Summary: t.inst.Summary, Incomplete: t.incomplete,
		})
	}
	return out
}

func isBudgetErr(err error) bool {
	var qt promql.ErrQueryTimeout
	var ts promql.ErrTooManySamples
	return errors.Is(err, errBudget) || errors.As(err, &qt) || errors.As(err, &ts) ||
		errors.Is(err, context.DeadlineExceeded) || isCELCancel(err)
}

func (e *Engine) evalRule(ctx context.Context, cr *compiledRule, rt *ruleRuntime, now time.Time, sc **stateCycle) ([]AlertEvent, error) {
	rctx, cancel := context.WithTimeout(ctx, cr.budget.MaxEvalTime)
	defer cancel()
	began := time.Now()
	var in evalInput
	var err error
	switch {
	case cr.Class == bundle.ClassState:
		if *sc == nil {
			*sc = e.newStateCycle()
		}
		in, err = e.evalState(rctx, cr, rt, *sc, now)
	case cr.nodePart:
		err = e.evalNodePart(rctx, cr, now)
	case cr.Class == bundle.ClassPromQL:
		in, err = e.evalPromQL(rctx, cr, rt, now)
	default:
		in, err = e.evalLogQL(cr, rt, now, began)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	rt.lastDur, rt.lastEval = time.Since(began), now
	rt.evaluations++
	var trans []transition
	if err == nil && !cr.nodePart {
		trans, err = rt.alerts.eval(now, cr.holdFor, cr.keepFor, in)
	}
	if err == nil {
		rt.lastErr, rt.budgetErr, rt.backoff, rt.stale = "", "", time.Time{}, in.reason
		return e.events(cr.ruleInfo, trans, now), nil
	}
	if isBudgetErr(err) || rctx.Err() != nil {
		rt.budgetErr, rt.lastErr, rt.backoff = err.Error(), "", now.Add(e.opts.BudgetBackoff)
	} else {
		rt.lastErr, rt.budgetErr = err.Error(), ""
	}
	rt.stale = "evaluation did not complete"
	return e.events(cr.ruleInfo, rt.alerts.staleAll(), now), nil
}

func (e *Engine) coverage(cr *compiledRule) Coverage {
	if cr.cluster && e.opts.Role == RoleCoordinator {
		if e.opts.ClusterCoverage != nil {
			return e.opts.ClusterCoverage(cr.ID, cr.Version)
		}
		return CoverageCovered
	}
	if e.opts.Coverage != nil {
		return e.opts.Coverage()
	}
	return CoverageCovered
}

func (e *Engine) promEngine(b bundle.Budget) *promql.Engine {
	k := engineKey{samples: b.MaxSamples, timeout: b.MaxEvalTime}
	if eng, ok := e.engines[k]; ok {
		return eng
	}
	step := e.opts.DefaultInterval.Milliseconds()
	eng := promql.NewEngine(promql.EngineOpts{
		MaxSamples:               b.MaxSamples,
		Timeout:                  b.MaxEvalTime,
		LookbackDelta:            e.opts.LookbackDelta,
		NoStepSubqueryIntervalFn: func(int64) int64 { return step },
	})
	e.engines[k] = eng
	return eng
}

func (e *Engine) query(ctx context.Context, b bundle.Budget, expr string, ts time.Time) (promql.Vector, error) {
	if e.opts.Queryable == nil {
		return nil, errors.New("no metrics queryable is configured")
	}
	q, err := e.promEngine(b).NewInstantQuery(ctx, e.opts.Queryable, nil, expr, ts)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	res := q.Exec(ctx)
	if res.Err != nil {
		return nil, res.Err
	}
	switch v := res.Value.(type) {
	case promql.Vector:
		return v, nil
	case promql.Scalar:
		return promql.Vector{{T: v.T, F: v.V, Metric: labels.EmptyLabels()}}, nil
	}
	return nil, fmt.Errorf("rule result is %s, want a vector or scalar", res.Value.Type())
}

func seriesLimit(cr *compiledRule, n int) error {
	if n > cr.budget.MaxSeries {
		return fmt.Errorf("%w: %d output series exceed max_series %d", errBudget, n, cr.budget.MaxSeries)
	}
	return nil
}

func (e *Engine) evalPromQL(ctx context.Context, cr *compiledRule, rt *ruleRuntime, now time.Time) (evalInput, error) {
	cov := e.coverage(cr)
	rt.coverage = cov
	if cov != CoverageCovered && cr.hasAbsent {
		return evalInput{incompleteRest: true, reason: "absent is not evaluated while coverage is " + cov.String()}, nil
	}
	vec, err := e.query(ctx, cr.budget, cr.evalExpr, now)
	if err != nil {
		return evalInput{}, err
	}
	if err := seriesLimit(cr, len(vec)); err != nil {
		return evalInput{}, err
	}
	in := evalInput{observed: e.observe(cr, vec)}
	if cov != CoverageCovered {
		in.incompleteRest, in.flagged, in.reason = true, true, "coverage is "+cov.String()
		return in, nil
	}
	missing, err := e.missingInputs(ctx, cr.inputs, now)
	if err != nil {
		return evalInput{}, err
	}
	if len(missing) > 0 {
		in.incompleteRest, in.flagged, in.reason = true, true, "no input series for "+strings.Join(missing, ", ")
		return in, nil
	}
	gone, err := e.goneInstances(ctx, cr, rt, in.observed, now)
	if err != nil {
		return evalInput{}, err
	}
	if len(gone) > 0 {
		in.incomplete, in.reason = gone, fmt.Sprintf("input series gone for %d instances", len(gone))
	}
	return in, nil
}

// probeSeries bounds the series read per input when checking one instance.
const probeSeries = 16

// goneInstances returns the unobserved active instances left without a live input series matching their labels.
func (e *Engine) goneInstances(ctx context.Context, cr *compiledRule, rt *ruleRuntime, observed []observation, now time.Time) (map[string]bool, error) {
	if len(cr.inputs) == 0 || len(rt.alerts.active) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(observed))
	for _, o := range observed {
		seen[o.key] = true
	}
	var keys []string
	for _, k := range rt.alerts.sortedKeys() {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	start, end := now.Add(-e.opts.LookbackDelta).UnixMilli(), now.UnixMilli()
	q, err := e.opts.Queryable.Querier(start, end)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	carried := make(map[string]map[string]bool, len(cr.inputs))
	for _, n := range cr.inputs {
		names, _, err := q.LabelNames(ctx, nil, labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, n))
		if err != nil {
			return nil, err
		}
		set := make(map[string]bool, len(names))
		for _, ln := range names {
			if _, ruleLabel := cr.labels[ln]; !ruleLabel && !cr.derived[ln] && ln != model.MetricNameLabel && ln != labels.AlertName {
				set[ln] = true
			}
		}
		carried[n] = set
	}
	gone := map[string]bool{}
	for i, k := range keys {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %w", errBudget, err)
		}
		// Beyond the series budget an instance is not checked and stays unresolved this cycle.
		if i >= cr.budget.MaxSeries {
			gone[k] = true
			continue
		}
		live, err := instanceLive(ctx, q, cr.inputs, carried, rt.alerts.active[k].Labels, start, end)
		if err != nil {
			return nil, err
		}
		if !live {
			gone[k] = true
		}
	}
	return gone, nil
}

// instanceLive reports whether any input has a live series carrying the instance's values for the labels it has.
func instanceLive(ctx context.Context, q storage.Querier, inputs []string, carried map[string]map[string]bool, lbls map[string]string, start, end int64) (bool, error) {
	for _, n := range inputs {
		ms := []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, n)}
		for ln, v := range lbls {
			if carried[n][ln] {
				ms = append(ms, labels.MustNewMatcher(labels.MatchEqual, ln, v))
			}
		}
		live, err := liveSeries(ctx, q, start, end, ms)
		if err != nil || live {
			return live, err
		}
	}
	return false, nil
}

// liveSeries reports whether a matching series has a latest sample in [start, end] that is not a staleness marker.
func liveSeries(ctx context.Context, q storage.Querier, start, end int64, ms []*labels.Matcher) (bool, error) {
	set := q.Select(ctx, false, &storage.SelectHints{Start: start, End: end, Limit: probeSeries}, ms...)
	var it chunkenc.Iterator
	for n := 0; n < probeSeries && set.Next(); n++ {
		it = set.At().Iterator(it)
		found, stale := false, false
		for vt := it.Seek(start); vt != chunkenc.ValNone && it.AtT() <= end; vt = it.Next() {
			found = true
			switch vt {
			case chunkenc.ValFloat:
				_, f := it.At()
				stale = value.IsStaleNaN(f)
			case chunkenc.ValHistogram:
				_, h := it.AtHistogram(nil)
				stale = value.IsStaleNaN(h.Sum)
			case chunkenc.ValFloatHistogram:
				_, h := it.AtFloatHistogram(nil)
				stale = value.IsStaleNaN(h.Sum)
			}
		}
		if err := it.Err(); err != nil {
			return false, err
		}
		if found && !stale {
			return true, nil
		}
	}
	return false, set.Err()
}

// missingInputs lists input metric names with no series in the lookback window (PRD G8: absence of
// telemetry is stale, never healthy, and never resolves a firing alert).
func (e *Engine) missingInputs(ctx context.Context, names []string, now time.Time) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	q, err := e.opts.Queryable.Querier(now.Add(-e.opts.LookbackDelta).UnixMilli(), now.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer q.Close()
	var missing []string
	for _, n := range names {
		set := q.Select(ctx, false, &storage.SelectHints{Start: now.Add(-e.opts.LookbackDelta).UnixMilli(), End: now.UnixMilli(), Limit: 1, Func: "series"}, labels.MustNewMatcher(labels.MatchEqual, model.MetricNameLabel, n))
		found := set.Next()
		if err := set.Err(); err != nil {
			return nil, err
		}
		if !found {
			missing = append(missing, n)
		}
	}
	return missing, nil
}

func (e *Engine) evalNodePart(ctx context.Context, cr *compiledRule, now time.Time) error {
	vec, err := e.query(ctx, cr.budget, cr.evalExpr, now)
	if err != nil {
		return err
	}
	if err := seriesLimit(cr, len(vec)); err != nil {
		return err
	}
	e.opts.Push(Part{RuleID: cr.ID, RuleVersion: cr.Version, BundleVersion: cr.BundleVersion, EvalTime: now, Vector: vec})
	return nil
}

func (e *Engine) evalLogQL(cr *compiledRule, rt *ruleRuntime, now, began time.Time) (evalInput, error) {
	cov := e.coverage(cr)
	rt.coverage = cov
	if cov != CoverageCovered && cr.hasAbsent {
		return evalInput{incompleteRest: true, reason: "absent_over_time is not evaluated while coverage is " + cov.String()}, nil
	}
	vec, err := cr.log.Eval(now)
	if err != nil {
		return evalInput{}, err
	}
	if d := time.Since(began); d > cr.budget.MaxEvalTime {
		return evalInput{}, fmt.Errorf("%w: evaluation took %s, exceeding max_eval_time %s", errBudget, d, cr.budget.MaxEvalTime)
	}
	if err := seriesLimit(cr, len(vec)); err != nil {
		return evalInput{}, err
	}
	in := evalInput{observed: e.observe(cr, vec)}
	if cov != CoverageCovered {
		in.incompleteRest, in.flagged, in.reason = true, true, "coverage is "+cov.String()
	}
	return in, nil
}

func (e *Engine) observe(cr *compiledRule, vec promql.Vector) []observation {
	out := make([]observation, 0, len(vec))
	for _, s := range vec {
		src := s.Metric.Map()
		lb := labels.NewBuilder(s.Metric)
		lb.Del(model.MetricNameLabel)
		for k, v := range cr.labels {
			lb.Set(k, expand(v, src, s.F))
		}
		lb.Set(labels.AlertName, cr.alert)
		lset := lb.Labels()
		lm := lset.Map()
		var ann map[string]string
		if len(cr.annotations) > 0 {
			ann = make(map[string]string, len(cr.annotations))
			for k, v := range cr.annotations {
				ann[k] = expand(v, src, s.F)
			}
		}
		out = append(out, observation{
			key: lset.String(), labels: lm, annotations: ann, summary: expand(cr.summary, src, s.F),
			value: s.F, resources: e.resolve(cr, lm),
		})
	}
	return out
}

func (e *Engine) resolve(cr *compiledRule, lm map[string]string) []string {
	ref := cr.meta.ResourceLabels
	if ref == nil || e.opts.ResolveResource == nil {
		return nil
	}
	name := lm[ref.Name]
	if name == "" {
		return nil
	}
	ns := ""
	if ref.Namespace != "" {
		ns = lm[ref.Namespace]
	}
	if uid, ok := e.opts.ResolveResource(ref.Kind, ns, name); ok {
		return []string{uid}
	}
	return nil
}

type stateCycle struct {
	st     *protocol.State
	g      *graph
	byKind map[string][]*protocol.Resource
	scopes map[string]protocol.ScopeState
	match  func(key, kind, ns string) bool
}

// defaultScopeMatch reads scope keys of the form [group/]Kind[|namespace]; an empty or * namespace covers all.
func defaultScopeMatch(key, kind, ns string) bool {
	left, right, _ := strings.Cut(key, "|")
	if i := strings.LastIndex(left, "/"); i >= 0 {
		left = left[i+1:]
	}
	return left == kind && (right == "" || right == "*" || right == ns)
}

func (e *Engine) newStateCycle() *stateCycle {
	sc := &stateCycle{scopes: map[string]protocol.ScopeState{}, match: e.opts.ScopeMatch}
	if sc.match == nil {
		sc.match = defaultScopeMatch
	}
	if e.opts.StateSource == nil {
		return sc
	}
	if sc.st = e.opts.StateSource(); sc.st == nil {
		return sc
	}
	sc.g = newGraph(sc.st)
	sc.byKind = map[string][]*protocol.Resource{}
	for _, r := range sc.st.Resources {
		sc.byKind[r.Kind] = append(sc.byKind[r.Kind], r)
	}
	for _, l := range sc.byKind {
		sort.Slice(l, func(i, j int) bool { return l[i].UID < l[j].UID })
	}
	return sc
}

func (sc *stateCycle) scope(kind, ns string) protocol.ScopeState {
	k := kind + "|" + ns
	if v, ok := sc.scopes[k]; ok {
		return v
	}
	worst := protocol.ScopeComplete
	for key, s := range sc.st.Scopes {
		if s.State > worst && sc.match(key, kind, ns) {
			worst = s.State
		}
	}
	sc.scopes[k] = worst
	return worst
}

func hasFields(r *protocol.Resource, paths []string) bool {
	for _, p := range paths {
		if _, ok := lookupField(r.Fields, p); !ok {
			return false
		}
	}
	return true
}

func (e *Engine) evalState(ctx context.Context, cr *compiledRule, rt *ruleRuntime, sc *stateCycle, now time.Time) (evalInput, error) {
	if sc.st == nil {
		return evalInput{incompleteRest: true, reason: "state snapshot unavailable"}, nil
	}
	holder := e.cur.holder
	holder.g = sc.g
	defer func() { holder.g = nil }()
	in := evalInput{incomplete: map[string]bool{}}
	nowVal := types.Timestamp{Time: now}
	var spent uint64
	for _, kind := range cr.kinds {
		for _, r := range sc.byKind[kind] {
			if err := ctx.Err(); err != nil {
				return in, fmt.Errorf("%w: %w", errBudget, err)
			}
			if sc.scope(kind, r.Namespace) >= protocol.ScopeUnavailable || !hasFields(r, cr.required) {
				in.incomplete[r.UID] = true
				continue
			}
			act := map[string]any{"r": sc.g.value(r), "now": nowVal}
			out, det, err := cr.state.prog.ContextEval(ctx, act)
			if det != nil && det.ActualCost() != nil {
				spent += *det.ActualCost()
			}
			if err != nil {
				if isCELCancel(err) || ctx.Err() != nil {
					return in, fmt.Errorf("%w: %w", errBudget, err)
				}
				in.incomplete[r.UID] = true
				continue
			}
			if spent > cr.state.cost {
				return in, fmt.Errorf("%w: CEL cost %d exceeds max_samples %d", errBudget, spent, cr.state.cost)
			}
			match, ok := out.Value().(bool)
			if !ok {
				return in, fmt.Errorf("expression returned %s for %s, want bool", out.Type().TypeName(), r.UID)
			}
			if !match {
				continue
			}
			lbls, err := stateLabels(ctx, cr, r, act)
			if err != nil {
				if isCELCancel(err) || ctx.Err() != nil {
					return in, fmt.Errorf("%w: %w", errBudget, err)
				}
				in.incomplete[r.UID] = true
				continue
			}
			in.observed = append(in.observed, observation{
				key: r.UID, labels: lbls, summary: expand(cr.summary, lbls, 1), value: 1,
				resources: []string{r.UID}, kind: r.Kind, namespace: r.Namespace,
			})
			if err := seriesLimit(cr, len(in.observed)); err != nil {
				return in, err
			}
		}
	}
	for key, inst := range rt.alerts.active {
		if in.incomplete[key] {
			continue
		}
		if _, ok := sc.st.Resources[key]; ok {
			continue
		}
		if sc.scope(inst.Kind, inst.Namespace) != protocol.ScopeComplete {
			in.incomplete[key] = true
		}
	}
	if n := len(in.incomplete); n > 0 {
		in.reason = fmt.Sprintf("%d instances incomplete: required fields missing or scopes unavailable", n)
	}
	return in, nil
}

func stateLabels(ctx context.Context, cr *compiledRule, r *protocol.Resource, act map[string]any) (map[string]string, error) {
	lbls := map[string]string{"kind": r.Kind, "name": r.Name}
	if r.Namespace != "" {
		lbls["namespace"] = r.Namespace
	}
	for _, lp := range cr.state.labels {
		if lp.prog == nil {
			lbls[lp.name] = lp.lit
			continue
		}
		v, _, err := lp.prog.ContextEval(ctx, act)
		if err != nil {
			return nil, err
		}
		lbls[lp.name] = celString(v)
	}
	return lbls, nil
}

func (e *Engine) publish(now time.Time) {
	var out []RuleState
	version := ""
	if e.cur != nil {
		version = e.cur.version
		for _, cr := range e.cur.rules {
			if !cr.skip {
				out = append(out, e.ruleState(cr, now))
			}
		}
	}
	e.viewMu.Lock()
	e.states, e.version = out, version
	e.viewMu.Unlock()
}

func (e *Engine) ruleState(cr *compiledRule, now time.Time) RuleState {
	s := RuleState{RuleID: cr.ID, Version: cr.Version, Class: cr.Class, Scope: cr.Scope, State: StateActive}
	switch {
	case cr.disabled:
		s.State = StateDisabled
		return s
	case cr.unsupported != "":
		s.State, s.Reason = StateUnsupported, cr.unsupported
		return s
	}
	rt := e.rt[cr.ID]
	s.LastEval, s.LastDuration, s.BackoffUntil = rt.lastEval, rt.lastDur, rt.backoff
	s.Pending, s.Firing = rt.alerts.counts()
	switch {
	case now.Before(rt.backoff):
		s.State, s.Reason = StateBudgetLimited, rt.budgetErr
	case rt.lastErr != "":
		s.State, s.Reason = StateFailed, rt.lastErr
	case rt.evaluations > 0 && rt.coverage == CoverageConverging:
		s.State, s.Reason = StateConverging, "contributing nodes run other bundle versions"
	case rt.stale != "":
		s.State, s.Reason = StateStale, rt.stale
	case cr.holdFor > 0 && !rt.resumed && now.Sub(rt.loadedAt) < cr.holdFor:
		s.State, s.Reason = StateWarmingUp, fmt.Sprintf("for %s has not elapsed since the rule was loaded", cr.holdFor)
	case e.opts.EvidenceLimited != nil && e.opts.EvidenceLimited(cr.ID):
		s.State, s.Reason = StateEvidenceLimited, "evidence ring share exceeded"
	}
	return s
}
