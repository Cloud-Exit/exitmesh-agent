package node

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/prometheus/promql/parser"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

// ruleState tracks the bundle staged for the next cycle and the metadata of the active one.
type ruleState struct {
	mu        sync.Mutex
	pending   *bundle.Active
	lastError string
	rejected  string

	// Owned by the evaluation loop.
	meta     map[string]bundle.RuleMeta
	building *logSet
}

// logRule is one compiled LogQL program and the rules sharing its expression.
type logRule struct {
	expr   string
	budget bundle.Budget
	prog   *logql.Program
	ids    []string
}

type logSet struct {
	byExpr map[string]*logRule
	rules  []*logRule
}

type logState struct {
	cur atomic.Pointer[logSet]
}

var promParser = parser.NewParser(parser.Options{})

func validators() bundle.Validators {
	opts := engine.Options{Role: engine.RoleNode, KubeSubset: state.PublishedSubset()}
	return bundle.Validators{
		PromQL: func(r bundle.AlertRule) error { return engine.ValidatePromQL(r, opts) },
		LogQL: func(r bundle.AlertRule) error {
			_, err := logql.CompileRule(r.Expr, r.Meta.Budget)
			return err
		},
		CEL: engine.ValidateCEL,
	}
}

func bundlePolicy(p config.Policy) bundle.Policy {
	return bundle.Policy{
		TargetType: bundle.TargetKubernetes,
		MaxBudget: bundle.Budget{
			MaxEvalTime: p.MaxRuleEvalTime.D(), MaxSamples: p.MaxRuleSamples, MaxSeries: p.MaxRuleSeries, CounterBytes: int(p.MaxCounterBytes),
		},
		MaxEvidence: bundle.EvidencePolicy{MaxBytes: int(p.MaxEvidenceBytes)},
	}
}

func enginePolicy(cfg *config.Config) engine.Policy {
	p := cfg.Policy
	return engine.Policy{
		MaxEvalTime: p.MaxRuleEvalTime.D(), MaxSamples: p.MaxRuleSamples, MaxSeries: p.MaxRuleSeries,
		MaxCounterBytes: int(p.MaxCounterBytes), DisabledRules: slices.Clone(p.DisabledRules), Capabilities: slices.Clone(cfg.Capabilities),
	}
}

func (a *Agent) loadLastKnownGood() error {
	act, ok, err := a.bstore.LoadLastKnownGood(a.vals, a.bpol)
	if err != nil {
		a.log.Warn("last known good bundle is not loadable; waiting for the coordinator", "err", err)
		return nil
	}
	if ok {
		a.stage(act)
		a.log.Info("last known good bundle loaded", "bundle", act.Bundle.Manifest.Version)
	}
	return nil
}

func (a *Agent) stage(act *bundle.Active) {
	a.rules.mu.Lock()
	a.rules.pending = act
	a.rules.mu.Unlock()
}

// accept verifies a coordinator payload locally: key manifests, then signature and validation.
func (a *Agent) accept(p *nodeapi.BundlePayload) (*bundle.Active, error) {
	if len(p.KeyManifestChain) > 0 {
		if _, err := a.verifier.AcceptManifests(p.KeyManifestChain...); err != nil {
			return nil, err
		}
	}
	if len(p.KeyManifest) > 0 {
		if _, err := a.verifier.AcceptManifest(p.KeyManifest); err != nil {
			return nil, err
		}
	}
	act, err := a.bstore.Activate(p.Archive, p.Signature, a.vals, a.bpol)
	if err != nil {
		return nil, err
	}
	if act.Bundle.Manifest.Version != p.Version {
		return nil, fmt.Errorf("%w: payload version %q carries bundle version %q", bundle.ErrInvalid, p.Version, act.Bundle.Manifest.Version)
	}
	return act, nil
}

func (a *Agent) bundleLoop(ctx context.Context) {
	back := a.t.RetryMin
	have := ""
	if v, ok, err := a.bstore.Current(); err == nil && ok {
		have = v
	}
	for ctx.Err() == nil {
		p, err := a.client.WaitBundle(ctx, have)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Debug("bundle poll failed", "err", err)
			if !sleepCtx(ctx, back) {
				return
			}
			back = min(2*back, a.t.RetryMax)
			continue
		}
		back = a.t.RetryMin
		if p == nil {
			continue
		}
		prev := have
		have = p.Version
		act, err := a.accept(p)
		if err != nil {
			a.rules.mu.Lock()
			a.rules.lastError, a.rules.rejected = err.Error(), p.Version
			a.rules.mu.Unlock()
			a.log.Warn("bundle rejected; last known good stays active", "bundle", p.Version, "active", prev, "err", err)
			continue
		}
		a.rules.mu.Lock()
		a.rules.lastError, a.rules.rejected = "", ""
		a.rules.mu.Unlock()
		a.stage(act)
		a.log.Info("bundle verified", "bundle", p.Version, "key", act.KeyID)
	}
}

// applyPending switches bundles between evaluation cycles, never during one.
func (a *Agent) applyPending() {
	a.rules.mu.Lock()
	act := a.rules.pending
	a.rules.pending = nil
	a.rules.mu.Unlock()
	if act == nil {
		return
	}
	a.rules.building = &logSet{byExpr: map[string]*logRule{}}
	err := a.eng.SetBundle(act.Bundle, engine.BundleResult{Unsupported: act.Result.Unsupported})
	build := a.rules.building
	a.rules.building = nil
	if err != nil {
		a.rules.mu.Lock()
		a.rules.lastError = err.Error()
		a.rules.mu.Unlock()
		a.log.Warn("bundle does not compile; previous bundle stays active", "bundle", act.Bundle.Manifest.Version, "err", err)
		if cur := a.eng.BundleVersion(); cur != "" && cur != act.Bundle.Manifest.Version {
			if _, rerr := a.bstore.Rollback(cur, a.vals, a.bpol); rerr != nil {
				a.log.Warn("restoring last known good failed", "bundle", cur, "err", rerr)
			}
		}
		return
	}
	meta := map[string]bundle.RuleMeta{}
	var window time.Duration
	retention := 2 * a.t.Facts
	for _, r := range act.Bundle.PromQL {
		meta[r.Meta.ID] = r.Meta
		if !a.ruleActive(r.Meta) {
			continue
		}
		rng := promRange(r.Expr)
		window = max(window, rng)
		retention = max(retention, rng+r.For)
	}
	weights := map[string]float64{}
	var logWindow time.Duration
	for _, r := range act.Bundle.LogQL {
		meta[r.Meta.ID] = r.Meta
		if lr := build.byExpr[r.Expr]; lr != nil && a.ruleActive(r.Meta) {
			lr.ids = append(lr.ids, r.Meta.ID)
			weights[r.Meta.ID] = 1
			logWindow = max(logWindow, lr.prog.Window())
		}
	}
	window = max(window, logWindow)
	for _, r := range act.Bundle.State {
		meta[r.Meta.ID] = r.Meta
	}
	a.rules.meta = meta
	a.cov.setWarmup(min(max(window, 2*a.cfg.Node.ScrapeInterval.D()), tsdb.HardCeiling), min(logWindow, tsdb.HardCeiling))
	a.ring.SetRules(weights)
	a.logsSet.cur.Store(build)
	if a.tailer != nil {
		a.tailer.SetFilter(a.streamFilter(build))
	}
	if a.db != nil {
		eff, err := a.db.SetRetention(retention)
		if err != nil {
			a.log.Warn("tsdb retention update failed", "err", err)
		} else {
			a.log.Info("bundle activated", "bundle", act.Bundle.Manifest.Version, "retention", eff)
		}
	} else {
		a.log.Info("bundle activated", "bundle", act.Bundle.Manifest.Version)
	}
}

func (a *Agent) ruleActive(m bundle.RuleMeta) bool {
	if m.Disabled || slices.Contains(a.cfg.Policy.DisabledRules, m.ID) {
		return false
	}
	for _, c := range m.Capabilities {
		if !a.caps[c] {
			return false
		}
	}
	return true
}

// compileLogQL is the engine's LogQL compiler; it reuses programs of unchanged rules so counters survive a bundle switch.
func (a *Agent) compileLogQL(expr string, b bundle.Budget) (engine.LogProgram, error) {
	build := a.rules.building
	if build == nil {
		return nil, errors.New("LogQL compilation outside a bundle switch")
	}
	if lr := build.byExpr[expr]; lr != nil {
		return lr.prog, nil
	}
	var prog *logql.Program
	if cur := a.logsSet.cur.Load(); cur != nil {
		if lr := cur.byExpr[expr]; lr != nil && lr.budget == b {
			prog = lr.prog
		}
	}
	if prog == nil {
		p, err := logql.CompileRule(expr, b)
		if err != nil {
			return nil, err
		}
		prog = p
	}
	lr := &logRule{expr: expr, budget: b, prog: prog}
	build.byExpr[expr] = lr
	build.rules = append(build.rules, lr)
	return prog, nil
}

// streamFilter selects only streams inside the namespace scope that some active LogQL rule references, never the agent's own pod.
func (a *Agent) streamFilter(set *logSet) func(map[string]string) bool {
	self := a.deps.PodName
	return func(l map[string]string) bool {
		if self != "" && l["pod"] == self || !a.scope.allows(l["namespace"]) {
			return false
		}
		for _, lr := range set.rules {
			if len(lr.ids) > 0 && lr.prog.Matches(l) {
				return true
			}
		}
		return false
	}
}

// promRange is the longest range an expression reads: range selectors and subqueries plus offsets.
func promRange(expr string) time.Duration {
	e, err := promParser.ParseExpr(expr)
	if err != nil {
		return 0
	}
	var longest time.Duration
	var walk func(n parser.Node, extra time.Duration)
	walk = func(n parser.Node, extra time.Duration) {
		switch x := n.(type) {
		case *parser.SubqueryExpr:
			walk(x.Expr, extra+x.Range+max(x.OriginalOffset, 0))
			return
		case *parser.MatrixSelector:
			off := time.Duration(0)
			if vs, ok := x.VectorSelector.(*parser.VectorSelector); ok {
				off = max(vs.OriginalOffset, 0)
			}
			longest = max(longest, extra+x.Range+off)
			return
		case *parser.VectorSelector:
			longest = max(longest, extra+max(x.OriginalOffset, 0))
			return
		}
		for _, c := range parser.Children(n) {
			walk(c, extra)
		}
	}
	walk(e, 0)
	return longest
}
