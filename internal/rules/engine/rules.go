package engine

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

type ruleInfo struct {
	ID            string `json:"id"`
	Version       int    `json:"version"`
	Class         string `json:"class"`
	Scope         string `json:"scope"`
	Severity      string `json:"severity,omitempty"`
	Category      string `json:"category,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
}

type compiledRule struct {
	ruleInfo
	meta        bundle.RuleMeta
	alert       string
	holdFor     time.Duration
	keepFor     time.Duration
	interval    time.Duration
	budget      bundle.Budget
	labels      map[string]string
	annotations map[string]string
	summary     string

	state    *stateProgram
	kinds    []string
	required []string

	evalExpr  string
	nodePart  bool
	cluster   bool
	hasAbsent bool
	inputs    []string
	log       LogProgram

	unsupported string
	disabled    bool
	skip        bool
}

func (r *compiledRule) evaluated() bool { return !r.skip && !r.disabled && r.unsupported == "" }

type compiledBundle struct {
	version string
	rules   []*compiledRule
	byID    map[string]*compiledRule
	holder  *graphHolder
}

func effectiveBudget(b bundle.Budget, p Policy) bundle.Budget {
	if b.MaxEvalTime <= 0 {
		b.MaxEvalTime = DefaultBudget.MaxEvalTime
	}
	if b.MaxSamples <= 0 {
		b.MaxSamples = DefaultBudget.MaxSamples
	}
	if b.MaxSeries <= 0 {
		b.MaxSeries = DefaultBudget.MaxSeries
	}
	if b.MaxComplexity <= 0 {
		b.MaxComplexity = DefaultBudget.MaxComplexity
	}
	if p.MaxEvalTime > 0 && b.MaxEvalTime > p.MaxEvalTime {
		b.MaxEvalTime = p.MaxEvalTime
	}
	if p.MaxSamples > 0 && b.MaxSamples > p.MaxSamples {
		b.MaxSamples = p.MaxSamples
	}
	if p.MaxSeries > 0 && b.MaxSeries > p.MaxSeries {
		b.MaxSeries = p.MaxSeries
	}
	if p.MaxComplexity > 0 && b.MaxComplexity > p.MaxComplexity {
		b.MaxComplexity = p.MaxComplexity
	}
	if p.MaxCounterBytes > 0 && (b.CounterBytes <= 0 || b.CounterBytes > p.MaxCounterBytes) {
		b.CounterBytes = p.MaxCounterBytes
	}
	return b
}

func stateID(r bundle.StateRule) string {
	if r.ID != "" {
		return r.ID
	}
	return r.Meta.ID
}

var quotedRe = regexp.MustCompile("\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`")
var logAbsentRe = regexp.MustCompile(`\babsent_over_time\s*\(`)

// logUsesAbsent reports whether a LogQL expression calls absent_over_time outside string literals.
func logUsesAbsent(expr string) bool {
	return logAbsentRe.MatchString(quotedRe.ReplaceAllString(expr, `""`))
}

func (e *Engine) compile(b *bundle.Bundle, res BundleResult) (*compiledBundle, error) {
	cb := &compiledBundle{version: b.Manifest.Version, byID: map[string]*compiledRule{}, holder: &graphHolder{}}
	env, err := newCELEnv(cb.holder)
	if err != nil {
		return nil, err
	}
	var errs []error
	add := func(cr *compiledRule) {
		if cr.ID == "" {
			errs = append(errs, errors.New("rule without id"))
			return
		}
		if _, dup := cb.byID[cr.ID]; dup {
			errs = append(errs, reject(cr.ID, "duplicate rule id"))
			return
		}
		cb.byID[cr.ID] = cr
		cb.rules = append(cb.rules, cr)
	}
	for _, sr := range b.State {
		cr := e.baseRule(sr.Meta, stateID(sr), bundle.ClassState, cb.version, res)
		if cr.Version == 0 {
			cr.Version = sr.Version
		}
		if cr.Scope == "" {
			cr.Scope = bundle.ScopeCluster
		}
		cr.alert, cr.holdFor, cr.keepFor, cr.interval = cr.ID, sr.For, sr.KeepFiringFor, sr.Interval
		cr.labels, cr.required = sr.Labels, sr.Meta.RequiredFields
		cr.kinds = slices.Compact(slices.Sorted(slices.Values(sr.Kinds)))
		cr.skip = e.opts.Role == RoleNode
		e.gate(cr, bundle.CapInventory)
		if !cr.disabled && cr.unsupported == "" {
			if cr.state, err = compileState(env, sr, cr.budget); err != nil {
				errs = append(errs, err)
			}
		}
		add(cr)
	}
	for _, ar := range b.PromQL {
		cr := e.alertRule(ar, bundle.ClassPromQL, cb.version, res)
		e.gate(cr, bundle.CapMetrics)
		if cr.evaluated() {
			if err := e.planPromQL(cr, ar); err != nil {
				errs = append(errs, err)
			}
		}
		add(cr)
	}
	for _, ar := range b.LogQL {
		cr := e.alertRule(ar, bundle.ClassLogQL, cb.version, res)
		cr.skip = e.opts.Role == RoleCoordinator
		e.gate(cr, bundle.CapLogs)
		switch {
		case !cr.evaluated():
		case cr.Scope == bundle.ScopeCluster:
			cr.unsupported = "cluster-scoped LogQL rules are not supported; LogQL rules evaluate node-local"
		case e.opts.CompileLogQL == nil:
			cr.unsupported = "no LogQL compiler is configured"
		default:
			if cr.log, err = e.opts.CompileLogQL(ar.Expr, cr.budget); err != nil {
				errs = append(errs, reject(cr.ID, "LogQL: %v", err))
			}
			cr.hasAbsent = logUsesAbsent(ar.Expr)
		}
		add(cr)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	sort.Slice(cb.rules, func(i, j int) bool { return cb.rules[i].ID < cb.rules[j].ID })
	return cb, nil
}

func (e *Engine) baseRule(m bundle.RuleMeta, id, class, version string, res BundleResult) *compiledRule {
	cr := &compiledRule{
		ruleInfo: ruleInfo{ID: id, Version: m.Version, Class: class, Scope: m.Scope, Severity: m.Severity, Category: m.Category, BundleVersion: version},
		meta:     m,
		budget:   effectiveBudget(m.Budget, e.opts.Policy),
		summary:  m.Summary,
	}
	cr.disabled = m.Disabled || slices.Contains(e.opts.Policy.DisabledRules, id)
	if r, ok := res.Unsupported[id]; ok {
		cr.unsupported = r
	} else if m.MinEngine > bundle.EngineVersion {
		cr.unsupported = fmt.Sprintf("requires engine version %d; this agent implements %d", m.MinEngine, bundle.EngineVersion)
	}
	return cr
}

func (e *Engine) alertRule(ar bundle.AlertRule, class, version string, res BundleResult) *compiledRule {
	cr := e.baseRule(ar.Meta, ar.Meta.ID, class, version, res)
	if cr.Scope == "" {
		cr.Scope = bundle.ScopeNode
	}
	cr.alert, cr.holdFor, cr.keepFor, cr.interval = ar.Alert, ar.For, ar.KeepFiringFor, ar.GroupInterval
	cr.labels, cr.annotations, cr.evalExpr = ar.Labels, ar.Annotations, ar.Expr
	if cr.summary == "" {
		cr.summary = ar.Annotations["summary"]
	}
	return cr
}

// gate marks a rule unsupported when a capability it needs is unavailable.
func (e *Engine) gate(cr *compiledRule, implied string) {
	if cr.unsupported != "" || e.opts.Policy.Capabilities == nil {
		return
	}
	for _, c := range append([]string{implied}, cr.meta.Capabilities...) {
		if !slices.Contains(e.opts.Policy.Capabilities, c) {
			cr.unsupported = "capability " + c + " is unavailable"
			return
		}
	}
}

// planPromQL validates a PromQL rule and decides what this role evaluates.
func (e *Engine) planPromQL(cr *compiledRule, ar bundle.AlertRule) error {
	a, err := analyzePromQL(ar, e.opts)
	if err != nil {
		return err
	}
	cr.hasAbsent = a.hasAbsent
	cr.cluster = cr.Scope == bundle.ScopeCluster
	switch e.opts.Role {
	case RoleNode:
		switch {
		case !cr.cluster:
		case a.split.NodeExpr == "":
			cr.skip = true
		case e.opts.Push == nil:
			cr.unsupported = "cluster rule parts need a coordinator push sink"
		default:
			cr.nodePart, cr.evalExpr = true, a.split.NodeExpr
		}
	case RoleCoordinator:
		if !cr.cluster {
			cr.skip = true
		} else {
			cr.evalExpr = a.split.CoordExpr
		}
	}
	if !cr.cluster {
		cr.inputs = promInputs(a.expr)
	}
	return nil
}

// promInputs returns the scraped metric names a rule reads outside absent calls; synthesized
// kube_* series are excluded because their absence is meaningful state, not missing telemetry.
func promInputs(expr parser.Expr) []string {
	seen := map[string]bool{}
	var out []string
	parser.Inspect(expr, func(n parser.Node, path []parser.Node) error {
		vs, ok := n.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		for _, p := range path {
			if c, ok := p.(*parser.Call); ok && isAbsent(c.Func.Name) {
				return nil
			}
		}
		name := vs.Name
		if name == "" {
			for _, m := range vs.LabelMatchers {
				if m.Name == model.MetricNameLabel && m.Type == labels.MatchEqual {
					name = m.Value
				}
			}
		}
		if name == "" || name == "ALERTS" || name == "ALERTS_FOR_STATE" || strings.HasPrefix(name, "kube_") || seen[name] {
			return nil
		}
		seen[name] = true
		out = append(out, name)
		return nil
	})
	sort.Strings(out)
	return out
}
