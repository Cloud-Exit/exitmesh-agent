package bundle

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template/parse"
	"time"

	"github.com/prometheus/prometheus/promql/parser"
)

// ReasonUpgradeRequired marks rules that need a newer rule engine (PRD U4).
const ReasonUpgradeRequired = "agent upgrade required"

// Validators check expressions; callers inject them to avoid import cycles. A nil validator skips that class.
type Validators struct {
	PromQL func(AlertRule) error
	LogQL  func(AlertRule) error
	CEL    func(StateRule) error
}

// Policy is the local administrator upper bound. Bundle values above a maximum are capped.
type Policy struct {
	// TargetType, when set, must equal the bundle target type.
	TargetType      string
	DefaultBudget   Budget
	MaxBudget       Budget
	DefaultEvidence EvidencePolicy
	MaxEvidence     EvidencePolicy
	DefaultInterval time.Duration
	MinInterval     time.Duration
	MaxInterval     time.Duration
	MaxFor          time.Duration
	MaxRules        int
}

// DefaultPolicy returns the built-in upper bounds.
func DefaultPolicy() Policy {
	return Policy{
		DefaultBudget:   Budget{MaxEvalTime: 2 * time.Second, MaxSamples: 500_000, MaxSeries: 10_000, MaxComplexity: 200, CounterBytes: 1 << 20},
		MaxBudget:       Budget{MaxEvalTime: 10 * time.Second, MaxSamples: 5_000_000, MaxSeries: 100_000, MaxComplexity: 1000, CounterBytes: 8 << 20},
		DefaultEvidence: EvidencePolicy{MaxSamples: 5, MaxBytes: 8 << 10},
		MaxEvidence:     EvidencePolicy{MaxSamples: 20, MaxBytes: 64 << 10, ContextLines: 5},
		DefaultInterval: time.Minute,
		MinInterval:     10 * time.Second,
		MaxInterval:     time.Hour,
		MaxFor:          24 * time.Hour,
		MaxRules:        2000,
	}
}

func (p Policy) normalized() Policy {
	d := DefaultPolicy()
	fillBudget(&p.DefaultBudget, d.DefaultBudget)
	fillBudget(&p.MaxBudget, d.MaxBudget)
	capBudget(&p.DefaultBudget, p.MaxBudget)
	if p.DefaultEvidence.MaxSamples == 0 {
		p.DefaultEvidence.MaxSamples = d.DefaultEvidence.MaxSamples
	}
	if p.DefaultEvidence.MaxBytes == 0 {
		p.DefaultEvidence.MaxBytes = d.DefaultEvidence.MaxBytes
	}
	if p.MaxEvidence.MaxSamples == 0 {
		p.MaxEvidence.MaxSamples = d.MaxEvidence.MaxSamples
	}
	if p.MaxEvidence.MaxBytes == 0 {
		p.MaxEvidence.MaxBytes = d.MaxEvidence.MaxBytes
	}
	capEvidence(&p.DefaultEvidence, p.MaxEvidence)
	for _, x := range []struct{ v, d *time.Duration }{
		{&p.DefaultInterval, &d.DefaultInterval}, {&p.MinInterval, &d.MinInterval},
		{&p.MaxInterval, &d.MaxInterval}, {&p.MaxFor, &d.MaxFor},
	} {
		if *x.v <= 0 {
			*x.v = *x.d
		}
	}
	p.DefaultInterval = min(max(p.DefaultInterval, p.MinInterval), p.MaxInterval)
	if p.MaxRules <= 0 {
		p.MaxRules = d.MaxRules
	}
	return p
}

func fillBudget(b *Budget, d Budget) {
	if b.MaxEvalTime <= 0 {
		b.MaxEvalTime = d.MaxEvalTime
	}
	if b.MaxSamples <= 0 {
		b.MaxSamples = d.MaxSamples
	}
	if b.MaxSeries <= 0 {
		b.MaxSeries = d.MaxSeries
	}
	if b.MaxComplexity <= 0 {
		b.MaxComplexity = d.MaxComplexity
	}
	if b.CounterBytes <= 0 {
		b.CounterBytes = d.CounterBytes
	}
}

func capBudget(b *Budget, m Budget) {
	b.MaxEvalTime = min(b.MaxEvalTime, m.MaxEvalTime)
	b.MaxSamples = min(b.MaxSamples, m.MaxSamples)
	b.MaxSeries = min(b.MaxSeries, m.MaxSeries)
	b.MaxComplexity = min(b.MaxComplexity, m.MaxComplexity)
	b.CounterBytes = min(b.CounterBytes, m.CounterBytes)
}

func capEvidence(e *EvidencePolicy, m EvidencePolicy) {
	e.MaxSamples = min(e.MaxSamples, m.MaxSamples)
	e.MaxBytes = min(e.MaxBytes, m.MaxBytes)
	e.ContextLines = min(e.ContextLines, m.ContextLines)
}

// Result holds per-rule verdicts in manifest order.
type Result struct {
	Active      []string
	Disabled    []string
	Unsupported map[string]string
	Rejected    map[string]string
}

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	labelPattern   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	severities     = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	capabilities   = map[string]bool{CapInventory: true, CapMetrics: true, CapLogs: true}
	classCap       = map[string]string{ClassState: CapInventory, ClassPromQL: CapMetrics, ClassLogQL: CapLogs}
	promParser     = parser.NewParser(parser.Options{})
)

func effectiveMinEngine(m RuleMeta) int { return max(m.MinEngine, 1) }

// Validate checks b against the engine and local policy, applying defaults in place; any rejection fails the bundle.
func Validate(b *Bundle, v Validators, p Policy) (Result, error) {
	res := Result{Unsupported: map[string]string{}, Rejected: map[string]string{}}
	p = p.normalized()
	if err := validateManifest(b.Manifest, p); err != nil {
		return res, err
	}
	state := map[string]*StateRule{}
	for i := range b.State {
		state[b.State[i].ID] = &b.State[i]
	}
	alerts := map[string]*AlertRule{}
	for i := range b.PromQL {
		alerts[b.PromQL[i].Meta.ID] = &b.PromQL[i]
	}
	for i := range b.LogQL {
		alerts[b.LogQL[i].Meta.ID] = &b.LogQL[i]
	}
	seen := map[string]bool{}
	for i := range b.Manifest.Rules {
		m := &b.Manifest.Rules[i]
		if seen[m.ID] {
			res.Rejected[m.ID] = "duplicate rule id"
			continue
		}
		seen[m.ID] = true
		if err := validateIdentity(*m, b.Manifest); err != nil {
			res.Rejected[ruleKey(m.ID, i)] = err.Error()
			continue
		}
		if effectiveMinEngine(*m) > EngineVersion {
			res.Unsupported[m.ID] = ReasonUpgradeRequired
			continue
		}
		if err := validateMeta(m, p); err != nil {
			res.Rejected[m.ID] = err.Error()
			continue
		}
		var err error
		switch m.Class {
		case ClassState:
			r, ok := state[m.ID]
			if !ok {
				err = errors.New("no state rule with this id")
				break
			}
			r.Meta = *m
			err = validateState(r, v, p)
		default:
			r, ok := alerts[m.ID]
			if !ok || r.Meta.Class != m.Class {
				err = fmt.Errorf("no %s alerting rule bound to this id", m.Class)
				break
			}
			r.Meta = *m
			err = validateAlert(r, v, p)
		}
		if err != nil {
			res.Rejected[m.ID] = err.Error()
			continue
		}
		if m.Disabled {
			res.Disabled = append(res.Disabled, m.ID)
			continue
		}
		res.Active = append(res.Active, m.ID)
	}
	if len(res.Rejected) > 0 {
		ids := make([]string, 0, len(res.Rejected))
		for id := range res.Rejected {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		msgs := make([]string, len(ids))
		for i, id := range ids {
			msgs[i] = fmt.Sprintf("%s: %s", id, res.Rejected[id])
		}
		return res, invalidf("%d rule(s) rejected: %s", len(ids), strings.Join(msgs, "; "))
	}
	return res, nil
}

func ruleKey(id string, i int) string {
	if id == "" {
		return fmt.Sprintf("rules[%d]", i)
	}
	return id
}

func validateManifest(m Manifest, p Policy) error {
	switch {
	case !versionPattern.MatchString(m.Version):
		return invalidf("manifest version %q is not a valid version string", m.Version)
	case m.SchemaVersion != SchemaVersion:
		return invalidf("schema_version %d is not supported (this agent implements %d)", m.SchemaVersion, SchemaVersion)
	case m.EngineVersion < 1:
		return invalidf("engine_version must be at least 1")
	case m.TargetType != TargetKubernetes && m.TargetType != TargetHost:
		return invalidf("unknown target_type %q", m.TargetType)
	case p.TargetType != "" && m.TargetType != p.TargetType:
		return invalidf("bundle target_type %q does not match this agent (%s)", m.TargetType, p.TargetType)
	case m.CreatedAt.IsZero():
		return invalidf("created_at is required")
	case len(m.Rules) > p.MaxRules:
		return invalidf("%d rules exceed the local limit of %d", len(m.Rules), p.MaxRules)
	}
	return nil
}

func validateIdentity(m RuleMeta, man Manifest) error {
	switch {
	case !idPattern.MatchString(m.ID):
		return fmt.Errorf("invalid rule id %q", m.ID)
	case m.Version < 1:
		return errors.New("version must be at least 1")
	case m.Target != man.TargetType:
		return fmt.Errorf("target %q does not match bundle target_type %q", m.Target, man.TargetType)
	case m.MinEngine < 0:
		return errors.New("min_engine must not be negative")
	case m.MinEngine > man.EngineVersion:
		return fmt.Errorf("min_engine %d exceeds bundle engine_version %d", m.MinEngine, man.EngineVersion)
	}
	return nil
}

func validateMeta(m *RuleMeta, p Policy) error {
	need, ok := classCap[m.Class]
	switch {
	case !ok:
		return fmt.Errorf("unknown class %q", m.Class)
	case m.Scope != ScopeNode && m.Scope != ScopeCluster:
		return fmt.Errorf("unknown scope %q", m.Scope)
	case m.Target == TargetHost && m.Scope == ScopeCluster:
		return errors.New("host rules cannot use cluster scope")
	case m.Category == "" || len(m.Category) > 128 || strings.ContainsAny(m.Category, "\r\n\t"):
		return errors.New("category is required, single line, at most 128 bytes")
	case !severities[m.Severity]:
		return fmt.Errorf("unknown severity %q", m.Severity)
	case m.Resolution != "" && m.Resolution != ResolveRecovery && m.Resolution != ResolveManual:
		return fmt.Errorf("unknown resolution %q", m.Resolution)
	case len(m.Summary) > 1024:
		return errors.New("summary exceeds 1024 bytes")
	}
	if len(m.Capabilities) == 0 {
		return errors.New("capabilities are required")
	}
	caps := map[string]bool{}
	for _, c := range m.Capabilities {
		if !capabilities[c] {
			return fmt.Errorf("unknown capability %q", c)
		}
		if caps[c] {
			return fmt.Errorf("duplicate capability %q", c)
		}
		caps[c] = true
	}
	if !caps[need] {
		return fmt.Errorf("class %s requires capability %q", m.Class, need)
	}
	for _, f := range m.RequiredFields {
		if f == "" || len(f) > 256 {
			return fmt.Errorf("invalid required field %q", f)
		}
	}
	for _, l := range m.DedupLabels() {
		if !labelPattern.MatchString(l) {
			return fmt.Errorf("dedup_key label %q is not a valid label name", l)
		}
	}
	if r := m.ResourceLabels; r != nil {
		if r.Kind == "" || !labelPattern.MatchString(r.Name) || (r.Namespace != "" && !labelPattern.MatchString(r.Namespace)) {
			return errors.New("resource_labels needs a kind and valid label names")
		}
	}
	for k := range m.Match {
		if !labelPattern.MatchString(k) {
			return fmt.Errorf("match label %q is not a valid label name", k)
		}
	}
	if m.Class == ClassState {
		if m.Group != "" || m.Alert != "" || m.Match != nil {
			return errors.New("state rules must not set group, alert, or match")
		}
	} else if m.File == "" || m.Group == "" || m.Alert == "" {
		return errors.New("file, group, and alert are required")
	}
	e, b := m.Evidence, m.Budget
	if e.MaxSamples < 0 || e.MaxBytes < 0 || e.ContextLines < 0 {
		return errors.New("evidence limits must not be negative")
	}
	if b.MaxEvalTime < 0 || b.MaxSamples < 0 || b.MaxSeries < 0 || b.MaxComplexity < 0 || b.CounterBytes < 0 {
		return errors.New("budget limits must not be negative")
	}
	if e.MaxSamples == 0 {
		e.MaxSamples = p.DefaultEvidence.MaxSamples
	}
	if e.MaxBytes == 0 {
		e.MaxBytes = p.DefaultEvidence.MaxBytes
	}
	capEvidence(&e, p.MaxEvidence)
	fillBudget(&b, p.DefaultBudget)
	capBudget(&b, p.MaxBudget)
	m.Evidence, m.Budget = e, b
	return nil
}

// DedupLabels returns the label names listed in dedup_key (comma separated).
func (m RuleMeta) DedupLabels() []string {
	if strings.TrimSpace(m.DedupKey) == "" {
		return nil
	}
	parts := strings.Split(m.DedupKey, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func checkDurations(forD, keep time.Duration, interval *time.Duration, p Policy) error {
	if forD < 0 || forD > p.MaxFor {
		return fmt.Errorf("for %s is outside [0, %s]", forD, p.MaxFor)
	}
	if keep < 0 || keep > p.MaxFor {
		return fmt.Errorf("keep_firing_for %s is outside [0, %s]", keep, p.MaxFor)
	}
	if *interval == 0 {
		*interval = p.DefaultInterval
	}
	if *interval < p.MinInterval || *interval > p.MaxInterval {
		return fmt.Errorf("interval %s is outside [%s, %s]", *interval, p.MinInterval, p.MaxInterval)
	}
	return nil
}

func validateAlert(r *AlertRule, v Validators, p Policy) error {
	if strings.TrimSpace(r.Expr) == "" {
		return errors.New("expr is required")
	}
	if err := checkDurations(r.For, r.KeepFiringFor, &r.GroupInterval, p); err != nil {
		return err
	}
	for k, t := range r.Labels {
		if err := checkTemplate(t); err != nil {
			return fmt.Errorf("label %q: %w", k, err)
		}
	}
	for k, t := range r.Annotations {
		if err := checkTemplate(t); err != nil {
			return fmt.Errorf("annotation %q: %w", k, err)
		}
	}
	if r.Meta.Disabled {
		return nil
	}
	if r.Meta.Class == ClassPromQL {
		if _, err := promParser.ParseExpr(r.Expr); err != nil {
			return fmt.Errorf("promql: %w", err)
		}
		if v.PromQL != nil {
			if err := v.PromQL(*r); err != nil {
				return fmt.Errorf("promql: %w", err)
			}
		}
		return nil
	}
	if v.LogQL != nil {
		if err := v.LogQL(*r); err != nil {
			return fmt.Errorf("logql: %w", err)
		}
	}
	return nil
}

func validateState(r *StateRule, v Validators, p Policy) error {
	switch {
	case r.Version != r.Meta.Version:
		return fmt.Errorf("state rule version %d differs from metadata version %d", r.Version, r.Meta.Version)
	case r.Target != r.Meta.Target:
		return fmt.Errorf("state rule target %q differs from metadata target %q", r.Target, r.Meta.Target)
	case strings.TrimSpace(r.Expr) == "":
		return errors.New("expr is required")
	case len(r.Kinds) == 0:
		return errors.New("kinds are required")
	}
	kinds := map[string]bool{}
	for _, k := range r.Kinds {
		if k == "" || kinds[k] {
			return fmt.Errorf("invalid or duplicate kind %q", k)
		}
		kinds[k] = true
	}
	for k := range r.Labels {
		if !labelPattern.MatchString(k) {
			return fmt.Errorf("label %q is not a valid label name", k)
		}
	}
	if err := checkDurations(r.For, r.KeepFiringFor, &r.Interval, p); err != nil {
		return err
	}
	if r.Meta.Disabled || v.CEL == nil {
		return nil
	}
	if err := v.CEL(*r); err != nil {
		return fmt.Errorf("cel: %w", err)
	}
	return nil
}

var forbiddenTemplateIdents = map[string]bool{
	"query": true, "graphLink": true, "tableLink": true, "externalURL": true, "pathPrefix": true,
	"$externalURL": true, "ExternalURL": true,
}

const templateDefs = "{{$labels := 0}}{{$externalLabels := 0}}{{$externalURL := 0}}{{$value := 0}}"

// checkTemplate rejects template functions that run queries or expand external URLs (PRD R7).
func checkTemplate(text string) error {
	if !strings.Contains(text, "{{") {
		return nil
	}
	t := parse.New("rule")
	t.Mode = parse.SkipFuncCheck
	trees := map[string]*parse.Tree{}
	if _, err := t.Parse(templateDefs+text, "{{", "}}", trees); err != nil {
		return err
	}
	for _, tree := range trees {
		if err := walkTemplate(tree.Root); err != nil {
			return err
		}
	}
	return nil
}

func walkTemplate(n parse.Node) error {
	switch x := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if x == nil {
			return nil
		}
		for _, c := range x.Nodes {
			if err := walkTemplate(c); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		return walkPipe(x.Pipe)
	case *parse.IfNode:
		return walkBranch(&x.BranchNode)
	case *parse.RangeNode:
		return walkBranch(&x.BranchNode)
	case *parse.WithNode:
		return walkBranch(&x.BranchNode)
	case *parse.TemplateNode:
		return walkPipe(x.Pipe)
	}
	return nil
}

func walkBranch(b *parse.BranchNode) error {
	if err := walkPipe(b.Pipe); err != nil {
		return err
	}
	if err := walkTemplate(b.List); err != nil {
		return err
	}
	return walkTemplate(b.ElseList)
}

func walkPipe(p *parse.PipeNode) error {
	if p == nil {
		return nil
	}
	for _, c := range p.Cmds {
		for _, a := range c.Args {
			if err := walkArg(a); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkArg(a parse.Node) error {
	var idents []string
	switch x := a.(type) {
	case *parse.IdentifierNode:
		idents = []string{x.Ident}
	case *parse.VariableNode:
		idents = x.Ident
	case *parse.FieldNode:
		idents = x.Ident
	case *parse.ChainNode:
		idents = x.Field
		if err := walkArg(x.Node); err != nil {
			return err
		}
	case *parse.PipeNode:
		return walkPipe(x)
	}
	for _, id := range idents {
		if forbiddenTemplateIdents[id] {
			return fmt.Errorf("template uses %q, which can run queries or reference external destinations", id)
		}
	}
	return nil
}

// Only returns a copy of b that keeps only the listed rules, for example Result.Active.
func (b *Bundle) Only(ids []string) *Bundle {
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	out := *b
	out.State, out.PromQL, out.LogQL = nil, nil, nil
	for _, r := range b.State {
		if keep[r.ID] {
			out.State = append(out.State, r)
		}
	}
	for _, r := range b.PromQL {
		if keep[r.Meta.ID] {
			out.PromQL = append(out.PromQL, r)
		}
	}
	for _, r := range b.LogQL {
		if keep[r.Meta.ID] {
			out.LogQL = append(out.LogQL, r)
		}
	}
	return &out
}
