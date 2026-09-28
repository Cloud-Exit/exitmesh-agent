// Package engine evaluates CEL state rules and PromQL and LogQL alerting rules (docs/promql-rules.md).
package engine

import (
	"time"

	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

// Roles decide which rules and which rule parts an engine evaluates.
const (
	RoleNode        = "node"
	RoleCoordinator = "coordinator"
	RoleHost        = "host"
)

// Alert transitions carried by AlertEvent.
const (
	TransitionFiring   = "firing"
	TransitionUpdate   = "update"
	TransitionResolved = "resolved"
	TransitionStale    = "stale"
)

// Per-rule states (PRD R9).
const (
	StateActive          = "active"
	StateUnsupported     = "unsupported"
	StateDisabled        = "disabled"
	StateStale           = "stale"
	StateWarmingUp       = "warming_up"
	StateFailed          = "failed"
	StateBudgetLimited   = "budget_limited"
	StateEvidenceLimited = "evidence_limited"
	StateConverging      = "converging"
)

// Coverage is the completeness of the telemetry a rule evaluates over.
type Coverage int

const (
	CoverageCovered Coverage = iota
	CoverageWarming
	CoverageUncovered
	// CoverageConverging means some contributing nodes run another bundle version.
	CoverageConverging
)

func (c Coverage) String() string {
	switch c {
	case CoverageCovered:
		return "covered"
	case CoverageWarming:
		return "warming"
	case CoverageUncovered:
		return "uncovered"
	case CoverageConverging:
		return "converging"
	}
	return "unknown"
}

// AlertEvent is one alert instance transition emitted to the sink.
type AlertEvent struct {
	RuleID        string
	RuleVersion   int
	BundleVersion string
	Class         string
	Scope         string
	Transition    string
	// InstanceKey is the resource UID for state rules and the canonical label set otherwise.
	InstanceKey  string
	Labels       map[string]string
	Annotations  map[string]string
	Value        float64
	ActiveAt     time.Time
	FiredAt      time.Time
	ResolvedAt   time.Time
	EvalTime     time.Time
	ResourceUIDs []string
	Severity     string
	Category     string
	Summary      string
	// Incomplete is set when the evaluation behind the event did not see all of its inputs.
	Incomplete bool
}

// RuleState reports one rule's evaluation state.
type RuleState struct {
	RuleID       string
	Version      int
	Class        string
	Scope        string
	State        string
	Reason       string
	LastEval     time.Time
	LastDuration time.Duration
	Pending      int
	Firing       int
	BackoffUntil time.Time
}

// Part is one node's pre-aggregated contribution to a cluster rule (PRD M4).
type Part struct {
	RuleID        string
	RuleVersion   int
	BundleVersion string
	EvalTime      time.Time
	Vector        promql.Vector
}

// LogProgram is a compiled LogQL rule expression evaluated over streaming counters.
type LogProgram interface {
	Eval(ts time.Time) (promql.Vector, error)
}

// LogProgramFunc adapts a function to LogProgram.
type LogProgramFunc func(ts time.Time) (promql.Vector, error)

// Eval calls f.
func (f LogProgramFunc) Eval(ts time.Time) (promql.Vector, error) { return f(ts) }

// Policy is the local administrator upper bound on rules. Zero values leave rule budgets uncapped.
type Policy struct {
	MaxEvalTime     time.Duration
	MaxSamples      int
	MaxSeries       int
	MaxComplexity   int
	MaxCounterBytes int
	DisabledRules   []string
	// Capabilities lists the capabilities available to rules; nil means all.
	Capabilities []string
}

// BundleResult carries per-rule outcomes of bundle validation performed before SetBundle.
type BundleResult struct {
	// Unsupported maps rule IDs to the reason they cannot run on this agent.
	Unsupported map[string]string
}

// DefaultBudget fills budget fields a rule leaves unset.
var DefaultBudget = bundle.Budget{
	MaxEvalTime:   10 * time.Second,
	MaxSamples:    1_000_000,
	MaxSeries:     1_000,
	MaxComplexity: 500,
}

// Labels used by pushed pre-aggregated series.
const (
	SplitMetric      = "exitmesh_split"
	LabelRule        = "__exitmesh_rule__"
	LabelRuleVersion = "__exitmesh_rule_version__"
	LabelNode        = "__exitmesh_node__"
	LabelPart        = "__exitmesh_part__"
)
