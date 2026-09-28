// Package bundle defines the rule bundle format (docs/bundle-format.md): parsing, validation,
// signature and key manifest verification.
package bundle

import "time"

// EngineVersion is the rule engine version implemented by this agent (PRD U1, U4).
const EngineVersion = 1

// Rule classes (PRD R3).
const (
	ClassState  = "state"
	ClassPromQL = "promql"
	ClassLogQL  = "logql"
)

// Evaluation scopes (PRD R4).
const (
	ScopeNode    = "node"
	ScopeCluster = "cluster"
)

// Target types (PRD H7).
const (
	TargetKubernetes = "kubernetes"
	TargetHost       = "host"
)

// Capabilities a rule can require (PRD 5.2).
const (
	CapInventory = "inventory"
	CapMetrics   = "metrics"
	CapLogs      = "logs"
)

// Resolution semantics.
const (
	ResolveRecovery = "recovery"
	ResolveManual   = "manual"
)

// Manifest is bundle.yaml.
type Manifest struct {
	Version       string     `yaml:"version"`
	EngineVersion int        `yaml:"engine_version"`
	SchemaVersion int        `yaml:"schema_version"`
	TargetType    string     `yaml:"target_type"`
	CreatedAt     time.Time  `yaml:"created_at"`
	Rules         []RuleMeta `yaml:"rules"`
}

// RuleMeta carries the metadata of one rule (PRD R4). For PromQL and LogQL rules it references
// an alerting rule in an upstream rule-group file by File, Group, and Alert.
type RuleMeta struct {
	ID      string `yaml:"id"`
	Version int    `yaml:"version"`
	Class   string `yaml:"class"`
	Target  string `yaml:"target"`
	Scope   string `yaml:"scope"`
	File    string `yaml:"file,omitempty"`
	Group   string `yaml:"group,omitempty"`
	Alert   string `yaml:"alert,omitempty"`
	// Match selects among alerting rules sharing File, Group, and Alert by their static labels.
	Match          map[string]string `yaml:"match,omitempty"`
	Category       string            `yaml:"category"`
	Severity       string            `yaml:"severity"`
	RequiredFields []string          `yaml:"required_fields,omitempty"`
	Capabilities   []string          `yaml:"capabilities"`
	Evidence       EvidencePolicy    `yaml:"evidence,omitempty"`
	DedupKey       string            `yaml:"dedup_key,omitempty"`
	Resolution     string            `yaml:"resolution,omitempty"`
	Budget         Budget            `yaml:"budget,omitempty"`
	MinEngine      int               `yaml:"min_engine,omitempty"`
	Disabled       bool              `yaml:"disabled,omitempty"`
	Summary        string            `yaml:"summary,omitempty"`
	// ResourceLabels maps alert labels to affected resources, for example
	// {kind: Pod, namespace: namespace, name: pod}.
	ResourceLabels *ResourceRef `yaml:"resource_labels,omitempty"`
}

// ResourceRef names the alert labels that identify an affected resource.
type ResourceRef struct {
	Kind      string `yaml:"kind"`
	Namespace string `yaml:"namespace,omitempty"`
	Name      string `yaml:"name"`
}

// EvidencePolicy bounds evidence per rule (PRD L5, L7).
type EvidencePolicy struct {
	MaxSamples   int `yaml:"max_samples,omitempty"`
	MaxBytes     int `yaml:"max_bytes,omitempty"`
	ContextLines int `yaml:"context_lines,omitempty"`
}

// Budget bounds evaluation cost per rule (PRD R6).
type Budget struct {
	MaxEvalTime   time.Duration `yaml:"max_eval_time,omitempty"`
	MaxSamples    int           `yaml:"max_samples,omitempty"`
	MaxSeries     int           `yaml:"max_series,omitempty"`
	MaxComplexity int           `yaml:"max_complexity,omitempty"`
	CounterBytes  int           `yaml:"counter_bytes,omitempty"`
}

// StateRule is one rule from state/*.yaml: a CEL predicate over normalized state.
type StateRule struct {
	ID            string            `yaml:"id"`
	Version       int               `yaml:"version"`
	Target        string            `yaml:"target"`
	Kinds         []string          `yaml:"kinds"`
	Expr          string            `yaml:"expr"`
	For           time.Duration     `yaml:"for,omitempty"`
	KeepFiringFor time.Duration     `yaml:"keep_firing_for,omitempty"`
	Interval      time.Duration     `yaml:"interval,omitempty"`
	Labels        map[string]string `yaml:"labels,omitempty"`
	Meta          RuleMeta          `yaml:"-"`
}

// AlertRule is one PromQL or LogQL alerting rule resolved from an upstream rule-group file.
type AlertRule struct {
	Meta          RuleMeta
	File          string
	Group         string
	GroupInterval time.Duration
	Alert         string
	Expr          string
	For           time.Duration
	KeepFiringFor time.Duration
	Labels        map[string]string
	Annotations   map[string]string
}

// Bundle is a parsed, verified rule bundle.
type Bundle struct {
	Manifest Manifest
	Digest   [32]byte
	State    []StateRule
	PromQL   []AlertRule
	LogQL    []AlertRule
	// Files holds the raw archive members for inspection and persistence.
	Files map[string][]byte
}
