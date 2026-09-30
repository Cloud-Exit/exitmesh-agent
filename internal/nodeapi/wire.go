// Package nodeapi implements the in-cluster HTTPS API between node agents and the coordinator (docs/architecture.md).
package nodeapi

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/metricfacts"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// ContentType is the media type of every request and response body.
const ContentType = "application/cbor"

// Body size caps.
const (
	MaxRequestBytes  = 16 << 20
	MaxResponseBytes = 20 << 20
)

const (
	maxNodeName = 253
	maxID       = 128
	maxVersion  = 256
)

// ErrInvalid reports a message that fails decoding or validation.
var ErrInvalid = errors.New("nodeapi: invalid message")

// ItemKind is the payload type of a queue item.
type ItemKind string

// Item kinds.
const (
	KindFinding     ItemKind = "finding"
	KindMetricFacts ItemKind = "metric_facts"
	KindSeries      ItemKind = "series"
)

// TaskKind is the type of a coordinator task.
type TaskKind string

// Task kinds.
const (
	TaskPromQLQuery TaskKind = "promql_query"
	TaskLogQLQuery  TaskKind = "logql_query"
	TaskLogRead     TaskKind = "log_read"
	TaskEvidence    TaskKind = "evidence_read"
)

// QueueUsage mirrors the node agent queue occupancy.
type QueueUsage struct {
	Bytes    int64  `cbor:"1,keyasint,omitempty"`
	Capacity int64  `cbor:"2,keyasint,omitempty"`
	Items    uint64 `cbor:"3,keyasint,omitempty"`
	Acked    uint64 `cbor:"4,keyasint,omitempty"`
	Next     uint64 `cbor:"5,keyasint,omitempty"`
}

// RegisterRequest is the body of POST /v1/node/register.
type RegisterRequest struct {
	Node          string            `cbor:"1,keyasint"`
	AgentVersion  string            `cbor:"2,keyasint,omitempty"`
	BundleVersion string            `cbor:"3,keyasint,omitempty"`
	Capabilities  []string          `cbor:"4,keyasint,omitempty"`
	Coverage      map[string]string `cbor:"5,keyasint,omitempty"`
	Warming       bool              `cbor:"6,keyasint,omitempty"`
	QueueUsage    QueueUsage        `cbor:"7,keyasint"`
	// Rules are the node-local rule states, at most MaxRuleStatuses, most severe first.
	Rules []RuleStatus `cbor:"8,keyasint,omitempty"`
	// Process is the node agent's user and effective capabilities, so a root agent is visible on the connector.
	Process *Process `cbor:"9,keyasint,omitempty"`
}

// Process is a process identity.
type Process struct {
	UID          int      `cbor:"1,keyasint" json:"uid"`
	GID          int      `cbor:"2,keyasint" json:"gid"`
	Capabilities []string `cbor:"3,keyasint,omitempty" json:"capabilities"`
}

const (
	maxProcessCaps = 64
	maxCapName     = 32
)

// Bounds of the rule states a registration carries.
const (
	MaxRuleStatuses = 1024
	MaxRuleReason   = 512
	maxRuleState    = 64
)

// RuleStatus is one node-local rule state.
type RuleStatus struct {
	RuleID          string `cbor:"1,keyasint"`
	Version         int    `cbor:"2,keyasint,omitempty"`
	State           string `cbor:"3,keyasint"`
	Reason          string `cbor:"4,keyasint,omitempty"`
	LastEvalMs      int64  `cbor:"5,keyasint,omitempty"`
	BudgetLimited   bool   `cbor:"6,keyasint,omitempty"`
	EvidenceLimited bool   `cbor:"7,keyasint,omitempty"`
}

func (r RuleStatus) validate() error {
	if r.RuleID == "" || len(r.RuleID) > maxID || r.State == "" || len(r.State) > maxRuleState || len(r.Reason) > MaxRuleReason {
		return invalid("rule status %q is malformed", r.RuleID)
	}
	return nil
}

// RuleStateRank orders rule states from the most to the least severe for reporting.
func RuleStateRank(state string) int {
	switch state {
	case engine.StateFailed:
		return 0
	case engine.StateBudgetLimited:
		return 1
	case engine.StateEvidenceLimited:
		return 2
	case engine.StateStale:
		return 3
	case engine.StateUnsupported:
		return 4
	case engine.StateConverging:
		return 5
	case engine.StateWarmingUp:
		return 6
	case engine.StateDisabled:
		return 7
	case engine.StateActive:
		return 9
	}
	return 8
}

// RegisterResponse answers a registration.
type RegisterResponse struct {
	TargetBundle string `cbor:"1,keyasint,omitempty"`
	ServerTimeMs int64  `cbor:"2,keyasint"`
}

// Sample is one pre-aggregated series point.
type Sample struct {
	Labels      map[string]string `cbor:"1,keyasint,omitempty"`
	Value       float64           `cbor:"2,keyasint"`
	TimestampMs int64             `cbor:"3,keyasint"`
}

// Part is engine.Part flattened for the wire.
type Part struct {
	RuleID        string   `cbor:"1,keyasint"`
	RuleVersion   int      `cbor:"2,keyasint,omitempty"`
	BundleVersion string   `cbor:"3,keyasint,omitempty"`
	EvalTimeMs    int64    `cbor:"4,keyasint"`
	Samples       []Sample `cbor:"5,keyasint,omitempty"`
}

// Item is one node queue entry.
type Item struct {
	Seq     uint64             `cbor:"1,keyasint"`
	Kind    ItemKind           `cbor:"2,keyasint"`
	Finding []byte             `cbor:"3,keyasint,omitempty"`
	Facts   []metricfacts.Fact `cbor:"4,keyasint,omitempty"`
	Part    *Part              `cbor:"5,keyasint,omitempty"`
}

// SubmitRequest is the body of POST /v1/node/records.
type SubmitRequest struct {
	Node  string `cbor:"1,keyasint"`
	Items []Item `cbor:"2,keyasint,omitempty"`
	// Queue identifies the node queue whose sequence space Items belong to; empty from agents that predate it.
	Queue string `cbor:"3,keyasint,omitempty"`
}

// SubmitResponse acknowledges items durably stored by the coordinator.
type SubmitResponse struct {
	AckedThrough uint64 `cbor:"1,keyasint"`
}

// BundlePayload is a signed rule bundle for distribution to node agents.
type BundlePayload struct {
	Version     string `cbor:"1,keyasint"`
	Archive     []byte `cbor:"2,keyasint"`
	Signature   []byte `cbor:"3,keyasint,omitempty"`
	KeyManifest []byte `cbor:"4,keyasint,omitempty"`
	// KeyManifestChain is forwarded unchanged from the control plane (ascending sequence).
	KeyManifestChain [][]byte `cbor:"5,keyasint,omitempty"`
}

// KubeSeries is one kube_* series value.
type KubeSeries struct {
	Labels map[string]string `cbor:"1,keyasint,omitempty"`
	Value  float64           `cbor:"2,keyasint"`
}

// KubeUpdate is the kube_* series set for one node at a revision.
type KubeUpdate struct {
	Revision uint64       `cbor:"1,keyasint"`
	Series   []KubeSeries `cbor:"2,keyasint,omitempty"`
}

// Task is an investigation or aggregation task assigned to a node.
type Task struct {
	ID         string   `cbor:"1,keyasint"`
	Kind       TaskKind `cbor:"2,keyasint"`
	Payload    []byte   `cbor:"3,keyasint,omitempty"`
	DeadlineMs int64    `cbor:"4,keyasint,omitempty"`
}

// TaskList is the body of a GET /v1/node/tasks response.
type TaskList struct {
	Tasks []Task `cbor:"1,keyasint,omitempty"`
}

// TaskResult is the body of POST /v1/node/tasks/{id}.
type TaskResult struct {
	ID      string `cbor:"1,keyasint"`
	Payload []byte `cbor:"2,keyasint,omitempty"`
	Error   string `cbor:"3,keyasint,omitempty"`
}

// Unknown keys are ignored on decode so node agents and the coordinator can differ by a release.
var decMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:   protocol.MaxNestingDepth,
		MaxArrayElements:  protocol.MaxContainerSize,
		MaxMapPairs:       protocol.MaxContainerSize,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		IntDec:            cbor.IntDecConvertNone,
		UTF8:              cbor.UTF8RejectInvalid,
		NaN:               cbor.NaNDecodeForbidden,
		Inf:               cbor.InfDecodeForbidden,
		DefaultMapType:    reflect.TypeFor[map[string]any](),
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

type validator interface{ validate() error }

type normalizer interface{ normalize() error }

// Marshal validates v when it is an API message and encodes it with deterministic CBOR.
func Marshal(v any) ([]byte, error) {
	if x, ok := v.(validator); ok {
		if err := x.validate(); err != nil {
			return nil, err
		}
	}
	return protocol.Marshal(v)
}

// Unmarshal strictly decodes b into v and validates it, rejecting bodies above MaxResponseBytes.
func Unmarshal(b []byte, v any) error { return decode(b, v, MaxResponseBytes, true) }

func decode(b []byte, v any, limit int64, validate bool) error {
	if int64(len(b)) > limit {
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrInvalid, len(b), limit)
	}
	rest, err := decMode.UnmarshalFirst(b, v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrInvalid, len(rest))
	}
	if n, ok := v.(normalizer); ok {
		if err := n.normalize(); err != nil {
			return err
		}
	}
	if x, ok := v.(validator); ok && validate {
		return x.validate()
	}
	return nil
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func checkNode(n string) error {
	if n == "" || len(n) > maxNodeName {
		return invalid("node name length %d", len(n))
	}
	return nil
}

func validID(id string) bool {
	if id == "" || len(id) > maxID {
		return false
	}
	for _, c := range []byte(id) {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':'
		if !ok {
			return false
		}
	}
	return true
}

func checkFinite(what string, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return invalid("%s is not finite", what)
	}
	return nil
}

func checkLabels(m map[string]string) error {
	for k := range m {
		if k == "" {
			return invalid("empty label name")
		}
	}
	return nil
}

func (r RegisterRequest) validate() error {
	if err := checkNode(r.Node); err != nil {
		return err
	}
	if len(r.BundleVersion) > maxVersion || len(r.AgentVersion) > maxVersion {
		return invalid("version too long")
	}
	if len(r.Rules) > MaxRuleStatuses {
		return invalid("%d rule states exceed %d", len(r.Rules), MaxRuleStatuses)
	}
	for _, rs := range r.Rules {
		if err := rs.validate(); err != nil {
			return err
		}
	}
	if p := r.Process; p != nil {
		if p.UID < 0 || p.GID < 0 || len(p.Capabilities) > maxProcessCaps {
			return invalid("process identity out of range")
		}
		for _, c := range p.Capabilities {
			if c == "" || len(c) > maxCapName {
				return invalid("capability name length %d", len(c))
			}
		}
	}
	return nil
}

func (r BundlePayload) validate() error {
	if r.Version == "" || len(r.Version) > maxVersion {
		return invalid("bundle version length %d", len(r.Version))
	}
	if len(r.Archive) == 0 {
		return invalid("bundle archive is empty")
	}
	return nil
}

func (u KubeUpdate) validate() error {
	for i, s := range u.Series {
		if err := checkLabels(s.Labels); err != nil {
			return err
		}
		if err := checkFinite(fmt.Sprintf("kube series %d value", i), s.Value); err != nil {
			return err
		}
	}
	return nil
}

func (t Task) validate() error {
	if !validID(t.ID) {
		return invalid("task id %q", t.ID)
	}
	if t.Kind == "" {
		return invalid("task %s has no kind", t.ID)
	}
	return nil
}

func (l TaskList) validate() error {
	for _, t := range l.Tasks {
		if err := t.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r TaskResult) validate() error {
	if !validID(r.ID) {
		return invalid("task id %q", r.ID)
	}
	return nil
}

func (p Part) validate() error {
	if p.RuleID == "" {
		return invalid("part has no rule id")
	}
	for i, s := range p.Samples {
		if err := checkLabels(s.Labels); err != nil {
			return err
		}
		if err := checkFinite(fmt.Sprintf("part sample %d value", i), s.Value); err != nil {
			return err
		}
	}
	return nil
}

// claims validates the item and returns the node names its payload names.
func (it Item) claims() ([]string, error) {
	if it.Seq == 0 {
		return nil, invalid("item sequence must be positive")
	}
	var nodes []string
	switch it.Kind {
	case KindFinding:
		if len(it.Facts) != 0 || it.Part != nil {
			return nil, invalid("finding item %d carries other payloads", it.Seq)
		}
		f, err := protocol.DecodeFinding(it.Finding)
		if err != nil {
			return nil, fmt.Errorf("%w: item %d finding: %w", ErrInvalid, it.Seq, err)
		}
		if f.Node != "" {
			nodes = append(nodes, f.Node)
		}
	case KindMetricFacts:
		if len(it.Finding) != 0 || it.Part != nil || len(it.Facts) == 0 {
			return nil, invalid("metric facts item %d is malformed", it.Seq)
		}
		for _, f := range it.Facts {
			if f.Node == "" && f.Pod == "" {
				return nil, invalid("item %d fact identifies no resource", it.Seq)
			}
			if _, err := protocol.NormalizeFields(f.Fields, false); err != nil {
				return nil, fmt.Errorf("%w: item %d fact %s: %w", ErrInvalid, it.Seq, f.Key(), err)
			}
			if f.Node != "" {
				nodes = append(nodes, f.Node)
			}
		}
	case KindSeries:
		if len(it.Finding) != 0 || len(it.Facts) != 0 || it.Part == nil {
			return nil, invalid("series item %d is malformed", it.Seq)
		}
		if err := it.Part.validate(); err != nil {
			return nil, err
		}
		for _, s := range it.Part.Samples {
			if n, ok := s.Labels[engine.LabelNode]; ok {
				nodes = append(nodes, n)
			}
		}
	default:
		return nil, invalid("item %d kind %q", it.Seq, it.Kind)
	}
	return nodes, nil
}

func (it Item) validate() error {
	_, err := it.claims()
	return err
}

func (it *Item) normalize() error {
	for i := range it.Facts {
		if it.Facts[i].Fields == nil {
			continue
		}
		n, err := protocol.NormalizeFields(it.Facts[i].Fields, false)
		if err != nil {
			return fmt.Errorf("%w: item %d fact: %w", ErrInvalid, it.Seq, err)
		}
		it.Facts[i].Fields = n
	}
	return nil
}

// claims validates the request and returns every node name it names, starting with Node.
func (r SubmitRequest) claims() ([]string, error) {
	if err := checkNode(r.Node); err != nil {
		return nil, err
	}
	if len(r.Items) == 0 {
		return nil, invalid("no items")
	}
	if r.Queue != "" && !validID(r.Queue) {
		return nil, invalid("queue id %q", r.Queue)
	}
	nodes := []string{r.Node}
	var prev uint64
	for _, it := range r.Items {
		if it.Seq <= prev {
			return nil, invalid("item sequence %d follows %d", it.Seq, prev)
		}
		prev = it.Seq
		n, err := it.claims()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n...)
	}
	return nodes, nil
}

func (r SubmitRequest) validate() error {
	_, err := r.claims()
	return err
}

func (r *SubmitRequest) normalize() error {
	for i := range r.Items {
		if err := r.Items[i].normalize(); err != nil {
			return err
		}
	}
	return nil
}

// PartFromEngine flattens an engine part, rejecting histogram samples and non-finite values.
func PartFromEngine(p engine.Part) (Part, error) {
	out := Part{RuleID: p.RuleID, RuleVersion: p.RuleVersion, BundleVersion: p.BundleVersion, EvalTimeMs: p.EvalTime.UnixMilli()}
	for _, s := range p.Vector {
		if s.H != nil {
			return Part{}, invalid("rule %s: histogram samples are not supported", p.RuleID)
		}
		out.Samples = append(out.Samples, Sample{Labels: s.Metric.Map(), Value: s.F, TimestampMs: s.T})
	}
	return out, out.validate()
}

// Engine converts the wire part back to an engine part.
func (p Part) Engine() engine.Part {
	out := engine.Part{RuleID: p.RuleID, RuleVersion: p.RuleVersion, BundleVersion: p.BundleVersion, EvalTime: time.UnixMilli(p.EvalTimeMs)}
	if len(p.Samples) > 0 {
		out.Vector = make(promql.Vector, len(p.Samples))
		for i, s := range p.Samples {
			out.Vector[i] = promql.Sample{Metric: labels.FromMap(s.Labels), F: s.Value, T: s.TimestampMs}
		}
	}
	return out
}
