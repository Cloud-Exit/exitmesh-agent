// Package investigate serves bounded live and lookback investigation tools with AST scope injection (docs/investigation.md).
package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/prometheus/prometheus/storage"
)

// Roles served by a Service.
const (
	RoleCoordinator = "coordinator"
	RoleHost        = "host"
)

// Tool names.
const (
	ToolState       = "state.query"
	ToolGraph       = "graph.query"
	ToolPromQL      = "promql.query"
	ToolLogQL       = "logql.query"
	ToolLogsQL      = "logsql.query"
	ToolLookback    = "lookback.query"
	ToolFindingSave = "finding.save"
	ToolEvidence    = "evidence.query"
)

// Audit outcomes.
const (
	OutcomeOK       = "ok"
	OutcomeLimited  = "limited"
	OutcomeRejected = "rejected"
	OutcomeError    = "error"
)

// LimitationNoLookback is appended when history beyond the in-cluster window is requested without a lookback source.
const LimitationNoLookback = "historical search requires connecting the customer's own monitoring stack as a lookback source"

// Options configures a Service.
type Options struct {
	Role string
	// State returns a snapshot that is not mutated while a call reads it.
	State       func() *protocol.State
	Local       *Executor
	Nodes       NodeRouter
	Coordinator storage.Queryable
	Lookback    []config.Lookback
	HTTPClient  *http.Client
	Limits      config.Investigation
	Audit       func(AuditRecord)
	SaveFinding func(findings.Observation) error
	Clock       func() time.Time
	Redactor    *redact.Redactor
}

// NodeRouter runs tasks on node agents.
type NodeRouter interface {
	Nodes() []string
	Run(ctx context.Context, node string, t nodeapi.Task) (nodeapi.TaskResult, error)
}

// AuditRecord is sanitized call metadata; it never carries credentials or result bodies.
type AuditRecord struct {
	RequestID       string    `json:"request_id"`
	Time            time.Time `json:"time"`
	Requester       string    `json:"requester"`
	Purpose         string    `json:"purpose"`
	Tool            string    `json:"tool"`
	Language        string    `json:"language,omitempty"`
	QueryHash       string    `json:"query_hash,omitempty"`
	Scope           Scope     `json:"scope"`
	Window          *Window   `json:"window,omitempty"`
	Limits          Limits    `json:"limits"`
	Source          string    `json:"source,omitempty"`
	Outcome         string    `json:"outcome"`
	Truncated       bool      `json:"truncated"`
	Limitations     int       `json:"limitations,omitempty"`
	ErrorClass      string    `json:"error_class,omitempty"`
	DurationMs      int64     `json:"duration_ms"`
	RetainedFinding bool      `json:"retained_finding,omitempty"`
}

// Service executes investigation tools; results are never retained.
type Service struct {
	o       Options
	sem     chan struct{}
	sources map[string]*source
	names   []string
	tools   map[string]toolDef
}

type toolDef struct {
	desc   string
	schema json.RawMessage
	run    func(ctx context.Context, c *call) (*Result, error)
}

// call is one validated request in flight.
type call struct {
	raw   json.RawMessage
	req   Request
	lim   Limits
	now   time.Time
	state *protocol.State
	scope *resolvedScope
	rec   *AuditRecord
}

// NewService validates options and lookback sources.
func NewService(o Options) (*Service, error) {
	switch o.Role {
	case RoleCoordinator:
	case RoleHost:
		if o.Local == nil {
			return nil, errors.New("investigate: host role needs a local executor")
		}
	default:
		return nil, fmt.Errorf("investigate: unknown role %q", o.Role)
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Redactor == nil {
		o.Redactor = redact.Default()
	}
	o.Limits = defaultLimits(o.Limits)
	s := &Service{o: o, sem: make(chan struct{}, o.Limits.MaxConcurrency), sources: map[string]*source{}}
	for _, l := range o.Lookback {
		if l.Name == "" || s.sources[l.Name] != nil {
			return nil, errors.New("investigate: lookback sources need unique names")
		}
		src, err := newSource(l, o.HTTPClient)
		if err != nil {
			return nil, fmt.Errorf("investigate: %w", err)
		}
		s.sources[l.Name] = src
		s.names = append(s.names, l.Name)
	}
	slices.Sort(s.names)
	s.tools = map[string]toolDef{
		ToolState:       {stateDesc, stateSchema, s.stateQuery},
		ToolGraph:       {graphDesc, graphSchema, s.graphQuery},
		ToolPromQL:      {promqlDesc, promqlSchema, s.promqlQuery},
		ToolLogQL:       {logqlDesc, logqlSchema, s.logqlQuery},
		ToolLogsQL:      {logsqlDesc, logsqlSchema, s.logsqlQuery},
		ToolLookback:    {lookbackDesc, lookbackSchema, s.lookbackQuery},
		ToolFindingSave: {findingDesc, findingSchema, s.findingSave},
		ToolEvidence:    {evidenceDesc, evidenceSchema, s.evidenceQuery},
	}
	return s, nil
}

// Tools lists the MCP tool definitions.
func (s *Service) Tools() []client.Tool {
	out := make([]client.Tool, 0, len(s.tools))
	for name, t := range s.tools {
		out = append(out, client.Tool{Name: name, Description: t.desc, InputSchema: t.schema})
	}
	slices.SortFunc(out, func(a, b client.Tool) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Call validates and runs one tool call and emits its audit record.
func (s *Service) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	begin := s.o.Clock()
	rec := AuditRecord{Tool: name, Time: begin}
	res, err := s.call(ctx, name, args, &rec)
	rec.DurationMs = s.o.Clock().Sub(begin).Milliseconds()
	switch {
	case err != nil:
		rec.ErrorClass = errClass(err)
		rec.Outcome = OutcomeError
		if rec.ErrorClass == ClassInvalid || rec.ErrorClass == ClassUnauthorized {
			rec.Outcome = OutcomeRejected
		}
	default:
		rec.Truncated = res.Truncated
		rec.Limitations = len(res.Limitations)
		rec.Outcome = OutcomeOK
		if len(res.Limitations) > 0 {
			rec.Outcome = OutcomeLimited
		}
	}
	if s.o.Audit != nil {
		s.o.Audit(rec)
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Service) call(ctx context.Context, name string, args json.RawMessage, rec *AuditRecord) (*Result, error) {
	def, ok := s.tools[name]
	if !ok {
		return nil, errorf(ClassInvalid, "unknown tool %q", name)
	}
	c := &call{raw: args, now: s.o.Clock(), rec: rec}
	if len(args) == 0 {
		c.raw = json.RawMessage("{}")
	}
	if err := json.Unmarshal(c.raw, &c.req); err != nil {
		return nil, errorf(ClassInvalid, "arguments: %v", err)
	}
	verr := c.req.validate()
	rec.RequestID, rec.Requester, rec.Purpose, rec.Scope, rec.Window = c.req.RequestID, c.req.Requester, c.req.Purpose, c.req.Scope, c.req.Window
	if verr != nil {
		return nil, verr
	}
	lim, err := clampLimits(c.req.Limits, s.o.Limits)
	if err != nil {
		return nil, err
	}
	c.lim, rec.Limits = lim, lim
	if s.o.State != nil {
		c.state = s.o.State()
	}
	if c.scope, err = resolveScope(c.req.Scope, c.state); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.timeout())
	defer cancel()
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, errorf(ClassBusy, "investigation concurrency limit %d reached", cap(s.sem))
	}
	res, err := def.run(ctx, c)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errorf(ClassTimeout, "call exceeded its %s timeout", lim.timeout())
		}
		return nil, err
	}
	if res.Limitations == nil {
		res.Limitations = []string{}
	}
	return res, nil
}

// newResult starts a result and records query metadata for audit.
func (c *call) newResult(source, lang, query, hashSource string) *Result {
	r := &Result{Source: source, Limits: c.lim, Language: lang, Query: query, Limitations: []string{}}
	if c.req.Window != nil {
		r.Window = *c.req.Window
	} else {
		r.Window = Window{Start: c.now.UnixMilli(), End: c.now.UnixMilli()}
	}
	c.rec.Source, c.rec.Language = source, lang
	if query != "" {
		r.QueryHash = protocol.QueryHash(lang, query, hashSource).String()
		c.rec.QueryHash = r.QueryHash
	}
	return r
}

// telemetry validates the window and derives the label scope for telemetry queries.
func (s *Service) telemetry(c *call) (telemetryScope, time.Time, time.Time, error) {
	start, end, err := c.req.Window.validate(s.o.Limits.MaxWindow.D(), c.now)
	if err != nil {
		return telemetryScope{}, start, end, err
	}
	ts := telemetryScope{namespaces: c.scope.telemetryNamespaces(), nodes: c.scope.telemetryNodes()}
	if len(ts.namespaces)+len(ts.nodes) == 0 && !c.scope.cluster {
		return ts, start, end, errorf(ClassUnauthorized, "scope binds no namespace or node for a telemetry query")
	}
	if s.o.Role == RoleHost {
		if len(ts.namespaces) > 0 {
			return ts, start, end, errorf(ClassUnauthorized, "host targets have no namespaces")
		}
		for _, n := range ts.nodes {
			if n != s.o.Local.o.Node {
				return ts, start, end, errorf(ClassUnauthorized, "node %s is not this host", n)
			}
		}
		ts.nodes = nil
	}
	return ts, start, end, nil
}

func stepOf(ms int64, start, end time.Time) (time.Duration, error) {
	if ms < 0 {
		return 0, errorf(ClassInvalid, "step_ms must not be negative")
	}
	step := time.Duration(ms) * time.Millisecond
	if step > 0 && int64(end.Sub(start)/step)+1 > maxRangePoints {
		return 0, errorf(ClassInvalid, "range query exceeds %d points per series; increase step_ms", maxRangePoints)
	}
	return step, nil
}

func (s *Service) checkReach(reach time.Duration) error {
	if reach > s.o.Limits.MaxWindow.D() {
		return errorf(ClassInvalid, "query ranges and offsets reach %s, beyond the maximum window %s", reach, s.o.Limits.MaxWindow.D())
	}
	return nil
}

// historyLimit reports I7 when the data a query needs predates the in-cluster retention.
func (s *Service) historyLimit(res *Result, earliest time.Time, retention time.Duration, metrics bool, now time.Time) {
	if retention <= 0 || !earliest.Before(now.Add(-retention)) {
		return
	}
	var compatible []string
	for _, n := range s.names {
		if s.sources[n].metrics() == metrics {
			compatible = append(compatible, n)
		}
	}
	if len(compatible) == 0 {
		res.limit("the query reaches before the in-cluster window (retention %s); %s", retention, LimitationNoLookback)
		return
	}
	res.limit("the query reaches before the in-cluster window (retention %s); extend it with lookback.query against %v", retention, compatible)
}

func (s *Service) redactTelemetry(t *Telemetry) {
	for i := range t.Lines {
		t.Lines[i].Text = s.o.Redactor.String(t.Lines[i].Text)
		for k, v := range t.Lines[i].Labels {
			t.Lines[i].Labels[k] = s.o.Redactor.KeyValue(k, v)
		}
	}
	for i := range t.Series {
		for k, v := range t.Series[i].Metric {
			t.Series[i].Metric[k] = s.o.Redactor.KeyValue(k, v)
		}
	}
}
