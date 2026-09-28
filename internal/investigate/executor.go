package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
)

// Executor defaults.
const (
	DefaultLookbackDelta    = 5 * time.Minute
	DefaultReadMaxLines     = 50000
	DefaultReadMaxBytes     = 16 << 20
	DefaultReadMaxScanBytes = 256 << 20
	maxRangePoints          = 11000
)

// ExecOptions configures a node agent or host Executor.
type ExecOptions struct {
	Node      string
	Queryable storage.Queryable
	// Retention reports the local TSDB retention; nil means unknown.
	Retention func() time.Duration
	// PodLogRoot is the /var/log/pods tree; empty disables pod log reads.
	PodLogRoot string
	Enrich     logs.EnrichFunc
	// HostLogPaths are the administrator-allowlisted host log files and directories.
	HostLogPaths []string
	Journal      logql.LineSource
	Evidence     EvidenceReader
	Limits       config.Investigation
	Redactor     *redact.Redactor
	// LookbackDelta is the PromQL staleness window.
	LookbackDelta time.Duration
	// ReadMaxLines and ReadMaxBytes bound lines held by one on-demand read before the pipeline runs.
	ReadMaxLines     int
	ReadMaxBytes     int64
	ReadMaxScanBytes int64
	Clock            func() time.Time
}

// Executor runs investigation tasks against local telemetry and retains nothing.
type Executor struct {
	o   ExecOptions
	sem chan struct{}
}

// TaskQuery is the JSON payload of promql_query, logql_query, and log_read tasks.
type TaskQuery struct {
	Query      string   `json:"query"`
	StartMs    int64    `json:"start_ms"`
	EndMs      int64    `json:"end_ms"`
	StepMs     int64    `json:"step_ms,omitempty"`
	Forward    bool     `json:"forward,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Pods       []string `json:"pods,omitempty"`
	Nodes      []string `json:"nodes,omitempty"`
	Limits     Limits   `json:"limits"`
}

// TaskResponse is the JSON payload of a task result.
type TaskResponse struct {
	Data        Telemetry `json:"data"`
	Truncated   bool      `json:"truncated"`
	Limitations []string  `json:"limitations,omitempty"`
	RetentionMs int64     `json:"retention_ms,omitempty"`
}

// EvidenceReader reads rule evidence without consuming it (evidence.Ring satisfies it).
type EvidenceReader interface {
	Peek(ruleID string, n int) []evidence.Sample
}

// NewExecutor applies defaults.
func NewExecutor(o ExecOptions) *Executor {
	o.Limits = defaultLimits(o.Limits)
	if o.Redactor == nil {
		o.Redactor = redact.Default()
	}
	if o.LookbackDelta <= 0 {
		o.LookbackDelta = DefaultLookbackDelta
	}
	if o.ReadMaxLines <= 0 {
		o.ReadMaxLines = DefaultReadMaxLines
	}
	if o.ReadMaxBytes <= 0 {
		o.ReadMaxBytes = DefaultReadMaxBytes
	}
	if o.ReadMaxScanBytes <= 0 {
		o.ReadMaxScanBytes = DefaultReadMaxScanBytes
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Executor{o: o, sem: make(chan struct{}, o.Limits.MaxConcurrency)}
}

// Execute runs one task; failures are reported in TaskResult.Error.
func (e *Executor) Execute(ctx context.Context, t nodeapi.Task) nodeapi.TaskResult {
	res := nodeapi.TaskResult{ID: t.ID}
	resp, err := e.execute(ctx, t)
	if err == nil {
		res.Payload, err = json.Marshal(resp)
	}
	if err != nil {
		res.Payload = nil
		res.Error = err.Error()
	}
	return res
}

func (e *Executor) execute(ctx context.Context, t nodeapi.Task) (*TaskResponse, error) {
	var q TaskQuery
	if err := decodeStrict(t.Payload, &q); err != nil {
		return nil, err
	}
	lim, err := clampLimits(q.Limits, e.o.Limits)
	if err != nil {
		return nil, err
	}
	w := Window{Start: q.StartMs, End: q.EndMs}
	start, end, err := w.validate(e.o.Limits.MaxWindow.D(), e.o.Clock())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.timeout())
	defer cancel()
	if t.DeadlineMs > 0 {
		var c2 context.CancelFunc
		ctx, c2 = context.WithDeadline(ctx, time.UnixMilli(t.DeadlineMs))
		defer c2()
	}
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return nil, errorf(ClassBusy, "executor busy until the task deadline")
	}
	if len(q.Pods) > 0 && len(q.Namespaces) != 1 {
		return nil, errorf(ClassUnauthorized, "a pod scope needs exactly one namespace")
	}
	m := telemetryScope{namespaces: q.Namespaces, pods: q.Pods, nodes: q.Nodes}.matchers()
	step := time.Duration(q.StepMs) * time.Millisecond
	switch t.Kind {
	case nodeapi.TaskPromQLQuery:
		if err := verifyPromQLScope(q.Query, m); err != nil {
			return nil, err
		}
		if e.o.Queryable == nil {
			return nil, errorf(ClassUnavailable, "metrics are not collected on node %s", e.o.Node)
		}
		resp, err := evalPromQL(ctx, e.o.Queryable, q.Query, start, end, step, lim, e.o.LookbackDelta)
		if err != nil {
			return nil, err
		}
		if e.o.Retention != nil {
			resp.RetentionMs = e.o.Retention().Milliseconds()
		}
		return resp, nil
	case nodeapi.TaskLogQLQuery, nodeapi.TaskLogRead:
		if err := verifyLogQLScope(q.Query, m); err != nil {
			return nil, err
		}
		_, bare, _, err := logqlShape(q.Query)
		if err != nil {
			return nil, err
		}
		if t.Kind == nodeapi.TaskLogRead && !bare {
			return nil, errorf(ClassInvalid, "log_read takes a stream selector without pipeline stages")
		}
		return e.runLogQL(ctx, q, start, end, step, lim)
	}
	if t.Kind == nodeapi.TaskEvidence {
		return e.readEvidence(q, start, end, lim)
	}
	return nil, errorf(ClassInvalid, "unknown task kind %q", t.Kind)
}

func (e *Executor) readEvidence(q TaskQuery, start, end time.Time, lim Limits) (*TaskResponse, error) {
	if q.Query == "" || len(q.Query) > maxRuleIDLen {
		return nil, errorf(ClassInvalid, "evidence_read needs a rule id")
	}
	if e.o.Evidence == nil {
		return nil, errorf(ClassUnavailable, "no evidence ring on %s", e.o.Node)
	}
	resp := &TaskResponse{Data: Telemetry{ResultType: TypeStreams}}
	bytes := 0
	samples := e.o.Evidence.Peek(q.Query, math.MaxInt32)
	for i := len(samples) - 1; i >= 0; i-- {
		s := samples[i]
		if s.Time.Before(start) || s.Time.After(end) {
			continue
		}
		if (len(q.Namespaces) > 0 && !slices.Contains(q.Namespaces, s.Labels[NamespaceLabel])) || (len(q.Pods) > 0 && !slices.Contains(q.Pods, s.Labels[PodLabel])) {
			continue
		}
		if len(resp.Data.Lines) >= lim.MaxLines || int64(bytes+len(s.Text)) > lim.MaxBytes {
			resp.Truncated = true
			break
		}
		bytes += len(s.Text)
		resp.Data.Lines = append(resp.Data.Lines, LogLine{Source: "evidence:" + q.Query, Time: s.Time, Labels: s.Labels, Text: e.o.Redactor.String(s.Text)})
	}
	return resp, nil
}

const maxRuleIDLen = 256

func verifyPromQLScope(query string, m []*labels.Matcher) error {
	expr, err := promParser.ParseExpr(query)
	if err != nil {
		return parseErr(LangPromQL, err)
	}
	var bad error
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if vs, ok := n.(*parser.VectorSelector); ok && bad == nil && !hasAllMatchers(vs.LabelMatchers, m) {
			bad = errorf(ClassUnauthorized, "selector %s is not bound to the task scope", vs.String())
		}
		return nil
	})
	return bad
}

func verifyLogQLScope(query string, m []*labels.Matcher) error {
	expr, err := logql.ParseExpr(query)
	if err != nil {
		return parseErr(LangLogQL, err)
	}
	var bad error
	walkLogQL(expr, func(le *logql.LogExpr, _ time.Duration) {
		if bad == nil && !hasAllMatchers(le.Matchers, m) {
			bad = errorf(ClassUnauthorized, "stream selector is not bound to the task scope")
		}
	})
	return bad
}

// evalPromQL evaluates a PromQL query with an engine sized from lim.
func evalPromQL(ctx context.Context, q storage.Queryable, query string, start, end time.Time, step time.Duration, lim Limits, lookback time.Duration) (*TaskResponse, error) {
	eng := promql.NewEngine(promql.EngineOpts{
		MaxSamples:               lim.MaxSamples,
		Timeout:                  lim.timeout(),
		LookbackDelta:            lookback,
		NoStepSubqueryIntervalFn: func(int64) int64 { return time.Minute.Milliseconds() },
		Parser:                   promParser,
	})
	var (
		qry promql.Query
		err error
	)
	if step > 0 {
		if int64(end.Sub(start)/step)+1 > maxRangePoints {
			return nil, errorf(ClassInvalid, "range query exceeds %d points per series; increase step_ms", maxRangePoints)
		}
		qry, err = eng.NewRangeQuery(ctx, q, nil, query, start, end, step)
	} else {
		qry, err = eng.NewInstantQuery(ctx, q, nil, query, end)
	}
	if err != nil {
		return nil, errorf(ClassInvalid, "promql: %v", err)
	}
	defer qry.Close()
	r := qry.Exec(ctx)
	resp := &TaskResponse{}
	var tooMany promql.ErrTooManySamples
	switch {
	case errors.As(r.Err, &tooMany):
		resp.Truncated = true
		resp.Limitations = append(resp.Limitations, fmt.Sprintf("sample limit %d exceeded; no result", lim.MaxSamples))
		resp.Data.ResultType = TypeVector
		return resp, nil
	case errors.Is(r.Err, context.DeadlineExceeded) || errors.As(r.Err, new(promql.ErrQueryTimeout)):
		return nil, errorf(ClassTimeout, "promql: query timed out")
	case r.Err != nil:
		return nil, errorf(ClassInvalid, "promql: %v", r.Err)
	}
	typ, series, hist, err := fromPromValue(r.Value)
	if err != nil {
		return nil, errorf(ClassInvalid, "promql: %v", err)
	}
	if hist {
		resp.Limitations = append(resp.Limitations, "native histogram samples are omitted")
	}
	warns, _ := r.Warnings.AsStrings(query, 10, 0)
	for _, w := range warns {
		resp.Limitations = append(resp.Limitations, "warning: "+w)
	}
	var limited []string
	resp.Data.ResultType = typ
	resp.Data.Series, limited = boundSeries(series, lim)
	if len(limited) > 0 {
		resp.Truncated = true
		resp.Limitations = append(resp.Limitations, limited...)
	}
	return resp, nil
}

func (e *Executor) runLogQL(ctx context.Context, q TaskQuery, start, end time.Time, step time.Duration, lim Limits) (*TaskResponse, error) {
	st := &readStats{}
	var srcs []logql.LineSource
	if e.o.PodLogRoot != "" {
		srcs = append(srcs, &podSource{e: e, stats: st})
	}
	if len(e.o.HostLogPaths) > 0 {
		srcs = append(srcs, &hostFileSource{paths: e.o.HostLogPaths, scanBudget: e.o.ReadMaxScanBytes, stats: st})
	}
	if e.o.Journal != nil {
		srcs = append(srcs, e.o.Journal)
	}
	if len(srcs) == 0 {
		return nil, errorf(ClassUnavailable, "logs are not collected on node %s", e.o.Node)
	}
	dir := logql.Backward
	if q.Forward {
		dir = logql.Forward
	}
	res, err := logql.RunQuery(ctx, q.Query, multiSource(srcs), logql.Limits{
		Start: start, End: end, Step: step, Direction: dir,
		MaxLines: lim.MaxLines, MaxBytes: int(min(lim.MaxBytes, int64(^uint(0)>>1))),
		MaxSeries: lim.MaxSeries, MaxSamples: lim.MaxSamples, Timeout: lim.timeout(),
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errorf(ClassTimeout, "logql: query timed out")
		}
		return nil, errorf(ClassInvalid, "logql: %v", err)
	}
	resp := &TaskResponse{Truncated: res.Truncated}
	for _, l := range res.Limited {
		resp.Limitations = append(resp.Limitations, "logql limit reached: "+l)
	}
	if st.omitted > 0 {
		resp.Truncated = true
		resp.Limitations = append(resp.Limitations, fmt.Sprintf("on-demand read kept the newest lines; %d older lines were not evaluated", st.omitted))
	}
	if st.scanLimited {
		resp.Truncated = true
		resp.Limitations = append(resp.Limitations, "on-demand read reached its scan byte bound; older data was not read")
	}
	if st.longLines > 0 {
		resp.Limitations = append(resp.Limitations, fmt.Sprintf("%d oversized lines were cut", st.longLines))
	}
	if st.untimed > 0 {
		resp.Limitations = append(resp.Limitations, fmt.Sprintf("%d host file lines carry no timestamp and use the file modification time", st.untimed))
	}
	switch res.Type {
	case logql.ResultStreams:
		resp.Data.ResultType = TypeStreams
		for _, l := range res.Lines {
			resp.Data.Lines = append(resp.Data.Lines, LogLine{Time: l.Time, Labels: e.redactLabels(labelMap(l.Labels)), Text: e.o.Redactor.String(l.Text)})
		}
	case logql.ResultVector:
		_, resp.Data.Series, _, _ = fromPromValue(res.Vector)
		resp.Data.ResultType = TypeVector
	case logql.ResultMatrix:
		_, resp.Data.Series, _, _ = fromPromValue(res.Matrix)
		resp.Data.ResultType = TypeMatrix
	}
	for i := range resp.Data.Series {
		resp.Data.Series[i].Metric = e.redactLabels(resp.Data.Series[i].Metric)
	}
	return resp, nil
}

func (e *Executor) redactLabels(m map[string]string) map[string]string {
	for k, v := range m {
		m[k] = e.o.Redactor.KeyValue(k, v)
	}
	return m
}

// podSource reads /var/log/pods on demand, whether or not a rule tails the stream.
type podSource struct {
	e     *Executor
	stats *readStats
}

func (p *podSource) Scan(ctx context.Context, req logql.SourceRequest, yield func(logql.Line) bool) error {
	o := p.e.o
	res, err := logs.ReadRange(ctx, o.PodLogRoot, req.Match, req.Start, req.End, logs.RangeOptions{
		MaxLines: o.ReadMaxLines, MaxBytes: o.ReadMaxBytes, MaxScanBytes: o.ReadMaxScanBytes, Node: o.Node, Enrich: o.Enrich,
	})
	if err != nil {
		return err
	}
	p.stats.omitted += res.Omitted
	p.stats.scanLimited = p.stats.scanLimited || res.ScanLimited
	for _, l := range res.Lines {
		if l.Truncated {
			p.stats.longLines++
		}
		if !yield(logql.Line{Labels: l.Labels, Time: l.Time, Text: l.Text}) {
			return nil
		}
	}
	return nil
}

type multiSource []logql.LineSource

func (ms multiSource) Scan(ctx context.Context, req logql.SourceRequest, yield func(logql.Line) bool) error {
	stopped := false
	wrapped := func(l logql.Line) bool {
		if !yield(l) {
			stopped = true
		}
		return !stopped
	}
	for _, s := range ms {
		if err := s.Scan(ctx, req, wrapped); err != nil {
			return err
		}
		if stopped {
			return nil
		}
	}
	return nil
}
