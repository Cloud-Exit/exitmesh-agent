package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	fanoutWorkers  = 16
	sourceLive     = "live"
	sourceHost     = "host"
	partCoordinate = "coordinator"
)

// part is one fan-out answer.
type part struct {
	name      string
	node      string
	resp      *TaskResponse
	err       error
	uncovered bool
}

func (s *Service) liveSource() string {
	if s.o.Role == RoleHost {
		return sourceHost
	}
	return sourceLive
}

func decodeTaskResult(tr nodeapi.TaskResult, err error) (*TaskResponse, error) {
	if err != nil {
		return nil, err
	}
	if tr.Error != "" {
		return nil, errors.New(tr.Error)
	}
	var resp TaskResponse
	if err := json.Unmarshal(tr.Payload, &resp); err != nil {
		return nil, fmt.Errorf("malformed task result: %w", err)
	}
	return &resp, nil
}

// live runs a task on the host executor, or on node agents plus optionally the coordinator series.
func (s *Service) live(ctx context.Context, c *call, kind nodeapi.TaskKind, tq TaskQuery, ts telemetryScope, coordinator bool, step time.Duration) []part {
	payload, _ := json.Marshal(tq)
	task := func(i int) nodeapi.Task {
		t := nodeapi.Task{ID: c.req.RequestID + "." + strconv.Itoa(i), Kind: kind, Payload: payload}
		if dl, ok := ctx.Deadline(); ok {
			t.DeadlineMs = dl.UnixMilli()
		}
		return t
	}
	if s.o.Role == RoleHost {
		resp, err := decodeTaskResult(s.o.Local.Execute(ctx, task(0)), nil)
		return []part{{name: sourceHost, node: s.o.Local.o.Node, resp: resp, err: err}}
	}
	var parts []part
	var known []string
	if s.o.Nodes != nil {
		known = s.o.Nodes.Nodes()
	}
	targets := known
	if len(ts.nodes) > 0 {
		targets = nil
		for _, n := range ts.nodes {
			if slicesContains(known, n) {
				targets = append(targets, n)
			} else {
				parts = append(parts, part{name: "node/" + n, node: n, uncovered: true})
			}
		}
	}
	nodeParts := make([]part, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, fanoutWorkers)
	for i, n := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			resp, err := decodeTaskResult(s.o.Nodes.Run(ctx, n, task(i)))
			nodeParts[i] = part{name: "node/" + n, node: n, resp: resp, err: err}
		}()
	}
	if coordinator && s.o.Coordinator != nil {
		start, end := time.UnixMilli(tq.StartMs), time.UnixMilli(tq.EndMs)
		resp, err := evalPromQL(ctx, s.o.Coordinator, tq.Query, start, end, step, tq.Limits, DefaultLookbackDelta)
		parts = append(parts, part{name: partCoordinate, resp: resp, err: err})
	}
	wg.Wait()
	return append(parts, nodeParts...)
}

func slicesContains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// merge combines answers, reports failures and uncovered nodes, and returns the shortest reported retention.
func (s *Service) merge(res *Result, parts []part, forward bool) (Telemetry, time.Duration, int) {
	var out Telemetry
	var retention time.Duration
	ok := 0
	for _, p := range parts {
		st := NodeStatus{Node: p.node, Status: NodeOK}
		switch {
		case p.uncovered:
			st.Status = NodeUncovered
			res.limit("node %s is not covered by a node agent; its data is missing", p.node)
		case p.err != nil:
			st.Status, st.Error = NodeFailed, truncateString(p.err.Error(), maxUpstreamMessage)
			res.limit("%s: query failed: %s", p.name, st.Error)
		default:
			ok++
			r := p.resp
			if out.ResultType == "" {
				out.ResultType = r.Data.ResultType
			}
			for _, l := range r.Limitations {
				res.limit("%s: %s", p.name, l)
			}
			res.Truncated = res.Truncated || r.Truncated
			st.Truncated, st.RetentionMs = r.Truncated, r.RetentionMs
			if d := time.Duration(r.RetentionMs) * time.Millisecond; d > 0 && (retention == 0 || d < retention) {
				retention = d
			}
			for _, sr := range r.Data.Series {
				sr.Source = p.name
				out.Series = append(out.Series, sr)
			}
			for _, l := range r.Data.Lines {
				l.Source = p.name
				out.Lines = append(out.Lines, l)
			}
		}
		if p.node != "" && s.o.Role == RoleCoordinator {
			out.Nodes = append(out.Nodes, st)
		}
	}
	if s.o.Role == RoleCoordinator && len(parts) == 0 {
		res.limit("no node agents are connected and no coordinator series apply; no data was read")
	}
	var limited []string
	if len(out.Lines) > 0 {
		out.Lines, limited = boundLines(out.Lines, res.Limits, forward)
	} else {
		out.Series, limited = boundSeries(out.Series, res.Limits)
	}
	if len(limited) > 0 {
		res.Truncated = true
		res.Limitations = append(res.Limitations, limited...)
	}
	s.redactTelemetry(&out)
	return out, retention, ok
}

const limitationPerSource = "the query aggregates or matches series, but each source evaluated it separately; results are labeled by source and not combined across nodes"

func parseDirection(d string) (bool, error) {
	switch d {
	case "", "backward":
		return false, nil
	case "forward":
		return true, nil
	}
	return false, errorf(ClassInvalid, "direction must be backward or forward")
}

type queryArgs struct {
	Request
	Query     string `json:"query"`
	StepMs    int64  `json:"step_ms,omitempty"`
	Direction string `json:"direction,omitempty"`
	Source    string `json:"source,omitempty"`
	Language  string `json:"language,omitempty"`
}

func (s *Service) promqlQuery(ctx context.Context, c *call) (*Result, error) {
	var a queryArgs
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	if a.Source != "" || a.Language != "" || a.Direction != "" {
		return nil, errorf(ClassInvalid, "promql.query takes query and step_ms; use lookback.query for external sources")
	}
	return s.promqlRun(ctx, c, a)
}

func (s *Service) promqlRun(ctx context.Context, c *call, a queryArgs) (*Result, error) {
	ts, start, end, err := s.telemetry(c)
	if err != nil {
		return nil, err
	}
	norm, err := InjectPromQL(a.Query, ts.matchers())
	if err != nil {
		return nil, err
	}
	reach, err := promReach(norm)
	if err != nil {
		return nil, err
	}
	if err := s.checkReach(reach); err != nil {
		return nil, err
	}
	step, err := stepOf(a.StepMs, start, end)
	if err != nil {
		return nil, err
	}
	src := s.liveSource()
	res := c.newResult(src, LangPromQL, norm, src)
	tq := TaskQuery{Query: norm, StartMs: start.UnixMilli(), EndMs: end.UnixMilli(), StepMs: a.StepMs, Namespaces: ts.namespaces, Nodes: ts.nodes, Limits: c.lim}
	data, retention, ok := s.merge(res, s.live(ctx, c, nodeapi.TaskPromQLQuery, tq, ts, true, step), false)
	if ok > 1 && promAggregates(norm) {
		res.limit(limitationPerSource)
	}
	res.RetentionMs = retention.Milliseconds()
	s.historyLimit(res, start.Add(-reach), retention, true, c.now)
	res.Data = data
	return res, nil
}

func (s *Service) logqlQuery(ctx context.Context, c *call) (*Result, error) {
	var a queryArgs
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	if a.Source != "" || a.Language != "" {
		return nil, errorf(ClassInvalid, "logql.query takes query, step_ms, and direction; use lookback.query for external sources")
	}
	return s.logqlRun(ctx, c, a)
}

func (s *Service) logqlRun(ctx context.Context, c *call, a queryArgs) (*Result, error) {
	ts, start, end, err := s.telemetry(c)
	if err != nil {
		return nil, err
	}
	norm, err := InjectLogQL(a.Query, ts.matchers())
	if err != nil {
		return nil, err
	}
	metric, bare, reach, err := logqlShape(norm)
	if err != nil {
		return nil, err
	}
	if err := s.checkReach(reach); err != nil {
		return nil, err
	}
	step, err := stepOf(a.StepMs, start, end)
	if err != nil {
		return nil, err
	}
	if step > 0 && !metric {
		return nil, errorf(ClassInvalid, "step_ms applies to metric queries only")
	}
	forward, err := parseDirection(a.Direction)
	if err != nil {
		return nil, err
	}
	kind := nodeapi.TaskLogQLQuery
	if bare {
		kind = nodeapi.TaskLogRead
	}
	src := s.liveSource()
	res := c.newResult(src, LangLogQL, norm, src)
	tq := TaskQuery{Query: norm, StartMs: start.UnixMilli(), EndMs: end.UnixMilli(), StepMs: a.StepMs, Forward: forward, Namespaces: ts.namespaces, Nodes: ts.nodes, Limits: c.lim}
	data, _, ok := s.merge(res, s.live(ctx, c, kind, tq, ts, false, step), forward)
	if ok > 1 && logqlAggregates(norm) {
		res.limit(limitationPerSource)
	}
	res.Data = data
	return res, nil
}

// lookupSource resolves a configured source; an unconfigured name is rejected.
func (s *Service) lookupSource(name string) (*source, error) {
	if name == "" {
		return nil, errorf(ClassInvalid, "source is required; configured lookback sources: %v", s.names)
	}
	src := s.sources[name]
	if src == nil {
		return nil, errorf(ClassUnauthorized, "lookback source %q is not configured", name)
	}
	return src, nil
}

func (s *Service) noSource(c *call, lang string) *Result {
	res := c.newResult("lookback", lang, "", "")
	res.limit("no lookback source is configured; %s", LimitationNoLookback)
	c.rec.ErrorClass = ClassUnavailable
	return res
}

func (s *Service) logsqlQuery(ctx context.Context, c *call) (*Result, error) {
	var a queryArgs
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	if a.Language != "" || a.Direction != "" {
		return nil, errorf(ClassInvalid, "logsql.query takes source, query, and step_ms")
	}
	return s.logsqlRun(ctx, c, a)
}

func (s *Service) logsqlRun(ctx context.Context, c *call, a queryArgs) (*Result, error) {
	if a.Source == "" && len(s.sources) == 0 {
		return s.noSource(c, LangLogsQL), nil
	}
	src, err := s.lookupSource(a.Source)
	if err != nil {
		return nil, err
	}
	if src.cfg.Type != config.SourceVictoriaLogs {
		return nil, errorf(ClassInvalid, "logsql.query runs only against VictoriaLogs sources; %s is %s", src.cfg.Name, src.cfg.Type)
	}
	ts, start, end, err := s.telemetry(c)
	if err != nil {
		return nil, err
	}
	hashQ, err := InjectLogsQL(a.Query, ts.namespaces, ts.nodes, time.Time{}, time.Time{})
	if err != nil {
		return nil, err
	}
	execQ, err := InjectLogsQL(a.Query, ts.namespaces, ts.nodes, start, end)
	if err != nil {
		return nil, err
	}
	step, err := stepOf(a.StepMs, start, end)
	if err != nil {
		return nil, err
	}
	stats := isLogsQLStats(execQ, end)
	if step > 0 && !stats {
		return nil, errorf(ClassInvalid, "step_ms applies to stats queries only")
	}
	res := c.newResult(src.cfg.Name, LangLogsQL, hashQ, src.cfg.Name)
	res.Executed = execQ
	return s.runLookback(ctx, c, res, src, lookbackQuery{query: execQ, metric: stats, start: start, end: end, step: step, lim: c.lim}, start)
}

func (s *Service) lookbackQuery(ctx context.Context, c *call) (*Result, error) {
	var a queryArgs
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	return s.lookbackRun(ctx, c, a)
}

func (s *Service) lookbackRun(ctx context.Context, c *call, a queryArgs) (*Result, error) {
	if a.Source == "" && len(s.sources) == 0 {
		return s.noSource(c, a.Language), nil
	}
	src, err := s.lookupSource(a.Source)
	if err != nil {
		return nil, err
	}
	ts, start, end, err := s.telemetry(c)
	if err != nil {
		return nil, err
	}
	step, err := stepOf(a.StepMs, start, end)
	if err != nil {
		return nil, err
	}
	forward, err := parseDirection(a.Direction)
	if err != nil {
		return nil, err
	}
	q := lookbackQuery{start: start, end: end, step: step, forward: forward, lim: c.lim}
	var norm string
	var reach time.Duration
	switch a.Language {
	case LangPromQL, LangMetricsQL:
		if !src.metrics() || (a.Language == LangMetricsQL && src.cfg.Type != config.SourceVictoriaMetrics) {
			return nil, errorf(ClassInvalid, "%s queries cannot run against %s source %s", a.Language, src.cfg.Type, src.cfg.Name)
		}
		if a.Direction != "" {
			return nil, errorf(ClassInvalid, "direction applies to log queries only")
		}
		if a.Language == LangPromQL {
			if norm, err = InjectPromQL(a.Query, ts.matchers()); err == nil {
				reach, err = promReach(norm)
			}
		} else if norm, err = InjectMetricsQL(a.Query, ts.matchers()); err == nil {
			reach, err = metricsqlReach(norm)
		}
		q.query, q.metric = norm, true
	case LangLogQL:
		if src.cfg.Type != config.SourceLoki && src.cfg.Type != config.SourceVictoriaLogs {
			return nil, errorf(ClassInvalid, "logql queries cannot run against %s source %s", src.cfg.Type, src.cfg.Name)
		}
		if norm, err = InjectLogQL(a.Query, ts.matchers()); err == nil {
			q.query = norm
			q.metric, _, reach, err = logqlShape(norm)
		}
		if err == nil && step > 0 && !q.metric {
			err = errorf(ClassInvalid, "step_ms applies to metric queries only")
		}
	default:
		return nil, errorf(ClassInvalid, "language must be promql, metricsql, or logql; native LogsQL uses logsql.query")
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkReach(reach); err != nil {
		return nil, err
	}
	res := c.newResult(src.cfg.Name, a.Language, norm, src.cfg.Name)
	if a.Language == LangLogQL && src.cfg.Type == config.SourceVictoriaLogs {
		if q.metric && step > 0 {
			return nil, errorf(ClassInvalid, "logql cannot be translated to LogsQL: range metric queries have no exact mapping (translation yields instant stats queries); omit step_ms")
		}
		translated, err := logql.ToLogsQL(norm)
		if err != nil {
			return nil, errorf(ClassInvalid, "logql cannot be translated to LogsQL: %v", err)
		}
		if q.query, err = InjectLogsQL(translated, ts.namespaces, ts.nodes, start, end); err != nil {
			return nil, err
		}
		res.Executed = q.query
	}
	return s.runLookback(ctx, c, res, src, q, start.Add(-reach))
}

// runLookback executes on an adapter, reporting retention and failures as limitations.
func (s *Service) runLookback(ctx context.Context, c *call, res *Result, src *source, q lookbackQuery, earliest time.Time) (*Result, error) {
	release, err := src.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if r, known := src.retentionOf(ctx); known {
		res.RetentionMs = r.Milliseconds()
		if earliest.Before(c.now.Add(-r)) {
			res.limit("the query reaches before the retention of lookback source %s (%s); older data has expired", src.cfg.Name, r)
		}
	} else {
		res.limit("the retention of lookback source %s is unknown; expired data cannot be reported", src.cfg.Name)
	}
	var resp *TaskResponse
	switch src.cfg.Type {
	case config.SourceLoki:
		resp, err = src.queryLoki(ctx, q)
	case config.SourceVictoriaLogs:
		resp, err = src.queryVictoriaLogs(ctx, q)
	default:
		resp, err = src.queryMetrics(ctx, q)
	}
	var ue *upstreamError
	if errors.As(err, &ue) {
		res.limit("lookback source %s: %s", src.cfg.Name, ue.msg)
		c.rec.ErrorClass = ue.class
		res.Data = Telemetry{}
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	res.Data, _, _ = s.merge(res, []part{{name: src.cfg.Name, resp: resp}}, q.forward)
	return res, nil
}

// promAggregates reports whether a PromQL query combines series, which per-node evaluation cannot do across nodes.
func promAggregates(query string) bool {
	expr, err := promParser.ParseExpr(query)
	if err != nil {
		return false
	}
	found := false
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		switch x := n.(type) {
		case *parser.AggregateExpr:
			found = true
		case *parser.BinaryExpr:
			found = found || (x.LHS.Type() == parser.ValueTypeVector && x.RHS.Type() == parser.ValueTypeVector)
		}
		return nil
	})
	return found
}

func logqlAggregates(query string) bool {
	e, err := logql.ParseExpr(query)
	if err != nil {
		return false
	}
	var walk func(logql.Expr) bool
	walk = func(e logql.Expr) bool {
		switch x := e.(type) {
		case *logql.VectorAggregation:
			return true
		case *logql.BinaryExpr:
			_, lnum := x.LHS.(*logql.NumberLiteral)
			_, rnum := x.RHS.(*logql.NumberLiteral)
			return (!lnum && !rnum) || walk(x.LHS) || walk(x.RHS)
		}
		return false
	}
	return walk(e)
}
