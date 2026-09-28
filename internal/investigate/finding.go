package investigate

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const (
	maxFindingLabels   = 32
	maxFindingEvidence = findings.DefaultMaxSamples
	defaultCategory    = "investigation"
)

var labelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (s *Service) findingSave(ctx context.Context, c *call) (*Result, error) {
	var a struct {
		Request
		Tool      string            `json:"tool"`
		Query     string            `json:"query"`
		Language  string            `json:"language,omitempty"`
		Source    string            `json:"source,omitempty"`
		StepMs    int64             `json:"step_ms,omitempty"`
		Direction string            `json:"direction,omitempty"`
		Severity  string            `json:"severity"`
		Summary   string            `json:"summary"`
		Category  string            `json:"category,omitempty"`
		Labels    map[string]string `json:"labels,omitempty"`
	}
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	if s.o.SaveFinding == nil {
		return nil, errorf(ClassUnavailable, "saving findings is not available on this agent")
	}
	sev := protocol.ParseSeverity(a.Severity)
	if a.Severity == "" || sev.String() != a.Severity {
		return nil, errorf(ClassInvalid, "severity %q is not a known severity", a.Severity)
	}
	if strings.TrimSpace(a.Summary) == "" || len(a.Summary) > 1024 {
		return nil, errorf(ClassInvalid, "summary is required (at most 1024 bytes)")
	}
	if len(a.Labels) > maxFindingLabels {
		return nil, errorf(ClassInvalid, "at most %d labels", maxFindingLabels)
	}
	for k, v := range a.Labels {
		if !labelNameRE.MatchString(k) || len(v) > 1024 {
			return nil, errorf(ClassInvalid, "label %q is invalid", k)
		}
	}
	qa := queryArgs{Request: a.Request, Query: a.Query, StepMs: a.StepMs, Direction: a.Direction, Source: a.Source, Language: a.Language}
	var (
		res *Result
		err error
	)
	switch a.Tool {
	case ToolPromQL:
		if a.Source != "" || a.Language != "" || a.Direction != "" {
			return nil, errorf(ClassInvalid, "promql.query takes query and step_ms")
		}
		res, err = s.promqlRun(ctx, c, qa)
	case ToolLogQL:
		if a.Source != "" || a.Language != "" {
			return nil, errorf(ClassInvalid, "logql.query takes query, step_ms, and direction")
		}
		res, err = s.logqlRun(ctx, c, qa)
	case ToolLogsQL:
		res, err = s.logsqlRun(ctx, c, qa)
	case ToolLookback:
		res, err = s.lookbackRun(ctx, c, qa)
	default:
		return nil, errorf(ClassInvalid, "tool must be promql.query, logql.query, logsql.query, or lookback.query")
	}
	if err != nil {
		return nil, err
	}
	tel, _ := res.Data.(Telemetry)
	if res.QueryHash == "" || len(tel.Series)+len(tel.Lines) == 0 {
		return nil, errorf(ClassInvalid, "the query returned no data; nothing to save (%s)", strings.Join(res.Limitations, "; "))
	}
	hash, err := protocol.ParseHash(res.QueryHash)
	if err != nil {
		return nil, errorf(ClassInternal, "query hash: %v", err)
	}
	obs := findings.Observation{
		Kind:     findings.Firing,
		Query:    &findings.QueryProvenance{Hash: hash, Requester: c.req.Requester},
		Labels:   a.Labels,
		Category: a.Category,
		Severity: sev,
		EvalTime: c.now,
		Summary:  a.Summary,
		Evidence: evidenceOf(tel),
		Facts: map[string]any{
			"source": res.Source, "language": res.Language, "series": int64(len(tel.Series)), "lines": int64(len(tel.Lines)),
			"truncated": res.Truncated, "window_start": res.Window.Start, "window_end": res.Window.End,
		},
	}
	if obs.Category == "" {
		obs.Category = defaultCategory
	}
	for _, r := range c.scope.resources {
		obs.Resources = append(obs.Resources, r.UID)
	}
	slices.Sort(obs.Resources)
	if nodes := c.scope.telemetryNodes(); len(nodes) == 1 {
		obs.Node = nodes[0]
	}
	if err := s.o.SaveFinding(obs); err != nil {
		return nil, errorf(ClassInternal, "saving finding: %v", err)
	}
	c.rec.RetainedFinding = true
	res.Data = map[string]any{"saved": true, "query_hash": res.QueryHash, "evidence": len(obs.Evidence)}
	return res, nil
}

func evidenceOf(t Telemetry) []protocol.Evidence {
	var out []protocol.Evidence
	for _, l := range t.Lines {
		if len(out) == maxFindingEvidence {
			break
		}
		out = append(out, protocol.Evidence{Source: l.Source, Time: uint64(l.Time.UnixMilli()), Text: l.Text, Labels: l.Labels})
	}
	for _, sr := range t.Series {
		if len(out) == maxFindingEvidence {
			break
		}
		if len(sr.Points) == 0 {
			continue
		}
		p := sr.Points[len(sr.Points)-1]
		out = append(out, protocol.Evidence{Source: sr.Source, Time: uint64(p.T), Text: fmt.Sprintf("%s %s", metricString(sr.Metric), strconv.FormatFloat(p.V, 'g', -1, 64)), Labels: sr.Metric})
	}
	return out
}

func metricString(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "__name__" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + strconv.Quote(m[k])
	}
	return m["__name__"] + "{" + strings.Join(parts, ",") + "}"
}
