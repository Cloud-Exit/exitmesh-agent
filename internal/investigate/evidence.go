package investigate

import (
	"context"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

// LangEvidence labels evidence reads in results and audit records.
const LangEvidence = "evidence"

type evidenceArgs struct {
	Request
	RuleID string `json:"rule_id"`
}

func (s *Service) evidenceQuery(ctx context.Context, c *call) (*Result, error) {
	var a evidenceArgs
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	if a.RuleID == "" || len(a.RuleID) > maxRuleIDLen {
		return nil, errorf(ClassInvalid, "rule_id is required")
	}
	ts, start, end, err := s.telemetry(c)
	if err != nil {
		return nil, err
	}
	src := s.liveSource()
	res := c.newResult(src, LangEvidence, a.RuleID, src)
	tq := TaskQuery{Query: a.RuleID, StartMs: start.UnixMilli(), EndMs: end.UnixMilli(), Namespaces: ts.namespaces, Nodes: ts.nodes, Limits: c.lim}
	data, _, _ := s.merge(res, s.live(ctx, c, nodeapi.TaskEvidence, tq, ts, false, 0), false)
	s.redactTelemetry(&data)
	res.Data = data
	return res, nil
}
