package investigate

import (
	"context"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
)

func TestEvidenceQueryIsNonDestructive(t *testing.T) {
	ring := evidence.New(1 << 20)
	ring.SetRules(map[string]float64{"r1": 1})
	now := time.Now()
	ring.Add("r1", evidence.Sample{Time: now.Add(-30 * time.Second), Labels: map[string]string{"namespace": "shop"}, Text: "panic: token=abc123"})
	ring.Add("r1", evidence.Sample{Time: now.Add(-20 * time.Second), Labels: map[string]string{"namespace": "other"}, Text: "fatal error"})
	ring.Add("r1", evidence.Sample{Time: now.Add(-2 * time.Hour), Labels: map[string]string{"namespace": "shop"}, Text: "old line"})
	svc, err := NewService(Options{Role: RoleHost, Local: NewExecutor(ExecOptions{Node: "h1", Evidence: ring})})
	if err != nil {
		t.Fatal(err)
	}
	run := func(rule string) *Result {
		t.Helper()
		v, err := svc.Call(context.Background(), ToolEvidence, args(t, map[string]any{"rule_id": rule, "window": win(time.Hour, 0), "scope": map[string]any{"cluster": true}}))
		if err != nil {
			t.Fatal(err)
		}
		return v.(*Result)
	}
	r := run("r1")
	lines := r.Data.(Telemetry).Lines
	if len(lines) != 2 || lines[0].Text != "fatal error" || lines[1].Text != "panic: token=<redacted>" {
		t.Fatalf("lines %+v", lines)
	}
	if again := run("r1").Data.(Telemetry).Lines; len(again) != 2 {
		t.Fatal("investigation consumed rule evidence")
	}
	if got, _ := ring.Take("r1", 10); len(got) != 3 {
		t.Fatalf("rule evidence lost: %d", len(got))
	}
	if len(run("unknown").Data.(Telemetry).Lines) != 0 {
		t.Fatal("unknown rule returned evidence")
	}
	if _, err := svc.Call(context.Background(), ToolEvidence, args(t, map[string]any{"window": win(time.Hour, 0), "scope": map[string]any{"cluster": true}})); errClass(err) != ClassInvalid {
		t.Fatalf("missing rule id: %v", err)
	}
}

func TestEvidenceExecutorScopesNamespaces(t *testing.T) {
	ring := evidence.New(1 << 20)
	ring.SetRules(map[string]float64{"r1": 1})
	now := time.Now()
	for _, ns := range []string{"shop", "other", "shop"} {
		ring.Add("r1", evidence.Sample{Time: now, Labels: map[string]string{"namespace": ns}, Text: ns})
	}
	resp, errStr := runTask(t, NewExecutor(ExecOptions{Node: "n1", Evidence: ring}), "evidence_read",
		TaskQuery{Query: "r1", StartMs: now.Add(-time.Minute).UnixMilli(), EndMs: now.Add(time.Minute).UnixMilli(), Namespaces: []string{"shop"}, Limits: Limits{MaxLines: 1}})
	if errStr != "" || len(resp.Data.Lines) != 1 || resp.Data.Lines[0].Text != "shop" || !resp.Truncated {
		t.Fatalf("%+v %s", resp, errStr)
	}
	if _, errStr := runTask(t, NewExecutor(ExecOptions{Node: "n1"}), "evidence_read", TaskQuery{Query: "r1", StartMs: now.Add(-time.Minute).UnixMilli(), EndMs: now.UnixMilli()}); errStr == "" {
		t.Fatal("missing ring must be unavailable")
	}
}
