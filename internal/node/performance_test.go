package node

import (
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/rulesdefault"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
)

func benchmarkLogAgent(t testing.TB) *Agent {
	t.Helper()
	archive, err := rulesdefault.Archive(bundle.TargetKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	bun, err := bundle.Parse(archive)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{ring: evidence.New(0), red: redact.Default()}
	set := &logSet{byExpr: map[string]*logRule{}}
	weights := map[string]float64{}
	for _, rule := range bun.LogQL {
		prog, err := logql.CompileRule(rule.Expr, rule.Meta.Budget)
		if err != nil {
			t.Fatal(err)
		}
		set.rules = append(set.rules, &logRule{expr: rule.Expr, prog: prog, ids: []string{rule.Meta.ID}})
		weights[rule.Meta.ID] = 1
	}
	a.ring.SetRules(weights)
	a.logsSet.cur.Store(set)
	return a
}

func benchmarkLogLine(text string) logs.Line {
	return logs.Line{Time: time.Now(), Text: text, Labels: map[string]string{
		"namespace": "production", "pod": "backend-6765dd6f58-abcde", "pod_uid": "01234567-abcd-0123-abcd-0123456789ab", "container": "backend",
		"node": "worker-01", "stream": "stdout", "workload": "backend", "workload_kind": "Deployment",
	}}
}

func BenchmarkDefaultLogRules(b *testing.B) {
	for _, tc := range []struct{ name, text string }{
		{"info", "level=info msg=request completed successfully status=200 duration=30ms " + strings.Repeat("x", 128)},
		{"error", "level=error msg=request failed while calling upstream status=500 duration=30ms " + strings.Repeat("x", 128)},
		{"no_fingerprint", "127.0.0.1 GET /healthz 200 0.001"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			a := benchmarkLogAgent(b)
			line := benchmarkLogLine(tc.text)
			b.ReportAllocs()
			b.SetBytes(int64(len(line.Text)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.onLine(line)
			}
		})
	}
}
