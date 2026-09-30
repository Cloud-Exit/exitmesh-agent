package config

import (
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

func TestPolicyBundleOnlyLowersLimits(t *testing.T) {
	d := bundle.DefaultPolicy()
	strict := Policy{MaxRuleEvalTime: Duration(time.Second), MaxRuleSamples: 10, MaxRuleSeries: 20, MaxCounterBytes: 1 << 10, MaxEvidenceBytes: 512}
	b := strict.Bundle(bundle.TargetHost)
	if b.TargetType != bundle.TargetHost {
		t.Fatalf("target %q", b.TargetType)
	}
	m := b.MaxBudget
	if m.MaxEvalTime != time.Second || m.MaxSamples != 10 || m.MaxSeries != 20 || m.CounterBytes != 1<<10 || b.MaxEvidence.MaxBytes != 512 {
		t.Fatalf("stricter local policy not applied: %+v evidence %+v", m, b.MaxEvidence)
	}
	loose := Policy{MaxRuleEvalTime: Duration(time.Hour), MaxRuleSamples: 1 << 40, MaxRuleSeries: 1 << 40, MaxCounterBytes: 1 << 40, MaxEvidenceBytes: 1 << 40}
	if got := loose.Bundle(bundle.TargetKubernetes); got.MaxBudget != d.MaxBudget || got.MaxEvidence != d.MaxEvidence {
		t.Fatalf("local policy raised the built-in ceilings: %+v %+v", got.MaxBudget, got.MaxEvidence)
	}
	if got := (Policy{}).Bundle(bundle.TargetKubernetes); got.MaxBudget != d.MaxBudget || got.MaxEvidence != d.MaxEvidence {
		t.Fatalf("unset local policy changed the ceilings: %+v", got.MaxBudget)
	}
}
