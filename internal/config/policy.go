package config

import (
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

// Bundle returns the built-in bundle limits for target, lowered where the local policy is stricter.
func (p Policy) Bundle(target string) bundle.Policy {
	b := bundle.DefaultPolicy()
	b.TargetType = target
	lowerD := func(cur *time.Duration, v time.Duration) {
		if v > 0 && v < *cur {
			*cur = v
		}
	}
	lowerI := func(cur *int, v int) {
		if v > 0 && v < *cur {
			*cur = v
		}
	}
	lowerD(&b.MaxBudget.MaxEvalTime, p.MaxRuleEvalTime.D())
	lowerI(&b.MaxBudget.MaxSamples, p.MaxRuleSamples)
	lowerI(&b.MaxBudget.MaxSeries, p.MaxRuleSeries)
	lowerI(&b.MaxBudget.CounterBytes, int(p.MaxCounterBytes))
	lowerI(&b.MaxEvidence.MaxBytes, int(p.MaxEvidenceBytes))
	return b
}
