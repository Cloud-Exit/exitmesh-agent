// Package validators builds the bundle validators backed by the real rule engines.
package validators

import (
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
)

// For returns validators for a target type; Kubernetes targets validate kube_* use against the published subset.
func For(targetType string) bundle.Validators {
	opts := engine.Options{}
	if targetType == bundle.TargetKubernetes {
		opts.KubeSubset = state.PublishedSubset()
	}
	return bundle.Validators{
		PromQL: func(r bundle.AlertRule) error { return engine.ValidatePromQL(r, opts) },
		LogQL: func(r bundle.AlertRule) error {
			_, err := logql.CompileRule(r.Expr, r.Meta.Budget)
			return err
		},
		CEL: engine.ValidateCEL,
	}
}
