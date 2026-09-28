package validators

import (
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

func TestFor(t *testing.T) {
	v := For(bundle.TargetKubernetes)
	good := bundle.AlertRule{Expr: `kube_pod_container_status_restarts_total > 3`, Meta: bundle.RuleMeta{Scope: bundle.ScopeNode, Class: bundle.ClassPromQL}}
	if err := v.PromQL(good); err != nil {
		t.Fatalf("valid promql rejected: %v", err)
	}
	bad := bundle.AlertRule{Expr: `kube_not_published_series > 0`, Meta: bundle.RuleMeta{Scope: bundle.ScopeNode, Class: bundle.ClassPromQL}}
	if err := v.PromQL(bad); err == nil {
		t.Fatal("unpublished kube series accepted")
	}
	if err := v.LogQL(bundle.AlertRule{Expr: `sum(count_over_time({namespace="a"} |= "error" [5m])) > 1`}); err != nil {
		t.Fatalf("valid logql rejected: %v", err)
	}
	if err := v.LogQL(bundle.AlertRule{Expr: `{a="b"} | line_format "x"`}); err == nil {
		t.Fatal("unsupported logql accepted")
	}
	if err := v.CEL(bundle.StateRule{ID: "s", Kinds: []string{"Pod"}, Expr: `r.fields["phase"] == "Failed"`, For: time.Minute}); err != nil {
		t.Fatalf("valid cel rejected: %v", err)
	}
	if err := v.CEL(bundle.StateRule{ID: "s", Kinds: []string{"Pod"}, Expr: `r.fields[`}); err == nil {
		t.Fatal("invalid cel accepted")
	}
}
