package coordinator

import (
	"slices"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

func TestFindingResources(t *testing.T) {
	resolve := func(kind, ns, name string) (string, bool) {
		if kind == "PersistentVolumeClaim" && ns == "db" && name == "data-0" {
			return "pvc-uid", true
		}
		return "", false
	}
	ref := &bundle.ResourceRef{Kind: "PersistentVolumeClaim", Namespace: "namespace", Name: "persistentvolumeclaim"}
	if got := findingResources(map[string]string{"namespace": "db", "persistentvolumeclaim": "data-0"}, ref, resolve); !slices.Equal(got, []string{"pvc-uid"}) {
		t.Fatalf("got %v", got)
	}
	for _, labels := range []map[string]string{{"namespace": "db"}, {"namespace": "other", "persistentvolumeclaim": "data-0"}} {
		if got := findingResources(labels, ref, resolve); got != nil {
			t.Fatalf("labels %v resolved to %v", labels, got)
		}
	}
	if findingResources(map[string]string{"persistentvolumeclaim": "data-0"}, nil, resolve) != nil {
		t.Fatal("rule without resource_labels resolved")
	}
}
