package coordinator

import (
	"reflect"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestWarningEvidenceNamesEachReasonOnTheFindingResources(t *testing.T) {
	at := time.Date(2026, 11, 7, 3, 0, 0, 0, time.UTC)
	st := protocol.NewState()
	st.Resources["pdb-1"] = &protocol.Resource{
		UID: "pdb-1", Kind: "policy/PodDisruptionBudget", Namespace: "observability", Name: "collector",
		Fields: map[string]any{
			"events.warning.NoPods":                          int64(3),
			"events.warning.CalculateExpectedPodCountFailed": int64(1),
			"events.warning.Stale":                           int64(0),
			"currentHealthy":                                 int64(0),
		},
	}
	st.Resources["node-1"] = &protocol.Resource{
		UID: "node-1", Kind: "Node", Name: "node-a",
		Fields: map[string]any{"events.warning.Rebooted": uint64(1)},
	}

	got := warningEvidence(st, []string{"pdb-1", "node-1", "gone"}, at)
	want := []protocol.Evidence{
		{Source: kubeSource, Time: uint64(at.UnixMilli()), Count: 1, Text: "Warning event CalculateExpectedPodCountFailed on policy/PodDisruptionBudget observability/collector: 1 in the last hour"},
		{Source: kubeSource, Time: uint64(at.UnixMilli()), Count: 3, Text: "Warning event NoPods on policy/PodDisruptionBudget observability/collector: 3 in the last hour"},
		{Source: kubeSource, Time: uint64(at.UnixMilli()), Count: 1, Text: "Warning event Rebooted on Node node-a: 1 in the last hour"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %+v\nwant %+v", got, want)
	}
	if warningEvidence(nil, []string{"pdb-1"}, at) != nil {
		t.Fatal("no state, no evidence")
	}
}
