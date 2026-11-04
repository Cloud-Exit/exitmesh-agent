package refcp_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

// fireDuringOutage disconnects the writer and fires n findings it can only report in the resume summary.
func fireDuringOutage(t *testing.T, h *harness, tid string, p *proc, w *clienttest.Writer, n int) map[string]bool {
	t.Helper()
	outage(t, h, tid, p)
	fired := map[string]bool{}
	for i := 0; i < n; i++ {
		fired[mustFire(t, w, fmt.Sprintf("outage-%03d", i))] = true
	}
	h.cp.SetUnavailable(false)
	return fired
}

// A summary larger than the control plane's message limit arrives in parts and is acted on once, whole.
func TestResumeSummaryInParts(t *testing.T) {
	h := newHarness(t, refcp.Options{MaxFrameBytes: 4 << 10, Conn: tunnel.ConnOptions{ReadLimit: 8 << 10}})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	h.waitDrained(w)
	earlier, _ := h.cp.Summaries(tid)
	fired := fireDuringOutage(t, h, tid, p, w, 60)
	h.waitDrained(w)

	sums, _ := h.cp.Summaries(tid)
	if len(sums) != len(earlier)+1 {
		t.Fatalf("summaries %d after %d", len(sums), len(earlier))
	}
	got := map[string]bool{}
	for _, e := range sums[len(sums)-1].Entries {
		got[e.FindingID] = true
	}
	if len(got) != len(fired) {
		t.Fatalf("summary holds %d findings, %d fired", len(got), len(fired))
	}
	ns, _ := h.cp.Notifications(tid)
	late := 0
	for _, n := range ns {
		if n.Source == refcp.SourceSummary {
			late++
		}
	}
	if late != len(fired) {
		t.Fatalf("late notifications %d, want %d", late, len(fired))
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{currentEpoch(w): w})
}

// A control plane without summary parts cannot take a summary over its message limit; the writer rebaselines
// instead of reconnecting with it forever.
func TestOversizedWholeSummaryRebaselines(t *testing.T) {
	h := newHarness(t, refcp.Options{WholeSummaries: true, MaxFrameBytes: 4 << 10})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	h.waitDrained(w)
	before := currentEpoch(w)
	earlier, _ := h.cp.Summaries(tid)
	fireDuringOutage(t, h, tid, p, w, 60)
	waitFor(t, "rebaseline", func() bool { return currentEpoch(w) != before })
	h.waitDrained(w)
	sums, _ := h.cp.Summaries(tid)
	for _, sum := range sums[len(earlier):] {
		if sum.Epoch == before {
			t.Fatalf("the oversized summary of epoch %s was delivered", before)
		}
	}
	eps, err := h.cp.Epochs(tid)
	if err != nil || len(eps) != 2 {
		t.Fatalf("epochs %d %v", len(eps), err)
	}
}

// One finding whose summary entry fits no part cannot be delivered even in parts; the writer rebaselines.
func TestSummaryEntryLargerThanAPartRebaselines(t *testing.T) {
	h := newHarness(t, refcp.Options{MaxFrameBytes: 4 << 10, Conn: tunnel.ConnOptions{ReadLimit: 8 << 10}})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	h.waitDrained(w)
	before := currentEpoch(w)
	earlier, _ := h.cp.Summaries(tid)
	outage(t, h, tid, p)
	mustFire(t, w, strings.Repeat("<", 1500))
	h.cp.SetUnavailable(false)
	waitFor(t, "rebaseline", func() bool { return currentEpoch(w) != before })
	h.waitDrained(w)
	sums, _ := h.cp.Summaries(tid)
	for _, sum := range sums[len(earlier):] {
		if sum.Epoch == before {
			t.Fatalf("a summary of epoch %s was delivered", before)
		}
	}
}
