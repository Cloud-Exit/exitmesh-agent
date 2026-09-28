package refcp_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

// Scenario 26: a graceful restart resumes the same epoch and delivers every pending record.
func TestGracefulRestartResumesEpoch(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	workload(t, w, "a", 5)
	mustFire(t, w, "crashloop")
	h.waitDrained(w)
	if err := p.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop: %v", err)
	}
	workload(t, w, "b", 3)
	store2 := w.Store.Reopen()
	w2 := w.Clone(store2)
	h.start(w2, nil)
	h.waitDrained(w2)
	eps := h.epochs(tid)
	if len(eps) != 1 || !eps[0].Open {
		t.Fatalf("epochs %+v", eps)
	}
	var rows []int
	for _, e := range h.cp.Audit(tid) {
		if e.Event == "hello" {
			rows = append(rows, e.Row)
		}
	}
	if len(rows) != 2 || rows[0] != 11 || rows[1] != 10 {
		t.Fatalf("hello rows %v, want [11 10]", rows)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{eps[0].ID: w2})
}

// Scenario 20: commit, lost acknowledgement, spool pressure, reconnect: no duplicate and no rewrite.
func TestCommitLostAckThenPressure(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	workload(t, w, "a", 3)
	h.waitDrained(w)
	h.cp.DisconnectAfterRecords(1)
	h.cp.SetUnavailable(true)
	seqD := mustApply(t, w, protocol.Update("a-1", map[string]any{"image": "nginx:2"}))
	ep := currentEpoch(w)
	waitFor(t, "commit of the unacknowledged record", func() bool {
		heads, _ := h.cp.Heads(tid)
		return heads[ep].Seq == seqD
	})
	waitFor(t, "disconnect", func() bool { return !p.c.Status().Connected })
	es := w.Store.Entries(0)
	if len(es) != 1 || es[0].Seq != seqD || es[0].State != client.TransmittedUnconfirmed {
		t.Fatalf("spool after lost ack: %+v", es)
	}
	sent := bytes.Clone(es[0].Bytes)
	workload(t, w, "b", 2)
	mustFire(t, w, "oom")
	folded, err := w.Store.Coalesce()
	if err != nil || folded < 2 {
		t.Fatalf("coalesce: %d %v", folded, err)
	}
	es = w.Store.Entries(0)
	if es[0].Seq != seqD || !bytes.Equal(es[0].Bytes, sent) || es[0].State != client.TransmittedUnconfirmed {
		t.Fatal("transmitted record changed under coalescing")
	}
	if len(es) != 2 || es[1].Type != protocol.TypeRange {
		t.Fatalf("expected the transmitted record and one range, got %d entries", len(es))
	}
	h.cp.SetUnavailable(false)
	h.waitDrained(w)
	st, _ := h.cp.Stats(tid)
	if st.Duplicates != 0 || st.Divergences != 0 {
		t.Fatalf("stats %+v", st)
	}
	recs, _ := h.cp.Records(tid, ep)
	for _, r := range recs {
		if r.Seq == seqD && !bytes.Equal(r.Bytes(), sent) {
			t.Fatal("committed record rewritten")
		}
	}
	spans, _ := h.cp.Unavailable(tid, ep)
	if len(spans) != 1 {
		t.Fatalf("unavailable spans %v", spans)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{ep: w})
}

// Acknowledgements dropped by the control plane are recovered by the next ack or resume.
func TestDroppedAndDelayedAcks(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	h.start(w, nil)
	h.waitDrained(w)
	h.cp.DropAcks(2)
	h.cp.DelayAcks(20 * time.Millisecond)
	workload(t, w, "a", 4)
	h.waitDrained(w)
	h.cp.DropAcks(1)
	mustApply(t, w, deployment("last", 1))
	ep := currentEpoch(w)
	waitFor(t, "commit", func() bool {
		heads, _ := h.cp.Heads(tid)
		e, _ := w.Store.Epoch()
		return heads[ep].Seq == e.Chain.Head
	})
	if drained(w) {
		t.Fatal("dropped acknowledgement was applied")
	}
	if err := h.cp.Disconnect(tid); err != nil {
		t.Fatal(err)
	}
	h.waitDrained(w)
	st, _ := h.cp.Stats(tid)
	if st.Duplicates != 0 {
		t.Fatalf("resume resent committed records: %+v", st)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{ep: w})
}
