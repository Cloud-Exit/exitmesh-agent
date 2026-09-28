package refcp_test

import (
	"errors"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

// Scenario 22: two incarnations on one spool; only the highest is accepted and the chain neither forks nor duplicates.
func TestConcurrentIncarnations(t *testing.T) {
	t.Run("successor forks after predecessor committed", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		tid, _, wA := h.target(protocol.TargetKubernetes, "")
		pA := h.start(wA, nil)
		workload(t, wA, "a", 3)
		h.waitDrained(wA)
		storeB := wA.Store.Reopen()
		wB := wA.Clone(storeB)
		e1 := currentEpoch(wA)
		seqX := mustApply(t, wA, deployment("x", 1))
		waitFor(t, "commit of X", func() bool {
			heads, _ := h.cp.Heads(tid)
			return heads[e1].Seq == seqX
		})
		if seqY := mustApply(t, wB, deployment("y", 2)); seqY != seqX {
			t.Fatalf("fork produced seq %d, want %d", seqY, seqX)
		}
		h.start(wB, nil)
		if code := stopCode(pA.exit()); code != client.HaltSuperseded {
			t.Fatalf("predecessor stopped with %q", code)
		}
		if _, err := wA.Apply(deployment("late", 1)); !errors.Is(err, client.ErrHalted) {
			t.Fatalf("halted writer appended: %v", err)
		}
		h.waitDrained(wB)
		eps := h.epochs(tid)
		if len(eps) != 2 || eps[0].Open || eps[0].ClosedAt != seqX || !eps[1].Open {
			t.Fatalf("epochs %+v", eps)
		}
		if eps[1].Owner != wA.Store.WriterID() || eps[1].OpenReason != protocol.OpenRebaseline || *eps[1].PrevEpoch != e1 {
			t.Fatalf("rebaseline epoch %+v", eps[1])
		}
		for id := range wB.Store.Transmitted() {
			if id.Epoch == e1 && id.Seq >= seqX {
				t.Fatalf("successor transmitted forked record %v", id)
			}
		}
		st, _ := h.cp.Stats(tid)
		if st.Duplicates != 0 || st.Divergences != 0 {
			t.Fatalf("stats %+v", st)
		}
		assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{e1: wA, eps[1].ID: wB})
	})
	t.Run("successor supersedes before predecessor transmits", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		tid, _, wA := h.target(protocol.TargetKubernetes, "")
		pA := h.start(wA, nil)
		workload(t, wA, "a", 2)
		h.waitDrained(wA)
		wB := wA.Clone(wA.Store.Reopen())
		h.start(wB, nil)
		if code := stopCode(pA.exit()); code != client.HaltSuperseded {
			t.Fatalf("predecessor stopped with %q", code)
		}
		workload(t, wB, "b", 3)
		h.waitDrained(wB)
		if len(h.epochs(tid)) != 1 {
			t.Fatal("epoch changed")
		}
		if n := auditCount(h.cp, tid, "session_superseded", ""); n != 1 {
			t.Fatalf("superseded audits %d", n)
		}
		assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{currentEpoch(wB): wB})
	})
}

// Scenario 23: an old coordinator reconnecting after its successor is rejected on incarnation regardless of order.
func TestOldCoordinatorAfterSuccessor(t *testing.T) {
	for _, attachedFirst := range []bool{true, false} {
		name := "predecessor never attached"
		if attachedFirst {
			name = "predecessor attached first"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, refcp.Options{})
			tid, _, wA := h.target(protocol.TargetKubernetes, "")
			if attachedFirst {
				pA := h.start(wA, nil)
				workload(t, wA, "a", 2)
				h.waitDrained(wA)
				if err := pA.stop(); err == nil {
					t.Fatal("stop returned nil")
				}
			}
			wB := wA.Clone(wA.Store.Reopen())
			h.start(wB, nil)
			workload(t, wB, "b", 2)
			h.waitDrained(wB)
			workload(t, wA, "stale", 2)
			pOld := h.start(wA, nil)
			if code := stopCode(pOld.exit()); code != protocol.CodeStaleIncarnation {
				t.Fatalf("old coordinator stopped with %q", code)
			}
			if code, _ := wA.Store.Halted(); code != protocol.CodeStaleIncarnation {
				t.Fatalf("old spool halt %q", code)
			}
			if n := auditCount(h.cp, tid, "hello", protocol.CodeStaleIncarnation); n != 1 {
				t.Fatalf("stale incarnation audits %d", n)
			}
			for id := range wA.Store.Transmitted() {
				if _, ok := wB.StateHashes(id.Epoch)[id.Seq]; !ok {
					t.Fatalf("old coordinator transmitted %v", id)
				}
			}
			assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{currentEpoch(wB): wB})
		})
	}
}

// Scenario 24: a new writer closes the old epoch at its head; the returning old writer is rejected writer_retired.
func TestPVCLostOldVolumeReturns(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, tok, wA := h.target(protocol.TargetKubernetes, "")
	pA := h.start(wA, nil)
	workload(t, wA, "a", 3)
	h.waitDrained(wA)
	if err := pA.stop(); err == nil {
		t.Fatal("stop returned nil")
	}
	e1 := currentEpoch(wA)
	committed, _ := wA.Store.LastCommitted()
	workload(t, wA, "unsent", 2)

	storeB := h.newStore("")
	if err := h.enroll(storeB, tok, protocol.TargetKubernetes); err != nil {
		t.Fatal(err)
	}
	wB := clienttest.NewWriter(storeB, h.clock)
	h.prepare(wB)
	h.start(wB, nil)
	workload(t, wB, "b", 2)
	h.waitDrained(wB)

	returned := wA.Clone(wA.Store.Reopen())
	pOld := h.start(returned, nil)
	if code := stopCode(pOld.exit()); code != protocol.CodeWriterRetired {
		t.Fatalf("old volume writer stopped with %q", code)
	}
	eps := h.epochs(tid)
	if len(eps) != 2 || eps[0].ID != e1 || eps[0].Open || eps[0].ClosedAt != committed.Seq || eps[0].Head.Seq != committed.Seq {
		t.Fatalf("old epoch %+v, committed %d", eps[0], committed.Seq)
	}
	if eps[1].Owner != storeB.WriterID() || !eps[1].Open {
		t.Fatalf("new epoch %+v", eps[1])
	}
	if n := auditCount(h.cp, tid, "writer_retired", ""); n != 1 {
		t.Fatalf("retire audits %d", n)
	}
	if n := auditCount(h.cp, tid, "hello", protocol.CodeWriterRetired); n != 1 {
		t.Fatalf("writer_retired rejections %d", n)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{e1: wA, eps[1].ID: wB})
}

// Scenarios 25 and 51: divergence closes the epoch at the committed head, rebaselines, and never reissues a record ID.
func TestDivergenceRebaseline(t *testing.T) {
	t.Run("record rejected as divergent", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		tid, _, w := h.target(protocol.TargetKubernetes, "")
		p := h.start(w, nil)
		workload(t, w, "a", 2)
		h.waitDrained(w)
		e1 := currentEpoch(w)
		head, _ := w.Store.LastCommitted()
		h.cp.RejectNext(protocol.CodeDivergence)
		mustApply(t, w, deployment("z", 1))
		waitFor(t, "rebaseline", func() bool { return currentEpoch(w) != e1 })
		h.waitDrained(w)
		workload(t, w, "b", 2)
		h.waitDrained(w)
		eps := h.epochs(tid)
		if len(eps) != 2 || eps[0].Open || eps[0].ClosedAt != head.Seq {
			t.Fatalf("epochs %+v, head %d", eps, head.Seq)
		}
		recs, _ := h.cp.Records(tid, eps[1].ID)
		ck := recs[0].Checkpoint
		if ck == nil || ck.Reason != protocol.ReasonRebaseline || *ck.PrevEpoch != e1 || *ck.PrevHead != head.Seq {
			t.Fatalf("new epoch does not start with a rebaseline checkpoint: %+v", recs[0].Envelope)
		}
		for id := range w.Store.Transmitted() {
			if id.Epoch == e1 && id.Seq > head.Seq {
				if _, err := h.cp.StateHashAt(tid, e1, id.Seq); err == nil {
					t.Fatalf("void record %v applied", id)
				}
			}
		}
		if n := auditCount(h.cp, tid, "record_rejected", protocol.CodeDivergence); n != 1 {
			t.Fatalf("divergence alarms %d", n)
		}
		if st := p.c.Status(); st.Rebaselines != 1 {
			t.Fatalf("status %+v", st)
		}
		assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{e1: w, eps[1].ID: w})
	})
	t.Run("committed head above the restored spool", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		tid, _, wA := h.target(protocol.TargetKubernetes, "")
		pA := h.start(wA, nil)
		workload(t, wA, "a", 2)
		h.waitDrained(wA)
		backup := wA.Clone(wA.Store.Reopen())
		workload(t, wA, "b", 3)
		h.waitDrained(wA)
		if err := pA.stop(); err == nil {
			t.Fatal("stop returned nil")
		}
		e1 := currentEpoch(wA)
		head, _ := wA.Store.LastCommitted()
		h.start(backup, nil)
		waitFor(t, "rebaseline", func() bool { return currentEpoch(backup) != e1 })
		h.waitDrained(backup)
		eps := h.epochs(tid)
		if len(eps) != 2 || eps[0].ClosedAt != head.Seq || *eps[1].PrevHead != head.Seq {
			t.Fatalf("epochs %+v", eps)
		}
		assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{e1: wA, eps[1].ID: backup})
	})
	t.Run("committed head is not the writer's record", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		tid, _, wA := h.target(protocol.TargetKubernetes, "")
		pA := h.start(wA, nil)
		h.waitDrained(wA)
		fork := wA.Clone(wA.Store.Reopen())
		inherited := fork.Store.Transmitted()
		workload(t, wA, "a", 2)
		h.waitDrained(wA)
		if err := pA.stop(); err == nil {
			t.Fatal("stop returned nil")
		}
		workload(t, fork, "f", 3)
		e1 := currentEpoch(wA)
		head, _ := wA.Store.LastCommitted()
		h.start(fork, nil)
		waitFor(t, "rebaseline", func() bool { return currentEpoch(fork) != e1 })
		h.waitDrained(fork)
		eps := h.epochs(tid)
		if len(eps) != 2 || eps[0].ClosedAt != head.Seq {
			t.Fatalf("epochs %+v", eps)
		}
		for id := range fork.Store.Transmitted() {
			if _, ok := inherited[id]; id.Epoch == e1 && !ok {
				t.Fatalf("fork transmitted %v", id)
			}
		}
		assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{e1: wA, eps[1].ID: fork})
	})
}
