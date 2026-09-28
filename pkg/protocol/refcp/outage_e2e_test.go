package refcp_test

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

func outage(t *testing.T, h *harness, tid string, p *proc) {
	t.Helper()
	h.cp.SetUnavailable(true)
	if err := h.cp.Disconnect(tid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "disconnect", func() bool { return !p.c.Status().Connected })
}

// Scenario 29: a 7-day outage replays in order under the rate limit and the pending anchor verifies.
func TestExtendedOutageReplay(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, func(o *client.Options) { o.ReplayBytesPerSecond = 40 << 10 })
	workload(t, w, "live", 3)
	h.waitDrained(w)
	outage(t, h, tid, p)
	for day := 0; day < 7; day++ {
		workload(t, w, fmt.Sprintf("d%d", day), 6)
		mustFire(t, w, fmt.Sprintf("alert-%d", day))
		if day%2 == 1 {
			mustResolve(t, w, fmt.Sprintf("alert-%d", day))
		}
		if day == 3 {
			if n, err := w.Store.Coalesce(); err != nil || n < 2 {
				t.Fatalf("coalesce: %d %v", n, err)
			}
		}
		h.clock.Advance(24 * time.Hour)
	}
	var backlog int64
	for _, e := range w.Store.Entries(0) {
		backlog += int64(len(e.Bytes))
	}
	ep := currentEpoch(w)
	start := time.Now()
	h.cp.SetUnavailable(false)
	waitFor(t, "pending replay anchor", func() bool {
		eps, _ := h.cp.Epochs(tid)
		return len(eps[0].Pending) == 1
	})
	h.waitDrained(w)
	if min := time.Duration(float64(backlog) / float64(40<<10) * 0.9 * float64(time.Second)); time.Since(start) < min {
		t.Fatalf("replay of %d bytes took %v, rate limit implies at least %v", backlog, time.Since(start), min)
	}
	caps := w.Captures()
	if len(caps) != 2 {
		t.Fatalf("captures %d", len(caps))
	}
	wm := caps[1].Watermark
	recs, _ := h.cp.Records(tid, ep)
	var anchor *protocol.Record
	for i, r := range recs {
		if i > 0 && r.Seq <= recs[i-1].Seq {
			t.Fatal("records out of chain order")
		}
		if r.Seq == wm {
			anchor = r
		}
	}
	if anchor == nil || anchor.Checkpoint == nil || anchor.Checkpoint.Reason != protocol.ReasonReplayAnchor {
		t.Fatalf("replay anchor at %d not committed", wm)
	}
	if b, _ := h.cp.Boundaries(tid); len(b) != 0 {
		t.Fatalf("boundaries %+v", b)
	}
	eps := h.epochs(tid)
	if len(eps) != 1 || len(eps[0].Pending) != 0 || eps[0].Watermark != wm {
		t.Fatalf("epoch %+v", eps)
	}
	if spans, _ := h.cp.Unavailable(tid, ep); len(spans) != 1 {
		t.Fatalf("unavailable %v", spans)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{ep: w})
}

// A replay anchor that disagrees with the replayed state opens a reconstruction boundary.
func TestReplayAnchorMismatchBoundary(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	h.waitDrained(w)
	outage(t, h, tid, p)
	workload(t, w, "a", 3)
	w.AnchorMutator = func(s *protocol.State) {
		s.Resources["ghost"] = &protocol.Resource{UID: "ghost", Kind: "Pod", Namespace: "default", Name: "ghost", Fields: map[string]any{}}
	}
	h.cp.SetUnavailable(false)
	h.waitDrained(w)
	caps := w.Captures()
	wm := caps[len(caps)-1].Watermark
	b, _ := h.cp.Boundaries(tid)
	if len(b) != 1 || b[0].Seq != wm || b[0].Expected != caps[len(caps)-1].AnchorHash {
		t.Fatalf("boundaries %+v, watermark %d", b, wm)
	}
	ep := currentEpoch(w)
	want := w.StateHashes(ep)
	for seq := uint64(1); seq < wm; seq++ {
		got, err := h.cp.StateHashAt(tid, ep, seq)
		if err != nil || got != want[seq] {
			t.Fatalf("seq %d below the boundary: %v", seq, err)
		}
	}
	if got, _ := h.cp.StateHashAt(tid, ep, wm); got != caps[len(caps)-1].AnchorHash {
		t.Fatal("reconstruction from the boundary does not use the anchor content")
	}
	if n := auditCount(h.cp, tid, "reconstruction_boundary", ""); n != 1 {
		t.Fatalf("boundary audits %d", n)
	}
}

// Scenario 30: resolved backlog findings never notify, open ones notify once late, events above W notify normally.
func TestLateDeliveryNotifications(t *testing.T) {
	h := newHarness(t, refcp.Options{LateThreshold: 15 * time.Minute})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	h.waitDrained(w)
	f3 := mustFire(t, w, "f3")
	f4 := mustFire(t, w, "f4")
	h.waitDrained(w)
	outage(t, h, tid, p)
	day := 24 * time.Hour
	h.clock.Advance(day)
	f1 := mustFire(t, w, "f1")
	h.clock.Advance(day)
	mustResolve(t, w, "f1")
	h.clock.Advance(day)
	f2 := mustFire(t, w, "f2")
	f2Eval := uint64(h.clock.Now().UnixMilli())
	workload(t, w, "x", 2)
	h.clock.Advance(day)
	mustResolve(t, w, "f3")
	if _, err := w.Update("f4"); err != nil {
		t.Fatal(err)
	}
	if n, err := w.Store.Coalesce(); err != nil || n < 2 {
		t.Fatalf("coalesce %d %v", n, err)
	}
	h.clock.Advance(3 * day)
	h.cpClock.Advance(7 * day)
	h.cp.SetUnavailable(false)
	h.waitDrained(w)
	f5 := mustFire(t, w, "f5")
	h.waitDrained(w)

	sums, _ := h.cp.Summaries(tid)
	if len(sums) != 2 {
		t.Fatalf("summaries %d", len(sums))
	}
	states := map[string]string{}
	for _, e := range sums[1].Entries {
		states[e.FindingID] = e.State
	}
	want := map[string]string{f1: protocol.LifecycleResolved, f2: protocol.LifecycleFiring, f3: protocol.LifecycleResolved, f4: protocol.LifecycleFiring}
	if len(states) != len(want) {
		t.Fatalf("summary %v", states)
	}
	for id, st := range want {
		if states[id] != st {
			t.Fatalf("summary state of %s is %q, want %q", id, states[id], st)
		}
	}
	ns, _ := h.cp.Notifications(tid)
	var got []string
	for _, n := range ns {
		got = append(got, n.FindingID)
	}
	if !slices.Equal(got, []string{f3, f4, f2, f5}) {
		t.Fatalf("notifications %v, want [f3 f4 f2 f5] = %v", got, []string{f3, f4, f2, f5})
	}
	for _, n := range ns[:2] {
		if n.Late || n.LateDelivered || n.Source != refcp.SourceRecord {
			t.Fatalf("live notification %+v", n)
		}
	}
	if n := ns[2]; !n.Late || !n.LateDelivered || n.Source != refcp.SourceSummary || n.EvalTime != f2Eval {
		t.Fatalf("late notification %+v", n)
	}
	if n := ns[3]; n.Late || n.LateDelivered || n.Source != refcp.SourceRecord || n.Seq <= sums[1].Watermark {
		t.Fatalf("post-watermark notification %+v", n)
	}
	fs, _ := h.cp.Findings(tid)
	final := map[string]string{}
	for _, f := range fs {
		final[f.FindingID] = f.State
	}
	if final[f1] != protocol.LifecycleResolved || final[f3] != protocol.LifecycleResolved || final[f2] != protocol.LifecycleFiring || final[f4] != protocol.LifecycleFiring || final[f5] != protocol.LifecycleFiring {
		t.Fatalf("findings %v", final)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{currentEpoch(w): w})
}

// Scenario 56: concurrent finding transitions and state changes during capture keep summary and anchor consistent at W.
func TestSingleWatermarkUnderConcurrency(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	h.waitDrained(w)
	outage(t, h, tid, p)
	for i := 0; i < 8; i++ {
		mustFire(t, w, fmt.Sprintf("k%d", i))
	}
	workload(t, w, "pre", 2)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(g), 7))
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				key := fmt.Sprintf("k%d", rng.IntN(8))
				if _, err := w.Resolve(key); err != nil {
					_, _, _ = w.Fire(key)
				}
				uid := fmt.Sprintf("g%d-%d", g, n)
				_, _ = w.Apply(deployment(uid, n))
			}
		}(g)
	}
	h.cp.SetUnavailable(false)
	waitFor(t, "summary", func() bool {
		s, _ := h.cp.Summaries(tid)
		return len(s) == 2
	})
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
	h.waitDrained(w)

	sums, _ := h.cp.Summaries(tid)
	sum := sums[1]
	ep := currentEpoch(w)
	recs, _ := h.cp.Records(tid, ep)
	type life struct {
		state string
		eval  uint64
	}
	asOfW := map[string]life{}
	touched := map[string]bool{}
	var anchor *protocol.Record
	note := func(seq uint64, f *protocol.Finding) {
		if seq >= sum.Watermark {
			return
		}
		st := protocol.LifecycleFiring
		if f.Transition == protocol.TransitionResolved {
			st = protocol.LifecycleResolved
		}
		asOfW[f.ID] = life{st, f.EvalTime}
		if seq > sum.Head {
			touched[f.ID] = true
		}
	}
	for _, r := range recs {
		switch r.Type {
		case protocol.TypeFinding:
			note(r.Seq, r.Finding)
		case protocol.TypeRange:
			for i := range r.Range.Findings {
				note(r.Range.Findings[i].Seq, &r.Range.Findings[i].Finding)
			}
		case protocol.TypeCheckpoint:
			if r.Seq == sum.Watermark {
				anchor = r
			}
		}
	}
	if len(sum.Entries) != len(touched) {
		t.Fatalf("summary has %d entries, %d findings touched in (%d, %d)", len(sum.Entries), len(touched), sum.Head, sum.Watermark)
	}
	for _, e := range sum.Entries {
		l, ok := asOfW[e.FindingID]
		if !ok || !touched[e.FindingID] || l.state != e.State || l.eval != e.EvalTime {
			t.Fatalf("summary entry %+v disagrees with the chain as of W: %+v", e, l)
		}
	}
	if anchor == nil || anchor.Checkpoint.Reason != protocol.ReasonReplayAnchor {
		t.Fatal("anchor missing at W")
	}
	before, err := h.cp.StateHashAt(tid, ep, sum.Watermark-1)
	if err != nil || before != anchor.Checkpoint.StateHash {
		t.Fatalf("anchor state differs from state at W-1: %v", err)
	}
	if b, _ := h.cp.Boundaries(tid); len(b) != 0 {
		t.Fatalf("boundaries %+v", b)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{ep: w})
}
