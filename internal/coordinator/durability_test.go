package coordinator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clienttesting "k8s.io/client-go/testing"

	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
}

// changeWhileDown deletes one pod, changes another, and adds a third, as happens while the coordinator is down.
func changeWhileDown(t *testing.T, e *env, image string) {
	t.Helper()
	if err := e.cl.dyn.Tracker().Delete(podGVR, "shop", "web-2"); err != nil {
		t.Fatal(err)
	}
	e.cl.setImage(t, "web-1", image)
	p := toU(t, testPod("web-3", "pod-3", "node-1", "nginx:1.27"), "v1", "Pod")
	if err := e.cl.dyn.Tracker().Create(podGVR, p, "shop"); err != nil {
		t.Fatal(err)
	}
}

func syntheticDelta(rs []*protocol.Record, after uint64) *protocol.Record {
	for _, r := range rs {
		if r.Seq > after && r.Delta != nil && r.Delta.Flags&protocol.FlagSynthetic != 0 && r.Delta.Uncertain != nil {
			return r
		}
	}
	return nil
}

func verifyReconstruction(t *testing.T, e *env, r *running, id protocol.EpochID) uint64 {
	t.Helper()
	_, head := e.committed(r)
	want, err := e.cp.StateHashAt(e.targetID, id, head)
	if err != nil {
		t.Fatal(err)
	}
	if r.c.stateView().Hash() != want {
		t.Fatal("reconstruction at the head differs from the coordinator state")
	}
	if !r.c.stateView().Equal(r.c.tracker.Snapshot()) {
		t.Fatal("chain head differs from the observed cluster")
	}
	return head
}

func TestGracefulRestartResumesEpochWithSyntheticDelta(t *testing.T) {
	e := newEnv(t)
	cfg := e.config()
	r := e.start(cfg)
	id, head := e.committed(r)
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	changeWhileDown(t, e, "nginx:1.29")
	r2 := e.start(cfg)
	if r2.c.sp.Incarnation() != 2 {
		t.Fatalf("incarnation %d", r2.c.sp.Incarnation())
	}
	eventually(t, "synthetic delta committed", func() bool { return syntheticDelta(e.records(id), head) != nil })
	d := syntheticDelta(e.records(id), head)
	kinds := map[string]bool{}
	for _, op := range d.Delta.Ops {
		kinds[op.Kind.String()+":"+op.UID] = true
	}
	if !kinds["delete:pod-2"] || !kinds["create:pod-3"] || !kinds["update:pod-1"] || d.Delta.Uncertain.Start > d.Delta.Uncertain.End {
		t.Fatalf("synthetic delta %+v", d.Delta)
	}
	id2, _ := e.committed(r2)
	if id2 != id || len(e.epochs()) != 1 {
		t.Fatalf("restart changed the epoch: %v", e.epochs())
	}
	verifyReconstruction(t, e, r2, id)
}

func TestCrashRestartResumesEpoch(t *testing.T) {
	e := newEnv(t)
	cfg := e.config()
	r := e.start(cfg)
	id, _ := e.committed(r)
	e.cl.setImage(t, "web-1", "nginx:1.28")
	eventually(t, "delta committed", func() bool { return hasFieldUpdate(e.records(id), "pod-1", "containers.app.image", "nginx:1.28") })
	_, head := e.committed(r)
	crashed := e.stateDir + "-crash"
	copyTree(t, e.stateDir, crashed)
	t.Cleanup(func() { os.RemoveAll(crashed) })
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	changeWhileDown(t, e, "nginx:1.30")
	cfg2 := e.config()
	cfg2.StateDir = crashed
	r2 := e.start(cfg2)
	eventually(t, "synthetic delta after crash", func() bool { return syntheticDelta(e.records(id), head) != nil })
	id2, _ := e.committed(r2)
	if id2 != id || len(e.epochs()) != 1 {
		t.Fatalf("crash restart changed the epoch: %v", e.epochs())
	}
	verifyReconstruction(t, e, r2, id)
	if err := e.cl.dyn.Tracker().Delete(podGVR, "shop", "web-3"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "live delta after recovery", func() bool {
		for _, rec := range e.records(id) {
			if rec.Delta != nil && rec.Delta.Flags&protocol.FlagSynthetic == 0 {
				for _, op := range rec.Delta.Ops {
					if op.Kind == protocol.OpDelete && op.UID == "pod-3" {
						return true
					}
				}
			}
		}
		return false
	})
	verifyReconstruction(t, e, r2, id)
}

func TestOutageLifecycleSummaryNoNotifications(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	id, _ := e.committed(r)
	archive, sig := e.trust.signed(t, "2026.09.1", badImageExpr)
	if err := e.cp.PublishBundle("kubernetes", "2026.09.1", archive, sig, e.trust.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bundle active", func() bool { return r.c.eng.BundleVersion() == "2026.09.1" })
	e.cp.DropAcks(1)
	e.cl.setImage(t, "web-2", "nginx:1.26")
	eventually(t, "commit with a lost acknowledgement", func() bool {
		heads, _ := e.cp.Heads(e.targetID)
		lc, _ := r.c.sp.LastCommitted()
		return hasFieldUpdate(e.records(id), "pod-2", "containers.app.image", "nginx:1.26") && heads[id].Seq > lc.Seq
	})
	e.cp.SetUnavailable(true)
	if err := e.cp.Disconnect(e.targetID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnected", func() bool { return !r.c.cl.Status().Connected })
	anchorsBefore := countCheckpoints(e.records(id))
	e.cl.setImage(t, "web-1", "nginx:bad")
	e.advancing("finding fired offline", 20*time.Second, func() bool { return r.c.fnd.OpenCount() == 1 })
	e.cl.setImage(t, "web-1", "nginx:1.28")
	e.advancing("finding resolved offline", 20*time.Second, func() bool { return r.c.fnd.OpenCount() == 0 })
	e.clock.Advance(7 * time.Hour)
	time.Sleep(100 * time.Millisecond)
	e.cp.SetUnavailable(false)
	eventually(t, "summary received", func() bool {
		ss, _ := e.cp.Summaries(e.targetID)
		for _, s := range ss {
			for _, en := range s.Entries {
				if en.RuleID == "bad-image" && en.State == protocol.LifecycleResolved {
					return true
				}
			}
		}
		return false
	})
	e.committed(r)
	eventually(t, "finding history replayed", func() bool {
		fs := findingsFor(e.findings(), "bad-image")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleResolved
	})
	ns, _ := e.cp.Notifications(e.targetID)
	fid := findingsFor(e.findings(), "bad-image")[0].FindingID
	for _, n := range ns {
		if n.FindingID == fid {
			t.Fatalf("a finding resolved during the outage notified: %+v", n)
		}
	}
	if got := countCheckpoints(e.records(id)) - anchorsBefore; got != 1 {
		t.Fatalf("checkpoints added across the outage: %d, want only the replay anchor", got)
	}
	bs, _ := e.cp.Boundaries(e.targetID)
	if len(bs) != 0 {
		t.Fatalf("replay anchor did not verify: %v", bs)
	}
}

func countCheckpoints(rs []*protocol.Record) int {
	n := 0
	for _, r := range rs {
		if r.Checkpoint != nil {
			n++
		}
	}
	return n
}

func TestSpoolPressureFindingRaisedAndResolved(t *testing.T) {
	e := newEnv(t, withCapacity("48Ki"))
	cfg := e.config()
	cfg.Spool.CoalesceAt = 1
	r := e.start(cfg)
	e.committed(r)
	e.cp.SetUnavailable(true)
	if err := e.cp.Disconnect(e.targetID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnected", func() bool { return !r.c.cl.Status().Connected })
	for i := 0; r.c.sp.Usage().Bytes*100 < r.c.sp.Usage().Capacity*85; i++ {
		img := fmt.Sprintf("nginx:%d", i)
		e.cl.setImage(t, "web-1", img)
		eventually(t, "image observed", func() bool {
			p := r.c.tracker.Snapshot().Resources["pod-1"]
			return p != nil && p.Fields["containers.app.image"] == img
		})
		if i > 5000 {
			t.Fatal("spool did not fill")
		}
	}
	eventually(t, "pressure finding", func() bool { return r.c.health().Spool.Pressure })
	e.cp.SetUnavailable(false)
	eventually(t, "pressure finding delivered", func() bool {
		fs := findingsFor(e.findings(), RuleSpoolPressure)
		return len(fs) == 1 && fs[0].State == protocol.LifecycleFiring
	})
	e.committed(r)
	e.advancing("pressure resolved", 24*time.Hour, func() bool {
		fs := findingsFor(e.findings(), RuleSpoolPressure)
		return len(fs) == 1 && fs[0].State == protocol.LifecycleResolved
	})
	fs := findingsFor(e.findings(), RuleSpoolPressure)
	if fs[0].BundleVersion != NoBundle {
		t.Fatalf("pressure finding provenance %+v", fs[0])
	}
}

func TestRebaselineWhenCoalescedSuffixExceedsCapacity(t *testing.T) {
	e := newEnv(t, withCapacity("24Ki"))
	r := e.start(e.config())
	first, _ := e.committed(r)
	e.cp.SetUnavailable(true)
	if err := e.cp.Disconnect(e.targetID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnected", func() bool { return !r.c.cl.Status().Connected })
	for i := 0; !r.c.rebaselineWanted(); i++ {
		if i > 400 {
			t.Fatal("spool never required a rebaseline")
		}
		name := fmt.Sprintf("burst-%03d", i)
		p := toU(t, testPod(name, "uid-"+name, "node-2", "nginx:1.27"), "v1", "Pod")
		if err := e.cl.dyn.Tracker().Create(podGVR, p, "shop"); err != nil {
			t.Fatal(err)
		}
		eventually(t, "pod observed", func() bool { return r.c.tracker.Snapshot().Resources["uid-"+name] != nil })
	}
	e.cp.SetUnavailable(false)
	eventually(t, "rebaselined epoch in sync", func() bool {
		es := e.epochs()
		if len(es) < 2 {
			return false
		}
		last := es[len(es)-1]
		ep, ok := r.c.sp.Epoch()
		if !ok || ep.ID != last.ID || !last.Open || last.OpenReason != protocol.OpenRebaseline || es[0].ID != first || es[0].Open {
			return false
		}
		if last.Head.Seq != ep.Chain.Head || r.c.health().Chain.Resyncing {
			return false
		}
		h, err := e.cp.StateHashAt(e.targetID, last.ID, last.Head.Seq)
		return err == nil && h == r.c.stateView().Hash() && r.c.stateView().Equal(r.c.tracker.Snapshot())
	})
	if len(r.c.health().Chain.Boundaries) == 0 {
		t.Fatal("rebaseline not reported as a reconstruction boundary")
	}
}

func TestDeferredCommitKeepsSnapshotAheadOfCommittedHead(t *testing.T) {
	e := newEnv(t)
	e.tune = func(t *Tuning) { t.SnapshotEvery = time.Hour }
	r := e.start(e.config())
	id, _ := e.committed(r)
	for i := 0; i < 3; i++ {
		e.cl.setImage(t, "web-1", fmt.Sprintf("nginx:1.%d", 40+i))
		eventually(t, "delta acknowledged", func() bool {
			heads, _ := e.cp.Heads(e.targetID)
			lc, _ := r.c.store.LastCommitted()
			return hasFieldUpdate(e.records(id), "pod-1", "containers.app.image", fmt.Sprintf("nginx:1.%d", 40+i)) && lc.Seq == heads[id].Seq
		})
	}
	st := r.c.store
	st.mu.Lock()
	snapSeq, pending := st.snapSeq, st.pending
	st.mu.Unlock()
	inner, _ := st.ClientStore.LastCommitted()
	if pending == nil || inner.Seq > snapSeq || r.c.sp.Usage().Records == 0 {
		t.Fatalf("commits were not deferred: spool head %d snapshot %d pending %+v", inner.Seq, snapSeq, pending)
	}
	ep, _ := r.c.sp.Epoch()
	var wrong protocol.Hash
	if err := st.Commit(ep.ID, ep.Chain.Head, wrong); err == nil {
		t.Fatal("deferred commit with a foreign chain hash accepted")
	}
	st.flush(true)
	st.mu.Lock()
	snapSeq = st.snapSeq
	st.mu.Unlock()
	if lc, _ := st.ClientStore.LastCommitted(); lc.Seq < pending.seq || snapSeq < lc.Seq {
		t.Fatalf("flush: committed %d, acknowledged %d, snapshot %d", lc.Seq, pending.seq, snapSeq)
	}
}

func TestPermissionLossIsNotDeletionAcrossRestart(t *testing.T) {
	e := newEnv(t)
	e.tune = func(t *Tuning) { t.CollectorRetry = 50 * time.Millisecond }
	cfg := e.config()
	r := e.start(cfg)
	id, head := e.committed(r)
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	var forbid atomic.Bool
	forbid.Store(true)
	e.cl.dyn.PrependReactor("list", "services", func(clienttesting.Action) (bool, runtime.Object, error) {
		if forbid.Load() {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "", errors.New("rbac removed"))
		}
		return false, nil, nil
	})
	r2 := e.start(cfg)
	eventually(t, "scope loss recorded", func() bool { return syntheticDelta(e.records(id), head) != nil })
	d := syntheticDelta(e.records(id), head)
	for _, op := range d.Delta.Ops {
		if op.Kind == protocol.OpDelete && op.UID == "svc-1" {
			t.Fatal("permission loss recorded as deletion")
		}
	}
	if r2.c.stateView().Resources["svc-1"] == nil {
		t.Fatal("service dropped from the chain head while its scope is unavailable")
	}
	if sc := r2.c.stateView().Scopes["Service|"]; sc.State != protocol.ScopeUnavailable {
		t.Fatalf("service scope %+v", sc)
	}
	forbid.Store(false)
	eventually(t, "scope restored", func() bool {
		sc := r2.c.stateView().Scopes["Service|"]
		return sc.State == protocol.ScopeComplete && r2.c.stateView().Equal(r2.c.tracker.Snapshot())
	})
	verifyReconstruction(t, e, r2, id)
}

func TestFailedSpoolCommitKeepsHeadAndResyncEmitsMissingDelta(t *testing.T) {
	e := newEnv(t)
	var fail atomic.Bool
	var failures atomic.Int64
	e.fault = func() error {
		if fail.Load() {
			failures.Add(1)
			return errors.New("injected metadata commit failure")
		}
		return nil
	}
	r := e.start(e.config())
	id, _ := e.committed(r)
	ctx := context.Background()
	n1 := e.nodeClient(t, r, "node-1", "node-1")
	const p95 = "containers.app.metric.memory.p95_bytes"
	facts := []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindMetricFacts, Facts: []metricFact{{Namespace: "shop", Pod: "web-1", Container: "app",
		Fields: map[string]any{"metric.memory.p95_bytes": int64(200 << 20)}}}}}
	fail.Store(true)
	if _, err := n1.Submit(ctx, "", facts); err == nil {
		t.Fatal("metric facts acknowledged while the spool commit fails")
	}
	if v, ok := r.c.stateView().Resources["pod-1"].Fields[p95]; ok {
		t.Fatalf("failed commit published metric fact %v to the chain head", v)
	}
	before := failures.Load()
	e.cl.setImage(t, "web-1", "nginx:1.28")
	eventually(t, "collector append failed", func() bool {
		p := r.c.tracker.Snapshot().Resources["pod-1"]
		return failures.Load() > before && p != nil && p.Fields["containers.app.image"] == "nginx:1.28" && r.c.health().Errors["append"] != ""
	})
	if img := r.c.stateView().Resources["pod-1"].Fields["containers.app.image"]; img != "nginx:1.27" {
		t.Fatalf("failed commit advanced the chain head to image %v", img)
	}
	if _, err := n1.Submit(ctx, "", facts); err == nil {
		t.Fatal("metric facts acknowledged while resynchronization cannot commit")
	}
	fail.Store(false)
	eventually(t, "missing delta emitted by resync", func() bool { return hasFieldUpdate(e.records(id), "pod-1", "containers.app.image", "nginx:1.28") })
	if acked, err := n1.Submit(ctx, "", facts); err != nil || acked != 1 {
		t.Fatalf("retried metric facts: acked %d err %v", acked, err)
	}
	eventually(t, "metric fact delta after the retry", func() bool { return hasFieldUpdate(e.records(id), "pod-1", p95, int64(200<<20)) })
	_, head := e.committed(r)
	want, err := e.cp.StateHashAt(e.targetID, id, head)
	if err != nil {
		t.Fatal(err)
	}
	if r.c.stateView().Hash() != want {
		t.Fatal("reconstruction at the head differs from the coordinator state")
	}
}

func TestRecoveryDeltaFailureKeepsRecoveredHead(t *testing.T) {
	e := newEnv(t)
	var fail atomic.Bool
	e.fault = func() error {
		if fail.Load() {
			return errors.New("injected metadata commit failure")
		}
		return nil
	}
	cfg := e.config()
	r := e.start(cfg)
	id, head := e.committed(r)
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	changeWhileDown(t, e, "nginx:1.29")
	fail.Store(true)
	r2 := e.start(cfg)
	st := r2.c.stateView()
	if st.Resources["pod-2"] == nil || st.Resources["pod-3"] != nil || st.Resources["pod-1"].Fields["containers.app.image"] != "nginx:1.27" {
		t.Fatal("a failed recovery delta advanced the chain head")
	}
	r2.c.statMu.Lock()
	ck := r2.c.stats.LastCheckpoint
	r2.c.statMu.Unlock()
	err := r2.c.store.Do(func(tx client.Tx) error {
		ep, _ := r2.c.store.Epoch()
		return hooks{r2.c}.Rebaseline(captureTx{tx: tx, reason: protocol.ReasonAnchor, epoch: ep})
	})
	if err == nil {
		t.Fatal("checkpoint committed while the spool fails")
	}
	r2.c.statMu.Lock()
	after := r2.c.stats.LastCheckpoint
	r2.c.statMu.Unlock()
	if after != ck {
		t.Fatalf("failed checkpoint recorded in chain stats: %+v, was %+v", after, ck)
	}
	fail.Store(false)
	eventually(t, "synthetic recovery delta after the fault", func() bool { return syntheticDelta(e.records(id), head) != nil })
	verifyReconstruction(t, e, r2, id)
}

func TestFailedCommitRollsBackFindingEpisode(t *testing.T) {
	e := newEnv(t)
	var fail atomic.Bool
	e.fault = func() error {
		if fail.Load() {
			return errors.New("injected metadata commit failure")
		}
		return nil
	}
	r := e.start(e.config())
	id, _ := e.committed(r)
	obs := findings.Observation{Kind: findings.Firing, Query: &findings.QueryProvenance{Hash: protocol.QueryHash("promql", "up", "live"), Requester: "tester"},
		DedupKey: "q|up", Category: "investigation", Severity: protocol.SeverityLow, EvalTime: time.Now(), Summary: "saved"}
	fail.Store(true)
	if err := r.c.saveQueryFinding(obs); err == nil {
		t.Fatal("finding saved while the spool commit fails")
	}
	if n := r.c.fnd.OpenCount(); n != 0 {
		t.Fatalf("failed commit left %d open episodes in the tracker", n)
	}
	fail.Store(false)
	if err := r.c.saveQueryFinding(obs); err != nil {
		t.Fatal(err)
	}
	eventually(t, "firing finding committed after the retry", func() bool {
		for _, rec := range e.records(id) {
			if rec.Finding != nil && rec.Finding.DedupKey == "q|up" && rec.Finding.Transition == protocol.TransitionFiring {
				return true
			}
		}
		return false
	})
}
