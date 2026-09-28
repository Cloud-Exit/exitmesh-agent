package refcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

// A changed machine ID raises an identity conflict: the host keeps spooling and retrying until resolved.
func TestHostMachineIDConflict(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetHost, "m-1")
	p := h.start(w, nil)
	workload(t, w, "a", 2)
	h.waitDrained(w)
	if err := p.stop(); err == nil {
		t.Fatal("stop returned nil")
	}
	store2 := w.Store.Reopen()
	id := store2.Identity()
	id.MachineID = "m-2"
	if err := store2.SetIdentity(id); err != nil {
		t.Fatal(err)
	}
	w2 := w.Clone(store2)
	p2 := h.start(w2, nil)
	waitFor(t, "identity conflict", func() bool { return p2.c.Status().LastErrorCode == protocol.CodeIdentityConflict })
	workload(t, w2, "spooled", 2)
	waitFor(t, "retries", func() bool { return auditCount(h.cp, tid, "hello", protocol.CodeIdentityConflict) >= 3 })
	if st := p2.c.Status(); st.Halted != "" || st.Connected {
		t.Fatalf("status during conflict %+v", st)
	}
	rows := map[int]int{}
	for _, e := range h.cp.Audit(tid) {
		if e.Code == protocol.CodeIdentityConflict {
			rows[e.Row]++
		}
	}
	if rows[3] != 1 || rows[2] < 2 {
		t.Fatalf("conflict rows %v", rows)
	}
	if err := h.cp.ResolveConflict(tid, "m-2"); err != nil {
		t.Fatal(err)
	}
	h.waitDrained(w2)
	eps := h.epochs(tid)
	if len(eps) != 1 {
		t.Fatalf("epochs %+v", eps)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{eps[0].ID: w2})
}

// A reinstalled host with a new writer conflicts until an administrator binding lets it open a new epoch.
func TestHostRebindingNewWriter(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, tok, wA := h.target(protocol.TargetHost, "m-1")
	pA := h.start(wA, nil)
	workload(t, wA, "a", 2)
	h.waitDrained(wA)
	if err := pA.stop(); err == nil {
		t.Fatal("stop returned nil")
	}
	storeB := h.newStore("m-9")
	if err := h.enroll(storeB, tok, protocol.TargetHost); err != nil {
		t.Fatal(err)
	}
	wB := clienttest.NewWriter(storeB, h.clock)
	h.prepare(wB)
	pB := h.start(wB, nil)
	waitFor(t, "identity conflict", func() bool { return pB.c.Status().LastErrorCode == protocol.CodeIdentityConflict })
	if err := h.cp.BindHost(tid); err != nil {
		t.Fatal(err)
	}
	if err := h.cp.ResolveConflict(tid, "m-9"); err != nil {
		t.Fatal(err)
	}
	h.waitDrained(wB)
	eps := h.epochs(tid)
	if len(eps) != 2 || eps[0].Open || eps[1].Owner != storeB.WriterID() {
		t.Fatalf("epochs %+v", eps)
	}
	hellos := 0
	for _, e := range h.cp.Audit(tid) {
		if e.Event == "hello" && e.Row == 14 {
			hellos++
		}
	}
	if hellos != 1 {
		t.Fatalf("row 14 hellos %d", hellos)
	}
	assertReconstruction(t, h.cp, tid, map[protocol.EpochID]*clienttest.Writer{eps[0].ID: wA, eps[1].ID: wB})
}

// A host group token enrolls each host as a new target.
func TestHostGroupEnrollment(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	_, tok, err := h.cp.CreateHostGroup()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range []string{"m-1", "m-2"} {
		s := h.newStore(m)
		if err := h.enroll(s, tok, protocol.TargetHost); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.Identity().TargetID)
		w := clienttest.NewWriter(s, h.clock)
		h.prepare(w)
		h.start(w, nil)
		h.waitDrained(w)
	}
	if ids[0] == ids[1] {
		t.Fatal("group enrollment reused a target")
	}
	if err := h.enroll(h.newStore("m-3"), tok, protocol.TargetKubernetes); err == nil {
		t.Fatal("group token enrolled a cluster")
	}
}

func TestCredentialRotation(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	h.waitDrained(w)
	old := w.Store.Identity().Credential
	credID, err := h.cp.RotateCredential(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	id := w.Store.Identity()
	if id.CredentialID != credID || id.Credential == old || id.Credential == "" {
		t.Fatalf("identity after rotation %+v", id)
	}
	if err := h.cp.Disconnect(tid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reconnect", func() bool { return p.c.Status().Sessions == 2 && p.c.Status().Connected })
	mustApply(t, w, deployment("after", 1))
	h.waitDrained(w)
	var last refcp.AuditEntry
	for _, e := range h.cp.Audit(tid) {
		if e.Event == "hello" {
			last = e
		}
	}
	if last.Credential != credID {
		t.Fatalf("reconnected with %s, want %s", last.Credential, credID)
	}
	if err := p.stop(); err == nil {
		t.Fatal("stop returned nil")
	}
	stale := w.Clone(w.Store.Reopen())
	sid := stale.Store.Identity()
	sid.Credential = old
	if err := stale.Store.SetIdentity(sid); err != nil {
		t.Fatal(err)
	}
	if code := stopCode(h.start(stale, nil).exit()); code != protocol.CodeUnauthorized {
		t.Fatalf("old credential: %q", code)
	}
}

func TestDeenrollment(t *testing.T) {
	t.Run("by the control plane", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		tid, tok, w := h.target(protocol.TargetKubernetes, "")
		p := h.start(w, nil)
		h.waitDrained(w)
		if err := h.cp.Deenroll(tid); err != nil {
			t.Fatal(err)
		}
		if code := stopCode(p.exit()); code != client.HaltDeenrolled {
			t.Fatalf("stopped with %q", code)
		}
		if id := w.Store.Identity(); id.Credential != "" || id.CredentialID != "" {
			t.Fatalf("credential kept: %+v", id)
		}
		if err := h.enroll(h.newStore(""), tok, protocol.TargetKubernetes); err == nil {
			t.Fatal("de-enrolled target accepted enrollment")
		}
	})
	t.Run("by the writer", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		tid, _, w := h.target(protocol.TargetKubernetes, "")
		p := h.start(w, nil)
		h.waitDrained(w)
		if err := p.c.Deenroll(context.Background(), "uninstall"); err != nil {
			t.Fatal(err)
		}
		if code := stopCode(p.exit()); code != client.HaltDeenrolled {
			t.Fatalf("stopped with %q", code)
		}
		if n := auditCount(h.cp, tid, "deenrolled", ""); n != 1 {
			t.Fatalf("deenroll audits %d", n)
		}
		if w.Store.Identity().Credential != "" {
			t.Fatal("credential kept")
		}
	})
}

// Hello rejections that require stopping halt the spool; retryable ones keep spooling.
func TestHelloRejectionCodes(t *testing.T) {
	for _, code := range []string{protocol.CodeUnauthorized, protocol.CodeWriterRetired, protocol.CodeEpochClosed, protocol.CodeNotOwner, protocol.CodeStaleIncarnation} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t, refcp.Options{})
			_, _, w := h.target(protocol.TargetKubernetes, "")
			h.cp.RejectNextHello(code)
			if got := stopCode(h.start(w, nil).exit()); got != code {
				t.Fatalf("stopped with %q", got)
			}
			if halted, _ := w.Store.Halted(); halted != code {
				t.Fatalf("halt %q", halted)
			}
			if _, err := w.Apply(deployment("x", 1)); !errors.Is(err, client.ErrHalted) {
				t.Fatalf("append after stop: %v", err)
			}
		})
	}
	for _, code := range []string{protocol.CodeIdentityConflict, protocol.CodeInvalidHello} {
		t.Run(code, func(t *testing.T) {
			h := newHarness(t, refcp.Options{})
			_, _, w := h.target(protocol.TargetKubernetes, "")
			h.cp.RejectNextHello(code)
			h.start(w, nil)
			h.waitDrained(w)
		})
	}
	t.Run("unknown credential at upgrade", func(t *testing.T) {
		h := newHarness(t, refcp.Options{})
		_, _, w := h.target(protocol.TargetKubernetes, "")
		id := w.Store.Identity()
		id.Credential = "not-a-credential"
		if err := w.Store.SetIdentity(id); err != nil {
			t.Fatal(err)
		}
		if got := stopCode(h.start(w, nil).exit()); got != protocol.CodeUnauthorized {
			t.Fatalf("stopped with %q", got)
		}
	})
}

func TestInvestigationToolsBundlesHealthCompat(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	fetched := make(chan *protocol.BundleFetchResult, 1)
	var p *proc
	w.OnBundle = func(b protocol.BundleAvailableParams) {
		res, err := p.c.FetchBundle(context.Background(), "")
		if err != nil {
			t.Error(err)
			return
		}
		fetched <- res
	}
	p = h.start(w, func(o *client.Options) { o.HealthInterval = 10 * time.Millisecond })
	mustApply(t, w, deployment("a", 1), deployment("b", 2))
	h.waitDrained(w)
	ctx := context.Background()

	tools, err := h.cp.ListTools(ctx, tid)
	if err != nil || len(tools) != 1 || tools[0].Name != "state.query" {
		t.Fatalf("tools %+v %v", tools, err)
	}
	res, err := h.cp.CallTool(ctx, tid, "state.query", map[string]any{"limit": 1})
	if err != nil || res.IsError {
		t.Fatalf("call %+v %v", res, err)
	}
	var q clienttest.StateQueryResult
	if err := json.Unmarshal(res.StructuredContent, &q); err != nil || len(q.Resources) != 1 || !q.Truncated {
		t.Fatalf("structured content %s %v", res.StructuredContent, err)
	}
	if res.Content[0].Type != "text" || !json.Valid([]byte(res.Content[0].Text)) {
		t.Fatalf("text content %+v", res.Content)
	}
	if res, err := h.cp.CallTool(ctx, tid, "no.such.tool", nil); err != nil || !res.IsError {
		t.Fatalf("unknown tool %+v %v", res, err)
	}
	if err := p.c.Audit(ctx, map[string]any{"request": "r1", "outcome": "ok"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "investigation audit", func() bool { return auditCount(h.cp, tid, "investigation", "") == 1 })

	archive, sig, km := []byte("bundle"), []byte("sig"), []byte("manifest")
	if err := h.cp.PublishBundle(protocol.TargetKubernetes, "2026.09.1", archive, sig, km); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-fetched:
		if b.Version != "2026.09.1" || !bytes.Equal(b.Bundle, archive) || !bytes.Equal(b.Signature, sig) || !bytes.Equal(b.KeyManifest, km) {
			t.Fatalf("bundle %+v", b)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("bundle not fetched")
	}
	if b, err := p.c.FetchBundle(ctx, "2026.09.1"); err != nil || b.Version != "2026.09.1" || len(b.Bundle) != 0 {
		t.Fatalf("fetch current %+v %v", b, err)
	}
	waitFor(t, "health reports", func() bool {
		r, _ := h.cp.HealthReports(tid)
		return len(r) >= 2
	})

	if err := h.cp.SetCompat(tid, protocol.Compat{Status: protocol.CompatOutdated, MinimumVersion: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	if err := h.cp.Disconnect(tid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "compat", func() bool { return p.c.Status().Compat.Status == protocol.CompatOutdated })
}

func TestEdgeHistory(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	p := h.start(w, nil)
	mustApply(t, w, deployment("d", 1), protocol.EdgeAdd("d", "owns", "rs1", map[string]any{"rev": 1}))
	h.clock.Advance(time.Hour)
	mustApply(t, w, protocol.EdgeReplace("d", "owns", "rs1", map[string]any{"rev": 2}, map[string]any{"rev": 1}), protocol.EdgeAdd("d", "selects", "p1", nil))
	h.waitDrained(w)
	outage(t, h, tid, p)
	h.clock.Advance(time.Hour)
	mustApply(t, w, protocol.EdgeRemove("d", "owns", "rs1", map[string]any{"rev": 2}))
	mustApply(t, w, protocol.EdgeAdd("d", "owns", "rs2", map[string]any{"rev": 3}))
	if n, err := w.Store.Coalesce(); err != nil || n != 2 {
		t.Fatalf("coalesce %d %v", n, err)
	}
	h.cp.SetUnavailable(false)
	h.waitDrained(w)
	all, err := h.cp.EdgeHistory(tid, "d", "owns", t0, t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var kinds []protocol.OpKind
	for _, c := range all {
		kinds = append(kinds, c.Op)
	}
	want := []protocol.OpKind{protocol.OpEdgeAdd, protocol.OpEdgeReplace, protocol.OpEdgeRemove, protocol.OpEdgeAdd}
	if len(kinds) != len(want) {
		t.Fatalf("edge history %v", kinds)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("edge history %v, want %v", kinds, want)
		}
	}
	if !all[2].Coalesced || !all[3].Coalesced || all[0].Coalesced {
		t.Fatalf("coalesced markers %+v", all)
	}
	early, _ := h.cp.EdgeHistory(tid, "d", "", t0, t0.Add(30*time.Minute))
	if len(early) != 1 || early[0].Type != "owns" {
		t.Fatalf("time-bounded history %+v", early)
	}
	sel, _ := h.cp.EdgeHistory(tid, "p1", "selects", t0, t0.Add(24*time.Hour))
	if len(sel) != 1 || sel[0].From != "d" {
		t.Fatalf("history by target uid %+v", sel)
	}
}
