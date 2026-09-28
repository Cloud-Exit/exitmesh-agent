package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestInitialCheckpointChangeAndStateRuleFinding(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	id, _ := e.committed(r)
	rs := e.records(id)
	if len(rs) == 0 || rs[0].Checkpoint == nil || rs[0].Checkpoint.Reason != protocol.ReasonInitial {
		t.Fatalf("first record is not the initial checkpoint: %+v", rs)
	}
	uids := map[string]bool{}
	for _, res := range rs[0].Checkpoint.Resources {
		uids[res.UID] = true
	}
	for _, u := range []string{"pod-1", "pod-2", "dep-1", "svc-1", "uid-node-1", "uid-node-2"} {
		if !uids[u] {
			t.Fatalf("initial checkpoint misses %s: %v", u, uids)
		}
	}
	if len(rs[0].Checkpoint.Scopes) == 0 {
		t.Fatal("initial checkpoint carries no scope status")
	}
	archive, sig := e.trust.signed(t, "2026.09.1", badImageExpr)
	if err := e.cp.PublishBundle(protocol.TargetKubernetes, "2026.09.1", archive, sig, e.trust.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bundle active", func() bool { return r.c.eng.BundleVersion() == "2026.09.1" })
	e.cl.setImage(t, "web-1", "nginx:bad")
	e.advancing("image delta and finding", 20*time.Second, func() bool {
		fs := findingsFor(e.findings(), "bad-image")
		return hasFieldUpdate(e.records(id), "pod-1", "containers.app.image", "nginx:bad") && len(fs) == 1 && fs[0].State == protocol.LifecycleFiring && fs[0].BundleVersion == "2026.09.1"
	})
	_, head := e.committed(r)
	want, err := e.cp.StateHashAt(e.targetID, id, head)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.c.stateView().Hash(); got != want {
		t.Fatal("coordinator chain head differs from the control plane reconstruction")
	}
	e.cl.setImage(t, "web-1", "nginx:1.28")
	e.advancing("finding resolved", 20*time.Second, func() bool {
		fs := findingsFor(e.findings(), "bad-image")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleResolved
	})
	eventually(t, "health report with placement and bundle", func() bool {
		hs, _ := e.cp.HealthReports(e.targetID)
		if len(hs) == 0 {
			return false
		}
		h := healthOf(t, hs[len(hs)-1])
		return h.Placement.Pinned && h.Placement.Volume == "pv-1" && h.Bundle.Target == "2026.09.1" && h.Bundle.State == "converged" &&
			h.Chain.LastCheckpoint.Seq >= 1 && h.Chain.LastDelta.Seq > h.Chain.LastCheckpoint.Seq && len(h.Rules) == 1 && h.Session.Connected
	})
	tools, err := e.cp.ListTools(context.Background(), e.targetID)
	if err != nil || len(tools) == 0 {
		t.Fatalf("tools %v %v", tools, err)
	}
	res, err := e.cp.CallTool(context.Background(), e.targetID, "state.query", map[string]any{
		"requester": "user@example.com", "purpose": "test", "scope": map[string]any{"cluster": true}, "kind": state.KindPod,
	})
	if err != nil || res.IsError || !contains(string(res.StructuredContent)+res.Content[0].Text, "web-1") {
		t.Fatalf("state.query over the tunnel: %+v %v", res, err)
	}
}

func TestNodeAgentSubmissionIdempotentAndImpersonation(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	e.committed(r)
	ctx := context.Background()
	n1 := e.nodeClient(t, r, "node-1", "node-1")
	if _, err := n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test", BundleVersion: "", Capabilities: []string{"metrics", "logs"}}); err != nil {
		t.Fatal(err)
	}
	f := protocol.Finding{
		ID: protocol.FindingID(e.targetID, "oom|node-1", 1000), DedupKey: "oom|node-1", Transition: protocol.TransitionFiring,
		Provenance: protocol.Provenance{Kind: protocol.ProvenanceRule, RuleID: "oom-logs", RuleVersion: 1, BundleVersion: "2026.09.1"},
		Category:   "errors", Severity: protocol.SeverityCritical, EvalTime: 1000, FirstSeen: 1000, LastSeen: 1000, Count: 1, Node: "node-1",
	}
	fb, err := protocol.EncodeFinding(&f)
	if err != nil {
		t.Fatal(err)
	}
	facts := nodeapi.Item{Seq: 2, Kind: nodeapi.KindMetricFacts, Facts: []metricFact{{Namespace: "shop", Pod: "web-1", Container: "app",
		Fields: map[string]any{"metric.memory.p95_bytes": int64(200 << 20)}}, {Namespace: "shop", Pod: "web-2", Container: "app",
		Fields: map[string]any{"metric.memory.p95_bytes": int64(1)}}}}
	items := []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindFinding, Finding: fb}, facts}
	for i := 0; i < 2; i++ {
		acked, err := n1.Submit(ctx, items)
		if err != nil || acked != 2 {
			t.Fatalf("submit %d: acked %d err %v", i, acked, err)
		}
	}
	id, _ := e.committed(r)
	eventually(t, "node finding visible", func() bool {
		fs := findingsFor(e.findings(), "oom-logs")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleFiring
	})
	n := 0
	facts2 := 0
	for _, rec := range e.records(id) {
		if rec.Finding != nil && rec.Finding.ID == f.ID {
			n++
		}
		if rec.Delta != nil && rec.Delta.Flags&protocol.FlagMetricFacts != 0 {
			facts2++
			for _, op := range rec.Delta.Ops {
				if op.UID == "pod-2" {
					t.Fatal("metric fact applied to a pod on another node")
				}
			}
		}
	}
	if n != 1 || facts2 != 1 {
		t.Fatalf("finding records %d, metric fact deltas %d; want 1 and 1", n, facts2)
	}
	if v := r.c.stateView().Resources["pod-1"].Fields["containers.app.metric.memory.p95_bytes"]; !protocol.ValueEqual(v, int64(200<<20)) {
		t.Fatalf("metric fact field %v", v)
	}
	if acked, err := n1.Submit(ctx, []nodeapi.Item{{Seq: 3, Kind: nodeapi.KindMetricFacts, Facts: []metricFact{{Namespace: "shop", Pod: "web-1", Container: "app",
		Fields: map[string]any{"metric.memory.p95_bytes": int64(201 << 20)}}}}}); err != nil || acked != 3 {
		t.Fatalf("below-threshold submit %d %v", acked, err)
	}
	e.committed(r)
	n = 0
	for _, rec := range e.records(id) {
		if rec.Delta != nil && rec.Delta.Flags&protocol.FlagMetricFacts != 0 {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("a change below the threshold produced a delta: %d metric fact deltas", n)
	}
	impostor := e.nodeClient(t, r, "node-1", "node-2")
	_, err = impostor.Submit(ctx, []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindFinding, Finding: fb}})
	var ae *nodeapi.Error
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusForbidden {
		t.Fatalf("impersonation not rejected: %v", err)
	}
	h := r.c.health()
	if h.Security.ImpersonationRejected != 1 || h.Security.Recent[0].ClaimedNode != "node-2" || h.Security.Recent[0].AuthenticatedNode != "node-1" {
		t.Fatalf("impersonation not audited in health: %+v", h.Security)
	}
	up, err := n1.WaitKube(ctx, 0)
	if err != nil || up == nil || up.Revision == 0 {
		t.Fatalf("kube series %v %v", up, err)
	}
	var sawNode, sawOther bool
	for _, s := range up.Series {
		if s.Labels["node"] == "node-1" && contains(s.Labels["__name__"], "kube_node") {
			sawNode = true
		}
		if s.Labels["pod"] == "web-2" {
			sawOther = true
		}
	}
	if !sawNode || sawOther {
		t.Fatalf("node-scoped kube series wrong: node %v other %v", sawNode, sawOther)
	}
	go func() {
		for i := 0; i < 20; i++ {
			ts, err := n1.WaitTasks(ctx)
			if err != nil {
				return
			}
			for _, tk := range ts {
				_ = n1.PostResult(ctx, nodeapi.TaskResult{ID: tk.ID, Payload: append([]byte("ok:"), tk.Payload...)})
				return
			}
		}
	}()
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := router{r.c}.Run(tctx, "node-1", nodeapi.Task{Kind: nodeapi.TaskPromQLQuery, Payload: []byte("q")})
	if err != nil || string(res.Payload) != "ok:q" {
		t.Fatalf("task round trip %q %v", res.Payload, err)
	}
	if _, err := (router{r.c}).Run(tctx, "node-2", nodeapi.Task{Kind: nodeapi.TaskPromQLQuery}); err == nil {
		t.Fatal("task routed to an uncovered node")
	}
}

func TestAdminStatusInvestigateAndDeenroll(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	e.committed(r)
	ctx := context.Background()
	ac := admin.Dial(e.stateDir)
	raw, err := ac.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h := healthOf(t, raw); h.TargetID != e.targetID || h.Role != "coordinator" || h.Placement.Volume != "pv-1" {
		t.Fatalf("status %+v", h)
	}
	args, _ := json.Marshal(map[string]any{"requester": "admin", "purpose": "local", "scope": map[string]any{"cluster": true}, "kind": state.KindDeployment})
	out, err := ac.Investigate(ctx, admin.InvestigateRequest{Tool: "state.query", Args: args})
	if err != nil || !contains(string(out), "dep-1") {
		t.Fatalf("investigate %s %v", out, err)
	}
	if err := ac.Commit(ctx, admin.CommitReceipt{}); err == nil {
		t.Fatal("commit receipt accepted outside the air-gap profile")
	}
	if err := ac.Deenroll(ctx, "decommission"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.done:
		r.done <- err
		if err != nil {
			t.Fatalf("de-enrolled coordinator exited with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("coordinator kept running after de-enrollment")
	}
	c, err := New(e.config(), Deps{Dynamic: e.cl.dyn, Metadata: e.cl.meta, Discovery: e.cl.disc})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(ctx); err == nil || !contains(err.Error(), "refuses to run") {
		t.Fatalf("halted spool started: %v", err)
	}
}

func TestSecondCoordinatorRefusesLockedSpool(t *testing.T) {
	e := newEnv(t)
	e.start(e.config())
	c, err := New(e.config(), Deps{Dynamic: e.cl.dyn, Metadata: e.cl.meta, Discovery: e.cl.disc})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(context.Background()); err == nil || !contains(err.Error(), "locked") {
		t.Fatalf("second coordinator ran: %v", err)
	}
}
