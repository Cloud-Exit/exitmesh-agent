package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

func startT0() time.Time { return time.Now().UTC().Truncate(time.Second) }

func enrolledFixture(t *testing.T, o fixtureOpts) *fixture {
	t.Helper()
	clk := newFakeClock(startT0())
	c := newCP(t, clk)
	s := newSigner(t, clk.Now())
	f := newFixture(t, clk, c, s, o)
	target, tok, err := c.srv.CreateTarget(protocol.TargetHost)
	if err != nil {
		t.Fatal(err)
	}
	f.target = target
	f.writeToken(tok)
	return f
}

func (f *fixture) publish(version, threshold string) {
	f.t.Helper()
	archive, sig := f.signer.build(f.t, version, threshold)
	if err := f.cp.srv.PublishBundle(protocol.TargetHost, version, archive, sig, f.signer.manifest); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) waitCommitted() {
	f.t.Helper()
	eventually(f.t, "every spooled record committed", func() bool {
		ep, ok := f.host.sp.Epoch()
		lc, lok := f.host.sp.LastCommitted()
		return ok && lok && lc.Seq == ep.Chain.Head && f.host.sp.Usage().Records == 0
	})
}

func TestHostRulesFireAndResolve(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{})
	f.publish("h1", "4")
	setLoad(t, 0.1)
	f.start()
	defer f.stop()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitTicking("bundle h1 active", func() bool { return f.status().Bundle.Version == "h1" })
	f.tick(0)
	f.waitCommitted()

	st, seq := f.committedState()
	if st == nil || seq == 0 {
		t.Fatal("no committed checkpoint")
	}
	if _, ok := st.Resources["host:unit:nginx.service"]; !ok {
		t.Fatalf("checkpoint lacks the nginx unit: %v", keysOf(st.Resources))
	}
	if s, ok := st.Scopes["host/fact/timers"]; !ok || s.State == protocol.ScopeUnavailable && s.Reason == "" {
		t.Fatalf("timer scope not reported: %+v", st.Scopes)
	}

	f.sd.setActive("cron.service", "failed")
	f.setPackages("nginx", "curl")
	setLoad(t, 9)
	f.appendLog("2026-09-27 ERROR login failed password=hunter2")
	f.appendLog("2026-09-27 INFO all good")
	f.tick(30 * time.Second)
	f.waitCommitted()
	fs := f.findings()
	if fs["app-errors"].State != "firing" {
		t.Fatalf("log rule must fire: %+v", fs)
	}
	if _, ok := fs["node-load-high"]; ok {
		t.Fatalf("metric rule fired before its for duration: %+v", fs)
	}
	for i := 0; i < 3; i++ {
		f.tick(30 * time.Second)
	}
	f.waitCommitted()
	fs = f.findings()
	if fs["node-load-high"].State != "firing" || fs["app-errors"].State != "resolved" {
		t.Fatalf("metric rule must fire after 1m and the log rule resolve after its window: %+v", fs)
	}
	st, _ = f.committedState()
	if got := st.Resources["host:unit:cron.service"].Fields["active_state"]; got != "failed" {
		t.Fatalf("delta not committed: cron active_state %v", got)
	}
	if !hasPackage(st, "curl") {
		t.Fatal("package delta not committed")
	}
	if !st.Equal(f.host.head.snapshot()) {
		t.Fatal("control plane state differs from the host head state")
	}

	now := f.clk.Now()
	res, err := f.cp.srv.CallTool(context.Background(), f.target, "promql.query", map[string]any{
		"requester": "user:test", "purpose": "acceptance", "scope": map[string]any{"cluster": true}, "query": "node_load1",
		"window": map[string]any{"start": now.Add(-time.Minute).UnixMilli(), "end": now.UnixMilli()},
	})
	if err != nil || res.IsError || !strings.Contains(string(res.StructuredContent), "node_load1") || !strings.Contains(string(res.StructuredContent), "9") {
		t.Fatalf("promql.query over the tunnel: %+v %v", res, err)
	}
	res, err = f.cp.srv.CallTool(context.Background(), f.target, "state.query", map[string]any{
		"requester": "user:test", "purpose": "acceptance", "scope": map[string]any{"cluster": true}, "kind": "host/Unit",
	})
	if err != nil || res.IsError || !strings.Contains(string(res.StructuredContent), "cron.service") {
		t.Fatalf("state.query over the tunnel: %+v %v", res, err)
	}
	var audited bool
	for _, a := range f.cp.srv.Audit(f.target) {
		audited = audited || (a.Event == "investigation" && strings.Contains(a.Detail, "promql.query"))
	}
	if !audited {
		t.Fatal("investigation audit not sent")
	}

	setLoad(t, 0.1)
	for i := 0; i < 4; i++ {
		f.tick(30 * time.Second)
	}
	f.waitCommitted()
	fs = f.findings()
	if fs["node-load-high"].State != "resolved" || fs["app-errors"].State != "resolved" {
		t.Fatalf("both rules must resolve: %+v", fs)
	}

	ep, _ := f.host.sp.Epoch()
	recs, err := f.cp.srv.Records(f.target, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	var evidence, deltas int
	for _, r := range recs {
		if strings.Contains(string(r.Bytes()), "hunter2") {
			t.Fatal("unredacted secret reached the control plane")
		}
		if r.Delta != nil {
			deltas++
		}
		if r.Finding != nil {
			for _, e := range r.Finding.Evidence {
				evidence++
				if !strings.Contains(e.Text, "ERROR login failed") || e.Source != "file:"+f.path("logs/app.log") {
					t.Fatalf("unexpected evidence %+v", e)
				}
				if strings.Contains(e.Text, "all good") {
					t.Fatal("unmatched line kept as evidence")
				}
			}
		}
	}
	if evidence == 0 || deltas == 0 {
		t.Fatalf("evidence %d, deltas %d", evidence, deltas)
	}
	h := f.status()
	if h.TSDB == nil || h.TSDB.Series == 0 || h.Metrics == nil || h.Metrics.Series == 0 {
		t.Fatalf("metrics not collected: %+v %+v", h.TSDB, h.Metrics)
	}
	if h.TSDB.RetentionSeconds != (30 * time.Minute).Seconds() {
		t.Fatalf("retention %v", h.TSDB.RetentionSeconds)
	}
	for _, r := range h.Rules {
		if r.State != "active" {
			t.Fatalf("rule %s state %s (%s)", r.ID, r.State, r.Reason)
		}
	}
	snap, ok, err := f.host.sp.LoadRecoverySnapshot()
	if err != nil || !ok {
		t.Fatalf("recovery snapshot: %v %v", ok, err)
	}
	r, err := protocol.Decode(snap)
	lc, _ := f.host.sp.LastCommitted()
	if err != nil || r.Seq < lc.Seq {
		t.Fatalf("snapshot seq %d below committed %d (%v)", r.Seq, lc.Seq, err)
	}
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasPackage(st *protocol.State, name string) bool {
	for _, r := range st.Resources {
		if r.Kind == "host/Package" && r.Fields["name"] == name {
			return true
		}
	}
	return false
}

func TestRefusesOnKubernetesNode(t *testing.T) {
	clk := newFakeClock(startT0())
	f := newFixture(t, clk, nil, newSigner(t, clk.Now()), fixtureOpts{})
	proc := f.path("kproc")
	writeFiles(proc, map[string]string{"4711/comm": "kubelet\n"})
	d := f.deps()
	d.Facts.ProcRoot = proc
	h, err := New(f.cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	err = h.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Helm chart") || !strings.Contains(err.Error(), "kubelet") {
		t.Fatalf("want refusal pointing to the Helm chart, got %v", err)
	}
	if _, err := os.Stat(f.cfg.StateDir); !os.IsNotExist(err) {
		t.Fatalf("state directory touched: %v", err)
	}
}

func TestNewRejectsOtherRoles(t *testing.T) {
	cfg := &config.Config{Role: config.RoleNode}
	if _, err := New(cfg, Deps{}); err == nil {
		t.Fatal("node role accepted")
	}
}

func TestRestartResumesTargetAndEpoch(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory}})
	f.start()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitCommitted()
	id1, wid1, inc1 := f.host.sp.Identity(), f.host.sp.WriterID(), f.host.sp.Incarnation()
	ep1, _ := f.host.sp.Epoch()
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.path("token")); err != nil {
		t.Fatal(err)
	}
	f.setPackages("nginx", "vim")
	f.start()
	defer f.stop()
	eventually(t, "reconnected", func() bool { return f.status().Session.Connected })
	f.waitCommitted()
	id2, wid2, inc2 := f.host.sp.Identity(), f.host.sp.WriterID(), f.host.sp.Incarnation()
	ep2, _ := f.host.sp.Epoch()
	if id2.TargetID != id1.TargetID || id2.Credential != id1.Credential || wid2 != wid1 || ep2.ID != ep1.ID || inc2 != inc1+1 {
		t.Fatalf("restart changed identity: %+v/%v/%d/%s -> %+v/%v/%d/%s", id1, wid1, inc1, ep1.ID, id2, wid2, inc2, ep2.ID)
	}
	if eps := f.epochs(); len(eps) != 1 {
		t.Fatalf("want one epoch, got %d", len(eps))
	}
	st, _ := f.committedState()
	if !hasPackage(st, "vim") {
		t.Fatal("change while stopped not delivered as a synthetic delta")
	}
	recs, _ := f.cp.srv.Records(f.target, ep2.ID)
	var synthetic bool
	for _, r := range recs {
		if r.Delta != nil && r.Delta.Flags&protocol.FlagSynthetic != 0 && r.Delta.Uncertain != nil {
			synthetic = true
		}
	}
	if !synthetic {
		t.Fatal("no synthetic delta with an uncertainty interval after restart")
	}
	fi, err := os.Stat(filepath.Join(f.cfg.StateDir, SpoolDirName))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("spool directory mode %v %v", fi.Mode(), err)
	}
	if err := filepath.Walk(f.cfg.StateDir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v", p, fi.Mode())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCrashRecoveryReplaysSpooledRecords(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory}})
	f.start()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitCommitted()
	f.cp.srv.SetUnavailable(true)
	if err := f.cp.srv.Disconnect(f.target); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnected", func() bool { return !f.status().Session.Connected })
	f.setPackages("nginx", "a1")
	f.tick(30 * time.Second)
	f.sd.setActive("nginx.service", "inactive")
	f.tick(30 * time.Second)
	want := f.host.head.snapshot()
	if f.host.sp.Usage().Records < 2 {
		t.Fatalf("deltas not spooled: %d", f.host.sp.Usage().Records)
	}
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	f.start()
	defer f.stop()
	if !f.host.head.snapshot().Equal(want) {
		t.Fatal("recovered state differs from the state at the chain head")
	}
	recs := f.host.sp.Usage().Records
	f.tick(30 * time.Second)
	if f.host.sp.Usage().Records != recs {
		t.Fatal("an unchanged host produced records after recovery")
	}
	f.cp.srv.SetUnavailable(false)
	eventually(t, "reconnected", func() bool {
		f.clk.Advance(time.Minute)
		return f.status().Session.Connected
	})
	f.waitCommitted()
	st, _ := f.committedState()
	if !st.Equal(want) {
		t.Fatal("replayed state differs")
	}
}

func TestIdentityConflictKeepsSpooling(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory}})
	f.start()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitCommitted()
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	writeFiles(f.dir, map[string]string{"etc/machine-id": "fedcba9876543210fedcba9876543210\n"})
	f.start()
	defer f.stop()
	eventually(t, "identity conflict reported", func() bool {
		f.clk.Advance(time.Minute)
		s := f.status()
		return s.Session.LastErrorCode == protocol.CodeIdentityConflict && s.Identity.Conflict
	})
	s := f.status()
	if s.Identity.Enrolled != "0123456789abcdef0123456789abcdef" || s.Identity.Current != "fedcba9876543210fedcba9876543210" {
		t.Fatalf("identity %+v", s.Identity)
	}
	var audited bool
	for _, a := range f.cp.srv.Audit(f.target) {
		audited = audited || a.Code == protocol.CodeIdentityConflict
	}
	if !audited {
		t.Fatal("control plane did not audit the conflict")
	}
	before := f.host.sp.Usage().Records
	f.setPackages("nginx", "clone-change")
	f.tick(30 * time.Second)
	if f.host.sp.Usage().Records <= before {
		t.Fatal("records are not spooled during the conflict")
	}
	if err := f.cp.srv.ResolveConflict(f.target, "fedcba9876543210fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "conflict resolved", func() bool {
		f.clk.Advance(time.Minute)
		f.tick(time.Second)
		s := f.status()
		return s.Session.Connected && !s.Identity.Conflict
	})
	f.waitCommitted()
	st, _ := f.committedState()
	if st == nil || !hasPackage(st, "clone-change") {
		t.Fatal("spooled records not delivered after resolution")
	}
}

func TestSevenDayOutageReplaysExactly(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory}})
	f.start()
	defer f.stop()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitCommitted()
	cred := f.host.sp.Identity().Credential
	f.cp.srv.SetUnavailable(true)
	if err := f.cp.srv.Disconnect(f.target); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnected", func() bool { return !f.status().Session.Connected })
	changes := 0
	for step := 0; step < 28; step++ {
		pkgs := []string{"nginx"}
		for i := 0; i <= step; i++ {
			pkgs = append(pkgs, "pkg"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		}
		f.setPackages(pkgs...)
		f.tick(6 * time.Hour)
		changes++
	}
	if got := f.host.sp.Usage().Records; got != changes {
		t.Fatalf("spooled %d records for %d changes", got, changes)
	}
	want := f.host.head.snapshot()
	f.cp.srv.SetUnavailable(false)
	eventually(t, "reconnected after 7 days", func() bool {
		f.clk.Advance(5 * time.Minute)
		return f.status().Session.Connected
	})
	f.waitCommitted()
	if f.host.sp.Identity().Credential != cred {
		t.Fatal("credential changed across the outage")
	}
	st, _ := f.committedState()
	if !st.Equal(want) {
		t.Fatal("replayed state differs from the host state")
	}
	stats, err := f.cp.srv.Stats(f.target)
	if err != nil || stats.Duplicates != 0 || stats.Rejected != 0 || stats.Divergences != 0 {
		t.Fatalf("stats %+v %v", stats, err)
	}
	ep, _ := f.host.sp.Epoch()
	recs, _ := f.cp.srv.Records(f.target, ep.ID)
	var deltas int
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Fatalf("gap at %d: seq %d", i, r.Seq)
		}
		if r.Delta != nil {
			deltas++
		}
	}
	if deltas != changes {
		t.Fatalf("delivered %d deltas for %d changes", deltas, changes)
	}
	if eps := f.epochs(); len(eps) != 1 {
		t.Fatalf("outage changed the epoch: %d epochs", len(eps))
	}
	var _ = refcp.SourceSummary
}
