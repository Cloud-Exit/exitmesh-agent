package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/journal"
	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

type fakeInvestigator struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeInvestigator) Tools() []client.Tool {
	return []client.Tool{{Name: "state.query", InputSchema: json.RawMessage(`{"type":"object"}`)}}
}

func (f *fakeInvestigator) Call(_ context.Context, name string, args json.RawMessage) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+string(args))
	if name != "state.query" {
		return nil, fmt.Errorf("unknown tool %s", name)
	}
	return map[string]any{"tool": name, "ok": true}, nil
}

func airgapFixture(t *testing.T) *fixture {
	t.Helper()
	clk := newFakeClock(startT0())
	s := newSigner(t, clk.Now())
	f := newFixture(t, clk, nil, s, fixtureOpts{airgap: true, caps: []string{config.CapInventory, config.CapLogs}})
	f.target = "host-airgap-1"
	f.writeToken("emx1_h_host-airgap-1_0123456789abcdefghij")
	archive, sig := s.build(t, "a1", "4")
	writeFiles(f.path("bundles"), map[string]string{
		bundle.FileArchive: string(archive), bundle.FileSignature: string(sig), bundle.FileKeyManifest: string(s.manifest),
	})
	return f
}

func exportFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*.emhpx"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAirGapExportCommitAndLocalInvestigation(t *testing.T) {
	f := airgapFixture(t)
	f.inv = &fakeInvestigator{}
	f.start()
	if v := f.status().Bundle.Version; v != "a1" {
		t.Fatalf("out-of-band bundle not active: %q (%v)", v, f.status().Errors)
	}
	f.setPackages("nginx", "offline-pkg")
	f.tick(30 * time.Second)
	if f.status().Session.Exported == 0 {
		t.Fatal("nothing exported")
	}
	exportDir := f.cfg.AirGap.ExportDir
	if len(exportFiles(t, exportDir)) != 0 {
		t.Fatal("export file finished before its roll")
	}
	f.tick(ExportRollAge)
	files := exportFiles(t, exportDir)
	if len(files) != 1 {
		t.Fatalf("want one rolled export file, got %v", files)
	}
	fh, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	hdr, recs, err := protocol.ReadExport(fh)
	fh.Close()
	if err != nil {
		t.Fatal(err)
	}
	wid := f.host.sp.WriterID()
	ep, _ := f.host.sp.Epoch()
	if hdr.TargetID != f.target || !bytes.Equal(hdr.WriterID, wid[:]) || !bytes.Equal(hdr.Epoch, ep.ID[:]) || len(recs) < 2 || recs[0].Checkpoint == nil {
		t.Fatalf("export header %+v with %d records", hdr, len(recs))
	}
	last := recs[len(recs)-1].Seq
	if !strings.HasSuffix(files[0], fmt.Sprintf("-1-%d.emhpx", last)) {
		t.Fatalf("export file name %s", files[0])
	}
	for _, e := range f.host.sp.Entries(1) {
		if e.State != spool.TransmittedUnconfirmed {
			t.Fatalf("exported record %d not marked transmitted", e.Seq)
		}
	}
	chain := f.host.sp.Entries(last)[0].ChainHash

	ac := admin.Dial(f.cfg.StateDir)
	ctx := context.Background()
	res, err := ac.Investigate(ctx, admin.InvestigateRequest{Tool: "state.query", Args: json.RawMessage(`{"kind":"host/Unit"}`)})
	if err != nil || !strings.Contains(string(res), `"ok":true`) {
		t.Fatalf("local investigation: %s %v", res, err)
	}
	if _, err := ac.Investigate(ctx, admin.InvestigateRequest{Tool: "nope"}); err == nil {
		t.Fatal("unknown tool accepted")
	}
	var buf bytes.Buffer
	if err := ac.Export(ctx, 0, &buf); err != nil {
		t.Fatal(err)
	}
	if h2, r2, err := protocol.ReadExport(&buf); err != nil || h2.TargetID != f.target || len(r2) != len(recs) {
		t.Fatalf("admin export: %+v %d %v", h2, len(r2), err)
	}
	if err := ac.Deenroll(ctx, "x"); err == nil {
		t.Fatal("air-gap de-enrollment accepted")
	}
	if err := ac.Commit(ctx, admin.CommitReceipt{Epoch: ep.ID.String(), Seq: last, ChainHash: protocol.Hash{1}.String()}); err == nil {
		t.Fatal("receipt with a wrong chain hash accepted")
	}
	if err := ac.Commit(ctx, admin.CommitReceipt{Epoch: ep.ID.String(), Seq: last, ChainHash: chain.String()}); err != nil {
		t.Fatal(err)
	}
	if lc, ok := f.host.sp.LastCommitted(); !ok || lc.Seq != last || f.host.sp.Usage().Records != 0 {
		t.Fatalf("receipt not applied: %+v %v", lc, ok)
	}
	if len(exportFiles(t, exportDir)) != 0 {
		t.Fatal("committed export file kept")
	}
	raw, err := ac.Status(ctx)
	if err != nil || !strings.Contains(string(raw), `"airgap":true`) || !strings.Contains(string(raw), f.target) {
		t.Fatalf("status %s %v", raw, err)
	}
	f.setPackages("nginx", "after-commit")
	f.tick(30 * time.Second)
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	if files := exportFiles(t, exportDir); len(files) != 1 {
		t.Fatalf("shutdown did not finish the open export file: %v", files)
	}
}

func TestAirGapDiscardsUnfinishedExport(t *testing.T) {
	f := airgapFixture(t)
	f.start()
	f.tick(30 * time.Second)
	through := f.status().Session.Exported
	ep, _ := f.host.sp.Epoch()
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	for _, p := range exportFiles(t, f.cfg.AirGap.ExportDir) {
		os.Remove(p)
	}
	part := filepath.Join(f.cfg.AirGap.ExportDir, "crashed.emhpx.part")
	writeFiles("/", map[string]string{part: "EMHPX1\ntorn"})
	db, err := kv.OpenBolt(filepath.Join(f.cfg.StateDir, MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	st, err := kv.NewBolt(db, "airgap")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(openExport{Path: part, Epoch: ep.ID.String(), First: 1})
	if err := st.Batch(map[string][]byte{keyOpenExport: b, cursorKey(ep.ID): []byte(strconv.FormatUint(through, 10))}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	f.start()
	f.tick(30 * time.Second)
	if _, err := os.Stat(part); !os.IsNotExist(err) {
		t.Fatal("unfinished export file kept")
	}
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	files := exportFiles(t, f.cfg.AirGap.ExportDir)
	if len(files) != 1 {
		t.Fatalf("records of the discarded file not exported again: %v", files)
	}
	fh, _ := os.Open(files[0])
	defer fh.Close()
	if _, recs, err := protocol.ReadExport(fh); err != nil || recs[0].Seq != 1 {
		t.Fatalf("re-export must start at seq 1: %v", err)
	}
}

func TestAdminDeenrollStopsAndHalts(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory}})
	f.inv = &fakeInvestigator{}
	f.start()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	tools, err := f.cp.srv.ListTools(context.Background(), f.target)
	if err != nil || len(tools) != 1 || tools[0].Name != "state.query" {
		t.Fatalf("tools %v %v", tools, err)
	}
	res, err := f.cp.srv.CallTool(context.Background(), f.target, "state.query", map[string]any{"kind": "host/Unit"})
	if err != nil || res.IsError {
		t.Fatalf("tools/call %+v %v", res, err)
	}
	if err := admin.Dial(f.cfg.StateDir).Deenroll(context.Background(), "decommissioned"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-f.done:
		if err != nil {
			t.Fatalf("de-enrolled host must stop cleanly, got %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("host kept running after de-enrollment")
	}
	sp, err := spool.Open(spool.Options{Dir: filepath.Join(f.cfg.StateDir, SpoolDirName)})
	if err != nil {
		t.Fatal(err)
	}
	id := sp.Identity()
	halt, halted := sp.Halted()
	sp.Close()
	if id.Credential != "" || !halted || halt.Code != client.HaltDeenrolled {
		t.Fatalf("credential %q halted %v %+v", id.Credential, halted, halt)
	}
	h, err := New(f.cfg, f.deps())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Run(context.Background()); err != nil {
		t.Fatalf("restart of a de-enrolled host must exit cleanly: %v", err)
	}
}

func TestOfflineExportAndDeenroll(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory}})
	f.start()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitCommitted()
	if err := Export(f.cfg, 0, &bytes.Buffer{}, f.deps()); !errors.Is(err, ErrRunning) {
		t.Fatalf("export while running: %v", err)
	}
	if err := Deenroll(context.Background(), f.cfg, "x", f.deps()); !errors.Is(err, ErrRunning) {
		t.Fatalf("deenroll while running: %v", err)
	}
	f.cp.srv.SetUnavailable(true)
	if err := f.cp.srv.Disconnect(f.target); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnected", func() bool { return !f.status().Session.Connected })
	f.setPackages("nginx", "pending")
	f.tick(30 * time.Second)
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Export(f.cfg, 0, &buf, f.deps()); err != nil {
		t.Fatal(err)
	}
	hdr, recs, err := protocol.ReadExport(&buf)
	if err != nil || hdr.TargetID != f.target || len(recs) != 1 || recs[0].Delta == nil {
		t.Fatalf("offline export %+v %d %v", hdr, len(recs), err)
	}
	f.cp.srv.SetUnavailable(false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := Deenroll(ctx, f.cfg, "host retired", f.deps()); err != nil {
		t.Fatal(err)
	}
	st, _ := f.committedState()
	if st == nil || !hasPackage(st, "pending") {
		t.Fatal("offline de-enrollment did not deliver spooled records first")
	}
	var revoked bool
	for _, a := range f.cp.srv.Audit(f.target) {
		revoked = revoked || strings.Contains(a.Event+a.Detail, "host retired")
	}
	if !revoked {
		t.Fatalf("de-enrollment not audited: %+v", f.cp.srv.Audit(f.target))
	}
	if err := Deenroll(ctx, f.cfg, "again", f.deps()); err == nil || !strings.Contains(err.Error(), "already de-enrolled") {
		t.Fatalf("second de-enrollment: %v", err)
	}
	node := *f.cfg
	node.Role = config.RoleCoordinator
	if err := Export(&node, 0, &buf, f.deps()); err == nil {
		t.Fatal("offline export accepted for the coordinator role")
	}
}

func TestLocalEndpointsLoopbackOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "# TYPE app_requests_total counter\napp_requests_total 42")
	}))
	defer srv.Close()
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory, config.CapMetrics}})
	f.cfg.Host.MetricsEndpoints = []string{srv.URL + "/metrics", "http://10.1.2.3:9100/metrics", "ftp://127.0.0.1/x"}
	f.cfg.Host.ScrapeInterval = config.Duration(time.Second)
	f.start()
	defer f.stop()
	s := f.status()
	if len(s.RejectedEndpoints) != 2 || !strings.Contains(s.RejectedEndpoints["http://10.1.2.3:9100/metrics"], "allowNonLoopback") {
		t.Fatalf("rejected %v", s.RejectedEndpoints)
	}
	eventually(t, "local endpoint scraped", func() bool {
		s := f.status()
		return len(s.ScrapeTargets) == 1 && s.ScrapeTargets[0].Health == "up"
	})
	q, err := f.host.db.Querier(0, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ss := q.Select(context.Background(), false, nil, labels.MustNewMatcher(labels.MatchEqual, "__name__", "app_requests_total"))
	if !ss.Next() {
		t.Fatal("scraped series missing from the TSDB")
	}
	targets, rejected := metricsTargets(config.Host{MetricsEndpoints: []string{"http://10.1.2.3:9100/metrics", "http://localhost:9100/metrics"}, AllowNonLoopback: true})
	if len(targets) != 2 || len(rejected) != 0 {
		t.Fatalf("allowNonLoopback: %v %v", targets, rejected)
	}
}

type fakeJournal struct {
	mu      sync.Mutex
	entries []journal.Entry
	saves   int
	closed  bool
}

func (j *fakeJournal) Refresh() error { return nil }
func (j *fakeJournal) Next() (journal.Entry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.entries) == 0 {
		return journal.Entry{}, false
	}
	e := j.entries[0]
	j.entries = j.entries[1:]
	return e, true
}
func (j *fakeJournal) SaveCursor() error { j.mu.Lock(); j.saves++; j.mu.Unlock(); return nil }
func (j *fakeJournal) FileErrors() map[string]error {
	return map[string]error{"/var/log/journal/x.journal": errors.New("corrupt")}
}
func (j *fakeJournal) Close() error { j.closed = true; return nil }
func (j *fakeJournal) push(unit, msg string, at time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, journal.Entry{Realtime: at, Fields: map[string]string{
		"_SYSTEMD_UNIT": unit, "SYSLOG_IDENTIFIER": strings.TrimSuffix(unit, ".service"), "PRIORITY": "4", "_TRANSPORT": "syslog", "MESSAGE": msg,
	}})
}

func TestJournalRuleFiresWithLabels(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory, config.CapLogs}})
	f.cfg.Host.Journal, f.cfg.Host.JournalDir = true, f.path("journal")
	f.publish("j1", "4")
	fj := &fakeJournal{}
	var opened journal.Options
	f.startWith(func(dp *Deps) {
		dp.OpenJournal = func(o journal.Options) (JournalReader, error) { opened = o; return fj, nil }
	})
	defer f.stop()
	if len(opened.Dirs) != 1 || opened.Dirs[0] != f.path("journal") || opened.Store == nil || opened.Since.IsZero() {
		t.Fatalf("journal options %+v", opened)
	}
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitTicking("bundle j1 active", func() bool { return f.status().Bundle.Version == "j1" })
	fj.push("cron.service", "Failed password for nobody", f.clk.Now())
	fj.push("sshd.service", "Failed password for root from 203.0.113.9 token=abcdef123456", f.clk.Now())
	f.tick(30 * time.Second)
	f.waitCommitted()
	fs := f.findings()
	if fs["ssh-failures"].State != "firing" {
		t.Fatalf("journal rule did not fire: %+v", fs)
	}
	s := f.status()
	if !s.Logs.Journal || s.Logs.JournalEntries != 2 || s.Logs.JournalErrors["/var/log/journal/x.journal"] == "" || fj.saves == 0 {
		t.Fatalf("journal health %+v saves %d", s.Logs, fj.saves)
	}
	ep, _ := f.host.sp.Epoch()
	recs, _ := f.cp.srv.Records(f.target, ep.ID)
	var found bool
	for _, r := range recs {
		if r.Finding == nil {
			continue
		}
		for _, e := range r.Finding.Evidence {
			found = true
			if e.Source != "journal:sshd.service" || e.Labels["unit"] != "sshd.service" || e.Labels["priority"] != "4" || e.Labels["transport"] != "syslog" || e.Labels["syslog_identifier"] != "sshd" {
				t.Fatalf("evidence %+v", e)
			}
			if strings.Contains(e.Text, "abcdef123456") {
				t.Fatal("secret in journal evidence")
			}
		}
	}
	if !found {
		t.Fatal("no journal evidence")
	}
}

func TestGroupTokenEnrollmentAndHealthReports(t *testing.T) {
	clk := newFakeClock(startT0())
	c := newCP(t, clk)
	f := newFixture(t, clk, c, newSigner(t, clk.Now()), fixtureOpts{caps: []string{config.CapInventory}})
	_, tok, err := c.srv.CreateHostGroup()
	if err != nil {
		t.Fatal(err)
	}
	f.writeToken(tok)
	f.startWith(func(d *Deps) { d.HealthInterval = time.Minute })
	defer f.stop()
	f.target = f.host.sp.Identity().TargetID
	if f.target == "" || f.host.sp.Identity().Credential == "" {
		t.Fatalf("group enrollment identity %+v", f.host.sp.Identity())
	}
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	eventually(t, "health report", func() bool {
		clk.Advance(time.Minute)
		r, _ := c.srv.HealthReports(f.target)
		return len(r) > 0
	})
	r, _ := c.srv.HealthReports(f.target)
	var h Health
	if err := json.Unmarshal(r[0], &h); err != nil || h.TargetID != f.target || h.Spool.Capacity != int64(f.cfg.Host.SpoolReserve) || h.Role != "host" {
		t.Fatalf("health %+v %v", h, err)
	}
	if h.UnavailableScopes["host/fact/processes"] == "" && len(h.UnavailableScopes) == 0 {
		t.Fatalf("unavailable facts not reported: %v", h.UnavailableScopes)
	}
}

type enrollmentClock struct {
	Clock
	waits  []time.Duration
	onWait func()
}

func (c *enrollmentClock) After(d time.Duration) <-chan time.Time {
	c.waits = append(c.waits, d)
	c.onWait()
	ch := make(chan time.Time, 1)
	ch <- c.Now()
	return ch
}

func TestEnrollmentRejectedKeepsRetryingAndReloadsToken(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory}})
	valid, err := readToken(f.cfg.EnrollmentTokenFile)
	if err != nil {
		t.Fatal(err)
	}
	f.writeToken(valid + "invalid")
	clk := &enrollmentClock{Clock: f.clk}
	clk.onWait = func() {
		if len(clk.waits) == 12 {
			f.writeToken(valid)
		}
	}
	var logs strings.Builder
	d := f.deps()
	d.Clock, d.Logger = clk, slog.New(slog.NewJSONHandler(&logs, nil))
	h, err := New(f.cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.open(); err != nil {
		t.Fatal(err)
	}
	defer h.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.ensureIdentity(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.enrollLoop(ctx); err != nil {
		t.Fatal(err)
	}
	if len(clk.waits) != 12 || strings.Count(logs.String(), "enrollment failed; retrying") != 12 {
		t.Fatal("not every rejected enrollment was retried and logged")
	}
	delay := time.Second
	for _, got := range clk.waits {
		if got != delay {
			t.Fatalf("enrollment delay %s, want %s", got, delay)
		}
		delay = min(2*delay, client.MaxBackoff)
	}
	if h.sp.Identity().Credential == "" || h.st.enrollError != "" {
		t.Fatal("enrollment did not recover after replacing the token")
	}
}

func TestBundleRejectionKeepsLastKnownGood(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{caps: []string{config.CapInventory, config.CapMetrics, config.CapLogs}})
	f.publish("b1", "4")
	f.start()
	defer f.stop()
	eventually(t, "connected", func() bool { return f.status().Session.Connected })
	f.waitTicking("b1 active", func() bool { return f.status().Bundle.Version == "b1" })
	f.publish("b2", "4 and on() kube_pod_info")
	eventually(t, "b2 rejected", func() bool { return strings.Contains(f.status().Bundle.Error, "b2 rejected") })
	if v := f.status().Bundle.Version; v != "b1" {
		t.Fatalf("active bundle %q after rejection", v)
	}
	other := newSigner(t, f.clk.Now())
	archive, sig := other.build(t, "b3", "4")
	if err := f.cp.srv.PublishBundle(protocol.TargetHost, "b3", archive, sig, f.signer.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b3 rejected", func() bool { return strings.Contains(f.status().Bundle.Error, "b3 rejected") })
	f.publish("b4", "8")
	eventually(t, "b4 active", func() bool { return f.status().Bundle.Version == "b4" })
	if err := f.stop(); err != nil {
		t.Fatal(err)
	}
	f.cp.srv.SetUnavailable(true)
	f.start()
	if v := f.status().Bundle.Version; v != "b4" {
		t.Fatalf("last known good not reloaded at start: %q", v)
	}
}

func TestStartupRefusals(t *testing.T) {
	clk := newFakeClock(startT0())
	f := newFixture(t, clk, nil, newSigner(t, clk.Now()), fixtureOpts{caps: []string{config.CapInventory}})
	f.writeToken("emx1_h_host-1_0123456789abcdefghij")
	unlock, err := spool.LockDir(f.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := New(f.cfg, f.deps())
	if err := h.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("lock held: %v", err)
	}
	unlock()
	noRoots := *f.cfg
	noRoots.Trust = config.Trust{}
	h, _ = New(&noRoots, f.deps())
	if err := h.Run(context.Background()); !errors.Is(err, bundle.ErrNoRoots) {
		t.Fatalf("no roots: %v", err)
	}
	f.writeToken("emx1_c_cluster-1_0123456789abcdefghij")
	h, _ = New(f.cfg, f.deps())
	if err := h.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "cluster token") {
		t.Fatalf("cluster token: %v", err)
	}
	os.Remove(f.path("token"))
	h, _ = New(f.cfg, f.deps())
	if err := h.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("no token: %v", err)
	}
	ag := *f.cfg
	ag.AirGap.Enabled = true
	f.writeToken("emx1_g_group-1_0123456789abcdefghij")
	h, _ = New(&ag, f.deps())
	if err := h.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "air-gap") {
		t.Fatalf("group token in air-gap: %v", err)
	}
}

func TestPromRetention(t *testing.T) {
	rule := func(expr string, forD time.Duration) bundle.AlertRule {
		return bundle.AlertRule{Expr: expr, For: forD, GroupInterval: time.Minute}
	}
	cases := []struct {
		rules []bundle.AlertRule
		want  time.Duration
	}{
		{nil, 30 * time.Minute},
		{[]bundle.AlertRule{rule(`rate(node_cpu_seconds_total[2h]) > 1`, 30*time.Minute)}, 2*time.Hour + 31*time.Minute},
		{[]bundle.AlertRule{rule(`max_over_time(rate(x[5m])[1h:1m] offset 30m) > 1`, 0)}, time.Hour + 30*time.Minute + 5*time.Minute + time.Minute},
		{[]bundle.AlertRule{rule(`rate(x[12h]) > 1`, time.Hour)}, 6 * time.Hour},
	}
	for _, c := range cases {
		if got := promRetention(c.rules); got != c.want {
			t.Errorf("%v: got %v want %v", c.rules, got, c.want)
		}
	}
}

func TestDiskBudgetProtectsSpoolReserve(t *testing.T) {
	f := enrolledFixture(t, fixtureOpts{})
	f.start()
	defer f.stop()
	f.tick(DefaultDiskInterval)
	d := f.status().Disk
	if d.Cap != int64(f.cfg.Host.DiskCap) || d.Reserved != int64(f.cfg.Host.SpoolReserve) || d.TSDB == 0 {
		t.Fatalf("disk report %+v", d)
	}
}
