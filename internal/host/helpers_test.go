package host

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

// metricsRoot is shared because node_exporter keeps its paths in process-global state.
var metricsRoot string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "exitmesh-host-test")
	if err != nil {
		panic(err)
	}
	metricsRoot = dir
	writeFiles(dir, map[string]string{
		"proc/loadavg":        "0.10 0.20 0.30 1/100 1234\n",
		"proc/meminfo":        "MemTotal:        8000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4000000 kB\nSwapTotal:       0 kB\nSwapFree:        0 kB\n",
		"proc/cpuinfo":        "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Test CPU\nphysical id\t: 0\ncore id\t\t: 0\ncpu cores\t: 1\n\n",
		"proc/self/mountinfo": "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
		"sys/block/sda/size":  "2000000\n",
		"sys/block/sda/dev":   "8:0\n",
	})
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func writeFiles(root string, files map[string]string) {
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			panic(err)
		}
	}
}

func setLoad(t *testing.T, v float64) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(metricsRoot, "proc/loadavg"), fmt.Appendf(nil, "%.2f 0.20 0.30 1/100 1234\n", v), 0o644); err != nil {
		t.Fatal(err)
	}
}

type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []waiter
}

type waiter struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, waiter{at: c.now.Add(d), ch: ch})
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	keep := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.at.After(c.now) {
			w.ch <- c.now
			continue
		}
		keep = append(keep, w)
	}
	c.waiters = keep
}

type fakeSystemd struct {
	mu    sync.Mutex
	units []hostfacts.SystemdUnit
}

func (f *fakeSystemd) ListUnits(context.Context) ([]hostfacts.SystemdUnit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostfacts.SystemdUnit(nil), f.units...), nil
}

func (f *fakeSystemd) Properties(_ context.Context, path, iface string, _ ...string) (map[string]any, error) {
	switch {
	case strings.HasSuffix(iface, ".Unit"):
		return map[string]any{"FragmentPath": "/lib/systemd/system/" + filepath.Base(path), "UnitFileState": "enabled"}, nil
	case strings.HasSuffix(iface, ".Service"):
		return map[string]any{"MainPID": uint32(0)}, nil
	}
	return map[string]any{}, nil
}

func (f *fakeSystemd) Close() error { return nil }

func (f *fakeSystemd) setActive(name, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.units {
		if f.units[i].Name == name {
			f.units[i].ActiveState, f.units[i].SubState = state, state
		}
	}
}

type cp struct {
	srv      *refcp.Server
	http     *httptest.Server
	endpoint string
	caFile   string
}

func newCP(t *testing.T, clk *fakeClock) *cp {
	t.Helper()
	c := &cp{srv: refcp.New(refcp.Options{Now: clk.Now})}
	c.http = httptest.NewTLSServer(c.srv)
	t.Cleanup(func() {
		c.srv.Close()
		c.http.Close()
	})
	c.endpoint = c.http.URL
	c.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(c.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.http.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// signer holds a deployment root key and a bundle signing key.
type signer struct {
	root, sign bundle.SigningKey
	manifest   []byte
}

func newSigner(t *testing.T, now time.Time) *signer {
	t.Helper()
	s := &signer{}
	var err error
	if s.root, err = bundle.GenerateKey("root-1"); err != nil {
		t.Fatal(err)
	}
	if s.sign, err = bundle.GenerateKey("sign-1"); err != nil {
		t.Fatal(err)
	}
	m, err := bundle.NewKeyManifest(1, now, []bundle.ManifestKey{{ID: s.sign.ID, PublicKey: s.sign.Public().PublicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.manifest, err = bundle.SignManifest(m, s.root); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *signer) trustRoot() string {
	return s.root.ID + ":" + base64.StdEncoding.EncodeToString(s.root.Public().PublicKey)
}

const testManifest = `version: "%s"
engine_version: 1
schema_version: 1
target_type: host
created_at: 2026-09-01T00:00:00Z
rules:
  - id: node-load-high
    version: 1
    class: promql
    target: host
    scope: node
    file: prometheus/node.yaml
    group: node-exporter
    alert: NodeLoadHigh
    category: saturation
    severity: high
    capabilities: [metrics]
  - id: app-errors
    version: 1
    class: logql
    target: host
    scope: node
    file: loki/app.yaml
    group: app
    alert: AppErrors
    category: errors
    severity: medium
    capabilities: [logs]
    evidence: {max_samples: 5}
    budget: {max_series: 100}
  - id: ssh-failures
    version: 1
    class: logql
    target: host
    scope: node
    file: loki/app.yaml
    group: app
    alert: SSHFailures
    category: security
    severity: high
    capabilities: [logs]
    budget: {max_series: 10}
`

const testPromRules = `groups:
  - name: node-exporter
    interval: 30s
    rules:
      - alert: NodeLoadHigh
        expr: node_load1 > %s
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Load average is high on {{ $labels.instance }}"
`

const testLokiRules = `groups:
  - name: app
    interval: 30s
    rules:
      - alert: AppErrors
        expr: sum by (filename) (count_over_time({filename=~".+/app.log"} |= "ERROR" [1m])) > 0
        labels:
          severity: warning
      - alert: SSHFailures
        expr: sum by (unit) (count_over_time({unit="sshd.service"} |= "Failed password" [1m])) > 0
`

// build packs and signs a host bundle; promExpr is the right-hand side of the load threshold.
func (s *signer) build(t *testing.T, version, promExpr string) (archive, sig []byte) {
	t.Helper()
	dir := t.TempDir()
	writeFiles(dir, map[string]string{
		"bundle.yaml":          fmt.Sprintf(testManifest, version),
		"prometheus/node.yaml": fmt.Sprintf(testPromRules, promExpr),
		"loki/app.yaml":        testLokiRules,
	})
	archive, err := bundle.Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sig, err = bundle.Sign(archive, s.sign); err != nil {
		t.Fatal(err)
	}
	return archive, sig
}

// fixture is one host with its own state, facts, and logs over the shared metrics tree.
type fixture struct {
	t      *testing.T
	dir    string
	clk    *fakeClock
	sd     *fakeSystemd
	cfg    *config.Config
	ticks  chan time.Time
	cycles chan time.Time
	signer *signer
	cp     *cp
	target string
	inv    Investigator

	host   *Host
	cancel context.CancelFunc
	done   chan error
}

type fixtureOpts struct {
	caps   []string
	airgap bool
}

func newFixture(t *testing.T, clk *fakeClock, c *cp, s *signer, o fixtureOpts) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, dir: dir, clk: clk, cp: c, signer: s, sd: &fakeSystemd{units: []hostfacts.SystemdUnit{
		{Name: "nginx.service", Description: "nginx", LoadState: "loaded", ActiveState: "active", SubState: "running", Path: "/org/freedesktop/systemd1/unit/nginx_2eservice"},
		{Name: "cron.service", Description: "cron", LoadState: "loaded", ActiveState: "active", SubState: "running", Path: "/org/freedesktop/systemd1/unit/cron_2eservice"},
	}}}
	writeFiles(dir, map[string]string{
		"etc/os-release":      "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
		"etc/machine-id":      "0123456789abcdef0123456789abcdef\n",
		"var/lib/dpkg/status": "Package: nginx\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.22.1-9\n\n",
		"logs/app.log":        "",
	})
	caps := o.caps
	if caps == nil {
		caps = []string{config.CapInventory, config.CapMetrics, config.CapLogs}
	}
	yaml := fmt.Sprintf("role: host\nendpoint: %q\nendpointCAFile: %q\nenrollmentTokenFile: %q\nstateDir: %q\ncapabilities: [%s]\ntrust:\n  roots: [%q]\nhost:\n  logFiles: [%q]\n  journal: false\n",
		"https://127.0.0.1:1", "", filepath.Join(dir, "token"), filepath.Join(dir, "state"), strings.Join(caps, ", "), s.trustRoot(), filepath.Join(dir, "logs"))
	if c != nil {
		yaml = strings.Replace(yaml, `"https://127.0.0.1:1"`, fmt.Sprintf("%q", c.endpoint), 1)
		yaml = strings.Replace(yaml, `endpointCAFile: ""`, fmt.Sprintf("endpointCAFile: %q", c.caFile), 1)
	}
	if o.airgap {
		yaml += fmt.Sprintf("airgap:\n  enabled: true\n  bundleDir: %q\n  exportDir: %q\n", filepath.Join(dir, "bundles"), filepath.Join(dir, "state/export"))
	}
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = cfg
	return f
}

func (f *fixture) writeToken(tok string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "token"), []byte(tok+"\n"), 0o640); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) path(p string) string { return filepath.Join(f.dir, p) }

func (f *fixture) deps() Deps {
	return Deps{
		Facts: hostfacts.Options{
			ProcRoot: filepath.Join(metricsRoot, "proc"), SysRoot: filepath.Join(metricsRoot, "sys"), EtcRoot: f.path("etc"),
			UsrLibRoot: f.path("usr/lib"), DpkgDir: f.path("var/lib/dpkg"), RPMPaths: []string{f.path("var/lib/rpm/rpmdb.sqlite")},
			APKInstalled: f.path("lib/apk/db/installed"), Systemd: f.sd,
			Uname: func() (hostfacts.Uname, error) {
				return hostfacts.Uname{Sysname: "Linux", Nodename: "web-1", Release: "6.1.0", Version: "#1 SMP", Machine: "x86_64"}, nil
			},
			Interfaces: func() ([]hostfacts.NetInterface, error) {
				return []hostfacts.NetInterface{{Name: "lo", Index: 1, MTU: 65536, Flags: []string{"up", "loopback"}, Addrs: []string{"127.0.0.1/8"}}}, nil
			},
			Statfs: func(string, *unix.Statfs_t) error { return unix.ENOENT },
			UID:    os.Getuid(),
		},
		FSRoot: metricsRoot, MetricsCollectors: []string{"loadavg", "meminfo"},
		Clock: f.clk, Ticks: f.ticks, CollectInterval: 30 * time.Second,
		OnCycle:        func(t time.Time) { f.cycles <- t },
		HealthInterval: -1, Investigator: f.inv,
	}
}

func (f *fixture) start() { f.t.Helper(); f.startWith(nil) }

func (f *fixture) startWith(mod func(*Deps)) {
	f.t.Helper()
	f.ticks, f.cycles = make(chan time.Time), make(chan time.Time, 16)
	d := f.deps()
	if mod != nil {
		mod(&d)
	}
	h, err := New(f.cfg, d)
	if err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.host, f.cancel, f.done = h, cancel, make(chan error, 1)
	go func() { f.done <- h.Run(ctx) }()
	select {
	case <-f.cycles:
	case err := <-f.done:
		f.t.Fatalf("host stopped at start: %v", err)
	case <-time.After(30 * time.Second):
		f.t.Fatal("host did not start")
	}
}

// tick advances the clock and waits for one full cycle.
func (f *fixture) tick(d time.Duration) {
	f.t.Helper()
	f.clk.Advance(d)
	select {
	case f.ticks <- f.clk.Now():
	case err := <-f.done:
		f.t.Fatalf("host stopped: %v", err)
	}
	select {
	case <-f.cycles:
	case err := <-f.done:
		f.t.Fatalf("host stopped: %v", err)
	case <-time.After(30 * time.Second):
		f.t.Fatal("cycle did not finish")
	}
}

func (f *fixture) stop() error {
	f.t.Helper()
	f.cancel()
	select {
	case err := <-f.done:
		f.host = nil
		return err
	case <-time.After(30 * time.Second):
		f.t.Fatal("host did not stop")
	}
	return nil
}

func (f *fixture) appendLog(line string) {
	f.t.Helper()
	fh, err := os.OpenFile(f.path("logs/app.log"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		f.t.Fatal(err)
	}
	defer fh.Close()
	if _, err := fh.WriteString(line + "\n"); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) setPackages(pkgs ...string) {
	f.t.Helper()
	var b strings.Builder
	for _, p := range pkgs {
		fmt.Fprintf(&b, "Package: %s\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\n", p)
	}
	writeFiles(f.dir, map[string]string{"var/lib/dpkg/status": b.String()})
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (f *fixture) status() Status { return f.host.status() }

func (f *fixture) epochs() []refcp.EpochView {
	f.t.Helper()
	eps, err := f.cp.srv.Epochs(f.target)
	if err != nil && !errors.Is(err, refcp.ErrUnknownTarget) {
		f.t.Fatal(err)
	}
	return eps
}

// committedState reconstructs the control plane's view at its committed head.
func (f *fixture) committedState() (*protocol.State, uint64) {
	f.t.Helper()
	eps := f.epochs()
	if len(eps) == 0 {
		return nil, 0
	}
	ep := eps[len(eps)-1]
	if ep.Head.Seq == 0 {
		return nil, 0
	}
	st, err := f.cp.srv.StateAt(f.target, ep.ID, ep.Head.Seq)
	if err != nil {
		return nil, 0
	}
	return st, ep.Head.Seq
}

func (f *fixture) findings() map[string]refcp.FindingState {
	out := map[string]refcp.FindingState{}
	fs, _ := f.cp.srv.Findings(f.target)
	for _, x := range fs {
		out[x.RuleID] = x
	}
	return out
}

// waitTicking runs zero-length cycles until cond holds, for work the cycle starts.
func (f *fixture) waitTicking(what string, cond func() bool) {
	f.t.Helper()
	eventually(f.t, what, func() bool {
		f.tick(0)
		return cond()
	})
}
