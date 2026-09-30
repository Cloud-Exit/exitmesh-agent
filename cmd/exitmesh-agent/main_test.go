package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/host"
	"github.com/cloud-exit/exitmesh-agent/internal/node"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
)

func runArgs(t *testing.T, ctx context.Context, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(ctx, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageVersionAndFlags(t *testing.T) {
	ctx := context.Background()
	if code, _, e := runArgs(t, ctx); code != 2 || !strings.Contains(e, "prepare-image") {
		t.Fatalf("no args: %d %q", code, e)
	}
	if code, o, _ := runArgs(t, ctx, "help"); code != 0 || !strings.Contains(o, "deenroll") {
		t.Fatalf("help: %d", code)
	}
	if code, _, e := runArgs(t, ctx, "frobnicate"); code != 2 || !strings.Contains(e, "unknown command") {
		t.Fatalf("unknown: %d %q", code, e)
	}
	version, commit = "1.2.3", "abc123"
	defer func() { version, commit = "dev", "none" }()
	code, o, _ := runArgs(t, ctx, "version")
	for _, want := range []string{"exitmesh-agent 1.2.3", "commit: abc123", "protocol: 1", "schema: 1", "engine: 1"} {
		if code != 0 || !strings.Contains(o, want) {
			t.Fatalf("version output %q lacks %q", o, want)
		}
	}
	cfg := writeConfig(t, t.TempDir(), "host")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"run"}, "--config is required"},
		{[]string{"version", "extra"}, "unexpected argument"},
		{[]string{"prepare-state", "--dir", t.TempDir()}, "--uid and --gid"},
		{[]string{"cleanup"}, "--dir is required"},
		{[]string{"cleanup", "--dir", "var/lib/exitmesh"}, "--dir must be an absolute path"},
		{[]string{"purge-state", "--dir", "/var/.."}, "--dir must not be the filesystem root"},
		{[]string{"prepare-image", "--dir", "/"}, "--dir must not be the filesystem root"},
		{[]string{"prepare-state", "--dir", "state", "--uid", "0", "--gid", "0"}, "--dir must be an absolute path"},
		{[]string{"export", "--config", cfg}, "--out is required"},
		{[]string{"commit", "--config", cfg}, "--receipt is required"},
		{[]string{"investigate", "--config", cfg}, "--tool is required"},
		{[]string{"investigate", "--config", cfg, "--tool", "x", "--args", "{nope"}, "not valid JSON"},
		{[]string{"status", "--bogus"}, "flag provided but not defined"},
		{[]string{"run", "--config", cfg, "--run-as", "0:0"}, "not a non-root UID:GID"},
	} {
		code, _, e := runArgs(t, ctx, c.args...)
		if code != 2 || !strings.Contains(e, c.want) {
			t.Errorf("%v: code %d stderr %q, want %q", c.args, code, e, c.want)
		}
	}
	if code, _, _ := runArgs(t, ctx, "cleanup", "-h"); code != 0 {
		t.Fatalf("-h exit %d", code)
	}
	if code, _, e := runArgs(t, ctx, "run", "--config", filepath.Join(t.TempDir(), "missing.yaml")); code != 1 || !strings.Contains(e, "missing.yaml") {
		t.Fatalf("missing config: %d %q", code, e)
	}
}

func writeConfig(t *testing.T, dir, role string) string {
	t.Helper()
	body := fmt.Sprintf("role: %s\nendpoint: https://exitmesh.example\nenrollmentTokenFile: %s\nstateDir: %s\ntrust:\n  roots: [\"root-1:MCowBQYDK2VwAyEA\"]\nlogging:\n  level: debug\n  format: text\n",
		role, filepath.Join(dir, "token"), filepath.Join(dir, "state"))
	if role == "node" {
		body += "coordinator:\n  serviceURL: https://coordinator:8443\n"
	}
	p := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoggerRedactsAndHonorsFormat(t *testing.T) {
	var buf bytes.Buffer
	cfg := &config.Config{Role: "host", Logging: config.Logging{Level: "info", Format: "json"}}
	log, err := newLogger(cfg, &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("hidden")
	log.Info("login", "password", "hunter2", "line", "token=abcdef1234567890")
	if strings.Contains(buf.String(), "hunter2") || strings.Contains(buf.String(), "abcdef1234567890") || strings.Contains(buf.String(), "hidden") {
		t.Fatalf("log output %s", buf.String())
	}
	if !json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Fatalf("not JSON: %s", buf.String())
	}
	buf.Reset()
	cfg.Logging = config.Logging{Level: "debug", Format: "text"}
	if log, err = newLogger(cfg, &buf); err != nil {
		t.Fatal(err)
	}
	log.Debug("visible")
	if !strings.Contains(buf.String(), "msg=visible") {
		t.Fatalf("text output %q", buf.String())
	}
	for _, l := range []config.Logging{{Level: "loud", Format: "json"}, {Level: "info", Format: "xml"}} {
		cfg.Logging = l
		if _, err := newLogger(cfg, io.Discard); err == nil {
			t.Fatalf("accepted %+v", l)
		}
	}
	_ = slog.LevelInfo
}

type recordingOps struct{ calls []string }

func (r *recordingOps) ops() fsOps {
	return fsOps{
		chown: func(p string, uid, gid int) error {
			r.calls = append(r.calls, fmt.Sprintf("chown %d:%d", uid, gid))
			return nil
		},
		chmod: func(p string, m os.FileMode) error {
			r.calls = append(r.calls, fmt.Sprintf("chmod %o", m))
			return os.Chmod(p, m)
		},
	}
}

func TestPrepareState(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	dir := filepath.Join(t.TempDir(), "state")
	rec := &recordingOps{}
	changed, err := prepareState(rec.ops(), dir, uid, gid)
	if err != nil || changed || len(rec.calls) != 0 {
		t.Fatalf("created directory: changed %v calls %v err %v", changed, rec.calls, err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err = prepareState(rec.ops(), dir, uid, gid)
	want := []string{"chown 0:0", "chmod 700", fmt.Sprintf("chown %d:%d", uid, gid)}
	if err != nil || !changed || strings.Join(rec.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("fix: changed %v calls %v err %v", changed, rec.calls, err)
	}
	rec.calls = nil
	if changed, err := prepareState(rec.ops(), dir, uid, gid); err != nil || changed || len(rec.calls) != 0 {
		t.Fatalf("second run not idempotent: %v %v %v", changed, rec.calls, err)
	}
	code, o, _ := runArgs(t, context.Background(), "prepare-state", "--dir", dir, "--uid", fmt.Sprint(uid), "--gid", fmt.Sprint(gid))
	if code != 0 || !strings.Contains(o, "already owned") {
		t.Fatalf("cli: %d %q", code, o)
	}
	if uid != 0 {
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		code, _, e := runArgs(t, context.Background(), "prepare-state", "--dir", dir, "--uid", fmt.Sprint(uid), "--gid", fmt.Sprint(gid))
		if code != 1 || !strings.Contains(e, "to root") {
			t.Fatalf("unprivileged chown must fail clearly: %d %q", code, e)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareState(rec.ops(), link, uid, gid); err == nil {
		t.Fatal("symbolic link accepted")
	}
}

func populate(t *testing.T, dir string) {
	t.Helper()
	for _, p := range []string{"spool/seg-1", "tsdb/wal/0001", "meta.db"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCleanupPurgeAndPrepareImage(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "exitmesh")
	populate(t, dir)
	unlock, err := spool.LockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"cleanup", "purge-state", "prepare-image"} {
		code, _, e := runArgs(t, ctx, cmd, "--dir", dir)
		if code != 1 || !strings.Contains(e, "locked by a running agent") {
			t.Fatalf("%s with the lock held: %d %q", cmd, code, e)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "meta.db")); err != nil {
		t.Fatal("state deleted while locked")
	}
	unlock()

	code, o, _ := runArgs(t, ctx, "prepare-image", "--dir", dir)
	ents, _ := os.ReadDir(dir)
	if code != 0 || len(ents) != 0 || !strings.Contains(o, "/etc/machine-id") {
		t.Fatalf("prepare-image: %d %q entries %v", code, o, ents)
	}
	populate(t, dir)
	if code, _, _ := runArgs(t, ctx, "purge-state", "--dir", dir); code != 0 {
		t.Fatal("purge-state failed")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("purge-state kept the directory")
	}
	if code, o, _ := runArgs(t, ctx, "cleanup", "--dir", dir); code != 0 || !strings.Contains(o, "clean") {
		t.Fatalf("cleanup of a missing directory: %d %q", code, o)
	}

	populate(t, dir)
	mi := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(mi, []byte("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n40 22 8:2 / "+strings.ReplaceAll(dir, " ", `\040`)+" rw - ext4 /dev/sdb1 rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := mountInfo
	mountInfo = mi
	defer func() { mountInfo = old }()
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan int, 1)
	var out bytes.Buffer
	var mu sync.Mutex
	go func() {
		mu.Lock()
		defer mu.Unlock()
		done <- run(wctx, []string{"cleanup", "--dir", dir, "--wait"}, &out, io.Discard)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ents, _ := os.ReadDir(dir)
		if len(ents) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cleanup --wait did not clean the mount point")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var unlocked func() error
	for time.Now().Before(deadline) {
		if unlocked, err = spool.LockDir(dir); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("cleanup --wait kept the lock: %v", err)
	}
	unlocked()
	select {
	case <-done:
		t.Fatal("cleanup --wait returned before termination")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("cleanup --wait exit %d", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(out.String(), "waiting for termination") {
		t.Fatalf("output %q", out.String())
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("mount point removed")
	}
	os.Remove(filepath.Join(dir, "LOCK"))
}

func TestIsMountPointAndUnescape(t *testing.T) {
	if got := unescapeMount(`/var/lib/a\040b\134c`); got != `/var/lib/a b\c` {
		t.Fatalf("unescape %q", got)
	}
	old := mountInfo
	mountInfo = filepath.Join(t.TempDir(), "absent")
	defer func() { mountInfo = old }()
	dir := t.TempDir()
	if mp, err := isMountPoint(dir); err != nil || mp {
		t.Fatalf("temp dir is not a mount point: %v %v", mp, err)
	}
}

func TestMemoryLimitFromCgroup(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc2", "0::/system.slice/exitmesh-agent.service\n")
	write("cg/system.slice/exitmesh-agent.service/memory.max", "201326592\n")
	write("cg/system.slice/memory.max", "max\n")
	if l, src, ok := cgroupMemoryLimit(filepath.Join(root, "proc2"), filepath.Join(root, "cg")); !ok || l != 201326592 || !strings.HasSuffix(src, "exitmesh-agent.service/memory.max") {
		t.Fatalf("v2 leaf: %d %s %v", l, src, ok)
	}
	write("cg/system.slice/memory.max", "100000000\n")
	if l, _, ok := cgroupMemoryLimit(filepath.Join(root, "proc2"), filepath.Join(root, "cg")); !ok || l != 100000000 {
		t.Fatalf("v2 tighter parent: %d %v", l, ok)
	}
	write("proc1", "12:pids:/docker/abc\n4:cpu,memory:/docker/abc\n")
	write("v1/memory/docker/abc/memory.limit_in_bytes", "268435456\n")
	if l, _, ok := cgroupMemoryLimit(filepath.Join(root, "proc1"), filepath.Join(root, "v1")); !ok || l != 268435456 {
		t.Fatalf("v1: %d %v", l, ok)
	}
	write("v1/memory/docker/abc/memory.limit_in_bytes", "9223372036854771712\n")
	if _, _, ok := cgroupMemoryLimit(filepath.Join(root, "proc1"), filepath.Join(root, "v1")); ok {
		t.Fatal("v1 unlimited reported as a limit")
	}
	write("proc0", "0::/\n")
	if _, _, ok := cgroupMemoryLimit(filepath.Join(root, "proc0"), filepath.Join(root, "none")); ok {
		t.Fatal("limit without memory.max")
	}
	if _, _, ok := cgroupMemoryLimit(filepath.Join(root, "absent"), root); ok {
		t.Fatal("limit without /proc/self/cgroup")
	}

	prev := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(prev)
	env := func(v string) func(string) string { return func(string) string { return v } }
	if _, _, ok := applyMemoryLimit(env("172MiB"), filepath.Join(root, "proc2"), filepath.Join(root, "cg")); ok {
		t.Fatal("GOMEMLIMIT from the environment overridden")
	}
	soft, _, ok := applyMemoryLimit(env(""), filepath.Join(root, "proc2"), filepath.Join(root, "cg"))
	if !ok || soft != 90000000 || debug.SetMemoryLimit(-1) != 90000000 {
		t.Fatalf("soft limit %d %v", soft, ok)
	}
}

type fakeBackend struct {
	mu       sync.Mutex
	receipt  admin.CommitReceipt
	reason   string
	tool     string
	args     string
	exported uint64
}

func (b *fakeBackend) Status(context.Context) (any, error) {
	return map[string]any{"role": "host", "target_id": "host-1"}, nil
}

func (b *fakeBackend) Investigate(_ context.Context, r admin.InvestigateRequest) (any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tool, b.args = r.Tool, string(r.Args)
	return map[string]any{"source": "local", "data": []int{1, 2}}, nil
}

func (b *fakeBackend) Export(_ context.Context, from uint64, w io.Writer) error {
	b.mu.Lock()
	b.exported = from
	b.mu.Unlock()
	_, err := io.WriteString(w, "EMHPX1\nrecords")
	return err
}

func (b *fakeBackend) Deenroll(_ context.Context, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reason = reason
	return nil
}

func (b *fakeBackend) Commit(_ context.Context, r admin.CommitReceipt) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.receipt = r
	return nil
}

func serveAdmin(t *testing.T, stateDir string, b admin.Backend) {
	t.Helper()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		admin.Serve(ctx, stateDir, b)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(stateDir, admin.SocketName)); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("admin socket not served")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAdminSubcommands(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := writeConfig(t, dir, "coordinator")
	if code, _, e := runArgs(t, ctx, "status", "--config", cfg); code != 1 || !strings.Contains(e, "is the agent running") {
		t.Fatalf("status without an agent: %d %q", code, e)
	}
	b := &fakeBackend{}
	serveAdmin(t, filepath.Join(dir, "state"), b)

	code, o, _ := runArgs(t, ctx, "status", "--config", cfg)
	if code != 0 || !strings.Contains(o, `"target_id": "host-1"`) {
		t.Fatalf("status: %d %q", code, o)
	}
	argsFile := filepath.Join(dir, "args.json")
	os.WriteFile(argsFile, []byte(`{"query":"node_load1"}`), 0o600)
	code, o, _ = runArgs(t, ctx, "investigate", "--config", cfg, "--tool", "promql.query", "--args", "@"+argsFile)
	if code != 0 || !strings.Contains(o, `"source": "local"`) || b.tool != "promql.query" || b.args != `{"query":"node_load1"}` {
		t.Fatalf("investigate: %d %q %s %s", code, o, b.tool, b.args)
	}
	if code, _, _ = runArgs(t, ctx, "investigate", "--config", cfg, "--tool", "state.query", "--args", `{"kind":"host/Unit"}`); code != 0 || b.args != `{"kind":"host/Unit"}` {
		t.Fatalf("inline args: %s", b.args)
	}
	code, o, _ = runArgs(t, ctx, "export", "--config", cfg, "--out", "-", "--from", "7")
	if code != 0 || o != "EMHPX1\nrecords" || b.exported != 7 {
		t.Fatalf("export to stdout: %d %q from %d", code, o, b.exported)
	}
	outFile := filepath.Join(dir, "x.emhpx")
	if code, _, _ = runArgs(t, ctx, "export", "--config", cfg, "--out", outFile); code != 0 {
		t.Fatal("export to file failed")
	}
	if got, _ := os.ReadFile(outFile); string(got) != "EMHPX1\nrecords" {
		t.Fatalf("export file %q", got)
	}
	receipt := filepath.Join(dir, "receipt.json")
	os.WriteFile(receipt, []byte(`{"epoch":"0123456789abcdef0123456789abcdef","seq":42,"chain_hash":"ab"}`), 0o600)
	code, o, _ = runArgs(t, ctx, "commit", "--config", cfg, "--receipt", receipt)
	if code != 0 || b.receipt.Seq != 42 || !strings.Contains(o, "through sequence 42") {
		t.Fatalf("commit: %d %q %+v", code, o, b.receipt)
	}
	os.WriteFile(receipt, []byte(`{"epoch":"x","seq":0}`), 0o600)
	if code, _, _ = runArgs(t, ctx, "commit", "--config", cfg, "--receipt", receipt); code != 1 {
		t.Fatal("incomplete receipt accepted")
	}
	if code, _, _ = runArgs(t, ctx, "deenroll", "--config", cfg, "--reason", "retired"); code != 0 || b.reason != "retired" {
		t.Fatalf("deenroll via socket: %d %q", code, b.reason)
	}
}

func TestHostOfflineFallbacks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := writeConfig(t, dir, "host")
	b := &fakeBackend{}
	serveAdmin(t, filepath.Join(dir, "state"), b)
	saved := offline
	defer func() { offline = saved }()
	var offlineCalls []string
	offline.export = func(_ *config.Config, from uint64, w io.Writer) error {
		offlineCalls = append(offlineCalls, "export")
		return host.ErrRunning
	}
	offline.deenroll = func(context.Context, *config.Config, string) error {
		offlineCalls = append(offlineCalls, "deenroll")
		return host.ErrRunning
	}
	if code, o, _ := runArgs(t, ctx, "export", "--config", cfg, "--out", "-"); code != 0 || o != "EMHPX1\nrecords" {
		t.Fatalf("running host export: %d %q", code, o)
	}
	if code, _, _ := runArgs(t, ctx, "deenroll", "--config", cfg); code != 0 || b.reason == "" {
		t.Fatal("running host deenroll")
	}
	if strings.Join(offlineCalls, ",") != "export,deenroll" {
		t.Fatalf("offline attempts %v", offlineCalls)
	}
	offline.export = func(_ *config.Config, _ uint64, w io.Writer) error {
		_, err := io.WriteString(w, "OFFLINE")
		return err
	}
	offline.deenroll = func(_ context.Context, _ *config.Config, reason string) error {
		if reason == "fail" {
			return errors.New("connection refused")
		}
		return nil
	}
	if code, o, _ := runArgs(t, ctx, "export", "--config", cfg, "--out", "-"); code != 0 || o != "OFFLINE" {
		t.Fatalf("stopped host export: %d %q", code, o)
	}
	b.reason = ""
	if code, o, _ := runArgs(t, ctx, "deenroll", "--config", cfg); code != 0 || !strings.Contains(o, "deleted locally") || b.reason != "" {
		t.Fatalf("stopped host deenroll: %d %q", code, o)
	}
	if code, _, e := runArgs(t, ctx, "deenroll", "--config", cfg, "--reason", "fail"); code != 1 || !strings.Contains(e, "connection refused") {
		t.Fatalf("offline failure: %d %q", code, e)
	}
	offline.export = func(*config.Config, uint64, io.Writer) error { return syscall.EACCES }
	out := filepath.Join(dir, "fail.emhpx")
	if code, _, _ := runArgs(t, ctx, "export", "--config", cfg, "--out", out); code != 1 {
		t.Fatal("failed export succeeded")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("partial export file left behind")
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary export file left behind")
	}
}

func TestReadArgs(t *testing.T) {
	if b, err := readArgs(""); err != nil || string(b) != "{}" {
		t.Fatalf("empty: %s %v", b, err)
	}
	if _, err := readArgs("@" + filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := readArgs("[1,"); !errors.Is(err, errUsage) {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestRolesDispatchAndVersion(t *testing.T) {
	version = "9.9.9"
	defer func() { version = "dev" }()
	r := roles()
	for _, role := range []string{config.RoleNode, config.RoleCoordinator, config.RoleHost} {
		if r[role] == nil {
			t.Fatalf("role %s not dispatched", role)
		}
	}
	if host.Version != "9.9.9" || node.Version != "9.9.9" {
		t.Fatalf("host version %q", host.Version)
	}
}

func TestDecodeCmd(t *testing.T) {
	chain := protocol.NewChain("t-1", protocol.EpochID{1}, protocol.WriterID{2})
	st := protocol.NewState()
	ck := &protocol.Record{Envelope: chain.Next(protocol.TypeCheckpoint, 1, 10), Checkpoint: st.Checkpoint(protocol.ReasonInitial, protocol.Interval{}, nil)}
	if _, err := protocol.Encode(ck); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(ck); err != nil {
		t.Fatal(err)
	}
	d := &protocol.Record{Envelope: chain.Next(protocol.TypeDelta, 1, 11), Delta: &protocol.Delta{Ops: []protocol.Op{protocol.Create("u", "Pod", "ns", "p", nil)}}}
	if _, err := protocol.Encode(d); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := protocol.NewExportWriter(&buf, protocol.ExportHeader{TargetID: "t-1", WriterID: make([]byte, 16), Epoch: make([]byte, 16), Incarnation: 1, AgentVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*protocol.Record{ck, d} {
		if err := w.Write(r.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "x.emhpx")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"decode", "--in", path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"records":2`) || !strings.Contains(lines[2], `"op":"create"`) || !strings.Contains(lines[2], `"chain_hash"`) {
		t.Fatalf("decode output:\n%s", out.String())
	}
	if code := run(context.Background(), []string{"decode"}, &out, &errb); code != 2 {
		t.Fatalf("missing --in exit %d", code)
	}
}
