package hostfacts

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func field(t *testing.T, s *Snapshot, uid, key string) any {
	t.Helper()
	r, ok := s.Resources[uid]
	if !ok {
		t.Fatalf("resource %s missing; have %v", uid, keys(s))
	}
	return r.Fields[key]
}

func keys(s *Snapshot) []string {
	var out []string
	for k := range s.Resources {
		out = append(out, k)
	}
	return out
}

func hasEdge(s *Snapshot, from, typ, to string) bool {
	_, ok := s.Edges[protocol.EdgeKey{From: from, Type: typ, To: to}]
	return ok
}

func eqList(v any, want ...string) bool {
	l, ok := v.([]any)
	if !ok || len(l) != len(want) {
		return false
	}
	for i := range l {
		if l[i] != want[i] {
			return false
		}
	}
	return true
}

func TestCollectDebianFixture(t *testing.T) {
	f := newDebianFixture(t)
	c := NewCollector(f.options())
	s := c.Collect(context.Background())

	os := uid(KindOS)
	if field(t, s, os, "id") != "debian" || field(t, s, os, "version_id") != "12" || field(t, s, os, "pretty_name") != "Debian GNU/Linux 12 (bookworm)" || field(t, s, os, "version_codename") != "bookworm" {
		t.Fatalf("os fields %v", s.Resources[os].Fields)
	}
	if field(t, s, os, "hostname") != "web-1" || field(t, s, os, "machine_id") != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("identity fields %v", s.Resources[os].Fields)
	}
	if _, ok := s.Resources[os].Fields["home_url"]; ok {
		t.Fatal("non-catalogued os-release key collected")
	}
	if field(t, s, uid(KindKernel), "release") != "6.1.0-18-amd64" || field(t, s, uid(KindKernel), "machine") != "x86_64" {
		t.Fatal("kernel fields")
	}
	cpu := uid(KindCPU)
	if field(t, s, cpu, "logical_cpus") != int64(4) || field(t, s, cpu, "cores") != int64(2) || field(t, s, cpu, "packages") != int64(1) || field(t, s, cpu, "vendor_id") != "GenuineIntel" {
		t.Fatalf("cpu fields %v", s.Resources[cpu].Fields)
	}
	if field(t, s, uid(KindMemory), "mem_total_bytes") != int64(8000000*1024) || field(t, s, uid(KindMemory), "swap_total_bytes") != int64(2097148*1024) {
		t.Fatal("memory fields")
	}

	sda, sda1, sda2, dm0 := uid(KindBlockDevice, "sda"), uid(KindBlockDevice, "sda1"), uid(KindBlockDevice, "sda2"), uid(KindBlockDevice, "dm-0")
	if field(t, s, sda, "model") != "QEMU HARDDISK" || field(t, s, sda, "rotational") != true || field(t, s, sda, "size_bytes") != int64(2000000*512) || field(t, s, sda, "device") != "8:0" {
		t.Fatalf("sda %v", s.Resources[sda].Fields)
	}
	if field(t, s, sda1, "partition") != int64(1) || !hasEdge(s, sda1, EdgePartitionOf, sda) || !hasEdge(s, sda2, EdgePartitionOf, sda) {
		t.Fatal("partitions")
	}
	if field(t, s, dm0, "dm_name") != "vg-var" || field(t, s, dm0, "rotational") != false {
		t.Fatal("dm-0")
	}
	if _, ok := s.Resources[uid(KindBlockDevice, "loop0")]; ok {
		t.Fatal("empty loop device collected")
	}

	root, home, srv, varm := uid(KindMount, "/", "/dev/sda1"), uid(KindMount, "/home", "/dev/sda2"), uid(KindMount, "/srv", "/dev/sda2"), uid(KindMount, "/var", "/dev/mapper/vg-var")
	for _, m := range []string{uid(KindMount, "/proc", "proc"), uid(KindMount, "/sys", "sysfs"), uid(KindMount, "/run/user/1000", "tmpfs"), uid(KindMount, "/var/lib/docker/overlay2/abc/merged", "overlay")} {
		if _, ok := s.Resources[m]; ok {
			t.Fatalf("excluded mount %s collected", m)
		}
	}
	if field(t, s, srv, "read_only") != true || field(t, s, root, "read_only") != false || field(t, s, home, "root") != "/@home" {
		t.Fatal("mount fields")
	}
	if !eqList(field(t, s, root, "options"), "relatime", "rw") {
		t.Fatalf("options %v", field(t, s, root, "options"))
	}
	if !hasEdge(s, root, EdgeDevice, sda1) || !hasEdge(s, home, EdgeDevice, sda2) || !hasEdge(s, varm, EdgeDevice, dm0) {
		t.Fatal("mount to device edges")
	}
	btr := uid(KindFilesystem, "btrfs", "/dev/sda2")
	if !hasEdge(s, home, EdgeFilesystem, btr) || !hasEdge(s, srv, EdgeFilesystem, btr) {
		t.Fatal("bind of one superblock must map to one filesystem")
	}
	rootFS := uid(KindFilesystem, "ext4", "/dev/sda1")
	if field(t, s, rootFS, "size_bytes") != int64(4096*1000000) || field(t, s, rootFS, "used_pct_bucket") != int64(50) || field(t, s, rootFS, "inodes_total") != int64(65536) {
		t.Fatalf("root fs %v", s.Resources[rootFS].Fields)
	}
	tmp := uid(KindFilesystem, "tmpfs", "tmpfs", "/tmp")
	if field(t, s, tmp, "capacity_unavailable") != ReasonCapacityDenied {
		t.Fatalf("tmp fs %v", s.Resources[tmp].Fields)
	}
	if _, ok := s.Resources[uid(KindFilesystem, "tmpfs", "tmpfs", "/run")]; !ok {
		t.Fatal("tmpfs /run filesystem missing")
	}
	if st := s.Status[FactFilesystems]; st.State != protocol.ScopePartial || st.Reason != ReasonCapacityDenied {
		t.Fatalf("filesystems status %+v", st)
	}

	eth0 := uid(KindInterface, "eth0")
	if !eqList(field(t, s, eth0, "addresses"), "10.0.0.5/24", "2001:db8::5054:ff:fe12:3456/64", "fe80::5054:ff:fe12:3456/64") {
		t.Fatalf("eth0 addresses %v", field(t, s, eth0, "addresses"))
	}
	if field(t, s, eth0, "operstate") != "up" || field(t, s, eth0, "hardware_addr") != "52:54:00:12:34:56" || field(t, s, eth0, "mtu") != int64(1500) {
		t.Fatal("eth0 fields")
	}
	if _, ok := s.Resources[uid(KindInterface, "veth1a2b3c")]; ok {
		t.Fatal("veth collected")
	}

	ssh := uid(KindSocket, "tcp", "0.0.0.0", "22")
	app := uid(KindSocket, "tcp", "127.0.0.1", "8080")
	orphan := uid(KindSocket, "tcp", "127.0.0.1", "9090")
	web := uid(KindSocket, "tcp6", "[::]", "80")
	dhcp := uid(KindSocket, "udp", "0.0.0.0", "68")
	if field(t, s, ssh, "uid") != int64(0) || field(t, s, ssh, "unavailable_reason") != ReasonOtherUserFD || !eqList(field(t, s, ssh, "unavailable_edges"), "process", "unit") {
		t.Fatalf("ssh socket %v", s.Resources[ssh].Fields)
	}
	if field(t, s, orphan, "unavailable_reason") != ReasonOwnerNotFound {
		t.Fatalf("orphan socket %v", s.Resources[orphan].Fields)
	}
	if l, ok := field(t, s, web, "inodes").([]any); !ok || len(l) != 2 || field(t, s, web, "uid") != int64(33) {
		t.Fatalf("reuseport socket %v", s.Resources[web].Fields)
	}
	if field(t, s, dhcp, "protocol") != "udp" || field(t, s, dhcp, "port") != int64(68) {
		t.Fatal("udp socket")
	}
	for _, r := range s.Resources {
		if r.Kind == KindSocket && (r.Fields["port"] == int64(53) || r.Fields["address"] == "10.0.0.5") {
			t.Fatalf("connected socket collected: %v", r.Fields)
		}
	}
	appProc := uid(KindProcess, "4242", "5000")
	if !hasEdge(s, app, EdgeProcess, appProc) {
		t.Fatal("own socket not mapped to its lowest-PID holder")
	}
	if _, ok := s.Resources[app].Fields["unavailable_edges"]; ok {
		t.Fatal("resolved socket marked unavailable")
	}
	myapp := uid(KindUnit, "myapp.service")
	if !hasEdge(s, app, EdgeUnit, myapp) {
		t.Fatal("socket to unit edge via cgroup")
	}
	if field(t, s, appProc, "cmdline") != "/opt/myapp/bin/myapp --password=<redacted> --port 8080" {
		t.Fatalf("allowlisted cmdline %v", field(t, s, appProc, "cmdline"))
	}
	nginxProc := uid(KindProcess, "1234", "900")
	if _, ok := s.Resources[nginxProc].Fields["cmdline"]; ok {
		t.Fatal("cmdline collected for a comm not on the allowlist")
	}
	if field(t, s, nginxProc, "uid") != int64(0) || field(t, s, nginxProc, "comm") != "nginx" {
		t.Fatal("nginx process fields")
	}
	nginx := uid(KindUnit, "nginx.service")
	if !hasEdge(s, nginx, EdgeMainProcess, nginxProc) || !hasEdge(s, myapp, EdgeMainProcess, appProc) {
		t.Fatal("unit to process edges")
	}
	if _, ok := s.Resources[uid(KindProcess, "4243", "5100")]; ok {
		t.Fatal("non-owner worker collected as a process")
	}

	for _, u := range []string{uid(KindUnit, "session-1.scope"), uid(KindUnit, "dev-sda.device"), uid(KindUnit, "gone.service")} {
		if _, ok := s.Resources[u]; ok {
			t.Fatalf("%s collected", u)
		}
	}
	if field(t, s, nginx, "unit_file_state") != "enabled" || field(t, s, nginx, "sub_state") != "running" || field(t, s, nginx, "fragment_path") != "/usr/lib/systemd/system/nginx.service" {
		t.Fatal("unit fields")
	}
	timer := uid(KindTimer, "myapp-cleanup.timer")
	if field(t, s, timer, "scheduled") != true || field(t, s, timer, "last_trigger_day") != time.UnixMicro(1789900000123456).UTC().Format(time.DateOnly) {
		t.Fatalf("timer %v", s.Resources[timer].Fields)
	}
	if !hasEdge(s, timer, EdgeTriggers, uid(KindUnit, "myapp-cleanup.service")) {
		t.Fatal("timer edge")
	}
	if _, ok := s.Resources[uid(KindUnit, "myapp-cleanup.timer")]; ok {
		t.Fatal("timer duplicated as a unit")
	}

	nginxPkg := uid(KindPackage, "dpkg", "nginx", "amd64")
	if field(t, s, nginxPkg, "version") != "1.22.1-9" || field(t, s, nginxPkg, "state") != "installed" {
		t.Fatal("nginx package")
	}
	if !hasEdge(s, nginxPkg, EdgeProvidesUnit, nginx) {
		t.Fatal("usr-merged package to unit edge")
	}
	myappPkg := uid(KindPackage, "dpkg", "myapp", "all")
	if field(t, s, myappPkg, "state") != "installed" || !hasEdge(s, myappPkg, EdgeProvidesUnit, myapp) || !hasEdge(s, myappPkg, EdgeProvidesUnit, timer) {
		t.Fatal("myapp package edges")
	}
	if _, ok := s.Resources[uid(KindPackage, "dpkg", "oldthing", "all")]; ok {
		t.Fatal("config-files package collected")
	}
	if _, ok := s.Resources[uid(KindPackage, "dpkg", "libc6", "amd64")]; !ok {
		t.Fatal("multi-arch package missing")
	}

	for _, e := range Catalog {
		st, ok := s.Status[e.ID]
		if !ok {
			t.Fatalf("no status for %s", e.ID)
		}
		want := protocol.ScopeComplete
		switch e.ID {
		case EdgeIDSocketProcess, EdgeIDSocketUnit, FactFilesystems:
			want = protocol.ScopePartial
		}
		if st.State != want {
			t.Fatalf("%s status %+v", e.ID, st)
		}
	}
	if st := s.Status[EdgeIDSocketProcess]; st.Reason != ReasonOtherUserFD {
		t.Fatalf("socket edge reason %+v", st)
	}
	for uid, r := range s.Resources {
		if _, err := protocol.NormalizeFields(r.Fields, false); err != nil {
			t.Fatalf("%s fields do not normalize: %v", uid, err)
		}
		for k, v := range r.Fields {
			if sv, ok := v.(string); ok && sv == "" {
				t.Fatalf("%s field %s rendered empty", uid, k)
			}
		}
	}
}

func TestSocketsOfAnotherUIDAreUnavailable(t *testing.T) {
	f := newDebianFixture(t)
	o := f.options()
	o.UID = f.uid + 1
	s := NewCollector(o).Collect(context.Background())
	app := uid(KindSocket, "tcp", "127.0.0.1", "8080")
	if s.Resources[app].Fields["unavailable_reason"] != ReasonOtherUserFD {
		t.Fatalf("socket of another UID: %v", s.Resources[app].Fields)
	}
	for k := range s.Edges {
		if k.Type == EdgeProcess || k.Type == EdgeUnit && strings.HasPrefix(k.From, "host:socket:") {
			t.Fatalf("edge %v produced without fd access", k)
		}
	}
	if st := s.Status[EdgeIDSocketProcess]; st.State != protocol.ScopeUnavailable || st.Reason != ReasonOtherUserFD {
		t.Fatalf("status %+v", st)
	}
}

func TestTrackerUnchangedHostProducesZeroOps(t *testing.T) {
	f := newDebianFixture(t)
	now := time.UnixMilli(1_700_000_000_000)
	tr := NewHostTracker(NewCollector(f.options()), nil, func() time.Time { return now })
	first, err := tr.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	creates, scopes := 0, 0
	for _, op := range first.Ops {
		switch op.Kind {
		case protocol.OpCreate:
			creates++
		case protocol.OpScopeSet:
			scopes++
		}
	}
	if creates != len(first.State.Resources) || scopes != len(Catalog) {
		t.Fatalf("initial ops: %d creates for %d resources, %d scope sets", creates, len(first.State.Resources), scopes)
	}
	base := protocol.NewState()
	if err := base.ApplyOps(first.Ops); err != nil {
		t.Fatal(err)
	}
	if !base.Equal(first.State) {
		t.Fatal("initial ops do not reproduce the state")
	}
	for i := 0; i < 3; i++ {
		now = now.Add(time.Minute)
		r, err := tr.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Ops) != 0 {
			t.Fatalf("collection %d of an unchanged host produced ops: %+v", i+2, r.Ops)
		}
		if r.Scopes[ScopeKey(FactUnits)].Since != 1_700_000_000_000 {
			t.Fatal("since moved without a status change")
		}
	}

	f.sd.props["/org/freedesktop/systemd1/unit/nginx_2eservice|"+ifaceService]["MainPID"] = uint32(1300)
	writeTree(t, f.root, map[string]string{
		"proc/1300/stat": procStat(1300, "nginx", 99000), "proc/1300/status": procStatus("nginx", 0),
		"var/lib/dpkg/status": strings.Replace(mustRead(t, f.path("var/lib/dpkg/status")), "1.22.1-9", "1.22.1-10", 1) + "\n",
	})
	r, err := tr.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, op := range r.Ops {
		kinds = append(kinds, op.Kind.String()+" "+op.UID+" "+op.EdgeType+" "+op.To)
	}
	want := []string{
		"update host:package:dpkg|nginx|amd64  ",
		"delete host:process:1234|900  ",
		"create host:process:1300|99000  ",
		"edge_remove host:unit:nginx.service main_process host:process:1234|900",
		"edge_add host:unit:nginx.service main_process host:process:1300|99000",
	}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("ops after restart and upgrade:\n%s", strings.Join(kinds, "\n"))
	}
	if err := base.ApplyOps(r.Ops); err != nil || !base.Equal(r.State) {
		t.Fatalf("delta does not reproduce the new state: %v", err)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTrackerCarriesForwardUnavailableFacts(t *testing.T) {
	f := newDebianFixture(t)
	now := time.UnixMilli(1_700_000_000_000)
	tr := NewHostTracker(NewCollector(f.options()), nil, func() time.Time { return now })
	first, err := tr.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.sd.listErr = errBusDown
	if err := os.Remove(f.path("etc/machine-id")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	r, err := tr.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range r.Ops {
		if op.Kind != protocol.OpScopeSet {
			t.Fatalf("collection failure produced a non-scope op: %v %s", op.Kind, op.UID)
		}
	}
	if !r.State.Equal(func() *protocol.State {
		s := first.State.Clone()
		for k, v := range r.Scopes {
			s.Scopes[k] = v
		}
		return s
	}()) {
		t.Fatal("resources or edges changed when facts became unavailable")
	}
	for _, id := range []string{FactUnits, FactTimers} {
		if st := r.Scopes[ScopeKey(id)]; st.State != protocol.ScopeUnavailable || st.Reason != ReasonDBus || st.Since != uint64(now.UnixMilli()) {
			t.Fatalf("%s scope %+v", id, st)
		}
	}
	for _, id := range []string{EdgeIDUnitProcess, EdgeIDPackageUnit, EdgeIDTimerUnit, EdgeIDSocketUnit} {
		if st := r.Scopes[ScopeKey(id)]; st.State != protocol.ScopeUnavailable || st.Reason != ReasonDependency {
			t.Fatalf("%s scope %+v", id, st)
		}
	}
	if st := r.Scopes[ScopeKey(FactMachineID)]; st.State != protocol.ScopeUnavailable || st.Reason != ReasonSourceAbsent {
		t.Fatalf("machine id scope %+v", st)
	}
	if r.State.Resources[uid(KindOS)].Fields["machine_id"] != "0123456789abcdef0123456789abcdef" {
		t.Fatal("machine id not carried forward")
	}

	f.sd.listErr = nil
	writeTree(t, f.root, map[string]string{"etc/machine-id": "0123456789abcdef0123456789abcdef\n"})
	now = now.Add(time.Minute)
	r, err = tr.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range r.Ops {
		if op.Kind != protocol.OpScopeSet || op.Scope.State == protocol.ScopeUnavailable {
			t.Fatalf("recovery op %v %s %+v", op.Kind, op.UID+op.ScopeKey, op.Scope)
		}
	}
}

func TestEmptyHostReportsEveryFactUnavailable(t *testing.T) {
	root := t.TempDir()
	c := NewCollector(Options{
		ProcRoot: filepath.Join(root, "proc"), SysRoot: filepath.Join(root, "sys"), EtcRoot: filepath.Join(root, "etc"),
		UsrLibRoot: filepath.Join(root, "usr/lib"), DpkgDir: filepath.Join(root, "dpkg"), RPMPaths: []string{filepath.Join(root, "rpm")},
		APKInstalled: filepath.Join(root, "apk"),
		DialSystemd:  func(context.Context) (Systemd, error) { return nil, errBusDown },
		Uname:        func() (Uname, error) { return Uname{}, errBusDown },
		Interfaces:   func() ([]NetInterface, error) { return nil, os.ErrPermission },
	})
	s := c.Collect(context.Background())
	if len(s.Resources) != 0 {
		t.Fatalf("resources from an empty tree: %v", keys(s))
	}
	want := map[string]string{
		FactOS: ReasonSourceAbsent, FactMachineID: ReasonSourceAbsent, FactHostname: ReasonReadFailed, FactKernel: ReasonReadFailed,
		FactCPU: ReasonSourceAbsent, FactMemory: ReasonSourceAbsent, FactBlockDevices: ReasonSourceAbsent, FactMounts: ReasonSourceAbsent,
		FactFilesystems: ReasonSourceAbsent, FactInterfaces: ReasonPermission, FactSockets: ReasonSourceAbsent, FactUnits: ReasonDBus,
		FactTimers: ReasonDBus, FactPackages: ReasonSourceAbsent,
	}
	for id, reason := range want {
		if st := s.Status[id]; st.State != protocol.ScopeUnavailable || st.Reason != reason {
			t.Fatalf("%s status %+v, want unavailable %s", id, st, reason)
		}
	}
	for _, e := range Catalog {
		st, ok := s.Status[e.ID]
		if !ok || st.State == protocol.ScopeUnavailable && st.Reason == "" {
			t.Fatalf("%s has no reasoned status: %+v", e.ID, st)
		}
	}
	tr := NewHostTracker(c, nil, nil)
	r, err := tr.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Scopes) != len(Catalog) {
		t.Fatalf("scopes %d for %d catalog entries", len(r.Scopes), len(Catalog))
	}
}

func TestDialedSystemdIsDroppedOnFailure(t *testing.T) {
	f := newDebianFixture(t)
	o := f.options()
	o.Systemd = nil
	dials := 0
	o.DialSystemd = func(context.Context) (Systemd, error) { dials++; return f.sd, nil }
	c := NewCollector(o)
	c.Collect(context.Background())
	c.Collect(context.Background())
	if dials != 1 {
		t.Fatalf("dials = %d, want a reused connection", dials)
	}
	f.sd.listErr = errBusDown
	c.Collect(context.Background())
	if !f.sd.closed {
		t.Fatal("failed connection not closed")
	}
	f.sd.listErr = nil
	s := c.Collect(context.Background())
	if dials != 2 || s.Status[FactUnits].State != protocol.ScopeComplete {
		t.Fatalf("dials = %d, units %+v", dials, s.Status[FactUnits])
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUsedBucketHysteresis(t *testing.T) {
	c := NewCollector(Options{})
	seq := []struct {
		pct  float64
		want int64
	}{{49.5, 40}, {50.5, 40}, {51.9, 40}, {52.1, 50}, {48.5, 50}, {47.9, 40}, {95, 90}}
	for _, s := range seq {
		if got := c.bucket("fs", s.pct); got != s.want {
			t.Fatalf("bucket(%v) = %d, want %d", s.pct, got, s.want)
		}
	}
}

func TestParsers(t *testing.T) {
	m := ParseOSRelease([]byte("# comment\nNAME='Red Hat Enterprise Linux'\nPRETTY_NAME=\"Red Hat \\\"Enterprise\\\" Linux 9.4 (Plow)\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=9.4\nbroken line\n"))
	if m["NAME"] != "Red Hat Enterprise Linux" || m["PRETTY_NAME"] != `Red Hat "Enterprise" Linux 9.4 (Plow)` || m["ID"] != "rhel" || m["VERSION_ID"] != "9.4" || m["ID_LIKE"] != "fedora" {
		t.Fatalf("os-release %v", m)
	}
	apk := ParseAPKInstalled([]byte("C:Q1abc=\nP:musl\nV:1.2.4-r2\nA:x86_64\nF:lib\nR:libc.musl-x86_64.so.1\n\nP:busybox\nV:1.36.1-r15\nA:x86_64\n"))
	if len(apk) != 2 || apk[0].Name != "musl" || apk[0].Version != "1.2.4-r2" || apk[1].Arch != "x86_64" || apk[1].Manager != "apk" {
		t.Fatalf("apk %+v", apk)
	}
	d := ParseDpkgStatus([]byte("Package: a\nStatus: install ok half-configured\nVersion: 1\nArchitecture: all\n\nPackage: b\nStatus: purge ok not-installed\n\nStatus: install ok installed\n"))
	if len(d) != 1 || d[0].State != "half-configured" {
		t.Fatalf("dpkg %+v", d)
	}
	if canonicalPath("/lib/systemd/system/x.service") != "/usr/lib/systemd/system/x.service" || canonicalPath("/etc/systemd/system/x.service") != "/etc/systemd/system/x.service" {
		t.Fatal("canonical path")
	}
}

func TestAPKHostWithoutSystemd(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release":       "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n",
		"lib/apk/db/installed": "P:musl\nV:1.2.5-r0\nA:x86_64\n\nP:openrc\nV:0.54-r1\nA:x86_64\n",
	})
	c := NewCollector(Options{EtcRoot: filepath.Join(root, "etc"), ProcRoot: filepath.Join(root, "proc"), SysRoot: filepath.Join(root, "sys"),
		DpkgDir: filepath.Join(root, "dpkg"), RPMPaths: []string{}, APKInstalled: filepath.Join(root, "lib/apk/db/installed"),
		DialSystemd: func(context.Context) (Systemd, error) { return nil, errBusDown }})
	s := c.Collect(context.Background())
	if s.Resources[uid(KindPackage, "apk", "openrc", "x86_64")].Fields["version"] != "0.54-r1" {
		t.Fatalf("apk packages %v", keys(s))
	}
	if st := s.Status[FactPackages]; st.State != protocol.ScopeComplete {
		t.Fatalf("packages %+v", st)
	}
	if st := s.Status[EdgeIDPackageUnit]; st.State != protocol.ScopeUnavailable || st.Reason != ReasonDependency {
		t.Fatalf("package unit edge %+v", st)
	}
}
