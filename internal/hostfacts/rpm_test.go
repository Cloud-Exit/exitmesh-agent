package hostfacts

import (
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// rpmdbTestdata locates the real rpm databases shipped in go-rpmdb's module (sqlite, ndb, bdb).
func rpmdbTestdata(t *testing.T) string {
	t.Helper()
	ver := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/knqyf263/go-rpmdb" {
				ver = d.Version
			}
		}
	}
	cache := os.Getenv("GOMODCACHE")
	if cache == "" {
		gp := os.Getenv("GOPATH")
		if gp == "" {
			home, _ := os.UserHomeDir()
			gp = filepath.Join(home, "go")
		}
		cache = filepath.Join(filepath.SplitList(gp)[0], "pkg", "mod")
	}
	pattern := filepath.Join(cache, "github.com", "knqyf263", "go-rpmdb@*", "pkg", "testdata")
	if ver != "" {
		pattern = filepath.Join(cache, "github.com", "knqyf263", "go-rpmdb@"+ver, "pkg", "testdata")
	}
	m, _ := filepath.Glob(pattern)
	if len(m) == 0 {
		t.Skipf("go-rpmdb module testdata not in the module cache (%s)", pattern)
	}
	sort.Strings(m)
	return m[len(m)-1]
}

func TestReadRPMBackends(t *testing.T) {
	dir := rpmdbTestdata(t)
	cases := []struct {
		file, name, version, arch string
		count                     int
		unit                      string
	}{
		{"fedora35/rpmdb.sqlite", "libgcc", "11.2.1-1.fc35", "x86_64", 138, "/usr/lib/systemd/system/dnf-makecache.timer"},
		{"sle15-bci/Packages.db", "glibc", "2.31-9.3.2", "x86_64", 35, "/usr/lib/systemd/system/rpmconfigcheck.service"},
		{"centos7-plain/Packages", "device-mapper", "7:1.02.146-4.el7", "x86_64", 144, "/usr/lib/systemd/system/blk-availability.service"},
	}
	for _, c := range cases {
		pkgs, err := ReadRPM(filepath.Join(dir, c.file))
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if len(pkgs) != c.count {
			t.Fatalf("%s: %d packages, want %d", c.file, len(pkgs), c.count)
		}
		found, unit := false, false
		for _, p := range pkgs {
			if p.Name == c.name && p.Version == c.version && p.Arch == c.arch && p.Manager == "rpm" {
				found = true
			}
			for _, u := range p.UnitFiles {
				if u == c.unit {
					unit = true
				}
			}
		}
		if !found || !unit {
			t.Fatalf("%s: package %s %s found=%v, unit %s found=%v", c.file, c.name, c.version, found, c.unit, unit)
		}
	}
	if _, err := ReadRPM(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Fatal("missing database read")
	}
}

func TestCollectRHELStyleHost(t *testing.T) {
	dir := rpmdbTestdata(t)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/os-release": "NAME=\"Fedora Linux\"\nVERSION=\"35 (Container Image)\"\nID=fedora\nVERSION_ID=35\nPRETTY_NAME=\"Fedora Linux 35 (Container Image)\"\nVARIANT_ID=container\n",
		"etc/machine-id": "fedcba9876543210fedcba9876543210\n",
	})
	sd := &fakeSystemd{
		units: []SystemdUnit{
			{Name: "dnf-makecache.timer", LoadState: "loaded", ActiveState: "active", SubState: "waiting", Path: "/t"},
			{Name: "dnf-makecache.service", LoadState: "loaded", ActiveState: "inactive", SubState: "dead", Path: "/s"},
		},
		props: map[string]map[string]any{
			"/t|" + ifaceUnit:    {"FragmentPath": "/usr/lib/systemd/system/dnf-makecache.timer", "UnitFileState": "enabled"},
			"/t|" + ifaceTimer:   {"Unit": "dnf-makecache.service", "NextElapseUSecRealtime": uint64(0), "LastTriggerUSec": uint64(0)},
			"/s|" + ifaceUnit:    {"FragmentPath": "/usr/lib/systemd/system/dnf-makecache.service", "UnitFileState": "static"},
			"/s|" + ifaceService: {"MainPID": uint32(0)},
		},
	}
	c := NewCollector(Options{
		EtcRoot: filepath.Join(root, "etc"), ProcRoot: filepath.Join(root, "proc"), SysRoot: filepath.Join(root, "sys"),
		DpkgDir: filepath.Join(root, "var/lib/dpkg"), APKInstalled: filepath.Join(root, "apk"),
		RPMPaths: []string{filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), filepath.Join(dir, "fedora35", "rpmdb.sqlite")},
		Systemd:  sd,
	})
	s := c.Collect(context.Background())
	if s.Resources[uid(KindOS)].Fields["id"] != "fedora" || s.Resources[uid(KindOS)].Fields["variant_id"] != "container" {
		t.Fatalf("os %v", s.Resources[uid(KindOS)].Fields)
	}
	dnf := uid(KindPackage, "rpm", "dnf", "noarch")
	if s.Resources[dnf].Fields["version"] != "4.9.0-1.fc35" {
		t.Fatalf("dnf package %v", s.Resources[dnf].Fields)
	}
	if !hasEdge(s, dnf, EdgeProvidesUnit, uid(KindTimer, "dnf-makecache.timer")) || !hasEdge(s, dnf, EdgeProvidesUnit, uid(KindUnit, "dnf-makecache.service")) {
		t.Fatal("rpm package to unit edges")
	}
	timer := s.Resources[uid(KindTimer, "dnf-makecache.timer")]
	if timer.Fields["scheduled"] != false {
		t.Fatal("unscheduled timer")
	}
	if _, ok := timer.Fields["last_trigger_day"]; ok {
		t.Fatal("never triggered timer has a last trigger day")
	}
	if st := s.Status[FactPackages]; st.State != protocol.ScopeComplete {
		t.Fatalf("packages %+v", st)
	}
	n := 0
	for _, r := range s.Resources {
		if r.Kind == KindPackage {
			n++
		}
	}
	if n != 138 {
		t.Fatalf("%d packages", n)
	}
	before := len(c.pkgs.dbs)
	c.Collect(context.Background())
	if len(c.pkgs.dbs) != before {
		t.Fatal("unchanged rpm database re-read into a new cache entry")
	}
}

func TestPackageReadFailureKeepsLastGood(t *testing.T) {
	f := newDebianFixture(t)
	c := NewCollector(f.options())
	s1 := c.Collect(context.Background())
	status := f.path("var/lib/dpkg/status")
	if err := os.Chmod(status, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(status, 0o644)
	if _, err := os.ReadFile(status); err == nil {
		t.Skip("running with privileges that bypass file modes")
	}
	writeTree(t, f.root, map[string]string{"var/lib/dpkg/info/touch.list": ""})
	now := time.Now().Add(time.Hour)
	if err := os.Chtimes(status, now, now); err != nil {
		t.Fatal(err)
	}
	s2 := c.Collect(context.Background())
	if st := s2.Status[FactPackages]; st.State != protocol.ScopeUnavailable || st.Reason != ReasonPermission {
		t.Fatalf("packages %+v", st)
	}
	for u, r := range s1.Resources {
		if r.Kind == KindPackage {
			if _, ok := s2.Resources[u]; !ok {
				t.Fatalf("package %s dropped on read failure", u)
			}
		}
	}
}

func TestFailingRPMDatabaseIsNotReread(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "rpmdb.sqlite")
	b, err := os.ReadFile(filepath.Join("sqlitedb", "testdata", "plain.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, b, 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewCollector(Options{ProcRoot: root, SysRoot: root, EtcRoot: root, DpkgDir: filepath.Join(root, "dpkg"), APKInstalled: filepath.Join(root, "apk"), RPMPaths: []string{db},
		DialSystemd: func(context.Context) (Systemd, error) { return nil, errBusDown }, Interfaces: func() ([]NetInterface, error) { return nil, nil }})
	reads := 0
	c.readRPMFile = func(p string) ([]Package, error) { reads++; return ReadRPM(p) }
	s := c.Collect(context.Background())
	if st := s.Status[FactPackages]; st.State != protocol.ScopeUnavailable || st.Reason != ReasonReadFailed {
		t.Fatalf("sqlite database without a Packages table: %+v", st)
	}
	s = c.Collect(context.Background())
	if reads != 1 || s.Status[FactPackages].Reason != ReasonReadFailed {
		t.Fatalf("unchanged failing database read %d times", reads)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(db, later, later); err != nil {
		t.Fatal(err)
	}
	c.Collect(context.Background())
	if reads != 2 {
		t.Fatalf("changed database read %d times", reads)
	}
}
