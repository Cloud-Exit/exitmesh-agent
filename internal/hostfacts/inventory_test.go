package hostfacts

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestSourcePackageParsers(t *testing.T) {
	for _, c := range []struct{ field, name, version, src, srcVer string }{
		{"", "libc6", "2.36-9", "libc6", "2.36-9"},
		{"glibc", "libc6", "2.36-9", "glibc", "2.36-9"},
		{"brotli (1.1.0-2)", "libbrotli1", "1.1.0-2build2", "brotli", "1.1.0-2"},
		{"  brotli   ( 1.1.0-2 ) ", "libbrotli1", "1.1.0-2build2", "brotli", "1.1.0-2"},
		{"brotli ()", "libbrotli1", "1.1.0-2build2", "brotli", "1.1.0-2build2"},
		{"brotli garbage", "libbrotli1", "1.1.0-2build2", "brotli", "1.1.0-2build2"},
	} {
		if s, v := dpkgSource(c.field, c.name, c.version); s != c.src || v != c.srcVer {
			t.Errorf("dpkgSource(%q) = %q %q, want %q %q", c.field, s, v, c.src, c.srcVer)
		}
	}
	for _, c := range []struct{ srpm, name, version, src, srcVer string }{
		{"brotli-1.0.9-6.el9.src.rpm", "libbrotli", "1.0.9-6.el9", "brotli", "1.0.9-6.el9"},
		{"lvm2-2.02.187-6.el7.src.rpm", "device-mapper", "7:1.02.146-4.el7", "lvm2", "7:2.02.187-6.el7"},
		{"python-requests-2.25.1-8.el9.nosrc.rpm", "python3-requests", "2.25.1-8.el9", "python-requests", "2.25.1-8.el9"},
		{"", "gpg-pubkey", "1-2", "gpg-pubkey", "1-2"},
		{"nodashes.src.rpm", "x", "1-1", "x", "1-1"},
		{"one-dash.src.rpm", "x", "1-1", "x", "1-1"},
		{"not-an-rpm-name", "x", "1-1", "x", "1-1"},
	} {
		if s, v := rpmSource(c.srpm, c.name, c.version); s != c.src || v != c.srcVer {
			t.Errorf("rpmSource(%q) = %q %q, want %q %q", c.srpm, s, v, c.src, c.srcVer)
		}
	}
	apk := ParseAPKInstalled([]byte("P:libcrypto3\nV:3.3.2-r1\nA:x86_64\no:openssl\n\nP:musl\nV:1.2.5-r0\nA:x86_64\n"))
	if len(apk) != 2 || apk[0].Source != "openssl" || apk[0].SourceVersion != "3.3.2-r1" || apk[1].Source != "musl" || apk[1].SourceVersion != "1.2.5-r0" {
		t.Fatalf("apk sources %+v", apk)
	}
}

func TestReadRPMSourcePackages(t *testing.T) {
	pkgs, err := ReadRPM(filepath.Join(rpmdbTestdata(t), "fedora35/rpmdb.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(pkgs, func(p Package) bool { return p.Name == "libgcc" })
	if i < 0 || pkgs[i].Source != "gcc" || pkgs[i].SourceVersion != "11.2.1-1.fc35" {
		t.Fatalf("libgcc source %+v", pkgs[i])
	}
	for _, p := range pkgs {
		if p.Source == "" || p.SourceVersion == "" {
			t.Fatalf("package without source %+v", p)
		}
	}
}

func TestInventoryDebianFixture(t *testing.T) {
	f := newDebianFixture(t)
	inv := NewCollector(f.options()).Inventory()
	if inv.State != protocol.ScopeComplete || inv.Reason != "" {
		t.Fatalf("state %v %q", inv.State, inv.Reason)
	}
	if inv.OS["id"] != "debian" || inv.OS["version_id"] != "12" || inv.OS["version_codename"] != "bookworm" || inv.OS["home_url"] != "" {
		t.Fatalf("os %v", inv.OS)
	}
	var names []string
	for _, p := range inv.Packages {
		names = append(names, p.Name)
		if p.UnitFiles != nil {
			t.Fatalf("unit files collected for %s", p.Name)
		}
	}
	if !slices.Equal(names, []string{"libbrotli1", "libc6", "myapp", "nginx"}) {
		t.Fatalf("packages %v", names)
	}
	if b := inv.Packages[0]; b.Source != "brotli" || b.SourceVersion != "1.1.0-2" || b.Version != "1.1.0-2+b2" || b.Arch != "amd64" || b.State != "installed" {
		t.Fatalf("libbrotli1 %+v", b)
	}
	if inv.Packages[2].State != "installed" {
		t.Fatalf("held package state %+v", inv.Packages[2])
	}
}

func TestInventoryFallsBackToUsrLibOSRelease(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"usr/lib/os-release":  "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID_LIKE=debian\n",
		"var/lib/dpkg/status": "Package: libbrotli1\nStatus: install ok installed\nArchitecture: amd64\nSource: brotli\nVersion: 1.1.0-2build2\n",
	})
	inv := NewCollector(Options{EtcRoot: filepath.Join(root, "etc"), UsrLibRoot: filepath.Join(root, "usr/lib"), DpkgDir: filepath.Join(root, "var/lib/dpkg"),
		RPMPaths: []string{filepath.Join(root, "rpm")}, APKInstalled: filepath.Join(root, "apk")}).Inventory()
	if inv.OS["id"] != "ubuntu" || inv.OS["version_id"] != "24.04" || inv.OS["id_like"] != "debian" {
		t.Fatalf("os %v", inv.OS)
	}
	if len(inv.Packages) != 1 || inv.Packages[0].Source != "brotli" || inv.Packages[0].SourceVersion != "1.1.0-2build2" {
		t.Fatalf("packages %+v", inv.Packages)
	}
}

func TestInventoryBelowHostRootFollowsHostSymlinks(t *testing.T) {
	root := t.TempDir()
	db, err := os.ReadFile(filepath.Join(rpmdbTestdata(t), "fedora35/rpmdb.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	// Absolute symlinks point into the host's own tree, never the agent container's.
	writeTree(t, root, map[string]string{
		"usr/lib/os-release":                "ID=rocky\nVERSION_ID=\"9.4\"\nID_LIKE=\"rhel centos fedora\"\n",
		"usr/lib/sysimage/rpm/rpmdb.sqlite": string(db),
		"etc/os-release":                    "->/usr/lib/os-release",
		"var/lib/rpm":                       "->/usr/lib/sysimage/rpm",
	})
	inv := NewCollector(Options{Root: root}).Inventory()
	if inv.OS["id"] != "rocky" || inv.OS["version_id"] != "9.4" {
		t.Fatalf("os %v", inv.OS)
	}
	if inv.State != protocol.ScopeComplete || len(inv.Packages) == 0 || inv.Packages[0].Manager != "rpm" {
		t.Fatalf("inventory %v %q %d packages", inv.State, inv.Reason, len(inv.Packages))
	}
}

func TestInventoryBelowHostRootWithoutDatabasesIsUnavailable(t *testing.T) {
	inv := NewCollector(Options{Root: t.TempDir()}).Inventory()
	if inv.State != protocol.ScopeUnavailable || inv.Reason != ReasonSourceAbsent {
		t.Fatalf("inventory %+v", inv)
	}
}

func TestInventoryWithoutDatabasesIsUnavailable(t *testing.T) {
	root := t.TempDir()
	inv := NewCollector(Options{EtcRoot: filepath.Join(root, "etc"), UsrLibRoot: filepath.Join(root, "usr/lib"), DpkgDir: filepath.Join(root, "dpkg"),
		RPMPaths: []string{filepath.Join(root, "rpm")}, APKInstalled: filepath.Join(root, "apk")}).Inventory()
	if inv.State != protocol.ScopeUnavailable || inv.Reason != ReasonSourceAbsent || len(inv.Packages) != 0 || len(inv.OS) != 0 {
		t.Fatalf("inventory %+v", inv)
	}
	if f := inv.Fields(); f["package_count"] != int64(0) || f["packages"] != nil || f["os"] != nil {
		t.Fatalf("fields %v", f)
	}
}

func TestInventoryKeepsLastGoodDatabase(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"dpkg/status":          "Package: a\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n",
		"lib/apk/db/installed": "P:musl\nV:1.2.5-r0\nA:x86_64\n",
	})
	c := NewCollector(Options{EtcRoot: filepath.Join(root, "etc"), UsrLibRoot: filepath.Join(root, "usr/lib"), DpkgDir: filepath.Join(root, "dpkg"),
		RPMPaths: []string{filepath.Join(root, "rpm")}, APKInstalled: filepath.Join(root, "lib/apk/db/installed")})
	if inv := c.Inventory(); inv.State != protocol.ScopeComplete || len(inv.Packages) != 2 {
		t.Fatalf("first inventory %+v", inv)
	}
	status := filepath.Join(root, "dpkg/status")
	if err := os.Remove(status); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(status, 0o755); err != nil {
		t.Fatal(err)
	}
	inv := c.Inventory()
	if inv.State != protocol.ScopePartial || inv.Reason != ReasonReadFailed || len(inv.Packages) != 2 || inv.Packages[1].Name != "a" {
		t.Fatalf("inventory after dpkg read failure %+v", inv)
	}
}

func TestInventoryNormalizeAndBounds(t *testing.T) {
	inv := Inventory{OS: map[string]string{"id": "ubuntu"}, Packages: []Package{
		{Manager: "dpkg", Name: "b", Version: "2", Arch: "amd64", State: "installed", UnitFiles: []string{"/x.service"}},
		{Manager: "dpkg", Name: "a", Version: "1", Arch: "amd64", State: "installed"},
		{Manager: "dpkg", Name: "b", Version: "2", Arch: "amd64", State: "installed"},
		{Manager: "apk", Name: "z", Version: "1"},
		{Manager: "dpkg", Name: "broken", Arch: "amd64"},
		{Manager: "dpkg", Name: "nul\x00", Version: "1"},
	}}
	inv.Normalize()
	if len(inv.Packages) != 3 || inv.Packages[0].Manager != "apk" || inv.Packages[1].Name != "a" || inv.Packages[2].UnitFiles != nil {
		t.Fatalf("normalized %+v", inv.Packages)
	}
	if inv.State != protocol.ScopeComplete || !inv.Valid() {
		t.Fatalf("small inventory state %v valid %v", inv.State, inv.Valid())
	}

	many := Inventory{}
	for i := range MaxInventoryPackages + 5 {
		many.Packages = append(many.Packages, Package{Manager: "dpkg", Name: fmt.Sprintf("p%06d", i), Version: "1"})
	}
	many.Normalize()
	if len(many.Packages) != MaxInventoryPackages || many.State != protocol.ScopePartial || many.Reason != ReasonLimitExceeded || !many.Valid() {
		t.Fatalf("count bound: %d packages, state %v %q", len(many.Packages), many.State, many.Reason)
	}

	big := Inventory{}
	long := strings.Repeat("x", maxInventoryString)
	for i := range 4000 {
		big.Packages = append(big.Packages, Package{Manager: "dpkg", Name: strconv.Itoa(i) + long[:maxInventoryString-len(strconv.Itoa(i))], Version: long, Source: long, SourceVersion: long, Arch: long, State: long})
	}
	big.Normalize()
	if len(big.Packages) >= 4000 || len(big.Packages) == 0 || big.State != protocol.ScopePartial || big.Reason != ReasonLimitExceeded || !big.WithinBounds() || !big.Valid() {
		t.Fatalf("byte bound: %d packages, state %v, within %v", len(big.Packages), big.State, big.WithinBounds())
	}
	b, err := protocol.Marshal(big.Fields())
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > protocol.MaxRecordBytes-64<<10 {
		t.Fatalf("largest inventory encodes to %d bytes, too close to the %d byte record limit", len(b), protocol.MaxRecordBytes)
	}
}

func TestInventoryValidRejects(t *testing.T) {
	ok := Package{Manager: "dpkg", Name: "a", Version: "1"}
	for name, inv := range map[string]Inventory{
		"no name":      {Packages: []Package{{Manager: "dpkg", Version: "1"}}},
		"no version":   {Packages: []Package{{Manager: "dpkg", Name: "a"}}},
		"no manager":   {Packages: []Package{{Name: "a", Version: "1"}}},
		"nul":          {Packages: []Package{{Manager: "dpkg", Name: "a\x00", Version: "1"}}},
		"long string":  {Packages: []Package{{Manager: "dpkg", Name: "a", Version: strings.Repeat("1", maxInventoryString+1)}}},
		"empty os key": {OS: map[string]string{"": "x"}, Packages: []Package{ok}},
		"long os":      {OS: map[string]string{"id": strings.Repeat("x", maxInventoryString+1)}},
		"state":        {State: protocol.ScopeUnavailable + 1},
		"count":        {Packages: slices.Repeat([]Package{ok}, MaxInventoryPackages+1)},
	} {
		if inv.Valid() {
			t.Errorf("%s: accepted", name)
		}
	}
	if !(Inventory{Packages: []Package{ok}}).Valid() {
		t.Fatal("valid inventory rejected")
	}
}

func TestInventoryDigestAndFields(t *testing.T) {
	a := Inventory{OS: map[string]string{"id": "ubuntu", "version_id": "24.04"}, Packages: []Package{
		{Manager: "dpkg", Name: "libbrotli1", Version: "1.1.0-2build2", Arch: "amd64", State: "installed", Source: "brotli", SourceVersion: "1.1.0-2build2"},
		{Manager: "dpkg", Name: "bash", Version: "5.2.21-2ubuntu4", Arch: "amd64", State: "installed", Source: "bash", SourceVersion: "5.2.21-2ubuntu4"},
	}}
	b := Inventory{OS: map[string]string{"version_id": "24.04", "id": "ubuntu"}, Packages: []Package{a.Packages[1], a.Packages[0]}, State: protocol.ScopePartial, Reason: ReasonReadFailed}
	a.Normalize()
	b.Normalize()
	if a.Digest() != b.Digest() || a.PackageSetUID() != b.PackageSetUID() {
		t.Fatal("digest depends on order or status")
	}
	if uid := a.PackageSetUID(); !strings.HasPrefix(uid, "host:packageset:") || len(uid) != len("host:packageset:")+32 {
		t.Fatalf("uid %q", uid)
	}
	c := b
	c.OS = map[string]string{"id": "ubuntu", "version_id": "22.04"}
	d := a
	d.Packages = slices.Clone(a.Packages)
	d.Packages[1].Version = "1.1.0-2ubuntu0.1"
	if c.Digest() == a.Digest() || d.Digest() == a.Digest() {
		t.Fatal("digest ignores content")
	}
	f := a.Fields()
	if f["package_count"] != int64(2) || f["os"].(map[string]any)["version_id"] != "24.04" {
		t.Fatalf("fields %v", f)
	}
	p := f["packages"].([]any)[1].(map[string]any)
	if p["name"] != "libbrotli1" || p["source"] != "brotli" || p["source_version"] != "1.1.0-2build2" || p["arch"] != "amd64" || p["manager"] != "dpkg" || p["state"] != "installed" {
		t.Fatalf("package field %v", p)
	}
	if _, err := protocol.NormalizeFields(f, false); err != nil {
		t.Fatalf("fields are not protocol values: %v", err)
	}
}

func TestBoundedCutsOnRuneBoundary(t *testing.T) {
	s := bounded(strings.Repeat("a", maxInventoryString-1) + "é" + "tail")
	if len(s) > maxInventoryString || !utf8.ValidString(s) || !strings.HasSuffix(s, "a") {
		t.Fatalf("bounded %q (%d bytes)", s[len(s)-4:], len(s))
	}
	if bounded("ok\xff") != "ok�" {
		t.Fatal("invalid UTF-8 not cleaned")
	}
}
