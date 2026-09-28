package hostfacts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/sqlitedb"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// DefaultRPMPaths are probed in order; the first existing database is read.
var DefaultRPMPaths = []string{
	"/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/var/lib/rpm/Packages.db", "/usr/lib/sysimage/rpm/Packages.db",
	"/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/Packages",
}

// Package is one installed package with the systemd unit files it owns.
type Package struct {
	Manager, Name, Version, Arch, State string
	UnitFiles                           []string
}

func stampOf(paths ...string) (string, error) {
	var b strings.Builder
	for i, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			if i > 0 && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", err
		}
		fmt.Fprintf(&b, "%s|%d|%d;", p, fi.ModTime().UnixNano(), fi.Size())
	}
	return b.String(), nil
}

type cachedPkgs struct {
	stamp string
	pkgs  []Package
}

type packageCache struct {
	dbs    map[string]cachedPkgs
	lists  map[string]cachedList
	failed map[string]cachedFailure
}

type cachedFailure struct {
	stamp string
	err   error
}

type cachedList struct {
	stamp string
	units []string
}

func newPackageCache() *packageCache {
	return &packageCache{dbs: map[string]cachedPkgs{}, lists: map[string]cachedList{}, failed: map[string]cachedFailure{}}
}

func isUnitPath(p string) bool {
	return strings.Contains(p, "/systemd/system/") && strings.IndexByte(filepath.Base(p), '.') > 0
}

// canonicalPath folds usr-merge aliases so /lib/systemd/... and /usr/lib/systemd/... compare equal.
func canonicalPath(p string) string {
	for _, pre := range []string{"/lib/", "/lib64/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(p, pre) {
			return "/usr" + p
		}
	}
	return p
}

// ParseDpkgStatus parses /var/lib/dpkg/status, returning packages that are not removed.
func ParseDpkgStatus(b []byte) []Package {
	var out []Package
	var cur map[string]string
	flush := func() {
		if cur == nil || cur["Package"] == "" {
			cur = nil
			return
		}
		st := strings.Fields(cur["Status"])
		state := ""
		if len(st) == 3 {
			state = st[2]
		}
		if state != "" && state != "not-installed" && state != "config-files" {
			out = append(out, Package{Manager: "dpkg", Name: cur["Package"], Version: cur["Version"], Arch: cur["Architecture"], State: state})
		}
		cur = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if cur == nil {
			cur = map[string]string{}
		}
		cur[k] = strings.TrimSpace(v)
	}
	flush()
	return out
}

// ParseAPKInstalled parses the apk installed database.
func ParseAPKInstalled(b []byte) []Package {
	var out []Package
	var cur *Package
	flush := func() {
		if cur != nil && cur.Name != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		if cur == nil {
			cur = &Package{Manager: "apk", State: "installed"}
		}
		switch line[0] {
		case 'P':
			cur.Name = line[2:]
		case 'V':
			cur.Version = line[2:]
		case 'A':
			cur.Arch = line[2:]
		}
	}
	flush()
	return out
}

// readDpkg returns the dpkg packages and the reason of the first unreadable file list, if any.
func (c *Collector) readDpkg(withUnits bool) ([]Package, string, error) {
	status := filepath.Join(c.o.DpkgDir, "status")
	stamp, err := stampOf(status)
	if err != nil {
		return nil, "", err
	}
	cp, ok := c.pkgs.dbs[status]
	if !ok || cp.stamp != stamp {
		b, err := os.ReadFile(status)
		if err != nil {
			return nil, "", err
		}
		cp = cachedPkgs{stamp: stamp, pkgs: ParseDpkgStatus(b)}
		c.pkgs.dbs[status] = cp
	}
	out := make([]Package, len(cp.pkgs))
	copy(out, cp.pkgs)
	if !withUnits {
		return out, "", nil
	}
	listReason := ""
	for i := range out {
		units, err := c.dpkgUnits(out[i])
		if err != nil && listReason == "" {
			listReason = reasonFor(err)
		}
		out[i].UnitFiles = units
	}
	return out, listReason, nil
}

func (c *Collector) dpkgUnits(p Package) ([]string, error) {
	info := filepath.Join(c.o.DpkgDir, "info")
	for _, name := range []string{p.Name + ":" + p.Arch + ".list", p.Name + ".list"} {
		path := filepath.Join(info, name)
		stamp, err := stampOf(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if cl, ok := c.pkgs.lists[path]; ok && cl.stamp == stamp {
			return cl.units, nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		var units []string
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			if l := sc.Text(); isUnitPath(l) {
				units = append(units, l)
			}
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		c.pkgs.lists[path] = cachedList{stamp: stamp, units: units}
		return units, nil
	}
	return nil, nil
}

// ReadRPM reads installed packages and their unit files from an rpm database of any supported backend.
func ReadRPM(path string) ([]Package, error) {
	sqlitedb.Register()
	db, err := rpmdb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	list, err := db.ListPackages()
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(list))
	for _, p := range list {
		v := p.Version + "-" + p.Release
		if p.Epoch != nil && *p.Epoch != 0 {
			v = strconv.Itoa(*p.Epoch) + ":" + v
		}
		pkg := Package{Manager: "rpm", Name: p.Name, Version: v, Arch: p.Arch, State: "installed"}
		files, err := p.InstalledFileNames()
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if isUnitPath(f) {
				pkg.UnitFiles = append(pkg.UnitFiles, f)
			}
		}
		out = append(out, pkg)
	}
	return out, nil
}

func (c *Collector) readRPM() ([]Package, bool, error) {
	for _, p := range c.o.RPMPaths {
		stamp, err := stampOf(p, p+"-wal")
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, true, err
		}
		if cp, ok := c.pkgs.dbs[p]; ok && cp.stamp == stamp {
			return cp.pkgs, true, nil
		}
		if f, ok := c.pkgs.failed[p]; ok && f.stamp == stamp {
			return nil, true, f.err
		}
		pkgs, err := c.readRPMFile(p)
		if err != nil {
			// go-rpmdb leaks its reader goroutine on errors, so an unchanged failing database is not re-read.
			c.pkgs.failed[p] = cachedFailure{stamp: stamp, err: err}
			return nil, true, err
		}
		delete(c.pkgs.failed, p)
		c.pkgs.dbs[p] = cachedPkgs{stamp: stamp, pkgs: pkgs}
		return pkgs, true, nil
	}
	return nil, false, nil
}

func (c *Collector) readAPK() ([]Package, error) {
	stamp, err := stampOf(c.o.APKInstalled)
	if err != nil {
		return nil, err
	}
	if cp, ok := c.pkgs.dbs[c.o.APKInstalled]; ok && cp.stamp == stamp {
		return cp.pkgs, nil
	}
	b, err := os.ReadFile(c.o.APKInstalled)
	if err != nil {
		return nil, err
	}
	pkgs := ParseAPKInstalled(b)
	c.pkgs.dbs[c.o.APKInstalled] = cachedPkgs{stamp: stamp, pkgs: pkgs}
	return pkgs, nil
}

func (c *Collector) collectPackages(s *Snapshot, units *unitSet) {
	withUnits := units.ok && len(units.byName) > 0
	var all []Package
	found := 0
	var t tally
	lastGood := func(key string) {
		if cp, ok := c.pkgs.dbs["last:"+key]; ok {
			all = append(all, cp.pkgs...)
		}
	}
	keep := func(key string, p []Package) {
		c.pkgs.dbs["last:"+key] = cachedPkgs{pkgs: p}
		all = append(all, p...)
	}
	p, listReason, err := c.readDpkg(withUnits)
	switch {
	case err == nil:
		found++
		t.good()
		keep("dpkg", p)
	case !errors.Is(err, fs.ErrNotExist):
		found++
		t.bad(reasonFor(err))
		lastGood("dpkg")
	}
	switch p, exists, err := c.readRPM(); {
	case err == nil && exists:
		found++
		t.good()
		keep("rpm", p)
	case err != nil:
		found++
		t.bad(reasonFor(err))
		lastGood("rpm")
	}
	switch p, err := c.readAPK(); {
	case err == nil:
		found++
		t.good()
		keep("apk", p)
	case !errors.Is(err, fs.ErrNotExist):
		found++
		t.bad(reasonFor(err))
		lastGood("apk")
	}
	if found == 0 {
		s.unavailable(FactPackages, ReasonSourceAbsent)
		s.unavailable(EdgeIDPackageUnit, ReasonDependency)
		return
	}
	st := t.status()
	s.set(FactPackages, st.State, st.Reason)
	groups := map[string]int{}
	for _, p := range all {
		groups[p.Manager+"|"+p.Name+"|"+p.Arch]++
	}
	byPath := map[string]string{}
	if withUnits {
		for _, u := range units.byName {
			if u.fragment != "" {
				byPath[canonicalPath(u.fragment)] = u.uid
			}
		}
	}
	for _, p := range all {
		u := uid(KindPackage, p.Manager, p.Name, p.Arch)
		if groups[p.Manager+"|"+p.Name+"|"+p.Arch] > 1 {
			u = uid(KindPackage, p.Manager, p.Name, p.Arch, p.Version)
		}
		fields := map[string]any{"manager": p.Manager, "name": clean(p.Name), "version": clean(p.Version), "state": p.State}
		if p.Arch != "" {
			fields["arch"] = clean(p.Arch)
		}
		s.add(u, KindPackage, p.Name, fields)
		for _, f := range p.UnitFiles {
			if target, ok := byPath[canonicalPath(f)]; ok {
				s.edge(u, EdgeProvidesUnit, target)
			}
		}
	}
	if !units.ok {
		s.unavailable(EdgeIDPackageUnit, ReasonDependency)
		return
	}
	switch {
	case st.State != protocol.ScopeComplete:
		s.set(EdgeIDPackageUnit, protocol.ScopePartial, ReasonDependency)
	case listReason != "":
		s.set(EdgeIDPackageUnit, protocol.ScopePartial, listReason)
	default:
		s.ok(EdgeIDPackageUnit)
	}
}
