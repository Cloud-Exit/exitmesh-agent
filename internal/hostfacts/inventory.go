package hostfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Bounds of one inventory so it fits a single protocol record; larger inventories are truncated and partial.
const (
	MaxInventoryPackages = 16384
	MaxInventoryBytes    = 2 << 20
	maxInventoryString   = 256
	pkgOverheadBytes     = 64
)

// Inventory is the distribution release and installed packages of one machine, the input of advisory matching.
type Inventory struct {
	// OS holds the cataloged os-release fields (id, id_like, version_id, version_codename, ...).
	OS       map[string]string
	Packages []Package
	// State and Reason are the scope status of the package databases.
	State  protocol.ScopeState
	Reason string
}

// readAt reads a host file below Options.Root.
func (c *Collector) readAt(path string) ([]byte, error) {
	resolved, err := c.at(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}

// Inventory reads os-release and every package database without unit file lists.
func (c *Collector) Inventory() Inventory {
	c.mu.Lock()
	defer c.mu.Unlock()
	inv := Inventory{OS: map[string]string{}}
	b, err := c.readAt(filepath.Join(c.o.EtcRoot, "os-release"))
	if errors.Is(err, fs.ErrNotExist) {
		b, err = c.readAt(filepath.Join(c.o.UsrLibRoot, "os-release"))
	}
	if err == nil {
		for k, v := range ParseOSRelease(b) {
			if f, ok := osReleaseFields[k]; ok && v != "" {
				inv.OS[f] = bounded(v)
			}
		}
	}
	all, st, found, _ := c.readPackages(false)
	if found == 0 {
		inv.State, inv.Reason = protocol.ScopeUnavailable, ReasonSourceAbsent
		return inv
	}
	inv.State, inv.Reason = st.State, st.Reason
	inv.Packages = make([]Package, 0, len(all))
	for _, p := range all {
		inv.Packages = append(inv.Packages, Package{
			Manager: p.Manager, Name: bounded(p.Name), Version: bounded(p.Version), Arch: bounded(p.Arch), State: bounded(p.State),
			Source: bounded(p.Source), SourceVersion: bounded(p.SourceVersion),
		})
	}
	inv.Normalize()
	return inv
}

// bounded cleans s and cuts it to maxInventoryString bytes on a rune boundary.
func bounded(s string) string {
	s = clean(s)
	if len(s) <= maxInventoryString {
		return s
	}
	cut := maxInventoryString
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Normalize sorts packages canonically, drops exact duplicates and malformed entries, and truncates to the bounds.
func (inv *Inventory) Normalize() {
	sort.Slice(inv.Packages, func(i, j int) bool { return pkgLess(inv.Packages[i], inv.Packages[j]) })
	out := inv.Packages[:0]
	for i, p := range inv.Packages {
		p.UnitFiles = nil
		if (i > 0 && pkgKey(p) == pkgKey(inv.Packages[i-1])) || !p.valid() {
			continue
		}
		out = append(out, p)
	}
	inv.Packages = out
	total := 0
	for i, p := range inv.Packages {
		total += p.size()
		if i >= MaxInventoryPackages || total > MaxInventoryBytes {
			inv.Packages = inv.Packages[:i]
			inv.State, inv.Reason = protocol.ScopePartial, ReasonLimitExceeded
			break
		}
	}
}

// size is the encoded size bound of one package entry used by the inventory byte budget.
func (p Package) size() int {
	n := pkgOverheadBytes
	for _, s := range pkgKey(p) {
		n += len(s)
	}
	return n
}

// WithinBounds reports whether the inventory respects the package count and byte budgets.
func (inv Inventory) WithinBounds() bool {
	if len(inv.Packages) > MaxInventoryPackages || len(inv.OS) > len(osReleaseFields) {
		return false
	}
	total := 0
	for _, p := range inv.Packages {
		total += p.size()
	}
	for k, v := range inv.OS {
		if len(k) > maxInventoryString || len(v) > maxInventoryString {
			return false
		}
		total += len(k) + len(v)
	}
	return total <= MaxInventoryBytes
}

func pkgKey(p Package) [7]string {
	return [7]string{p.Manager, p.Name, p.Arch, p.Version, p.Source, p.SourceVersion, p.State}
}

func pkgLess(a, b Package) bool {
	ka, kb := pkgKey(a), pkgKey(b)
	for i := range ka {
		if ka[i] != kb[i] {
			return ka[i] < kb[i]
		}
	}
	return false
}

// Fields returns the protocol fields of the inventory content: os and packages. State and Reason are not content.
func (inv Inventory) Fields() map[string]any {
	osm := map[string]any{}
	for k, v := range inv.OS {
		if v != "" {
			osm[k] = v
		}
	}
	pkgs := make([]any, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		m := map[string]any{"manager": p.Manager, "name": p.Name, "version": p.Version}
		for k, v := range map[string]string{"arch": p.Arch, "state": p.State, "source": p.Source, "source_version": p.SourceVersion} {
			if v != "" {
				m[k] = v
			}
		}
		pkgs = append(pkgs, m)
	}
	f := map[string]any{"package_count": int64(len(pkgs))}
	if len(osm) > 0 {
		f["os"] = osm
	}
	if len(pkgs) > 0 {
		f["packages"] = pkgs
	}
	return f
}

// PackageSetUID is the UID of the host/PackageSet resource holding the inventory content.
func (inv Inventory) PackageSetUID() string { return "host:packageset:" + inv.Digest()[:32] }

// Digest identifies the inventory content: equal OS fields and package lists give equal digests.
func (inv Inventory) Digest() string {
	h := sha256.New()
	keys := make([]string, 0, len(inv.OS))
	for k := range inv.OS {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	field := func(parts ...string) {
		for i, p := range parts {
			if i > 0 {
				h.Write([]byte{0})
			}
			h.Write([]byte(p))
		}
		h.Write([]byte{'\n'})
	}
	for _, k := range keys {
		field("os", k, inv.OS[k])
	}
	for _, p := range inv.Packages {
		k := pkgKey(p)
		field(append([]string{"pkg"}, k[:]...)...)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Valid reports whether the inventory is within bounds, names every package fully, and has bounded NUL-free strings.
func (inv Inventory) Valid() bool {
	if inv.State > protocol.ScopeUnavailable || !inv.WithinBounds() {
		return false
	}
	for k, v := range inv.OS {
		if k == "" || strings.IndexByte(k, 0) >= 0 || strings.IndexByte(v, 0) >= 0 {
			return false
		}
	}
	for _, p := range inv.Packages {
		if !p.valid() {
			return false
		}
	}
	return true
}

func (p Package) valid() bool {
	if p.Manager == "" || p.Name == "" || p.Version == "" {
		return false
	}
	for _, s := range pkgKey(p) {
		if len(s) > maxInventoryString || strings.IndexByte(s, 0) >= 0 {
			return false
		}
	}
	return true
}
