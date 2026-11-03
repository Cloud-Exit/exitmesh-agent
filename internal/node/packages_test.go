package node

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const ubuntuDpkg = `Package: libbrotli1
Status: install ok installed
Architecture: amd64
Source: brotli
Version: %s

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.21-2ubuntu4
`

func writeHostRoot(t *testing.T, root, brotli string) {
	t.Helper()
	for p, body := range map[string]string{
		"usr/lib/os-release":  "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
		"var/lib/dpkg/status": fmt.Sprintf(ubuntuDpkg, brotli),
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func packagesHarness(t *testing.T, root string) *harness {
	h := newHarness(t, options{caps: "metrics, logs, packages", extraNode: "  hostRoot: " + root + "\n"})
	h.deps.Timing.Packages = 20 * time.Millisecond
	return h
}

func (h *harness) waitInventories(n int) []nodeapi.Item {
	h.t.Helper()
	h.waitFor("package inventories", func() bool { return len(h.coord.received(nodeapi.KindPackages)) >= n })
	return h.coord.received(nodeapi.KindPackages)
}

func (h *harness) packagesCoverage() string {
	req, _ := h.coord.lastRegister()
	return req.Coverage["packages"]
}

func TestNodeSendsPackageInventoryOnChange(t *testing.T) {
	root := t.TempDir()
	writeHostRoot(t, root, "1.1.0-2build2")
	h := packagesHarness(t, root)
	h.start()

	inv := h.waitInventories(1)[0].Inventory
	if inv == nil || protocol.ScopeState(inv.State) != protocol.ScopeComplete || inv.OS["id"] != "ubuntu" || inv.OS["version_id"] != "24.04" || len(inv.Packages) != 2 {
		t.Fatalf("inventory %+v", inv)
	}
	if b := inv.Packages[1]; b.Name != "libbrotli1" || b.Source != "brotli" || b.Version != "1.1.0-2build2" || b.SourceVersion != "1.1.0-2build2" {
		t.Fatalf("libbrotli1 %+v", b)
	}
	h.waitFor("packages coverage", func() bool { return h.packagesCoverage() == coverageAvailable })

	time.Sleep(200 * time.Millisecond)
	if n := len(h.coord.received(nodeapi.KindPackages)); n != 1 {
		t.Fatalf("unchanged inventory sent %d times", n)
	}

	writeHostRoot(t, root, "1.1.0-2ubuntu0.1")
	items := h.waitInventories(2)
	if v := items[1].Inventory.Packages[1].Version; v != "1.1.0-2ubuntu0.1" {
		t.Fatalf("upgraded version %q", v)
	}

	h.clock.Advance(7 * time.Hour)
	items = h.waitInventories(3)
	if items[2].Inventory.Packages[1].Version != "1.1.0-2ubuntu0.1" {
		t.Fatal("refresh changed content")
	}

	if err := h.shutdown(); err != nil {
		t.Fatal(err)
	}
	h.start()
	h.waitFor("packages coverage after restart", func() bool { return h.packagesCoverage() == coverageAvailable })
	time.Sleep(200 * time.Millisecond)
	if n := len(h.coord.received(nodeapi.KindPackages)); n != 3 {
		t.Fatalf("restart resent an unchanged inventory: %d items", n)
	}
}

func TestNodeReportsUnavailablePackageInventory(t *testing.T) {
	h := packagesHarness(t, t.TempDir())
	h.start()
	inv := h.waitInventories(1)[0].Inventory
	if protocol.ScopeState(inv.State) != protocol.ScopeUnavailable || inv.Reason != "source_absent" || len(inv.Packages) != 0 {
		t.Fatalf("inventory %+v", inv)
	}
	h.waitFor("unavailable coverage", func() bool { return h.packagesCoverage() == "unavailable: source_absent" })
}

func TestNodeWithoutPackagesCapability(t *testing.T) {
	h := newHarness(t, options{caps: "metrics, logs"})
	h.start()
	h.waitFor("disabled coverage", func() bool { return h.packagesCoverage() == "unavailable: capability disabled" })
	if n := len(h.coord.received(nodeapi.KindPackages)); n != 0 {
		t.Fatalf("%d inventories without the capability", n)
	}
	if req, _ := h.coord.lastRegister(); slices.Contains(req.Capabilities, "packages") {
		t.Fatalf("capabilities %v", req.Capabilities)
	}
}
