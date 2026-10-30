package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostMetricsReachTheTSDB(t *testing.T) {
	root := t.TempDir()
	proc, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	dev := filepath.Join(sys, "devices", "pci0000:00", "net", "eth0")
	for path, body := range map[string]string{
		filepath.Join(proc, "meminfo"):               "MemTotal: 2048 kB\nMemAvailable: 512 kB\n",
		filepath.Join(proc, "stat"):                  "cpu  100 0 50 800 10 0 0 0 0 0\n",
		filepath.Join(dev, "statistics", "rx_bytes"): "100\n",
		filepath.Join(dev, "statistics", "tx_bytes"): "200\n",
		filepath.Join(dev, "speed"):                  "1000\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(sys, "class", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../devices/pci0000:00/net/eth0", filepath.Join(sys, "class", "net", "eth0")); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, options{caps: "metrics", extraNode: "  procPath: " + proc + "\n  sysPath: " + sys + "\n"})
	h.start()
	h.waitFor("node memory series", func() bool {
		v := h.instant(`node_memory_MemAvailable_bytes{node="` + testNode + `"}`)
		return len(v) == 1 && v[0].F == 512*1024
	})
	h.waitFor("node filesystem series", func() bool {
		return len(h.instant(`node_filesystem_avail_bytes{node="`+testNode+`"}`)) == 1
	})
	h.waitFor("node network series", func() bool {
		v := h.instant(`node_network_speed_bytes{node="` + testNode + `", device="eth0"}`)
		return len(v) == 1 && v[0].F == 1.25e8
	})
}

func TestHostMetricsCanBeDisabled(t *testing.T) {
	h := newHarness(t, options{caps: "metrics", extraNode: "  hostMetrics: false\n"})
	h.start()
	h.waitScrapes(2)
	if v := h.instant("node_memory_MemTotal_bytes"); len(v) != 0 {
		t.Fatalf("node memory gathered while disabled: %v", v)
	}
}
