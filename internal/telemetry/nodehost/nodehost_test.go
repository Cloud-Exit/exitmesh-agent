package nodehost

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// netDevice lays out a sysfs device under devices/<parent>/net/<name> linked from class/net.
func netDevice(t *testing.T, sys, parent, name, rx, tx, speed string) {
	t.Helper()
	dev := filepath.Join(sys, "devices", parent, "net", name)
	write(t, filepath.Join(dev, "statistics", "rx_bytes"), rx+"\n")
	write(t, filepath.Join(dev, "statistics", "tx_bytes"), tx+"\n")
	if speed != "" {
		write(t, filepath.Join(dev, "speed"), speed+"\n")
	}
	link := filepath.Join(sys, "class", "net", name)
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(filepath.Dir(link), dev)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, link); err != nil {
		t.Fatal(err)
	}
}

func gather(t *testing.T, c *Collector) (map[string]float64, Stats) {
	t.Helper()
	got := map[string]float64{}
	st, err := c.Gather(func(l labels.Labels, v float64) {
		if l.Get("node") != "node-a" {
			t.Fatalf("series %s lacks the node label", l)
		}
		got[l.Get(labels.MetricName)+"/"+l.Get("device")] = v
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func TestGatherReadsMemoryAndPhysicalDevices(t *testing.T) {
	root := t.TempDir()
	proc, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	write(t, filepath.Join(proc, "meminfo"), "MemTotal:       65536000 kB\nMemFree:  1000 kB\nMemAvailable:   16384000 kB\nHugePages_Total:       0\n")
	netDevice(t, sys, "pci0000:00/0000:c1:00.0", "enp193s0f0np0", "1000", "2000", "10000")
	netDevice(t, sys, "pci0000:00/0000:c1:00.1", "enp193s0f1np1", "5", "6", "-1")
	netDevice(t, sys, "virtual", "cni0", "7", "8", "")
	netDevice(t, sys, "virtual", "lo", "9", "9", "")

	got, st := gather(t, New(Options{ProcPath: proc, SysPath: sys, Node: "node-a"}))
	want := map[string]float64{
		"node_memory_MemTotal_bytes/":                     65536000 * 1024,
		"node_memory_MemAvailable_bytes/":                 16384000 * 1024,
		"node_network_receive_bytes_total/enp193s0f0np0":  1000,
		"node_network_transmit_bytes_total/enp193s0f0np0": 2000,
		"node_network_speed_bytes/enp193s0f0np0":          1.25e9,
		"node_network_receive_bytes_total/enp193s0f1np1":  5,
		"node_network_transmit_bytes_total/enp193s0f1np1": 6,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if st.Devices != 2 || st.Series != len(want) || st.NetworkError != "" {
		t.Fatalf("stats %+v", st)
	}
}

func TestGatherWithoutHostSysfsKeepsMemory(t *testing.T) {
	proc := filepath.Join(t.TempDir(), "proc")
	write(t, filepath.Join(proc, "meminfo"), "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	got, st := gather(t, New(Options{ProcPath: proc, SysPath: filepath.Join(t.TempDir(), "missing"), Node: "node-a"}))
	if len(got) != 2 || st.Devices != 0 || st.NetworkError == "" {
		t.Fatalf("got %v, stats %+v", got, st)
	}
}

func TestGatherFailsWithoutMeminfo(t *testing.T) {
	proc := filepath.Join(t.TempDir(), "proc")
	write(t, filepath.Join(proc, "meminfo"), "MemTotal: 1024 kB\n")
	if _, err := New(Options{ProcPath: proc, Node: "node-a"}).Gather(func(labels.Labels, float64) {}); err == nil {
		t.Fatal("meminfo without MemAvailable gathered")
	}
	if _, err := New(Options{ProcPath: filepath.Join(t.TempDir(), "none"), Node: "node-a"}).Gather(func(labels.Labels, float64) {}); err == nil {
		t.Fatal("missing meminfo gathered")
	}
}

func TestDevicesAreBounded(t *testing.T) {
	sys := filepath.Join(t.TempDir(), "sys")
	for _, n := range []string{"eth2", "eth0", "eth1"} {
		netDevice(t, sys, "pci0000:00/"+n, n, "1", "1", "1000")
	}
	proc := filepath.Join(t.TempDir(), "proc")
	write(t, filepath.Join(proc, "meminfo"), "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	got, st := gather(t, New(Options{ProcPath: proc, SysPath: sys, Node: "node-a", MaxDevices: 2}))
	if st.Devices != 2 || got["node_network_receive_bytes_total/eth2"] != 0 || got["node_network_receive_bytes_total/eth0"] != 1 {
		t.Fatalf("got %v, stats %+v", got, st)
	}
}
