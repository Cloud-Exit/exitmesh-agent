package nodehost

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
)

const procStat = "cpu  1000 50 300 8000 100 10 20 5 0 0\ncpu0 500 25 150 4000 50 5 10 2 0 0\nintr 1\n"

// proc writes a /proc with meminfo and stat.
func proc(t *testing.T, dir, meminfo string) string {
	t.Helper()
	write(t, filepath.Join(dir, "meminfo"), meminfo)
	write(t, filepath.Join(dir, "stat"), procStat)
	return dir
}

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
		got[l.Get(model.MetricNameLabel)+"/"+l.Get("device")+l.Get("mode")] = v
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func TestGatherReadsMemoryAndPhysicalDevices(t *testing.T) {
	root := t.TempDir()
	procDir, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	proc(t, procDir, "MemTotal:       65536000 kB\nMemFree:  1000 kB\nMemAvailable:   16384000 kB\nHugePages_Total:       0\n")
	netDevice(t, sys, "pci0000:00/0000:c1:00.0", "enp193s0f0np0", "1000", "2000", "10000")
	netDevice(t, sys, "pci0000:00/0000:c1:00.1", "enp193s0f1np1", "5", "6", "-1")
	netDevice(t, sys, "virtual", "cni0", "7", "8", "")
	netDevice(t, sys, "virtual", "lo", "9", "9", "")

	fs := t.TempDir()
	got, st := gather(t, New(Options{ProcPath: procDir, SysPath: sys, Node: "node-a", Filesystems: []string{fs, fs, filepath.Join(root, "missing")}}))
	if got["node_filesystem_size_bytes/"] <= 0 || got["node_filesystem_avail_bytes/"] <= 0 {
		t.Fatalf("filesystem series missing: %v", got)
	}
	delete(got, "node_filesystem_size_bytes/")
	delete(got, "node_filesystem_avail_bytes/")
	for _, m := range []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"} {
		delete(got, "node_cpu_seconds_total/"+m)
	}
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
	if st.Devices != 2 || st.Series != len(want)+2+8 || st.NetworkError != "" {
		t.Fatalf("stats %+v", st)
	}
}

func TestGatherWithoutHostSysfsKeepsMemory(t *testing.T) {
	p := proc(t, filepath.Join(t.TempDir(), "proc"), "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	got, st := gather(t, New(Options{ProcPath: p, SysPath: filepath.Join(t.TempDir(), "missing"), Node: "node-a"}))
	if len(got) != 10 || st.Devices != 0 || st.NetworkError == "" {
		t.Fatalf("got %v, stats %+v", got, st)
	}
}

func TestGatherFailsWithoutMeminfo(t *testing.T) {
	p := proc(t, filepath.Join(t.TempDir(), "proc"), "MemTotal: 1024 kB\n")
	if _, err := New(Options{ProcPath: p, Node: "node-a"}).Gather(func(labels.Labels, float64) {}); err == nil {
		t.Fatal("meminfo without MemAvailable gathered")
	}
	p = filepath.Join(t.TempDir(), "proc")
	write(t, filepath.Join(p, "meminfo"), "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	write(t, filepath.Join(p, "stat"), "intr 1\n")
	if _, err := New(Options{ProcPath: p, Node: "node-a"}).Gather(func(labels.Labels, float64) {}); err == nil {
		t.Fatal("stat without a cpu line gathered")
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
	p := proc(t, filepath.Join(t.TempDir(), "proc"), "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	got, st := gather(t, New(Options{ProcPath: p, SysPath: sys, Node: "node-a", MaxDevices: 2}))
	if st.Devices != 2 || got["node_network_receive_bytes_total/eth2"] != 0 || got["node_network_receive_bytes_total/eth0"] != 1 {
		t.Fatalf("got %v, stats %+v", got, st)
	}
}

func TestCPUSecondsSumEveryCPU(t *testing.T) {
	p := proc(t, filepath.Join(t.TempDir(), "proc"), "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	got, _ := gather(t, New(Options{ProcPath: p, Node: "node-a"}))
	want := map[string]float64{"user": 10, "nice": 0.5, "system": 3, "idle": 80, "iowait": 1, "irq": 0.1, "softirq": 0.2, "steal": 0.05}
	for mode, v := range want {
		if got["node_cpu_seconds_total/"+mode] != v {
			t.Errorf("%s = %v, want %v", mode, got["node_cpu_seconds_total/"+mode], v)
		}
	}
}
