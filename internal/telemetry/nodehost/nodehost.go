// Package nodehost reads the node's CPU, memory, filesystems, and physical network interface counters for the node agent, with node_exporter series names.
package nodehost

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
)

// DefaultMaxDevices bounds the network devices read per gather.
const DefaultMaxDevices = 64

// Options configures a Collector.
type Options struct {
	// ProcPath holds meminfo; a container's /proc reports the node's memory.
	ProcPath string
	// SysPath is the node's sysfs; it must be the host mount, since a pod's own /sys lists only the pod's interfaces.
	SysPath string
	// Filesystems are host paths mounted into the agent; each distinct filesystem among them is reported once, labeled with the first path.
	Filesystems []string
	Node        string
	MaxDevices  int
}

// Collector gathers node_cpu_*, node_memory_*, node_filesystem_*, and node_network_* series.
type Collector struct {
	o Options
}

// Stats describes one gather.
type Stats struct {
	Series int
	// Devices is the number of physical network devices read; zero when sysfs is unavailable.
	Devices int
	// NetworkError explains why network devices could not be read; empty when they were.
	NetworkError string
}

// New returns a Collector with defaults applied.
func New(o Options) *Collector {
	if o.ProcPath == "" {
		o.ProcPath = "/proc"
	}
	if o.MaxDevices <= 0 {
		o.MaxDevices = DefaultMaxDevices
	}
	return &Collector{o: o}
}

// Gather emits every series once; a memory read failure fails the gather, a network failure is reported in Stats.
func (c *Collector) Gather(emit func(l labels.Labels, v float64)) (Stats, error) {
	var st Stats
	mem, err := readMeminfo(filepath.Join(c.o.ProcPath, "meminfo"))
	if err != nil {
		return st, err
	}
	for _, k := range []string{"MemTotal", "MemAvailable"} {
		v, ok := mem[k]
		if !ok {
			return st, fmt.Errorf("nodehost: meminfo has no %s", k)
		}
		emit(c.labels("node_memory_"+k+"_bytes"), v)
		st.Series++
	}
	cpu, err := readCPU(filepath.Join(c.o.ProcPath, "stat"))
	if err != nil {
		return st, err
	}
	for i, mode := range cpuModes {
		emit(c.labels("node_cpu_seconds_total", "mode", mode), cpu[i])
		st.Series++
	}
	st.Series += c.gatherFilesystems(emit)
	if c.o.SysPath == "" {
		st.NetworkError = "no host sysfs path configured"
		return st, nil
	}
	devs, err := c.devices()
	if err != nil {
		st.NetworkError = err.Error()
		return st, nil
	}
	for _, d := range devs {
		base := filepath.Join(c.o.SysPath, "class", "net", d)
		rx, errRx := readUint(filepath.Join(base, "statistics", "rx_bytes"))
		tx, errTx := readUint(filepath.Join(base, "statistics", "tx_bytes"))
		if errRx != nil || errTx != nil {
			continue
		}
		emit(c.labels("node_network_receive_bytes_total", "device", d), float64(rx))
		emit(c.labels("node_network_transmit_bytes_total", "device", d), float64(tx))
		st.Series += 2
		if mbps, err := readInt(filepath.Join(base, "speed")); err == nil && mbps > 0 {
			emit(c.labels("node_network_speed_bytes", "device", d), float64(mbps)*125_000)
			st.Series++
		}
		st.Devices++
	}
	return st, nil
}

func (c *Collector) labels(name string, kv ...string) labels.Labels {
	all := append([]string{model.MetricNameLabel, name, "node", c.o.Node}, kv...)
	return labels.FromStrings(all...)
}

// devices lists physical interfaces: sysfs links them under /devices, virtual ones (bridges, veths, tunnels) under /devices/virtual.
func (c *Collector) devices() ([]string, error) {
	dir := filepath.Join(c.o.SysPath, "class", "net")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("nodehost: network devices: %w", err)
	}
	var out []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil || strings.Contains(target, "/devices/virtual/") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	if len(out) > c.o.MaxDevices {
		out = out[:c.o.MaxDevices]
	}
	return out, nil
}

// cpuModes are the /proc/stat cpu line columns in order.
var cpuModes = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

// userHZ is the fixed tick rate of /proc/stat on Linux.
const userHZ = 100

// readCPU returns the seconds per mode summed over every CPU, from the aggregate cpu line.
func readCPU(path string) ([]float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nodehost: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		if len(fields) < len(cpuModes)+1 {
			return nil, fmt.Errorf("nodehost: cpu line has %d columns, want %d", len(fields)-1, len(cpuModes))
		}
		out := make([]float64, len(cpuModes))
		for i := range cpuModes {
			v, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("nodehost: cpu %s: %w", cpuModes[i], err)
			}
			out[i] = float64(v) / userHZ
		}
		return out, nil
	}
	return nil, errors.New("nodehost: stat has no cpu line")
}

func readMeminfo(path string) (map[string]float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("nodehost: %w", err)
	}
	defer f.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			v *= 1024
		}
		out[key] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nodehost: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("nodehost: meminfo is empty")
	}
	return out, nil
}

func readUint(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

func readInt(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}
