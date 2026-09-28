package nodemetrics

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/node_exporter/collector"
	"google.golang.org/protobuf/proto"
)

var fixtureFiles = map[string]string{
	"proc/stat": `cpu  10132153 290696 3084719 46828483 16683 0 25195 0 0 0
cpu0 1393280 32966 572056 13343292 6130 0 17875 0 0 0
cpu1 1335567 42426 538418 13463003 5476 0 3688 0 0 0
intr 8885917 17 0 0 0 0 0 0 0 1 79281 0 0 0 0 0 0 0 231237 0 0 0 0 250586 103 0 0 0 0 0 0 0 0 0 0 0 0 0 0
ctxt 38014093
btime 1418183276
processes 26442
procs_running 2
procs_blocked 1
softirq 5057579 250191 1481983 1647 211099 186066 0 1783454 622196 12499 510444
`,
	"proc/meminfo":         "MemTotal:       15666184 kB\nMemFree:          440324 kB\nMemAvailable:    9000000 kB\nBuffers:         1020128 kB\nCached:         12007640 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n",
	"proc/loadavg":         "0.25 0.50 0.75 1/497 11947\n",
	"proc/vmstat":          "nr_free_pages 110050\npgpgin 100\npgpgout 200\npswpin 0\npswpout 0\npgfault 12345\npgmajfault 10\noom_kill 0\n",
	"proc/sys/fs/file-nr":  "1024\t0\t1631329\n",
	"proc/pressure/cpu":    "some avg10=0.00 avg60=0.00 avg300=0.00 total=14036781\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
	"proc/pressure/memory": "some avg10=0.00 avg60=0.00 avg300=0.00 total=5000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=3000000\n",
	"proc/pressure/io":     "some avg10=0.00 avg60=0.00 avg300=0.00 total=7000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=6000000\n",
	"proc/pressure/irq":    "full avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n",
	"proc/diskstats":       "   8       0 sda 25354637 34367663 1003346126 18492372 28444756 11134226 505697032 63877960 0 9653880 82621804\n",
	"proc/1/mountinfo":     "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
	"proc/self/mountinfo":  "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
	"proc/net/dev":         "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:  1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n  eth0: 5000      50    0    0    0     0          0         0     6000      60    0    0    0     0       0          0\n",
	"sys/devices/system/clocksource/clocksource0/available_clocksource": "tsc hpet acpi_pm\n",
	"sys/devices/system/cpu/cpu0/online":                                "1\n",
	"sys/devices/system/cpu/cpu1/online":                                "1\n",
	"sys/devices/system/clocksource/clocksource0/current_clocksource":   "tsc\n",
}

var (
	fixtureOnce sync.Once
	fixtureDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fixtureDir != "" {
		os.RemoveAll(fixtureDir)
	}
	os.Exit(code)
}

func fixture(t *testing.T) string {
	t.Helper()
	fixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nodemetrics")
		if err != nil {
			t.Fatal(err)
		}
		for p, c := range fixtureFiles {
			full := filepath.Join(dir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		fixtureDir = dir
	})
	return fixtureDir
}

func fixtureExporter(t *testing.T, max int) *Exporter {
	t.Helper()
	dir := fixture(t)
	e, err := New(Options{ProcPath: filepath.Join(dir, "proc"), SysPath: filepath.Join(dir, "sys"), UdevDataPath: filepath.Join(dir, "udev"), MaxSeries: max,
		Now: func() time.Time { return time.UnixMilli(1_700_000_000_000) }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type got struct {
	labels map[string]string
	value  float64
	ts     int64
}

func gather(t *testing.T, e *Exporter) ([]got, Stats) {
	t.Helper()
	var out []got
	st, err := e.Gather(func(l map[string]string, v float64, ts int64) { out = append(out, got{l, v, ts}) })
	if err != nil {
		t.Fatal(err)
	}
	return out, st
}

func find(samples []got, name string, match map[string]string) (float64, bool) {
	for _, s := range samples {
		if s.labels["__name__"] != name {
			continue
		}
		ok := true
		for k, v := range match {
			if s.labels[k] != v {
				ok = false
			}
		}
		if ok {
			return s.value, true
		}
	}
	return 0, false
}

func TestGatherFixtureProcfs(t *testing.T) {
	samples, st := gather(t, fixtureExporter(t, 0))
	if st.Series != len(samples) || st.DroppedSeries != 0 {
		t.Fatalf("stats %+v for %d samples", st, len(samples))
	}
	checks := []struct {
		name  string
		match map[string]string
		want  float64
	}{
		{"node_memory_MemTotal_bytes", nil, 15666184 * 1024},
		{"node_memory_MemAvailable_bytes", nil, 9000000 * 1024},
		{"node_load1", nil, 0.25},
		{"node_load15", nil, 0.75},
		{"node_boot_time_seconds", nil, 1418183276},
		{"node_context_switches_total", nil, 38014093},
		{"node_procs_running", nil, 2},
		{"node_filefd_allocated", nil, 1024},
		{"node_filefd_maximum", nil, 1631329},
		{"node_vmstat_pgfault", nil, 12345},
		{"node_pressure_cpu_waiting_seconds_total", nil, 14.036781},
		{"node_pressure_memory_stalled_seconds_total", nil, 3},
		{"node_cpu_seconds_total", map[string]string{"cpu": "0", "mode": "user"}, 13932.80},
		{"node_disk_reads_completed_total", map[string]string{"device": "sda"}, 25354637},
		{"node_scrape_collector_success", map[string]string{"collector": "meminfo"}, 1},
		{"node_scrape_collector_success", map[string]string{"collector": "vmstat"}, 1},
		{"node_time_clocksource_current_info", map[string]string{"clocksource": "tsc"}, 1},
	}
	for _, c := range checks {
		v, ok := find(samples, c.name, c.match)
		if !ok {
			t.Fatalf("%s%v missing", c.name, c.match)
		}
		if diff := v - c.want; diff > 1e-6 || diff < -1e-6 {
			t.Fatalf("%s%v = %v, want %v", c.name, c.match, v, c.want)
		}
	}
	if _, ok := find(samples, "node_uname_info", nil); !ok {
		t.Fatal("node_uname_info missing")
	}
	collectors := map[string]bool{}
	for _, s := range samples {
		if s.labels["__name__"] == "node_scrape_collector_success" {
			collectors[s.labels["collector"]] = true
		}
		if !strings.HasPrefix(s.labels["__name__"], "node_") {
			t.Fatalf("non-node series %v", s.labels)
		}
		if s.labels["__name__"] == "node_time_seconds" {
			continue
		}
		if s.ts != 1_700_000_000_000 {
			t.Fatalf("timestamp %d on %v", s.ts, s.labels)
		}
	}
	for _, c := range DefaultCollectors {
		if !collectors[c] {
			t.Fatalf("collector %s did not run", c)
		}
	}
	if collectors["systemd"] {
		t.Fatal("systemd collector enabled by default")
	}
}

func TestSeriesGuardDropsWholeFamilies(t *testing.T) {
	all, _ := gather(t, fixtureExporter(t, 0))
	e := fixtureExporter(t, 20)
	samples, st := gather(t, e)
	if st.Series > 20 || st.Series != len(samples) || st.DroppedSeries != len(all)-len(samples) || len(st.DroppedFamilies) == 0 {
		t.Fatalf("guard stats %+v with %d of %d samples", st, len(samples), len(all))
	}
	names := map[string]bool{}
	for _, s := range samples {
		names[s.labels["__name__"]] = true
	}
	for _, f := range st.DroppedFamilies {
		if names[f] {
			t.Fatalf("family %s both dropped and appended", f)
		}
	}
}

func TestProcessGlobalConfiguration(t *testing.T) {
	fixtureExporter(t, 0)
	if _, err := New(Options{ProcPath: "/elsewhere/proc", SysPath: filepath.Join(fixture(t), "sys")}); err == nil {
		t.Fatal("second configuration with other paths accepted")
	}
	dir := fixture(t)
	if _, err := New(Options{ProcPath: filepath.Join(dir, "proc"), SysPath: filepath.Join(dir, "sys"), UdevDataPath: filepath.Join(dir, "udev"), Collectors: []string{"meminfo"}}); err == nil {
		t.Fatal("second configuration with other collectors accepted")
	}
}

func TestExpandSummaryAndHistogram(t *testing.T) {
	sum := &dto.MetricFamily{Name: proto.String("node_x"), Type: dto.MetricType_SUMMARY.Enum(), Metric: []*dto.Metric{{
		Label:   []*dto.LabelPair{{Name: proto.String("a"), Value: proto.String("b")}},
		Summary: &dto.Summary{SampleCount: proto.Uint64(4), SampleSum: proto.Float64(10), Quantile: []*dto.Quantile{{Quantile: proto.Float64(0.5), Value: proto.Float64(2)}}},
	}}}
	s := expand(sum, 5)
	if len(s) != 3 || s[0].labels["quantile"] != "0.5" || s[0].labels["a"] != "b" || s[1].labels["__name__"] != "node_x_sum" || s[2].value != 4 || s[2].ts != 5 {
		t.Fatalf("summary %+v", s)
	}
	hist := &dto.MetricFamily{Name: proto.String("node_h"), Type: dto.MetricType_HISTOGRAM.Enum(), Metric: []*dto.Metric{{
		TimestampMs: proto.Int64(9),
		Histogram:   &dto.Histogram{SampleCount: proto.Uint64(3), SampleSum: proto.Float64(1.5), Bucket: []*dto.Bucket{{UpperBound: proto.Float64(0.1), CumulativeCount: proto.Uint64(1)}}},
	}}}
	h := expand(hist, 5)
	if len(h) != 4 || h[0].labels["le"] != "0.1" || h[1].labels["le"] != "+Inf" || h[1].value != 3 || h[3].labels["__name__"] != "node_h_count" || h[0].ts != 9 {
		t.Fatalf("histogram %+v", h)
	}
	if formatFloat(-1/zero()) != "-Inf" || formatFloat(zero()/zero()) != "NaN" {
		t.Fatal("formatFloat")
	}
}

func zero() float64 { return 0 }

type panicky struct{}

func (panicky) Update(chan<- prometheus.Metric) error { panic("boom") }

type noData struct{}

func (noData) Update(chan<- prometheus.Metric) error { return collector.ErrNoData }

func TestPanickingCollectorFailsAlone(t *testing.T) {
	e, err := newExporter(map[string]collector.Collector{"bad": panicky{}, "empty": noData{}}, Options{MaxSeries: 10, Now: time.Now, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	samples, st := gather(t, e)
	if v, ok := find(samples, "node_scrape_collector_success", map[string]string{"collector": "bad"}); !ok || v != 0 {
		t.Fatalf("bad collector success %v %v", v, ok)
	}
	if v, ok := find(samples, "node_scrape_collector_success", map[string]string{"collector": "empty"}); !ok || v != 0 {
		t.Fatalf("no-data collector success %v %v", v, ok)
	}
	if len(st.FailedCollectors) != 1 || st.FailedCollectors[0] != "bad" {
		t.Fatalf("failed collectors %v", st.FailedCollectors)
	}
}
