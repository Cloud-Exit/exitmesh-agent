// Package nodemetrics runs upstream node_exporter collectors in process so node_* series and upstream rules work unchanged.
package nodemetrics

import (
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/node_exporter/collector"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

// Appender receives one sample; labels include __name__.
type Appender func(labels map[string]string, value float64, tsMs int64)

// DefaultCollectors fit the H15 host budget; stat provides node_boot_time_seconds on Linux.
var DefaultCollectors = []string{"cpu", "meminfo", "loadavg", "filesystem", "diskstats", "netdev", "uname", "time", "stat", "filefd", "vmstat", "pressure", "timex"}

// DefaultMaxSeries bounds one gather; the H15 reference host produces about 3,000 node_* series.
const DefaultMaxSeries = 5000

// Options configures the exporter.
type Options struct {
	ProcPath     string
	SysPath      string
	RootfsPath   string
	UdevDataPath string
	Collectors   []string
	MaxSeries    int
	Logger       *slog.Logger
	Now          func() time.Time
}

// Exporter gathers node_exporter metrics.
type Exporter struct {
	reg *prometheus.Registry
	sc  *safeCollector
	max int
	now func() time.Time
}

// Stats describes one gather.
type Stats struct {
	Series           int
	DroppedSeries    int
	DroppedFamilies  []string
	FailedCollectors []string
}

type config struct {
	proc, sys, rootfs, udev string
	collectors              string
}

var (
	globalMu sync.Mutex
	applied  *config
)

// New applies node_exporter's process-global flags once; a later call with other paths or collectors fails.
func New(o Options) (*Exporter, error) {
	if o.ProcPath == "" {
		o.ProcPath = "/proc"
	}
	if o.SysPath == "" {
		o.SysPath = "/sys"
	}
	if o.RootfsPath == "" {
		o.RootfsPath = "/"
	}
	if o.UdevDataPath == "" {
		o.UdevDataPath = "/run/udev/data"
	}
	if o.Collectors == nil {
		o.Collectors = DefaultCollectors
	}
	if o.MaxSeries <= 0 {
		o.MaxSeries = DefaultMaxSeries
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(redact.NewHandler(slog.Default().Handler(), redact.Default()))
	}
	cols := slices.Clone(o.Collectors)
	slices.Sort(cols)
	cols = slices.Compact(cols)
	cfg := &config{proc: o.ProcPath, sys: o.SysPath, rootfs: o.RootfsPath, udev: o.UdevDataPath, collectors: fmt.Sprint(cols)}

	globalMu.Lock()
	defer globalMu.Unlock()
	if applied != nil && *applied != *cfg {
		return nil, fmt.Errorf("nodemetrics: node_exporter is already configured in this process with %+v", *applied)
	}
	if applied == nil {
		args := []string{"--path.procfs=" + o.ProcPath, "--path.sysfs=" + o.SysPath, "--path.rootfs=" + o.RootfsPath, "--path.udev.data=" + o.UdevDataPath}
		for _, c := range cols {
			args = append(args, "--collector."+c)
		}
		if _, err := kingpin.CommandLine.Parse(args); err != nil {
			return nil, fmt.Errorf("nodemetrics: applying node_exporter flags: %w", err)
		}
	}
	nc, err := collector.NewNodeCollector(o.Logger, cols...)
	if err != nil {
		return nil, fmt.Errorf("nodemetrics: %w", err)
	}
	applied = cfg
	return newExporter(nc.Collectors, o)
}

func newExporter(cols map[string]collector.Collector, o Options) (*Exporter, error) {
	sc := &safeCollector{cols: cols, logger: o.Logger}
	reg := prometheus.NewRegistry()
	if err := reg.Register(sc); err != nil {
		return nil, fmt.Errorf("nodemetrics: %w", err)
	}
	return &Exporter{reg: reg, sc: sc, max: o.MaxSeries, now: o.Now}, nil
}

var (
	scrapeDurationDesc = prometheus.NewDesc("node_scrape_collector_duration_seconds", "node_exporter: Duration of a collector scrape.", []string{"collector"}, nil)
	scrapeSuccessDesc  = prometheus.NewDesc("node_scrape_collector_success", "node_exporter: Whether a collector succeeded.", []string{"collector"}, nil)
)

// safeCollector runs node_exporter collectors like NodeCollector does, but a panicking collector fails alone instead of the process.
type safeCollector struct {
	cols   map[string]collector.Collector
	logger *slog.Logger
	mu     sync.Mutex
	failed []string
}

func (s *safeCollector) Describe(chan<- *prometheus.Desc) {}

func (s *safeCollector) Collect(ch chan<- prometheus.Metric) {
	var wg sync.WaitGroup
	for name, c := range s.cols {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.run(name, c, ch)
		}()
	}
	wg.Wait()
}

func (s *safeCollector) run(name string, c collector.Collector, ch chan<- prometheus.Metric) {
	begin := time.Now()
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return c.Update(ch)
	}()
	success := 1.0
	if err != nil {
		success = 0
		if !collector.IsNoDataError(err) {
			s.logger.Warn("node collector failed", "collector", name, "err", err)
			s.mu.Lock()
			s.failed = append(s.failed, name)
			s.mu.Unlock()
		}
	}
	ch <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, time.Since(begin).Seconds(), name)
	ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, success, name)
}

func (s *safeCollector) takeFailed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failed
	s.failed = nil
	slices.Sort(f)
	return f
}

// Gather appends whole metric families in name order while they fit the series limit and reports the rest.
func (e *Exporter) Gather(app Appender) (Stats, error) {
	fams, gerr := e.reg.Gather()
	now := e.now().UnixMilli()
	st := Stats{FailedCollectors: e.sc.takeFailed()}
	for _, f := range fams {
		samples := expand(f, now)
		if st.Series+len(samples) > e.max {
			st.DroppedSeries += len(samples)
			st.DroppedFamilies = append(st.DroppedFamilies, f.GetName())
			continue
		}
		st.Series += len(samples)
		for _, s := range samples {
			app(s.labels, s.value, s.ts)
		}
	}
	return st, gerr
}

type sample struct {
	labels map[string]string
	value  float64
	ts     int64
}

func expand(f *dto.MetricFamily, now int64) []sample {
	var out []sample
	name := f.GetName()
	for _, m := range f.GetMetric() {
		ts := now
		if m.TimestampMs != nil {
			ts = m.GetTimestampMs()
		}
		base := map[string]string{}
		for _, lp := range m.GetLabel() {
			base[lp.GetName()] = lp.GetValue()
		}
		add := func(n string, v float64, extra ...string) {
			l := make(map[string]string, len(base)+2)
			for k, v := range base {
				l[k] = v
			}
			l["__name__"] = n
			for i := 0; i+1 < len(extra); i += 2 {
				l[extra[i]] = extra[i+1]
			}
			out = append(out, sample{labels: l, value: v, ts: ts})
		}
		switch f.GetType() {
		case dto.MetricType_COUNTER:
			add(name, m.GetCounter().GetValue())
		case dto.MetricType_GAUGE:
			add(name, m.GetGauge().GetValue())
		case dto.MetricType_UNTYPED:
			add(name, m.GetUntyped().GetValue())
		case dto.MetricType_SUMMARY:
			s := m.GetSummary()
			for _, q := range s.GetQuantile() {
				add(name, q.GetValue(), "quantile", formatFloat(q.GetQuantile()))
			}
			add(name+"_sum", s.GetSampleSum())
			add(name+"_count", float64(s.GetSampleCount()))
		case dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM:
			h := m.GetHistogram()
			inf := false
			for _, b := range h.GetBucket() {
				if math.IsInf(b.GetUpperBound(), 1) {
					inf = true
				}
				add(name+"_bucket", float64(b.GetCumulativeCount()), "le", formatFloat(b.GetUpperBound()))
			}
			if !inf {
				add(name+"_bucket", float64(h.GetSampleCount()), "le", "+Inf")
			}
			add(name+"_sum", h.GetSampleSum())
			add(name+"_count", float64(h.GetSampleCount()))
		}
	}
	return out
}

func formatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
