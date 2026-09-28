package host

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/journal"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/nodemetrics"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/disk"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/scrape"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

// DefaultJournalDirs are read when host.journalDir is empty.
var DefaultJournalDirs = []string{"/var/log/journal", "/run/log/journal"}

const maxJournalBatch = 10_000

func (h *Host) openTelemetry() error {
	hc := h.cfg.Host
	var shrinker disk.Shrinker
	if h.cfg.HasCapability(config.CapMetrics) {
		db, err := tsdb.Open(filepath.Join(h.cfg.StateDir, TSDBDirName), tsdb.Options{
			Retention: promRetention(nil), MaxBytes: int64(hc.TSDBMax), Logger: h.log,
		})
		if err != nil {
			return fmt.Errorf("host: tsdb: %w", err)
		}
		h.db, shrinker = db, db
		h.exporter, err = nodemetrics.New(nodemetrics.Options{
			ProcPath: h.deps.Facts.ProcRoot, SysPath: h.deps.Facts.SysRoot, RootfsPath: h.deps.FSRoot,
			UdevDataPath: filepath.Join(h.deps.FSRoot, "run/udev/data"), Collectors: h.deps.MetricsCollectors,
			Logger: h.log, Now: h.clk.Now,
		})
		if err != nil {
			return fmt.Errorf("host: node metrics: %w", err)
		}
		targets, rejected := metricsTargets(hc)
		h.st.rejectedEndpoints = rejected
		for u, why := range rejected {
			h.log.Warn("metrics endpoint refused", "url", u, "reason", why)
		}
		h.scraper = scrape.NewManager(scrape.Options{Appendable: db, DefaultInterval: hc.ScrapeInterval.D(), Logger: h.log})
		h.scraper.Sync(targets)
	}
	if h.cfg.HasCapability(config.CapLogs) {
		if len(hc.LogFiles) > 0 {
			store, err := h.bucket("logs")
			if err != nil {
				return err
			}
			h.files, err = logs.NewFileTailer(logs.FileOptions{
				Paths: hc.LogFiles, Store: store, Sink: h.onFileLine, OnEvent: h.onLogEvent, Clock: h.clk.Now,
			})
			if err != nil {
				return fmt.Errorf("host: log files: %w", err)
			}
			h.files.SetFilter(h.streamFilter)
		}
		if hc.Journal {
			store, err := h.bucket("journal")
			if err != nil {
				return err
			}
			dirs := h.journalDirs()
			if h.jr, err = h.deps.OpenJournal(journal.Options{Dirs: dirs, Store: store, Since: h.clk.Now()}); err != nil {
				h.jr = nil
				h.setErr(&h.st.journalError, err)
				h.log.Warn("journal unavailable", "dirs", dirs, "err", err)
			}
		}
	}
	h.budget = disk.DiskBudget(h.cfg.StateDir, int64(hc.DiskCap), disk.Options{
		TSDB: shrinker, TSDBDir: TSDBDirName, SpoolDir: SpoolDirName, SpoolReserve: int64(hc.SpoolReserve),
	})
	return nil
}

// metricsTargets admits loopback endpoints only, unless host.allowNonLoopback (H5).
func metricsTargets(hc config.Host) ([]scrape.Target, map[string]string) {
	var out []scrape.Target
	rejected := map[string]string{}
	for _, raw := range hc.MetricsEndpoints {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			rejected[raw] = "not an http or https URL"
			continue
		}
		if !hc.AllowNonLoopback && !isLoopback(u.Hostname()) {
			rejected[raw] = "not a loopback address; set host.allowNonLoopback to scrape it"
			continue
		}
		out = append(out, scrape.Target{URL: raw})
	}
	return out, rejected
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (h *Host) gatherMetrics(now time.Time) {
	app := h.db.Appender(context.Background())
	var appendErrs int
	stats, err := h.exporter.Gather(func(l map[string]string, v float64, ts int64) {
		if _, err := app.Append(0, labels.FromMap(l), ts, v); err != nil {
			appendErrs++
		}
	})
	if err != nil {
		_ = app.Rollback()
		h.setErr(&h.st.metricsError, err)
		return
	}
	if err := app.Commit(); err != nil {
		h.setErr(&h.st.metricsError, err)
		return
	}
	h.mu.Lock()
	h.st.lastGather, h.st.metrics, h.st.metricsAppendErrors, h.st.metricsError = now, stats, appendErrs, ""
	h.mu.Unlock()
}

func (h *Host) streamFilter(l map[string]string) bool {
	for _, lp := range h.rules.programs() {
		if lp.p.Matches(l) {
			return true
		}
	}
	return false
}

// observeLine counts a line for every program selecting its stream and keeps matches as redacted evidence.
func (h *Host) observeLine(l map[string]string, ts time.Time, text string) {
	for _, lp := range h.rules.programs() {
		if !lp.p.Matches(l) {
			continue
		}
		if lp.p.Observe(l, ts, text) {
			for _, id := range lp.rules {
				h.ring.Add(id, evidence.Sample{Time: ts, Labels: l, Text: text})
			}
		}
	}
}

func (h *Host) onFileLine(ln logs.Line) { h.observeLine(ln.Labels, ln.Time, ln.Text) }

func (h *Host) onLogEvent(ev logs.Event) {
	h.mu.Lock()
	h.st.logGaps++
	h.mu.Unlock()
	h.log.Warn("log input gap", "kind", ev.Kind, "path", ev.Path, "lost_bytes", ev.LostBytes, "detail", ev.Detail)
}

func (h *Host) pollLogs(ctx context.Context, now time.Time) {
	if h.files != nil {
		if err := h.files.Poll(ctx); err != nil {
			h.setErr(&h.st.logsError, err)
		} else {
			h.setErr(&h.st.logsError, nil)
		}
	}
	if h.jr == nil {
		return
	}
	if err := h.jr.Refresh(); err != nil {
		h.setErr(&h.st.journalError, err)
		return
	}
	n := 0
	for ; n < maxJournalBatch; n++ {
		e, ok := h.jr.Next()
		if !ok {
			break
		}
		if l := e.Labels(); h.streamFilter(l) {
			h.observeLine(l, e.Realtime, e.Message())
		}
	}
	if n > 0 {
		if err := h.jr.SaveCursor(); err != nil {
			h.setErr(&h.st.journalError, err)
			return
		}
	}
	var fileErrs map[string]string
	for p, err := range h.jr.FileErrors() {
		if fileErrs == nil {
			fileErrs = map[string]string{}
		}
		fileErrs[p] = h.red.String(err.Error())
	}
	h.mu.Lock()
	h.st.journalFileErrors = fileErrs
	h.st.journalEntries += uint64(n)
	h.st.lastJournal = now
	h.st.journalError = ""
	h.mu.Unlock()
}

func (h *Host) checkpointLogs() {
	if h.files != nil {
		if err := h.files.Checkpoint(); err != nil {
			h.setErr(&h.st.logsError, err)
		}
	}
	if h.jr != nil {
		if err := h.jr.SaveCursor(); err != nil {
			h.setErr(&h.st.journalError, err)
		}
	}
}

func (h *Host) checkDisk(ctx context.Context) {
	rep, err := h.budget.Check(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.disk = rep
	if err != nil {
		h.st.diskError = h.red.String(err.Error())
	} else {
		h.st.diskError = ""
	}
}
