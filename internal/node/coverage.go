package node

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/scrape"
)

const (
	capMetrics = config.CapMetrics
	capLogs    = config.CapLogs

	coverageAvailable = "available"
	coverageWarming   = "warming"
	reasonReimaged    = "reimaged"
)

type coverageState struct {
	mu        sync.Mutex
	warmup    time.Duration
	logWarmup time.Duration
	gaps      map[string]uint64
	logsErr   string
	logsCheck time.Time
	cycles    uint64
}

func (c *coverageState) setWarmup(all, logs time.Duration) {
	c.mu.Lock()
	c.warmup, c.logWarmup = all, logs
	c.mu.Unlock()
}

func (c *coverageState) logGap(e logs.Event) {
	c.mu.Lock()
	if c.gaps == nil {
		c.gaps = map[string]uint64{}
	}
	c.gaps[string(e.Kind)]++
	c.mu.Unlock()
}

func (c *coverageState) markEvaluated() {
	c.mu.Lock()
	c.cycles++
	c.mu.Unlock()
}

func (c *coverageState) evaluatedCycles() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cycles
}

func (c *coverageState) logsUnavailable() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logsErr
}

// checkLogsRoot refreshes whether the pod log root is readable, at most every ten seconds.
func (c *coverageState) checkLogsRoot(root string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.logsCheck.IsZero() && time.Since(c.logsCheck) < 10*time.Second {
		return
	}
	c.logsCheck = time.Now()
	f, err := os.Open(root)
	if err == nil {
		_, err = f.Readdirnames(1)
		_ = f.Close()
	}
	c.logsErr = ""
	if err != nil && !errors.Is(err, io.EOF) {
		c.logsErr = err.Error()
	}
}

func (a *Agent) kubeletStatus() []scrape.TargetStatus {
	if a.scraper == nil {
		return nil
	}
	var out []scrape.TargetStatus
	for _, s := range a.scraper.Status() {
		if s.Labels["job"] == "kubelet" {
			out = append(out, s)
		}
	}
	return out
}

func (a *Agent) kubeletScraped() bool {
	st := a.kubeletStatus()
	for _, s := range st {
		if s.Health == scrape.HealthUnknown {
			return false
		}
	}
	return len(st) > 0
}

// kubeletDown reports that no kubelet endpoint is being scraped successfully.
func (a *Agent) kubeletDown() bool { return a.kubeletReason() != "" }

func (a *Agent) kubeletReason() string {
	st := a.kubeletStatus()
	if len(st) == 0 {
		return "no kubelet targets"
	}
	var reasons []string
	for _, s := range st {
		switch s.Health {
		case scrape.HealthUp, scrape.HealthUnknown:
			return ""
		default:
			reasons = append(reasons, s.Labels["metrics_path"]+": "+s.Reason)
		}
	}
	return strings.Join(reasons, ", ")
}

// coverageReport describes each capability as available, warming, or unavailable with a reason.
func (a *Agent) coverageReport() map[string]string {
	out := map[string]string{}
	warm := a.warming()
	warmValue := coverageWarming
	if a.fresh && warm {
		warmValue += ": " + reasonReimaged
	}
	for _, c := range []string{capMetrics, capLogs} {
		if !a.caps[c] {
			out[c] = "unavailable: capability disabled"
		}
	}
	if a.caps[capMetrics] {
		switch r := a.kubeletReason(); {
		case a.gate != nil && a.gate.paused.Load():
			out[capMetrics] = "unavailable: " + errDiskCap.Error()
		case warm:
			out[capMetrics] = warmValue
		case r != "":
			out[capMetrics] = "unavailable: kubelet " + r
		default:
			out[capMetrics] = coverageAvailable
		}
		out["metrics.pod_targets"] = a.podTargetSummary()
		if a.budget != nil {
			r := a.budget.Last()
			if r.Pressure {
				out["disk"] = fmt.Sprintf("pressure: %d of %d bytes used, tsdb at %d, %d samples refused", r.Effective, r.Cap, r.TSDB, a.gate.dropped.Load())
			} else {
				out["disk"] = fmt.Sprintf("ok: %d of %d bytes used", r.Effective, r.Cap)
			}
		}
	}
	if a.caps[capLogs] {
		a.cov.checkLogsRoot(a.cfg.Node.LogsPath)
		switch r := a.cov.logsUnavailable(); {
		case r != "":
			out[capLogs] = "unavailable: " + r
		case a.logsSet.cur.Load() == nil:
			out[capLogs] = coverageWarming + ": no rule bundle"
		case warm:
			out[capLogs] = warmValue
		default:
			out[capLogs] = coverageAvailable
		}
		a.cov.mu.Lock()
		if len(a.cov.gaps) > 0 {
			kinds := make([]string, 0, len(a.cov.gaps))
			for k, n := range a.cov.gaps {
				kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
			}
			sort.Strings(kinds)
			out["logs.gaps"] = strings.Join(kinds, ",")
		}
		a.cov.mu.Unlock()
		if lim := a.ring.LimitedRules(); len(lim) > 0 {
			out["logs.evidence_limited"] = strings.Join(lim, ",")
		}
		if set := a.logsSet.cur.Load(); set != nil {
			var lim []string
			for _, lr := range set.rules {
				if lr.prog.Status().BudgetLimited {
					lim = append(lim, lr.ids...)
				}
			}
			if len(lim) > 0 {
				sort.Strings(lim)
				out["logs.budget_limited"] = strings.Join(lim, ",")
			}
		}
	}
	if !a.pods.synced() {
		out["pods"] = "syncing"
	} else {
		out["pods"] = coverageAvailable
	}
	if d := a.deliv.droppedSummary(); d != "" {
		out["queue.dropped"] = d
	}
	a.rules.mu.Lock()
	if a.rules.rejected != "" {
		out["bundle"] = "rejected " + a.rules.rejected + ": " + a.rules.lastError
	}
	a.rules.mu.Unlock()
	return out
}

func (a *Agent) podTargetSummary() string {
	if a.scraper == nil {
		return ""
	}
	counts := map[scrape.Health]int{}
	reasons := map[string]int{}
	for _, s := range a.scraper.Status() {
		if s.Labels["job"] == "kubelet" {
			continue
		}
		counts[s.Health]++
		if s.Reason != "" && s.Health != scrape.HealthUp {
			reasons[s.Reason]++
		}
	}
	msg := fmt.Sprintf("%d up, %d down, %d dropped", counts[scrape.HealthUp], counts[scrape.HealthDown], counts[scrape.HealthDropped])
	if len(reasons) > 0 {
		rs := make([]string, 0, len(reasons))
		for r, n := range reasons {
			rs = append(rs, fmt.Sprintf("%s=%d", r, n))
		}
		sort.Strings(rs)
		msg += " (" + strings.Join(rs, ",") + ")"
	}
	return msg
}
