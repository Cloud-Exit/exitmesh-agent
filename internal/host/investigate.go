package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/journal"
	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// openInvestigation builds the host investigation service over the local TSDB, log files, journal, and evidence (PRD H8).
func (h *Host) openInvestigation() error {
	if h.deps.Investigator != nil {
		h.inv = h.deps.Investigator
		return nil
	}
	node, _ := os.Hostname()
	eo := investigate.ExecOptions{
		Node: node, Evidence: h.ring, Limits: h.cfg.Investigation, Redactor: h.red, Clock: h.clk.Now,
	}
	if h.db != nil {
		eo.Queryable, eo.Retention = h.db, h.db.Retention
	}
	if h.cfg.HasCapability(config.CapLogs) {
		eo.HostLogPaths = h.cfg.Host.LogFiles
		if h.cfg.Host.Journal {
			eo.Journal = journalSource{dirs: h.journalDirs(), open: h.deps.OpenJournal}
		}
	}
	svc, err := investigate.NewService(investigate.Options{
		Role: investigate.RoleHost, State: h.head.snapshot, Local: investigate.NewExecutor(eo),
		Lookback: h.cfg.Lookback, Limits: h.cfg.Investigation, Audit: h.audit, SaveFinding: h.saveFinding,
		Clock: h.clk.Now, Redactor: h.red,
	})
	if err != nil {
		return fmt.Errorf("host: investigation: %w", err)
	}
	h.inv = svc
	return nil
}

func (h *Host) journalDirs() []string {
	if h.cfg.Host.JournalDir != "" {
		return []string{h.cfg.Host.JournalDir}
	}
	return DefaultJournalDirs
}

func (h *Host) audit(r investigate.AuditRecord) {
	h.log.Info("investigation", "tool", r.Tool, "outcome", r.Outcome, "requester", r.Requester, "query_hash", r.QueryHash, "duration_ms", r.DurationMs)
	if h.cl == nil || h.cfg.AirGap.Enabled {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.cl.Audit(ctx, r); err != nil && !errors.Is(err, client.ErrNotConnected) {
		h.log.Warn("investigation audit not sent", "err", err)
	}
}

func (h *Host) saveFinding(o findings.Observation) error {
	return h.do(func(tx *hostTx) error {
		_, err := h.tracker.AddQueryFinding(o, tx.finding)
		return err
	})
}

// journalSource reads the journal on demand for investigations with its own reader, retaining nothing.
type journalSource struct {
	dirs []string
	open func(journal.Options) (JournalReader, error)
}

func (j journalSource) Scan(ctx context.Context, req logql.SourceRequest, yield func(logql.Line) bool) error {
	r, err := j.open(journal.Options{Dirs: j.dirs, Since: req.Start})
	if err != nil {
		return err
	}
	defer r.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		e, ok := r.Next()
		if !ok {
			return nil
		}
		if e.Realtime.Before(req.Start) || e.Realtime.After(req.End) {
			continue
		}
		l := e.Labels()
		match := true
		for _, m := range req.Matchers {
			if !m.Matches(l[m.Name]) {
				match = false
				break
			}
		}
		if match && !yield(logql.Line{Labels: l, Time: e.Realtime, Text: e.Message()}) {
			return nil
		}
	}
}
