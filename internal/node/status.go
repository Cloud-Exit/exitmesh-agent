package node

import (
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/disk"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/scrape"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

// Status is a snapshot of a running agent.
type Status struct {
	Node          string
	AgentVersion  string
	BundleVersion string
	TargetBundle  string
	BundleError   string
	Warming       bool
	Coverage      map[string]string
	Rules         []engine.RuleState
	Queue         spool.QueueUsage
	Acked         uint64
	Dropped       string
	DeliveryError string
	OpenFindings  int
	Disk          disk.Report
	TSDB          tsdb.Stats
	Targets       []scrape.TargetStatus
	Logs          logs.Stats
	Evidence      evidence.Stats
}

// Status reports the agent's state; it is only meaningful while Run is active.
func (a *Agent) Status() Status {
	s := Status{
		Node: a.node, AgentVersion: a.deps.AgentVersion, BundleVersion: a.eng.BundleVersion(), Warming: a.warming(),
		Coverage: a.coverageReport(), Rules: a.eng.RuleStates(), Queue: a.queue.Usage(), Dropped: a.deliv.droppedSummary(),
		OpenFindings: a.tracker.OpenCount(), Evidence: a.ring.Stats(),
	}
	a.rules.mu.Lock()
	s.BundleError = a.rules.lastError
	a.rules.mu.Unlock()
	a.deliv.mu.Lock()
	s.TargetBundle, s.Acked, s.DeliveryError = a.deliv.target, a.deliv.acked, a.deliv.lastError
	a.deliv.mu.Unlock()
	if a.budget != nil {
		s.Disk = a.budget.Last()
	}
	if a.db != nil {
		s.TSDB = a.db.Stats()
	}
	if a.scraper != nil {
		s.Targets = a.scraper.Status()
	}
	if a.tailer != nil {
		s.Logs = a.tailer.Stats()
	}
	return s
}
