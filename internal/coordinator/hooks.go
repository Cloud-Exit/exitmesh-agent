package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// hooks connects the writer session to the chain head, findings, bundles, investigation, and health.
type hooks struct{ c *Coordinator }

func (h hooks) noteCheckpoint(e *client.Entry) {
	now := h.c.now()
	h.c.statMu.Lock()
	h.c.stats.LastCheckpoint = seqTime{Seq: e.Seq, Time: now}
	h.c.stats.DeltasSinceAnchor, h.c.stats.LastAnchor = 0, now
	h.c.statMu.Unlock()
}

// CaptureReplay appends the replay anchor and returns the lifecycle summary at the same sequence (SPEC 8.4 step 3).
func (h hooks) CaptureReplay(tx client.CaptureTx) (protocol.SummaryParams, error) {
	c := h.c
	if c.rebaselineWanted() {
		c.log.Warn("spool exceeds capacity after full coalescing; rebaselining at the committed head", "head", tx.Committed())
		return protocol.SummaryParams{}, &client.DivergenceError{Head: tx.Committed(), Reason: "spool capacity exceeded after full coalescing"}
	}
	if c.headState() == nil {
		return protocol.SummaryParams{}, errNotReady
	}
	e, err := client.AppendCheckpoint(tx, c.headState(), c.interval(), c.caps)
	if err != nil {
		return protocol.SummaryParams{}, err
	}
	h.noteCheckpoint(e)
	entries := append(c.fnd.Summary(tx.Committed(), e.Seq), c.nfi.Summary(tx.Committed(), e.Seq)...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].FindingID < entries[j].FindingID })
	return protocol.SummaryParams{Epoch: tx.Epoch().ID, Watermark: e.Seq, Head: tx.Committed(), Entries: entries}, nil
}

// Rebaseline appends the full checkpoint that opens an epoch.
func (h hooks) Rebaseline(tx client.CaptureTx) error {
	st := h.c.headState()
	if st == nil {
		return errNotReady
	}
	e, err := client.AppendCheckpoint(tx, st, h.c.interval(), h.c.caps)
	if err == nil {
		h.noteCheckpoint(e)
	}
	return err
}

func (h hooks) BundleAvailable(p protocol.BundleAvailableParams) {
	if protocolBundleAvailable(p) {
		h.c.log.Info("bundle available", "version", p.Version)
		h.c.bundles.want()
	}
}

func (h hooks) Tools() []client.Tool { return h.c.inv.Tools() }

func (h hooks) Tool(ctx context.Context, name string, args json.RawMessage) (any, error) {
	return h.c.inv.Call(ctx, name, args)
}

func (h hooks) Health() any { return h.c.health() }

func (c *Coordinator) auditInvestigation(r investigate.AuditRecord) {
	c.log.Info("investigation", "tool", r.Tool, "requester", r.Requester, "outcome", r.Outcome, "duration_ms", r.DurationMs)
	if c.airgap {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.cl.Audit(ctx, r); err != nil && !errors.Is(err, client.ErrNotConnected) {
		c.log.Warn("investigation audit", "err", err)
	}
}

func (c *Coordinator) saveQueryFinding(o findings.Observation) error {
	return c.do(func(t *txn) error {
		_, err := c.fnd.AddQueryFinding(o, t.emitFinding)
		return err
	})
}

// Health is the agent health record (PRD 8.1).
type Health struct {
	Role        string            `json:"role"`
	Version     string            `json:"version"`
	Time        time.Time         `json:"time"`
	TargetID    string            `json:"target_id"`
	WriterID    string            `json:"writer_id"`
	Incarnation uint64            `json:"incarnation"`
	AirGap      bool              `json:"airgap"`
	Session     sessionHealth     `json:"session"`
	Spool       spoolHealth       `json:"spool"`
	Bundle      bundleView        `json:"bundle"`
	Rules       []ruleHealth      `json:"rules"`
	Nodes       []NodeStatus      `json:"nodes"`
	Placement   placementReport   `json:"storage_placement"`
	Chain       chainHealth       `json:"chain"`
	Coverage    []scopeHealth     `json:"coverage"`
	Unsupported []string          `json:"unsupported_resources,omitempty"`
	Security    securityHealth    `json:"security"`
	Findings    findingsHealth    `json:"findings"`
	Errors      map[string]string `json:"errors,omitempty"`
}

type sessionHealth struct {
	Connected      bool   `json:"connected"`
	Epoch          string `json:"epoch"`
	Registered     bool   `json:"registered"`
	CommittedHead  uint64 `json:"committed_head"`
	Watermark      uint64 `json:"watermark"`
	BacklogRecords int    `json:"backlog_records"`
	BacklogBytes   int64  `json:"backlog_bytes"`
	Rebaselines    int    `json:"rebaselines"`
	LastError      string `json:"last_error,omitempty"`
	LastErrorCode  string `json:"last_error_code,omitempty"`
	Halted         string `json:"halted,omitempty"`
	Compat         string `json:"compat,omitempty"`
}

type spoolHealth struct {
	Bytes                  int64     `json:"bytes"`
	DiskBytes              int64     `json:"disk_bytes"`
	Capacity               int64     `json:"capacity"`
	UsageRatio             float64   `json:"usage_ratio"`
	Records                int       `json:"records"`
	InFlightBytes          int64     `json:"inflight_bytes"`
	WindowBytes            int64     `json:"window_bytes"`
	Oldest                 time.Time `json:"oldest,omitempty"`
	AppendRate             float64   `json:"append_bytes_per_second"`
	ProjectedWindowSeconds float64   `json:"projected_window_seconds"`
	Unbounded              bool      `json:"projected_window_unbounded"`
	Pressure               bool      `json:"pressure"`
	RebaselineRequired     bool      `json:"rebaseline_required"`
	ReliefError            string    `json:"relief_error,omitempty"`
}

type ruleHealth struct {
	ID       string    `json:"id"`
	Version  int       `json:"version"`
	Class    string    `json:"class"`
	Scope    string    `json:"scope"`
	State    string    `json:"state"`
	Reason   string    `json:"reason,omitempty"`
	LastEval time.Time `json:"last_eval,omitempty"`
	Pending  int       `json:"pending"`
	Firing   int       `json:"firing"`
}

type chainHealth struct {
	LastCheckpoint    seqTime    `json:"last_checkpoint"`
	LastDelta         seqTime    `json:"last_delta"`
	LastFinding       seqTime    `json:"last_finding"`
	Head              uint64     `json:"head"`
	DeltasSinceAnchor int        `json:"deltas_since_anchor"`
	Boundaries        []boundary `json:"reconstruction_boundaries,omitempty"`
	Resyncing         bool       `json:"resyncing"`
}

type scopeHealth struct {
	Key    string `json:"key"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type securityHealth struct {
	ImpersonationRejected int                  `json:"impersonation_rejected"`
	Recent                []nodeapi.AuditEvent `json:"recent,omitempty"`
}

type findingsHealth struct {
	Open int `json:"open"`
}

func scopeState(s protocol.ScopeState) string {
	switch s {
	case protocol.ScopePartial:
		return "partial"
	case protocol.ScopeUnavailable:
		return "unavailable"
	}
	return "complete"
}

func (c *Coordinator) health() Health {
	h := Health{Role: "coordinator", Version: Version, Time: c.now(), TargetID: c.targetID, WriterID: c.sp.WriterID().String(),
		Incarnation: c.sp.Incarnation(), AirGap: c.airgap}
	st := c.cl.Status()
	h.Session = sessionHealth{Connected: st.Connected, Epoch: st.Epoch.String(), Registered: st.Registered, CommittedHead: st.Head,
		Watermark: st.Watermark, BacklogRecords: st.BacklogRecords, BacklogBytes: st.BacklogBytes, Rebaselines: st.Rebaselines,
		LastError: st.LastError, LastErrorCode: st.LastErrorCode, Halted: st.Halted, Compat: st.Compat.Status}
	u := c.sp.Usage()
	h.Spool = spoolHealth{Bytes: u.Bytes, DiskBytes: u.DiskBytes, Capacity: u.Capacity, Records: u.Records, InFlightBytes: u.InFlightBytes,
		WindowBytes: u.WindowBytes, Oldest: u.Oldest, AppendRate: u.AppendRate, RebaselineRequired: u.RebaselineRequired}
	if u.Capacity > 0 {
		h.Spool.UsageRatio = float64(u.Bytes) / float64(u.Capacity)
	}
	if u.ProjectedWindow == time.Duration(math.MaxInt64) {
		h.Spool.Unbounded = true
	} else {
		h.Spool.ProjectedWindowSeconds = u.ProjectedWindow.Seconds()
	}
	if u.ReliefError != nil {
		h.Spool.ReliefError = u.ReliefError.Error()
	}
	c.evMu.Lock()
	h.Spool.Pressure = c.pressure
	c.evMu.Unlock()
	h.Bundle = c.convergence()
	for _, r := range c.eng.RuleStates() {
		h.Rules = append(h.Rules, ruleHealth{ID: r.RuleID, Version: r.Version, Class: r.Class, Scope: r.Scope, State: r.State, Reason: r.Reason,
			LastEval: r.LastEval, Pending: r.Pending, Firing: r.Firing})
	}
	h.Nodes = c.nodes.list()
	if ep, ok := c.sp.Epoch(); ok {
		h.Chain.Head = ep.Chain.Head
	}
	if c.col != nil {
		cov := c.col.Coverage()
		for _, s := range cov.Scopes {
			h.Coverage = append(h.Coverage, scopeHealth{Key: s.Key, State: scopeState(s.State), Reason: s.Reason})
		}
		h.Unsupported = cov.Unsupported
	}
	c.sinkMu.Lock()
	h.Chain.Resyncing = c.observed != nil
	c.sinkMu.Unlock()
	h.Findings.Open = c.fnd.OpenCount()
	c.statMu.Lock()
	h.Placement = c.place
	h.Chain.LastCheckpoint, h.Chain.LastDelta, h.Chain.LastFinding = c.stats.LastCheckpoint, c.stats.LastDelta, c.stats.LastFinding
	h.Chain.DeltasSinceAnchor = c.stats.DeltasSinceAnchor
	h.Chain.Boundaries = append([]boundary(nil), c.stats.Boundaries...)
	h.Security = securityHealth{ImpersonationRejected: c.auditN, Recent: append([]nodeapi.AuditEvent(nil), c.audits...)}
	if len(c.lastErrs) > 0 {
		h.Errors = map[string]string{}
		for k, v := range c.lastErrs {
			h.Errors[k] = v
		}
	}
	c.statMu.Unlock()
	return h
}
