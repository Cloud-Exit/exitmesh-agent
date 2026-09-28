package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/nodemetrics"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/disk"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

type runtimeStatus struct {
	scopes              map[string]protocol.ScopeStatus
	lastCollect         time.Time
	lastGather          time.Time
	lastJournal         time.Time
	metrics             nodemetrics.Stats
	metricsAppendErrors int
	rejectedEndpoints   map[string]string
	disk                disk.Report
	logGaps             uint64
	journalEntries      uint64
	sessionID           string
	journalFileErrors   map[string]string
	exported            uint64
	exportFiles         int

	enrollError, bundleError, evalError, findingsError, metricsError string
	logsError, journalError, diskError, exportError                  string
}

// Health is the agent.health payload (PRD 8.1 host fields).
type Health struct {
	Role              string             `json:"role"`
	Agent             protocol.AgentInfo `json:"agent"`
	TargetID          string             `json:"target_id"`
	WriterID          string             `json:"writer_id"`
	Incarnation       uint64             `json:"incarnation"`
	Epoch             string             `json:"epoch,omitempty"`
	Head              uint64             `json:"head"`
	Capabilities      []string           `json:"capabilities"`
	Freshness         Freshness          `json:"freshness"`
	Spool             SpoolHealth        `json:"spool"`
	Disk              disk.Report        `json:"disk"`
	TSDB              *TSDBHealth        `json:"tsdb,omitempty"`
	Metrics           *MetricsHealth     `json:"metrics,omitempty"`
	Bundle            BundleHealth       `json:"bundle"`
	Rules             []RuleHealth       `json:"rules"`
	UnavailableScopes map[string]string  `json:"unavailable_scopes"`
	ScrapeTargets     []ScrapeHealth     `json:"scrape_targets,omitempty"`
	RejectedEndpoints map[string]string  `json:"rejected_endpoints,omitempty"`
	Logs              LogsHealth         `json:"logs"`
	EvidenceLimited   []string           `json:"evidence_limited_rules"`
	Identity          machineState       `json:"identity"`
	AirGap            bool               `json:"airgap"`
	Errors            map[string]string  `json:"errors,omitempty"`
}

// Freshness is the time of the last successful collection per source.
type Freshness struct {
	State   time.Time `json:"state,omitzero"`
	Metrics time.Time `json:"metrics,omitzero"`
	Journal time.Time `json:"journal,omitzero"`
}

// SpoolHealth reports spool use and the projected outage window.
type SpoolHealth struct {
	Bytes                  int64     `json:"bytes"`
	Capacity               int64     `json:"capacity"`
	Records                int       `json:"records"`
	InFlightBytes          int64     `json:"in_flight_bytes"`
	Oldest                 time.Time `json:"oldest,omitzero"`
	ProjectedWindowSeconds float64   `json:"projected_window_seconds"`
	RebaselineRequired     bool      `json:"rebaseline_required"`
}

// TSDBHealth reports the local TSDB.
type TSDBHealth struct {
	Series           uint64  `json:"series"`
	Bytes            int64   `json:"bytes"`
	RetentionSeconds float64 `json:"retention_seconds"`
	MaxBytes         int64   `json:"max_bytes"`
}

// MetricsHealth reports the last node metrics gather.
type MetricsHealth struct {
	Series           int      `json:"series"`
	DroppedSeries    int      `json:"dropped_series"`
	DroppedFamilies  []string `json:"dropped_families,omitempty"`
	FailedCollectors []string `json:"failed_collectors,omitempty"`
	AppendErrors     int      `json:"append_errors"`
}

// BundleHealth reports the active rule bundle.
type BundleHealth struct {
	Version     string            `json:"version,omitempty"`
	Unsupported map[string]string `json:"unsupported,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// RuleHealth is one rule state (PRD R9).
type RuleHealth struct {
	ID      string    `json:"id"`
	Version int       `json:"version"`
	Class   string    `json:"class"`
	State   string    `json:"state"`
	Reason  string    `json:"reason,omitempty"`
	Pending int       `json:"pending"`
	Firing  int       `json:"firing"`
	Last    time.Time `json:"last_eval,omitzero"`
}

// ScrapeHealth is one local metrics endpoint.
type ScrapeHealth struct {
	URL       string    `json:"url"`
	Health    string    `json:"health"`
	Reason    string    `json:"reason,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Last      time.Time `json:"last_scrape,omitzero"`
	Series    int       `json:"series"`
}

// LogsHealth reports log inputs.
type LogsHealth struct {
	Files          int               `json:"files"`
	Streams        int               `json:"streams"`
	Lines          uint64            `json:"lines"`
	Gaps           uint64            `json:"gaps"`
	Journal        bool              `json:"journal"`
	JournalEntries uint64            `json:"journal_entries"`
	JournalErrors  map[string]string `json:"journal_file_errors,omitempty"`
}

// Status is the admin status document: health plus the session.
type Status struct {
	Health
	Session SessionStatus `json:"session"`
}

// SessionStatus reports the writer session.
type SessionStatus struct {
	Connected      bool            `json:"connected"`
	SessionID      string          `json:"session_id,omitempty"`
	Registered     bool            `json:"registered"`
	Committed      uint64          `json:"committed"`
	BacklogRecords int             `json:"backlog_records"`
	BacklogBytes   int64           `json:"backlog_bytes"`
	LastError      string          `json:"last_error,omitempty"`
	LastErrorCode  string          `json:"last_error_code,omitempty"`
	Halted         string          `json:"halted,omitempty"`
	Compat         protocol.Compat `json:"compat"`
	Exported       uint64          `json:"exported_through,omitempty"`
}

func (h *Host) health() Health {
	id := h.sp.Identity()
	wid := h.sp.WriterID()
	out := Health{
		Role: config.RoleHost, Agent: h.agentInfo(), TargetID: id.TargetID, WriterID: wid.String(),
		Incarnation: h.sp.Incarnation(), Capabilities: h.cfg.Capabilities, AirGap: h.cfg.AirGap.Enabled,
		UnavailableScopes: map[string]string{}, EvidenceLimited: []string{}, Rules: []RuleHealth{},
	}
	if ep, ok := h.sp.Epoch(); ok {
		out.Epoch, out.Head = ep.ID.String(), ep.Chain.Head
	}
	u := h.sp.Usage()
	out.Spool = SpoolHealth{Bytes: u.Bytes, Capacity: u.Capacity, Records: u.Records, InFlightBytes: u.InFlightBytes,
		Oldest: u.Oldest, ProjectedWindowSeconds: u.ProjectedWindow.Seconds(), RebaselineRequired: u.RebaselineRequired}
	if h.db != nil {
		s := h.db.Stats()
		out.TSDB = &TSDBHealth{Series: s.Series, Bytes: s.Bytes, RetentionSeconds: s.Retention.Seconds(), MaxBytes: s.MaxBytes}
	}
	if h.eng != nil {
		for _, r := range h.eng.RuleStates() {
			out.Rules = append(out.Rules, RuleHealth{ID: r.RuleID, Version: r.Version, Class: r.Class, State: r.State,
				Reason: r.Reason, Pending: r.Pending, Firing: r.Firing, Last: r.LastEval})
		}
	}
	if h.ring != nil {
		out.EvidenceLimited = append(out.EvidenceLimited, h.ring.LimitedRules()...)
	}
	if h.scraper != nil {
		for _, t := range h.scraper.Status() {
			out.ScrapeTargets = append(out.ScrapeTargets, ScrapeHealth{URL: t.URL, Health: string(t.Health), Reason: t.Reason,
				LastError: h.red.String(t.LastError), Last: t.LastScrape, Series: t.Series})
		}
	}
	if h.files != nil {
		s := h.files.Stats()
		out.Logs.Files, out.Logs.Streams, out.Logs.Lines = s.Files, s.Streams, s.Lines
	}
	h.rules.mu.Lock()
	out.Bundle.Version, out.Bundle.Unsupported = h.rules.version, h.rules.unsupported
	h.rules.mu.Unlock()

	h.mu.Lock()
	defer h.mu.Unlock()
	st := &h.st
	out.Freshness = Freshness{State: st.lastCollect, Metrics: st.lastGather, Journal: st.lastJournal}
	out.Disk = st.disk
	if h.exporter != nil {
		out.Metrics = &MetricsHealth{Series: st.metrics.Series, DroppedSeries: st.metrics.DroppedSeries,
			DroppedFamilies: st.metrics.DroppedFamilies, FailedCollectors: st.metrics.FailedCollectors, AppendErrors: st.metricsAppendErrors}
	}
	for k, s := range st.scopes {
		if s.State == protocol.ScopeUnavailable || s.State == protocol.ScopePartial {
			out.UnavailableScopes[k] = s.Reason
		}
	}
	out.RejectedEndpoints = st.rejectedEndpoints
	out.Logs.Gaps, out.Logs.Journal, out.Logs.JournalEntries = st.logGaps, h.jr != nil, st.journalEntries
	out.Logs.JournalErrors = st.journalFileErrors
	out.Bundle.Error = st.bundleError
	out.Identity = h.machine
	errs := map[string]string{"enroll": st.enrollError, "bundle": st.bundleError, "evaluation": st.evalError, "findings": st.findingsError,
		"metrics": st.metricsError, "logs": st.logsError, "journal": st.journalError, "disk": st.diskError, "export": st.exportError}
	for k, v := range errs {
		if v != "" {
			if out.Errors == nil {
				out.Errors = map[string]string{}
			}
			out.Errors[k] = v
		}
	}
	return out
}

func (h *Host) status() Status {
	s := Status{Health: h.health()}
	cs := h.cl.Status()
	s.Session = SessionStatus{Connected: cs.Connected, SessionID: cs.SessionID, Registered: cs.Registered, Committed: cs.Head,
		BacklogRecords: cs.BacklogRecords, BacklogBytes: cs.BacklogBytes, LastError: h.red.String(cs.LastError),
		LastErrorCode: cs.LastErrorCode, Halted: cs.Halted, Compat: cs.Compat}
	if lc, ok := h.sp.LastCommitted(); ok {
		s.Session.Committed = lc.Seq
	}
	if cs.LastErrorCode == protocol.CodeIdentityConflict {
		s.Identity.Conflict = true
		if s.Identity.Reason == "" {
			s.Identity.Reason = "the control plane reported an identity conflict"
		}
	}
	h.mu.Lock()
	s.Session.Exported = h.st.exported
	h.mu.Unlock()
	return s
}

type hooks struct{ h *Host }

func (k hooks) CaptureReplay(tx client.CaptureTx) (protocol.SummaryParams, error) {
	e, err := k.h.checkpoint(tx)
	if err != nil {
		return protocol.SummaryParams{}, err
	}
	return protocol.SummaryParams{Entries: k.h.tracker.Summary(tx.Committed(), e.Seq)}, nil
}

func (k hooks) Rebaseline(tx client.CaptureTx) error {
	_, err := k.h.checkpoint(tx)
	return err
}

func (k hooks) BundleAvailable(p protocol.BundleAvailableParams) {
	if p.TargetType != protocol.TargetHost || k.h.runCtx == nil {
		return
	}
	k.h.fetchBundle(k.h.runCtx)
}

func (k hooks) Tools() []client.Tool {
	if k.h.inv == nil {
		return nil
	}
	return k.h.inv.Tools()
}

func (k hooks) Tool(ctx context.Context, name string, args json.RawMessage) (any, error) {
	return k.h.investigate(ctx, name, args)
}

func (k hooks) Health() any { return k.h.health() }

func (h *Host) checkpoint(tx client.CaptureTx) (*client.Entry, error) {
	iv := h.head.interval()
	h.head.mu.Lock()
	defer h.head.mu.Unlock()
	return client.AppendCheckpoint(tx, h.head.state, iv, h.cfg.Capabilities)
}

// ErrNoInvestigator is returned when this agent was started without investigation tools.
var ErrNoInvestigator = errors.New("host: no investigation service is configured on this agent")

func (h *Host) investigate(ctx context.Context, name string, args json.RawMessage) (any, error) {
	if h.inv == nil {
		return nil, ErrNoInvestigator
	}
	return h.inv.Call(ctx, name, args)
}

// Status implements admin.Backend.
func (h *Host) Status(context.Context) (any, error) { return h.status(), nil }

// Investigate implements admin.Backend (PRD A9 local investigation).
func (h *Host) Investigate(ctx context.Context, req admin.InvestigateRequest) (any, error) {
	return h.investigate(ctx, req.Tool, req.Args)
}

// Export implements admin.Backend; in the air-gap profile exported records are marked transmitted first.
func (h *Host) Export(_ context.Context, fromSeq uint64, w io.Writer) error {
	return writeExport(h.sp, fromSeq, w, h.cfg.AirGap.Enabled, h.clk.Now())
}

// Deenroll implements admin.Backend: revoke the credential over the active session, then stop writing.
func (h *Host) Deenroll(ctx context.Context, reason string) error {
	if h.cfg.AirGap.Enabled {
		return errors.New("de-enrollment needs a connection to ExitMesh; in the air-gap profile an administrator de-enrolls the host in ExitMesh")
	}
	if err := h.cl.Deenroll(ctx, reason); err != nil {
		if errors.Is(err, client.ErrNotConnected) {
			return errors.New("not connected to ExitMesh; de-enrollment needs an active session, retry once status shows connected")
		}
		return err
	}
	return nil
}

// Commit implements admin.Backend: apply an air-gap commit receipt.
func (h *Host) Commit(_ context.Context, r admin.CommitReceipt) error {
	if !h.cfg.AirGap.Enabled {
		return errors.New("commit receipts apply only in the air-gap profile")
	}
	epoch, err := protocol.ParseID(r.Epoch)
	if err != nil {
		return fmt.Errorf("receipt epoch: %w", err)
	}
	hash, err := protocol.ParseHash(r.ChainHash)
	if err != nil {
		return fmt.Errorf("receipt chain hash: %w", err)
	}
	if err := h.store.Commit(epoch, r.Seq, hash); err != nil {
		return err
	}
	h.pruneExports(epoch, r.Seq)
	return nil
}

func writeExport(sp *spool.Spool, fromSeq uint64, w io.Writer, mark bool, now time.Time) error {
	id := sp.Identity()
	ep, ok := sp.Epoch()
	if !ok {
		return errors.New("export: no epoch is open in this spool")
	}
	wid := sp.WriterID()
	lc, _ := sp.LastCommitted()
	ew, err := protocol.NewExportWriter(w, protocol.ExportHeader{
		TargetID: id.TargetID, WriterID: wid[:], Incarnation: sp.Incarnation(), Epoch: ep.ID[:],
		LastCommitted: lc.Seq, ExportedAt: uint64(now.UnixMilli()), AgentVersion: Version,
	})
	if err != nil {
		return err
	}
	_, err = eachPage(sp, fromSeq, mark, ew.Write)
	return err
}

// eachPage visits spooled records from seq on, optionally marking each page transmitted first.
func eachPage(sp *spool.Spool, from uint64, mark bool, fn func([]byte) error) (uint64, error) {
	var last uint64
	for {
		es := sp.Entries(from)
		if len(es) == 0 {
			return last, nil
		}
		if mark {
			seqs := make([]uint64, 0, len(es))
			for _, e := range es {
				if e.State == spool.NeverTransmitted {
					seqs = append(seqs, e.Seq)
				}
			}
			if len(seqs) > 0 {
				if err := sp.MarkTransmitted(seqs...); err != nil {
					return last, err
				}
			}
		}
		for _, e := range es {
			if err := fn(e.Bytes); err != nil {
				return last, err
			}
			last = e.Seq
		}
		from = last + 1
	}
}
