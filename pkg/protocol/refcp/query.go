package refcp

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type epoch struct {
	id         protocol.EpochID
	owner      protocol.WriterID
	open       bool
	closedAt   uint64
	openReason string
	prevEpoch  *protocol.EpochID
	prevHead   *uint64
	registered time.Time
	records    []*protocol.Record
	bySeq      map[uint64]*protocol.Record
	chain      map[uint64]protocol.Hash
	head       protocol.ChainPoint
	replayer   *protocol.Replayer
	pending    map[uint64]*protocol.Record
	watermark  uint64
}

func newEpoch(targetID string, id protocol.EpochID, owner protocol.WriterID) *epoch {
	g := protocol.Genesis(targetID, id, owner)
	return &epoch{
		id: id, owner: owner, open: true, bySeq: map[uint64]*protocol.Record{},
		chain: map[uint64]protocol.Hash{0: g}, head: protocol.ChainPoint{ChainHash: g},
		replayer: protocol.NewReplayer(targetID, id, owner), pending: map[uint64]*protocol.Record{},
	}
}

// AuditEntry is one audited event.
type AuditEntry struct {
	Time        time.Time
	Target      string
	Session     string
	Event       string
	Row         int
	Code        string
	Writer      protocol.WriterID
	Incarnation uint64
	Epoch       protocol.EpochID
	Seq         uint64
	Credential  string
	Alarm       bool
	Detail      string
}

// Notification sources.
const (
	SourceSummary = "summary"
	SourceRecord  = "record"
)

// Notification is one notification decision (SPEC 8.5).
type Notification struct {
	Target    string
	FindingID string
	DedupKey  string
	Severity  string
	EvalTime  uint64
	// Late marks a backlog notification decided from the lifecycle summary.
	Late bool
	// LateDelivered marks an evaluation time older than the late-delivery threshold on arrival.
	LateDelivered bool
	Source        string
	Epoch         protocol.EpochID
	Seq           uint64
	Time          time.Time
}

// FindingState is the committed lifecycle of one finding episode.
type FindingState struct {
	FindingID     string
	DedupKey      string
	State         string
	Transition    string
	Severity      string
	RuleID        string
	BundleVersion string
	FirstSeen     uint64
	LastSeen      uint64
	EvalTime      uint64
	Count         uint64
	Epoch         protocol.EpochID
	Seq           uint64
}

// Boundary is a reconstruction boundary: a checkpoint that did not match replayed state.
type Boundary struct {
	Epoch    protocol.EpochID
	Seq      uint64
	Expected protocol.Hash
	Got      protocol.Hash
}

// Stats counts record handling per target.
type Stats struct {
	Committed   int
	Duplicates  int
	Rejected    int
	Divergences int
}

// EpochView describes one epoch in registration order.
type EpochView struct {
	ID         protocol.EpochID
	Owner      protocol.WriterID
	Open       bool
	Head       protocol.ChainPoint
	ClosedAt   uint64
	OpenReason string
	PrevEpoch  *protocol.EpochID
	PrevHead   *uint64
	Watermark  uint64
	Pending    []uint64
	Registered time.Time
}

// EdgeChange is one committed edge operation.
type EdgeChange struct {
	Epoch     protocol.EpochID
	Seq       uint64
	Time      time.Time
	Op        protocol.OpKind
	From      string
	Type      string
	To        string
	Attrs     map[string]any
	PrevAttrs map[string]any
	// Coalesced marks a folded range operation; Span is its unavailable interior.
	Coalesced bool
	Span      protocol.Span
}

func (s *Server) epochLocked(targetID string, id protocol.EpochID) (*target, *epoch, error) {
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, nil, err
	}
	ep, ok := t.epochs[id]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnknownEpoch, id)
	}
	return t, ep, nil
}

// Epochs lists a target's epochs in registration order.
func (s *Server) Epochs(targetID string) ([]EpochView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	out := make([]EpochView, 0, len(t.order))
	for _, id := range t.order {
		ep := t.epochs[id]
		v := EpochView{
			ID: id, Owner: ep.owner, Open: ep.open, Head: ep.head, ClosedAt: ep.closedAt, OpenReason: ep.openReason,
			PrevEpoch: ep.prevEpoch, PrevHead: ep.prevHead, Watermark: ep.watermark, Registered: ep.registered,
		}
		for seq := range ep.pending {
			v.Pending = append(v.Pending, seq)
		}
		slices.Sort(v.Pending)
		out = append(out, v)
	}
	return out, nil
}

// Heads returns the committed head of every epoch.
func (s *Server) Heads(targetID string) (map[protocol.EpochID]protocol.ChainPoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	out := make(map[protocol.EpochID]protocol.ChainPoint, len(t.epochs))
	for id, ep := range t.epochs {
		out[id] = ep.head
	}
	return out, nil
}

// Records returns the committed records of an epoch in chain order. Callers must not mutate them.
func (s *Server) Records(targetID string, id protocol.EpochID) ([]*protocol.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ep, err := s.epochLocked(targetID, id)
	if err != nil {
		return nil, err
	}
	return slices.Clone(ep.records), nil
}

// StateAt reconstructs the state at seq; range interiors return protocol.ErrUnavailable.
func (s *Server) StateAt(targetID string, id protocol.EpochID, seq uint64) (*protocol.State, error) {
	s.mu.Lock()
	_, ep, err := s.epochLocked(targetID, id)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if seq == 0 || seq > ep.head.Seq {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %d (head %d)", ErrNotCommitted, seq, ep.head.Seq)
	}
	recs := slices.Clone(ep.records)
	s.mu.Unlock()
	return protocol.Reconstruct(recs, seq)
}

// StateHashAt returns the state hash at seq from the verified replay of the epoch.
func (s *Server) StateHashAt(targetID string, id protocol.EpochID, seq uint64) (protocol.Hash, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ep, err := s.epochLocked(targetID, id)
	if err != nil {
		return protocol.Hash{}, err
	}
	if seq == 0 || seq > ep.head.Seq {
		return protocol.Hash{}, fmt.Errorf("%w: %d (head %d)", ErrNotCommitted, seq, ep.head.Seq)
	}
	return ep.replayer.StateHashAt(seq)
}

// Findings returns the committed lifecycle of every finding of a target, ordered by finding ID.
func (s *Server) Findings(targetID string) ([]FindingState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	out := make([]FindingState, 0, len(t.findings))
	for _, f := range t.findings {
		out = append(out, *f)
	}
	slices.SortFunc(out, func(a, b FindingState) int {
		if a.FindingID < b.FindingID {
			return -1
		}
		if a.FindingID > b.FindingID {
			return 1
		}
		return 0
	})
	return out, nil
}

// Notifications returns the notification log of a target in decision order.
func (s *Server) Notifications(targetID string) ([]Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	return slices.Clone(t.notifications), nil
}

// Summaries returns every lifecycle summary received for a target.
func (s *Server) Summaries(targetID string) ([]protocol.SummaryParams, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	return slices.Clone(t.summaries), nil
}

// Audit returns the audit log, for one target or for all when targetID is empty.
func (s *Server) Audit(targetID string) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AuditEntry
	for _, e := range s.audit {
		if targetID == "" || e.Target == targetID {
			out = append(out, e)
		}
	}
	return out
}

// Boundaries returns the reconstruction boundaries of a target.
func (s *Server) Boundaries(targetID string) ([]Boundary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	return slices.Clone(t.boundaries), nil
}

// Unavailable returns the coalesced range interiors of an epoch.
func (s *Server) Unavailable(targetID string, id protocol.EpochID) ([]protocol.Span, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ep, err := s.epochLocked(targetID, id)
	if err != nil {
		return nil, err
	}
	return slices.Clone(ep.replayer.Unavailable), nil
}

// Stats returns record handling counters of a target.
func (s *Server) Stats(targetID string) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return Stats{}, err
	}
	return t.stats, nil
}

// HealthReports returns the agent.health payloads received for a target.
func (s *Server) HealthReports(targetID string) ([]json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	return slices.Clone(t.health), nil
}

// EdgeHistory returns committed changes of edges touching uid (optionally one edge type) with record time in [from, to].
func (s *Server) EdgeHistory(targetID, uid, edgeType string, from, to time.Time) ([]EdgeChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return nil, err
	}
	var out []EdgeChange
	for _, id := range t.order {
		for _, r := range t.epochs[id].records {
			ts := time.UnixMilli(int64(r.Time))
			if ts.Before(from) || ts.After(to) {
				continue
			}
			var ops []protocol.Op
			var span protocol.Span
			coalesced := false
			switch r.Type {
			case protocol.TypeDelta:
				ops = r.Delta.Ops
			case protocol.TypeRange:
				ops, coalesced = r.Range.Ops, r.Range.From < r.Range.To
				span = protocol.Span{From: r.Range.From, To: r.Range.To - 1}
			}
			for _, op := range ops {
				if op.Kind < protocol.OpEdgeAdd || op.Kind > protocol.OpEdgeReplace {
					continue
				}
				if op.UID != uid && op.To != uid {
					continue
				}
				if edgeType != "" && op.EdgeType != edgeType {
					continue
				}
				out = append(out, EdgeChange{
					Epoch: id, Seq: r.Seq, Time: ts, Op: op.Kind, From: op.UID, Type: op.EdgeType, To: op.To,
					Attrs: protocol.CloneFields(op.Attrs), PrevAttrs: protocol.CloneFields(op.PrevAttrs), Coalesced: coalesced, Span: span,
				})
			}
		}
	}
	return out, nil
}
