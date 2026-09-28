package refcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

type outMsg struct {
	method     string
	params     any
	ack        bool
	closeAfter bool
}

type session struct {
	id   string
	srv  *Server
	conn *tunnel.Conn
	cred *credential

	// Guarded by srv.mu.
	target      *target
	writer      protocol.WriterID
	incarnation uint64
	epoch       protocol.EpochID
	superseded  bool
	closed      bool

	qmu    sync.Mutex
	queue  []outMsg
	signal chan struct{}

	mcpMu   sync.Mutex
	mcpDone bool
}

func newSession(s *Server, conn *tunnel.Conn, cred *credential) *session {
	return &session{id: "s-" + randHex(8), srv: s, conn: conn, cred: cred, signal: make(chan struct{}, 1)}
}

func (ss *session) enqueue(m outMsg) {
	ss.qmu.Lock()
	ss.queue = append(ss.queue, m)
	ss.qmu.Unlock()
	select {
	case ss.signal <- struct{}{}:
	default:
	}
}

func (ss *session) sendLoop() {
	for {
		ss.qmu.Lock()
		q := ss.queue
		ss.queue = nil
		ss.qmu.Unlock()
		for _, m := range q {
			if m.ack {
				ss.srv.mu.Lock()
				d := ss.srv.faults.delayAcks
				ss.srv.mu.Unlock()
				if d > 0 {
					select {
					case <-time.After(d):
					case <-ss.conn.Done():
						return
					}
				}
			}
			if m.method != "" {
				if err := ss.conn.Notify(context.Background(), m.method, m.params); err != nil {
					return
				}
			}
			if m.closeAfter {
				_ = ss.conn.Close()
				return
			}
		}
		select {
		case <-ss.signal:
		case <-ss.conn.Done():
			return
		}
	}
}

func (ss *session) initMCP(ctx context.Context) error {
	ss.mcpMu.Lock()
	defer ss.mcpMu.Unlock()
	if ss.mcpDone {
		return nil
	}
	var res client.InitializeResult
	p := map[string]any{"protocolVersion": client.MCPProtocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "refcp", "version": "1"}}
	if err := ss.conn.Call(ctx, protocol.MethodInitialize, p, &res); err != nil {
		return fmt.Errorf("refcp: mcp initialize: %w", err)
	}
	if err := ss.conn.Notify(ctx, "notifications/initialized", nil); err != nil {
		return err
	}
	ss.mcpDone = true
	return nil
}

func rpcErr(code string, msg string) *protocol.RPCError {
	c := protocol.RPCForbidden
	switch code {
	case protocol.CodeUnauthorized:
		c = protocol.RPCUnauthorized
	case protocol.CodeInvalidHello:
		c = protocol.RPCInvalidRequest
	}
	return &protocol.RPCError{Code: c, Message: msg, Data: &protocol.RPCErrorData{Code: code}}
}

func (ss *session) handle(ctx context.Context, req *client.Request) (any, error) {
	switch req.Method {
	case protocol.MethodHello:
		var p protocol.HelloParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &protocol.RPCError{Code: protocol.RPCInvalidParams, Message: err.Error(), Data: &protocol.RPCErrorData{Code: protocol.CodeInvalidHello}}
		}
		return ss.hello(&p)
	case protocol.MethodSummary:
		var p protocol.SummaryParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &protocol.RPCError{Code: protocol.RPCInvalidParams, Message: err.Error()}
		}
		return ss.summary(&p)
	case protocol.MethodBundleFetch:
		var p protocol.BundleFetchParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &protocol.RPCError{Code: protocol.RPCInvalidParams, Message: err.Error()}
		}
		return ss.bundleFetch(&p)
	case protocol.MethodDeenroll:
		var p protocol.DeenrollParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, &protocol.RPCError{Code: protocol.RPCInvalidParams, Message: err.Error()}
			}
		}
		return ss.deenroll(&p)
	case protocol.MethodHealth:
		ss.srv.mu.Lock()
		if t := ss.attachedLocked(); t != nil {
			t.health = append(t.health, append(json.RawMessage(nil), req.Params...))
		}
		ss.srv.mu.Unlock()
		return nil, nil
	case protocol.MethodAudit:
		ss.srv.mu.Lock()
		if t := ss.attachedLocked(); t != nil {
			ss.srv.auditLocked(AuditEntry{Target: t.id, Session: ss.id, Event: "investigation", Detail: string(req.Params)})
		}
		ss.srv.mu.Unlock()
		return nil, nil
	}
	if req.Notification {
		return nil, nil
	}
	return nil, &protocol.RPCError{Code: protocol.RPCMethodNotFound, Message: "method not found: " + req.Method}
}

func (ss *session) attachedLocked() *target {
	if ss.target == nil || ss.superseded || ss.closed {
		return nil
	}
	return ss.target
}

func (t *target) ownership(s *Server) *protocol.OwnershipState {
	st := &protocol.OwnershipState{
		TargetType: t.typ, Revoked: t.deenrolled, OpenEpoch: t.open, Epochs: map[protocol.EpochID]*protocol.EpochInfo{},
		Retired: t.retired, HighestIncarnation: t.highest, EnrolledMachineID: t.machineID, Conflict: t.conflict,
		PendingBinding: t.pendingBinding,
		ChainHashAt: func(e protocol.EpochID, seq uint64) (protocol.Hash, bool) {
			ep, ok := t.epochs[e]
			if !ok {
				return protocol.Hash{}, false
			}
			h, ok := ep.chain[seq]
			return h, ok
		},
	}
	for id, ep := range t.epochs {
		st.Epochs[id] = &protocol.EpochInfo{ID: id, Owner: ep.owner, Open: ep.open, Head: ep.head, ClosedAt: ep.closedAt}
	}
	if a := t.active; a != nil && !a.closed {
		st.Active = &protocol.ActiveSession{SessionID: a.id, Writer: a.writer, Incarnation: a.incarnation}
	}
	return st
}

func (ss *session) hello(h *protocol.HelloParams) (any, error) {
	s := ss.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := AuditEntry{Target: h.TargetID, Session: ss.id, Event: "hello", Writer: h.WriterID, Incarnation: h.Incarnation, Epoch: h.Epoch, Credential: ss.cred.id}
	if code := s.faults.rejectHello; code != "" {
		s.faults.rejectHello = ""
		entry.Code, entry.Detail = code, "injected"
		s.auditLocked(entry)
		return nil, rpcErr(code, "injected rejection")
	}
	if ss.target != nil {
		entry.Code = protocol.CodeInvalidHello
		s.auditLocked(entry)
		return nil, rpcErr(protocol.CodeInvalidHello, "session already attached")
	}
	t := s.targets[h.TargetID]
	valid := t != nil && !ss.cred.revoked && ss.cred.target == h.TargetID && ss.cred.writer == h.WriterID
	if t == nil {
		entry.Code, entry.Row = protocol.CodeUnauthorized, 1
		s.auditLocked(entry)
		return nil, rpcErr(protocol.CodeUnauthorized, "unknown target")
	}
	if h.Agent.Protocol != protocol.Version {
		entry.Code = protocol.CodeUnsupportedProtocol
		s.auditLocked(entry)
		return nil, rpcErr(protocol.CodeUnsupportedProtocol, fmt.Sprintf("protocol %d not supported", h.Agent.Protocol))
	}
	d := protocol.Decide(t.ownership(s), h, valid)
	entry.Row, entry.Code, entry.Alarm = d.Row, d.Code, d.Alarm
	if d.SetConflict {
		t.conflict = true
	}
	if !d.Accept {
		s.auditLocked(entry)
		return nil, rpcErr(d.Code, fmt.Sprintf("hello rejected by ownership row %d", d.Row))
	}
	if d.CloseEpoch != nil {
		s.closeEpochLocked(t, *d.CloseEpoch)
	}
	if d.RetireWriter != nil {
		t.retired[*d.RetireWriter] = true
		s.auditLocked(AuditEntry{Target: t.id, Event: "writer_retired", Writer: *d.RetireWriter})
	}
	if d.ClearBinding {
		t.pendingBinding = false
	}
	if d.OpenEpoch {
		s.openEpochLocked(t, h)
	}
	if d.Supersede && t.active != nil && t.active != ss {
		old := t.active
		old.superseded = true
		old.enqueue(outMsg{method: protocol.MethodSuperseded, params: protocol.SupersededParams{SessionID: old.id}})
		s.auditLocked(AuditEntry{Target: t.id, Session: old.id, Event: "session_superseded", Writer: old.writer, Incarnation: old.incarnation})
	}
	if h.Incarnation > t.highest[h.WriterID] {
		t.highest[h.WriterID] = h.Incarnation
	}
	t.active = ss
	ss.target, ss.writer, ss.incarnation, ss.epoch = t, h.WriterID, h.Incarnation, h.Epoch
	entry.Detail = d.Outcome
	s.auditLocked(entry)
	ep := t.epochs[h.Epoch]
	return protocol.HelloResult{
		Decision: d.Outcome, SessionID: ss.id, Epoch: h.Epoch, Head: ep.head,
		WindowBytes: s.opts.WindowBytes, MaxFrameBytes: s.opts.MaxFrameBytes, Compat: t.compat,
	}, nil
}

func (s *Server) openEpochLocked(t *target, h *protocol.HelloParams) {
	ep := newEpoch(t.id, h.Epoch, h.WriterID)
	ep.registered = s.now()
	if h.EpochOpen != nil {
		ep.openReason = h.EpochOpen.Reason
		ep.prevEpoch, ep.prevHead = h.EpochOpen.PrevEpoch, h.EpochOpen.PrevHead
	}
	t.epochs[h.Epoch] = ep
	t.order = append(t.order, h.Epoch)
	id := h.Epoch
	t.open = &id
	s.auditLocked(AuditEntry{Target: t.id, Event: "epoch_opened", Writer: h.WriterID, Epoch: h.Epoch, Detail: ep.openReason})
}

func (s *Server) closeEpochLocked(t *target, id protocol.EpochID) {
	ep := t.epochs[id]
	if ep == nil || !ep.open {
		return
	}
	ep.open = false
	ep.closedAt = ep.head.Seq
	ep.pending = map[uint64]*protocol.Record{}
	if t.open != nil && *t.open == id {
		t.open = nil
	}
	s.auditLocked(AuditEntry{Target: t.id, Event: "epoch_closed", Epoch: id, Seq: ep.head.Seq})
}

func (ss *session) summary(p *protocol.SummaryParams) (any, error) {
	s := ss.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	t := ss.attachedLocked()
	if t == nil || p.Epoch != ss.epoch {
		return nil, &protocol.RPCError{Code: protocol.RPCInvalidRequest, Message: "no accepted session for this epoch"}
	}
	ep := t.epochs[p.Epoch]
	if p.Watermark > ep.watermark {
		ep.watermark = p.Watermark
	}
	t.summaries = append(t.summaries, *p)
	for _, e := range p.Entries {
		if e.State == protocol.LifecycleResolved {
			continue
		}
		s.notifyLocked(t, Notification{
			FindingID: e.FindingID, DedupKey: e.DedupKey, EvalTime: e.EvalTime, Late: true,
			Source: SourceSummary, Epoch: p.Epoch, Seq: p.Watermark, Severity: e.Severity,
		})
	}
	return struct{}{}, nil
}

func (ss *session) bundleFetch(p *protocol.BundleFetchParams) (any, error) {
	s := ss.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	t := ss.attachedLocked()
	if t == nil {
		return nil, &protocol.RPCError{Code: protocol.RPCInvalidRequest, Message: "no accepted session"}
	}
	if p.TargetType != t.typ {
		return nil, &protocol.RPCError{Code: protocol.RPCInvalidParams, Message: "target type mismatch"}
	}
	b := s.bundles[t.typ]
	if b == nil {
		return nil, &protocol.RPCError{Code: protocol.RPCInvalidParams, Message: "no bundle published for " + t.typ}
	}
	if p.Have == b.version {
		return protocol.BundleFetchResult{Version: b.version}, nil
	}
	return protocol.BundleFetchResult{Version: b.version, Bundle: b.archive, Signature: b.signature, KeyManifest: b.keyManifest, KeyManifestChain: b.keyManifestChain}, nil
}

func (ss *session) deenroll(p *protocol.DeenrollParams) (any, error) {
	s := ss.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	t := ss.attachedLocked()
	if t == nil {
		return nil, &protocol.RPCError{Code: protocol.RPCInvalidRequest, Message: "no accepted session"}
	}
	s.deenrollLocked(t, "writer: "+p.Reason)
	return struct{}{}, nil
}

func rejectCode(err error) string {
	switch c := protocol.CodeOf(err); c {
	case protocol.ErrInvalidChain.Code, protocol.ErrInvalidOp.Code, protocol.ErrUnsupportedField.Code, protocol.ErrInvalidStateHash.Code:
		return c
	}
	return protocol.ErrUnsupportedField.Code
}

func (ss *session) reject(t *target, seq uint64, code, msg string) {
	s := ss.srv
	t.stats.Rejected++
	alarm := code == protocol.CodeDivergence
	if alarm {
		t.stats.Divergences++
	}
	s.auditLocked(AuditEntry{Target: t.id, Session: ss.id, Event: "record_rejected", Writer: ss.writer, Incarnation: ss.incarnation, Epoch: ss.epoch, Seq: seq, Code: code, Alarm: alarm, Detail: msg})
	ss.enqueue(outMsg{method: protocol.MethodReject, params: protocol.RejectParams{Epoch: ss.epoch, Seq: seq, Code: code, Message: msg}})
}

func (ss *session) onFrame(_ context.Context, frame []byte) {
	s := ss.srv
	recs, derr := protocol.DecodeBatchFrame(frame)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss.target == nil || ss.superseded || ss.closed {
		e := AuditEntry{Session: ss.id, Event: "frame_rejected", Writer: ss.writer, Incarnation: ss.incarnation, Epoch: ss.epoch, Detail: "no attached session"}
		if ss.target != nil {
			e.Target = ss.target.id
		}
		s.auditLocked(e)
		return
	}
	t := ss.target
	if derr != nil {
		ss.reject(t, 0, rejectCode(derr), derr.Error())
		return
	}
	ep := t.epochs[ss.epoch]
	before := ep.head.Seq
	acked := false
	disconnect := false
	for _, b := range recs {
		ok, dup, cut := ss.ingest(t, ep, b)
		acked = acked || dup
		disconnect = disconnect || cut
		if !ok || disconnect {
			break
		}
	}
	if disconnect {
		ss.enqueue(outMsg{closeAfter: true})
		return
	}
	if ep.head.Seq == before && !acked {
		return
	}
	if s.faults.dropAcks > 0 {
		s.faults.dropAcks--
		return
	}
	ss.enqueue(outMsg{method: protocol.MethodAck, params: protocol.AckParams{Epoch: ep.id, Seq: ep.head.Seq, ChainHash: ep.head.ChainHash}, ack: true})
}

// ingest handles one record: ok is false when processing of the frame must stop.
func (ss *session) ingest(t *target, ep *epoch, b []byte) (ok, dup, disconnect bool) {
	s := ss.srv
	r, err := protocol.Decode(b)
	if err != nil {
		ss.reject(t, 0, rejectCode(err), err.Error())
		return false, false, false
	}
	if code := s.faults.rejectNext; code != "" {
		s.faults.rejectNext = ""
		ss.reject(t, r.Seq, code, "injected rejection")
		return false, false, false
	}
	if r.TargetID != t.id || r.Epoch != ep.id {
		ss.reject(t, r.Seq, protocol.ErrInvalidChain.Code, "record outside the session epoch")
		return false, false, false
	}
	if prev, found := ep.bySeq[r.Seq]; found {
		if prev.Hash() == r.Hash() {
			t.stats.Duplicates++
			return true, true, false
		}
		ss.reject(t, r.Seq, protocol.CodeDivergence, "record id already committed with a different hash")
		return false, false, false
	}
	if r.Seq <= ep.head.Seq {
		ss.reject(t, r.Seq, protocol.CodeDivergence, "record id inside a committed range")
		return false, false, false
	}
	if p, found := ep.pending[r.Seq]; found {
		if p.Hash() != r.Hash() {
			ss.reject(t, r.Seq, protocol.CodeDivergence, "record id already received with a different hash")
			return false, false, false
		}
		if r.Parent != ep.head.Seq {
			t.stats.Duplicates++
			return true, true, false
		}
	}
	if r.Parent != ep.head.Seq {
		if r.Type == protocol.TypeCheckpoint && r.Checkpoint.Reason == protocol.ReasonReplayAnchor {
			ep.pending[r.Seq] = r
			return true, false, false
		}
		ss.reject(t, r.Seq, protocol.ErrInvalidChain.Code, fmt.Sprintf("record %d has parent %d, committed head is %d", r.Seq, r.Parent, ep.head.Seq))
		return false, false, false
	}
	if err := s.commitLocked(t, ep, r); err != nil {
		ss.reject(t, r.Seq, rejectCode(err), err.Error())
		return false, false, false
	}
	delete(ep.pending, r.Seq)
	disconnect = s.countCommit()
	for {
		p, found := ep.pending[ep.head.Seq+1]
		if !found {
			break
		}
		delete(ep.pending, p.Seq)
		if err := s.commitLocked(t, ep, p); err != nil {
			ss.reject(t, p.Seq, rejectCode(err), err.Error())
			return false, false, disconnect
		}
		disconnect = s.countCommit() || disconnect
	}
	return true, false, disconnect
}

func (s *Server) countCommit() bool {
	if s.faults.disconnectAfter <= 0 {
		return false
	}
	s.faults.disconnectAfter--
	return s.faults.disconnectAfter == 0
}

func (s *Server) commitLocked(t *target, ep *epoch, r *protocol.Record) error {
	nb := len(ep.replayer.Boundaries)
	h, err := ep.replayer.Apply(r)
	if err != nil {
		return err
	}
	ep.records = append(ep.records, r)
	ep.bySeq[r.Seq] = r
	ep.chain[r.Seq] = h
	ep.head = protocol.ChainPoint{Seq: r.Seq, ChainHash: h}
	t.stats.Committed++
	for _, b := range ep.replayer.Boundaries[nb:] {
		t.boundaries = append(t.boundaries, Boundary{Epoch: ep.id, Seq: b.Seq, Expected: b.Expected, Got: b.Got})
		s.auditLocked(AuditEntry{Target: t.id, Event: "reconstruction_boundary", Epoch: ep.id, Seq: b.Seq, Alarm: true})
	}
	switch r.Type {
	case protocol.TypeFinding:
		s.findingLocked(t, ep, r.Seq, r.Finding)
	case protocol.TypeRange:
		for i := range r.Range.Findings {
			f := &r.Range.Findings[i]
			s.findingLocked(t, ep, f.Seq, &f.Finding)
		}
	}
	return nil
}

func lifecycle(tr protocol.Transition) string {
	switch tr {
	case protocol.TransitionResolved:
		return protocol.LifecycleResolved
	case protocol.TransitionStale:
		return protocol.LifecycleStale
	}
	return protocol.LifecycleFiring
}

func (s *Server) findingLocked(t *target, ep *epoch, seq uint64, f *protocol.Finding) {
	fs := t.findings[f.ID]
	if fs == nil {
		fs = &FindingState{FindingID: f.ID, DedupKey: f.DedupKey, FirstSeen: f.FirstSeen}
		t.findings[f.ID] = fs
	}
	fs.State, fs.Transition = lifecycle(f.Transition), f.Transition.String()
	fs.EvalTime, fs.LastSeen, fs.Count = f.EvalTime, f.LastSeen, f.Count
	fs.Severity, fs.Epoch, fs.Seq = f.Severity.String(), ep.id, seq
	fs.RuleID, fs.BundleVersion = f.Provenance.RuleID, f.Provenance.BundleVersion
	if seq <= ep.watermark || f.Transition != protocol.TransitionFiring {
		return
	}
	s.notifyLocked(t, Notification{
		FindingID: f.ID, DedupKey: f.DedupKey, EvalTime: f.EvalTime, Source: SourceRecord,
		Epoch: ep.id, Seq: seq, Severity: f.Severity.String(),
	})
}

func (s *Server) notifyLocked(t *target, n Notification) {
	if t.notified[n.FindingID] {
		return
	}
	t.notified[n.FindingID] = true
	now := s.now()
	n.Target, n.Time = t.id, now
	n.LateDelivered = now.Sub(time.UnixMilli(int64(n.EvalTime))) > s.opts.LateThreshold
	t.notifications = append(t.notifications, n)
}

func (s *Server) auditLocked(e AuditEntry) {
	e.Time = s.now()
	s.audit = append(s.audit, e)
}
