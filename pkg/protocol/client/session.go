package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type session struct {
	c      *Client
	conn   Conn
	ctx    context.Context
	cancel context.CancelCauseFunc
	wake   chan struct{}

	epoch    protocol.EpochID
	window   int64
	maxFrame int64
	anchor   uint64
	cursor   uint64
	limiter  limiter

	mu            sync.Mutex
	inflight      map[uint64]int64
	inflightBytes int64
	acked         uint64
}

func newSession(parent context.Context, c *Client, conn Conn) *session {
	ctx, cancel := context.WithCancelCause(parent)
	s := &session{
		c: c, conn: conn, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1),
		inflight: map[uint64]int64{}, limiter: limiter{rate: float64(c.opts.ReplayBytesPerSecond)},
	}
	go func() {
		select {
		case <-conn.Done():
			cancel(ErrDisconnected)
		case <-ctx.Done():
		}
	}()
	return s
}

func (s *session) close() { s.cancel(context.Canceled) }

func (s *session) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *session) call(method string, params, result any) error {
	ctx, cancel := context.WithTimeout(s.ctx, s.c.opts.CallTimeout)
	defer cancel()
	err := s.conn.Call(ctx, method, params, result)
	if err != nil && s.ctx.Err() != nil {
		if cause := context.Cause(s.ctx); cause != nil {
			return cause
		}
	}
	return err
}

func (s *session) hello() (*protocol.HelloResult, error) {
	st := s.c.opts.Store
	id := st.Identity()
	ep, ok := st.Epoch()
	if !ok {
		return nil, ErrNoEpoch
	}
	p := protocol.HelloParams{
		TargetID: id.TargetID, TargetType: id.TargetType, WriterID: st.WriterID(), Incarnation: st.Incarnation(),
		Epoch: ep.ID, MachineID: id.MachineID, Agent: s.c.opts.Agent,
	}
	if !ep.Registered {
		p.EpochOpen = &protocol.EpochOpen{Reason: ep.OpenReason, PrevEpoch: ep.PrevEpoch, PrevHead: ep.PrevHead}
	}
	if lc, ok := st.LastCommitted(); ok {
		p.LastCommitted = &lc
	}
	var res protocol.HelloResult
	if err := s.call(protocol.MethodHello, p, &res); err != nil {
		return nil, classifyHello(err, st)
	}
	if res.Epoch != ep.ID {
		return nil, fmt.Errorf("hello accepted epoch %s, presented %s", res.Epoch, ep.ID)
	}
	if res.Decision != protocol.DecisionResume && res.Decision != protocol.DecisionOpened {
		return nil, fmt.Errorf("hello: unknown decision %q", res.Decision)
	}
	if !ep.Registered {
		if err := st.MarkRegistered(); err != nil {
			return nil, err
		}
	}
	s.epoch = ep.ID
	s.window = res.WindowBytes
	if s.window <= 0 {
		s.window = protocol.DefaultWindowSize
	}
	s.maxFrame = res.MaxFrameBytes
	if s.maxFrame <= 0 || s.maxFrame > protocol.MaxFramePayload {
		s.maxFrame = protocol.MaxFramePayload
	}
	return &res, nil
}

func classifyHello(err error, st Store) error {
	code := RPCErrorCode(err)
	switch code {
	case "":
		return err
	case protocol.CodeUnauthorized, protocol.CodeWriterRetired, protocol.CodeEpochClosed, protocol.CodeNotOwner,
		protocol.CodeStaleIncarnation, protocol.CodeUnsupportedProtocol:
		return &StopError{Code: code}
	case protocol.CodeDivergence:
		lc, _ := st.LastCommitted()
		return &DivergenceError{Head: lc.Seq, Reason: "hello rejected: " + err.Error()}
	}
	return &RejectError{Code: code, Err: err}
}

// verifyHead is resume step 2 (SPEC 8.4): the committed head must be the writer's own record.
func verifyHead(st Store, ep EpochState, h protocol.ChainPoint) error {
	div := func(reason string) error { return &DivergenceError{Head: h.Seq, Reason: reason} }
	if h.Seq > ep.Chain.Head {
		return div(fmt.Sprintf("committed head %d above highest assigned sequence %d", h.Seq, ep.Chain.Head))
	}
	lc, ok := st.LastCommitted()
	if ok && lc.Seq > h.Seq {
		return div(fmt.Sprintf("committed head %d below last committed %d", h.Seq, lc.Seq))
	}
	if h.Seq == 0 {
		return nil
	}
	if ok && lc.Seq == h.Seq {
		if lc.ChainHash != h.ChainHash {
			return div("chain hash differs at the committed head")
		}
		return nil
	}
	if es := st.Entries(h.Seq); len(es) > 0 && es[0].Seq == h.Seq {
		if es[0].ChainHash != h.ChainHash {
			return div("chain hash differs at the committed head")
		}
		return nil
	}
	return div(fmt.Sprintf("committed head %d is inside a coalesced range", h.Seq))
}

func (s *session) resume(res *protocol.HelloResult) error {
	st := s.c.opts.Store
	h := res.Head
	ep, ok := st.Epoch()
	if !ok || ep.ID != s.epoch {
		return ErrWrongEpoch
	}
	if err := verifyHead(st, ep, h); err != nil {
		return err
	}
	if h.Seq > 0 {
		if err := st.Commit(ep.ID, h.Seq, h.ChainHash); err != nil {
			if errors.Is(err, ErrDivergence) {
				return &DivergenceError{Head: h.Seq, Reason: err.Error()}
			}
			return err
		}
	}
	s.cursor, s.acked = h.Seq, h.Seq
	s.c.setHead(h.Seq)
	if len(st.Entries(h.Seq+1)) == 0 {
		return nil
	}
	var sum protocol.SummaryParams
	var anchor *Entry
	err := st.Do(func(tx Tx) error {
		cur, _ := st.Epoch()
		ct := &captureTx{tx: tx, reason: protocol.ReasonReplayAnchor, epoch: cur, committed: h.Seq}
		var err error
		if sum, err = s.c.opts.Hooks.CaptureReplay(ct); err != nil {
			return err
		}
		anchor, err = ct.single()
		return err
	})
	if err != nil {
		return fmt.Errorf("capture replay anchor: %w", err)
	}
	sum.Epoch, sum.Watermark, sum.Head = ep.ID, anchor.Seq, h.Seq
	if sum.Entries == nil {
		sum.Entries = []protocol.SummaryEntry{}
	}
	if err := s.call(protocol.MethodSummary, sum, nil); err != nil {
		return err
	}
	s.anchor = anchor.Seq
	s.c.setWatermark(anchor.Seq)
	return s.send([]*Entry{anchor})
}

func (s *session) stream() error {
	health := s.healthTimer()
	for {
		select {
		case <-health:
			s.reportHealth()
			health = s.healthTimer()
		default:
		}
		progressed, err := s.sendNext()
		if err != nil {
			return err
		}
		if progressed {
			continue
		}
		select {
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		case <-s.c.opts.Store.Notify():
		case <-s.wake:
		case <-health:
			s.reportHealth()
			health = s.healthTimer()
		}
	}
}

func (s *session) healthTimer() <-chan time.Time {
	if s.c.opts.HealthInterval < 0 {
		return nil
	}
	return s.c.clock.After(s.c.opts.HealthInterval)
}

func (s *session) reportHealth() {
	if err := s.conn.Notify(s.ctx, protocol.MethodHealth, s.c.opts.Hooks.Health()); err != nil {
		s.c.log.Warn("health report", "err", err)
	}
}

// frameOverhead bounds the CBOR array and byte string headers per record.
const frameOverhead = 9

// replaySlices splits one second of rate-limited replay into this many frames.
const replaySlices = 8

func (s *session) sendNext() (bool, error) {
	entries := s.c.opts.Store.Entries(s.cursor + 1)
	s.mu.Lock()
	inflight, anchorBytes := s.inflightBytes, s.inflight[s.anchor]
	s.mu.Unlock()
	var batch []*Entry
	var size int64
	moved := false
	frameCap := s.maxFrame
	if s.limiter.rate > 0 && len(entries) > 0 && entries[0].Seq < s.anchor {
		frameCap = min(frameCap, int64(s.limiter.rate/replaySlices))
	}
	for _, e := range entries {
		if e.Seq == s.anchor {
			if len(batch) > 0 {
				break
			}
			s.cursor, moved = e.Seq, true
			continue
		}
		n := int64(len(e.Bytes))
		if len(batch) >= s.c.opts.MaxBatchRecords {
			break
		}
		if len(batch) > 0 && size+n+frameOverhead*int64(len(batch)+2) > frameCap {
			break
		}
		onlyAnchor := len(batch) == 0 && inflight-anchorBytes <= 0
		if inflight+size+n > s.window && !onlyAnchor {
			break
		}
		batch = append(batch, e)
		size += n
	}
	if len(batch) == 0 {
		return moved, nil
	}
	if s.anchor != 0 && batch[0].Seq < s.anchor {
		if err := s.limiter.wait(s.ctx, s.c.clock, size); err != nil {
			return false, context.Cause(s.ctx)
		}
	}
	if err := s.send(batch); err != nil {
		if errors.Is(err, ErrNotSpooled) {
			return true, nil
		}
		return false, err
	}
	s.cursor = batch[len(batch)-1].Seq
	return true, nil
}

// send marks entries transmitted, then sends the bytes read back after marking, which can no longer change.
func (s *session) send(batch []*Entry) error {
	st := s.c.opts.Store
	seqs := make([]uint64, len(batch))
	for i, e := range batch {
		seqs[i] = e.Seq
	}
	if err := st.MarkTransmitted(seqs...); err != nil {
		return err
	}
	fresh := st.Entries(seqs[0])
	byts := make([][]byte, 0, len(seqs))
	sizes := make([]int64, 0, len(seqs))
	j := 0
	for _, e := range fresh {
		if j < len(seqs) && e.Seq == seqs[j] {
			byts = append(byts, e.Bytes)
			sizes = append(sizes, int64(len(e.Bytes)))
			j++
		}
	}
	if j != len(seqs) {
		return fmt.Errorf("%w: batch changed while marking", ErrNotSpooled)
	}
	frame, err := protocol.EncodeBatchFrame(byts, !s.c.opts.DisableCompression)
	if err != nil {
		return err
	}
	s.mu.Lock()
	for i, seq := range seqs {
		if seq > s.acked {
			if _, ok := s.inflight[seq]; !ok {
				s.inflight[seq] = sizes[i]
				s.inflightBytes += sizes[i]
			}
		}
	}
	s.mu.Unlock()
	if err := s.conn.SendBinary(s.ctx, frame); err != nil {
		if cause := context.Cause(s.ctx); s.ctx.Err() != nil && cause != nil {
			return cause
		}
		return err
	}
	return nil
}

func (s *session) onAck(p protocol.AckParams) {
	if p.Epoch != s.epoch {
		return
	}
	st := s.c.opts.Store
	if err := st.Commit(p.Epoch, p.Seq, p.ChainHash); err != nil {
		if errors.Is(err, ErrDivergence) {
			lc, _ := st.LastCommitted()
			s.cancel(&DivergenceError{Head: lc.Seq, Reason: "acknowledgement: " + err.Error()})
			return
		}
		s.c.log.Warn("commit acknowledgement", "seq", p.Seq, "err", err)
		return
	}
	s.mu.Lock()
	if p.Seq > s.acked {
		s.acked = p.Seq
	}
	for seq, n := range s.inflight {
		if seq <= p.Seq {
			delete(s.inflight, seq)
			s.inflightBytes -= n
		}
	}
	s.mu.Unlock()
	s.c.setHead(p.Seq)
	s.signal()
}

func (s *session) onReject(p protocol.RejectParams) {
	if p.Epoch != s.epoch {
		return
	}
	if p.Code == protocol.CodeEpochClosed {
		s.cancel(&StopError{Code: protocol.CodeEpochClosed})
		return
	}
	lc, _ := s.c.opts.Store.LastCommitted()
	s.cancel(&DivergenceError{Head: lc.Seq, Reason: fmt.Sprintf("record %d rejected: %s %s", p.Seq, p.Code, p.Message)})
}

func invalidParams(err error) error {
	return &protocol.RPCError{Code: protocol.RPCInvalidParams, Message: err.Error()}
}

func (s *session) handle(ctx context.Context, req *Request) (any, error) {
	h := s.c.opts.Hooks
	decode := func(v any) error {
		if len(req.Params) == 0 {
			return nil
		}
		return json.Unmarshal(req.Params, v)
	}
	switch req.Method {
	case protocol.MethodAck:
		var p protocol.AckParams
		if err := decode(&p); err != nil {
			return nil, invalidParams(err)
		}
		s.onAck(p)
		return nil, nil
	case protocol.MethodReject:
		var p protocol.RejectParams
		if err := decode(&p); err != nil {
			return nil, invalidParams(err)
		}
		s.onReject(p)
		return nil, nil
	case protocol.MethodSuperseded:
		s.cancel(&StopError{Code: HaltSuperseded})
		return nil, nil
	case protocol.MethodDeenrolled:
		if err := s.c.clearCredential(); err != nil {
			s.c.log.Error("delete credential", "err", err)
		}
		s.cancel(&StopError{Code: HaltDeenrolled})
		return nil, nil
	case protocol.MethodBundleAvailable:
		var p protocol.BundleAvailableParams
		if err := decode(&p); err != nil {
			return nil, invalidParams(err)
		}
		go h.BundleAvailable(p)
		return nil, nil
	case protocol.MethodCredentialRotate:
		var p protocol.CredentialRotateParams
		if err := decode(&p); err != nil {
			return nil, invalidParams(err)
		}
		if p.Credential == "" {
			return nil, invalidParams(errors.New("empty credential"))
		}
		id := s.c.opts.Store.Identity()
		id.Credential, id.CredentialID = p.Credential, p.CredentialID
		if err := s.c.opts.Store.SetIdentity(id); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	case protocol.MethodInitialize:
		return InitializeResult{
			ProtocolVersion: MCPProtocolVersion,
			Capabilities:    map[string]any{"tools": map[string]any{"listChanged": false}},
			ServerInfo:      ServerInfo{Name: "exitmesh-agent", Version: s.c.opts.Agent.Version},
		}, nil
	case protocol.MethodPing:
		return struct{}{}, nil
	case protocol.MethodToolsList:
		tools := h.Tools()
		if tools == nil {
			tools = []Tool{}
		}
		return ToolsListResult{Tools: tools}, nil
	case protocol.MethodToolsCall:
		var p CallToolParams
		if err := decode(&p); err != nil {
			return nil, invalidParams(err)
		}
		if p.Name == "" {
			return nil, invalidParams(errors.New("missing tool name"))
		}
		return ToolResult(h.Tool(ctx, p.Name, p.Arguments)), nil
	}
	if req.Notification {
		return nil, nil
	}
	return nil, &protocol.RPCError{Code: protocol.RPCMethodNotFound, Message: "method not found: " + req.Method}
}

// limiter charges each replay frame before it is sent, so n bytes never go out faster than n/rate.
type limiter struct {
	rate float64
	next time.Time
}

func (l *limiter) wait(ctx context.Context, clk Clock, n int64) error {
	if l.rate <= 0 {
		return nil
	}
	now := clk.Now()
	if l.next.Before(now) {
		l.next = now
	}
	l.next = l.next.Add(time.Duration(float64(n) / l.rate * float64(time.Second)))
	d := l.next.Sub(now)
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-clk.After(d):
		return nil
	}
}
