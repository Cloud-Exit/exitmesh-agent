// Package refcp is an in-memory reference control plane for contract and end-to-end tests.
package refcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// Options configures a Server.
type Options struct {
	Now           func() time.Time
	LateThreshold time.Duration // default 15m
	WindowBytes   int64         // default protocol.DefaultWindowSize
	MaxFrameBytes int64         // default protocol.MaxFramePayload
	Conn          tunnel.ConnOptions
	Logger        *slog.Logger
}

// Errors returned by management and query methods.
var (
	ErrUnknownTarget = errors.New("refcp: unknown target")
	ErrUnknownEpoch  = errors.New("refcp: unknown epoch")
	ErrNotCommitted  = errors.New("refcp: sequence not committed")
	ErrNoSession     = errors.New("refcp: target has no active session")
)

type credential struct {
	id, secret, target string
	writer             protocol.WriterID
	machineID          string
	revoked            bool
}

type group struct{ id, secret string }

type bundle struct {
	version                         string
	archive, signature, keyManifest []byte
	keyManifestChain                [][]byte
}

type target struct {
	id, typ, secret string
	deenrolled      bool
	epochs          map[protocol.EpochID]*epoch
	order           []protocol.EpochID
	open            *protocol.EpochID
	retired         map[protocol.WriterID]bool
	highest         map[protocol.WriterID]uint64
	active          *session
	machineID       string
	conflict        bool
	pendingBinding  bool
	compat          protocol.Compat
	notifications   []Notification
	notified        map[string]bool
	findings        map[string]*FindingState
	summaries       []protocol.SummaryParams
	health          []json.RawMessage
	boundaries      []Boundary
	stats           Stats
}

type faults struct {
	dropAcks        int
	disconnectAfter int
	delayAcks       time.Duration
	rejectNext      string
	rejectHello     string
}

// Server is the reference control plane. It is safe for concurrent use.
type Server struct {
	opts Options
	log  *slog.Logger

	mu          sync.Mutex
	targets     map[string]*target
	groups      map[string]*group
	creds       map[string]*credential
	bundles     map[string]*bundle
	sessions    map[*session]bool
	audit       []AuditEntry
	faults      faults
	unavailable bool
	closed      chan struct{}
	closeOnce   sync.Once
}

// New returns an empty control plane.
func New(opts Options) *Server {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.LateThreshold <= 0 {
		opts.LateThreshold = 15 * time.Minute
	}
	if opts.WindowBytes <= 0 {
		opts.WindowBytes = protocol.DefaultWindowSize
	}
	if opts.MaxFrameBytes <= 0 {
		opts.MaxFrameBytes = protocol.MaxFramePayload
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{
		opts: opts, log: log, targets: map[string]*target{}, groups: map[string]*group{},
		creds: map[string]*credential{}, bundles: map[string]*bundle{}, sessions: map[*session]bool{},
		closed: make(chan struct{}),
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Server) now() time.Time { return s.opts.Now() }

func (s *Server) newTarget(typ string) *target {
	t := &target{
		id: "t-" + randHex(6), typ: typ, secret: randHex(16), epochs: map[protocol.EpochID]*epoch{},
		retired: map[protocol.WriterID]bool{}, highest: map[protocol.WriterID]uint64{}, notified: map[string]bool{},
		findings: map[string]*FindingState{}, compat: protocol.Compat{Status: protocol.CompatOK},
	}
	s.targets[t.id] = t
	return t
}

func (s *Server) targetLocked(id string) (*target, error) {
	t, ok := s.targets[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownTarget, id)
	}
	return t, nil
}

// CreateTarget registers a target and returns its enrollment token (emx1_c_ or emx1_h_).
func (s *Server) CreateTarget(targetType string) (targetID, token string, err error) {
	kind := protocol.TokenCluster
	switch targetType {
	case protocol.TargetKubernetes:
	case protocol.TargetHost:
		kind = protocol.TokenHost
	default:
		return "", "", fmt.Errorf("refcp: unknown target type %q", targetType)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.newTarget(targetType)
	s.auditLocked(AuditEntry{Target: t.id, Event: "target_created", Detail: targetType})
	return t.id, fmt.Sprintf("emx1_%s_%s_%s", kind, t.id, t.secret), nil
}

// CreateHostGroup returns a host group enrollment token (emx1_g_); each enrollment creates a host target.
func (s *Server) CreateHostGroup() (groupID, token string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := &group{id: "g-" + randHex(6), secret: randHex(16)}
	s.groups[g.id] = g
	return g.id, fmt.Sprintf("emx1_%s_%s_%s", protocol.TokenHostGroup, g.id, g.secret), nil
}

// BindHost records a pending administrator binding: the next new writer takes over the host (row 14).
func (s *Server) BindHost(targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return err
	}
	if t.typ != protocol.TargetHost {
		return fmt.Errorf("refcp: %s is not a host target", targetID)
	}
	t.pendingBinding = true
	s.auditLocked(AuditEntry{Target: t.id, Event: "binding_pending"})
	return nil
}

// ResolveConflict clears an identity conflict; a non-empty machineID becomes the enrolled machine ID.
func (s *Server) ResolveConflict(targetID, machineID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return err
	}
	t.conflict = false
	if machineID != "" {
		t.machineID = machineID
		for _, c := range s.creds {
			if c.target == t.id && !c.revoked {
				c.machineID = machineID
			}
		}
	}
	s.auditLocked(AuditEntry{Target: t.id, Event: "conflict_resolved", Detail: machineID})
	return nil
}

// Deenroll revokes every credential of the target and tells an attached writer to stop.
func (s *Server) Deenroll(targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return err
	}
	s.deenrollLocked(t, "administrator")
	if t.active != nil {
		t.active.enqueue(outMsg{method: protocol.MethodDeenrolled, closeAfter: true})
	}
	return nil
}

func (s *Server) deenrollLocked(t *target, reason string) {
	t.deenrolled = true
	for _, c := range s.creds {
		if c.target == t.id {
			c.revoked = true
		}
	}
	s.auditLocked(AuditEntry{Target: t.id, Event: "deenrolled", Detail: reason})
}

// RotateCredential sends a new credential to the attached writer and revokes the old one once it is persisted.
func (s *Server) RotateCredential(ctx context.Context, targetID string) (string, error) {
	s.mu.Lock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		s.mu.Unlock()
		return "", err
	}
	ss := t.active
	if ss == nil {
		s.mu.Unlock()
		return "", ErrNoSession
	}
	old := ss.cred
	nc := &credential{id: "c-" + randHex(6), secret: randHex(24), target: t.id, writer: old.writer, machineID: old.machineID}
	s.creds[nc.secret] = nc
	s.mu.Unlock()
	err = ss.conn.Call(ctx, protocol.MethodCredentialRotate, protocol.CredentialRotateParams{Credential: nc.secret, CredentialID: nc.id}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		delete(s.creds, nc.secret)
		return "", fmt.Errorf("refcp: credential.rotate: %w", err)
	}
	old.revoked = true
	s.auditLocked(AuditEntry{Target: t.id, Event: "credential_rotated", Detail: old.id + " -> " + nc.id})
	return nc.id, nil
}

// SetCompat sets the compatibility verdict returned in hello results.
func (s *Server) SetCompat(targetID string, c protocol.Compat) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return err
	}
	t.compat = c
	return nil
}

// PublishBundle stores the latest bundle for a target type and announces it to attached writers.
func (s *Server) PublishBundle(targetType, version string, archive, signature, keyManifest []byte) error {
	if version == "" {
		return errors.New("refcp: bundle version required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles[targetType] = &bundle{version: version, archive: archive, signature: signature, keyManifest: keyManifest}
	for _, t := range s.targets {
		if t.typ == targetType && t.active != nil {
			t.active.enqueue(outMsg{method: protocol.MethodBundleAvailable, params: protocol.BundleAvailableParams{Version: version, TargetType: targetType}})
		}
	}
	return nil
}

// PublishKeyManifestChain sets the earlier key manifests served with bundles for targetType.
func (s *Server) PublishKeyManifestChain(targetType string, chain [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bundles[targetType]
	if !ok {
		return errors.New("refcp: publish a bundle before its key manifest chain")
	}
	b.keyManifestChain = chain
	return nil
}

// CallTool forwards an MCP tools/call to the target's attached writer.
func (s *Server) CallTool(ctx context.Context, targetID, name string, args any) (*client.CallToolResult, error) {
	s.mu.Lock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	ss := t.active
	s.mu.Unlock()
	if ss == nil {
		return nil, ErrNoSession
	}
	if err := ss.initMCP(ctx); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	var res client.CallToolResult
	if err := ss.conn.Call(ctx, protocol.MethodToolsCall, client.CallToolParams{Name: name, Arguments: raw}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListTools returns the tools advertised by the target's attached writer.
func (s *Server) ListTools(ctx context.Context, targetID string) ([]client.Tool, error) {
	s.mu.Lock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	ss := t.active
	s.mu.Unlock()
	if ss == nil {
		return nil, ErrNoSession
	}
	if err := ss.initMCP(ctx); err != nil {
		return nil, err
	}
	var res client.ToolsListResult
	if err := ss.conn.Call(ctx, protocol.MethodToolsList, struct{}{}, &res); err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// SetUnavailable makes enrollment and new tunnel connections fail with 503; attached sessions continue.
func (s *Server) SetUnavailable(v bool) {
	s.mu.Lock()
	s.unavailable = v
	s.mu.Unlock()
}

// DropAcks commits the next n acknowledged frames without sending their acknowledgement.
func (s *Server) DropAcks(n int) {
	s.mu.Lock()
	s.faults.dropAcks = n
	s.mu.Unlock()
}

// DisconnectAfterRecords closes the session right after the n-th next committed record, before acknowledging it.
func (s *Server) DisconnectAfterRecords(n int) {
	s.mu.Lock()
	s.faults.disconnectAfter = n
	s.mu.Unlock()
}

// DelayAcks delays every acknowledgement by d.
func (s *Server) DelayAcks(d time.Duration) {
	s.mu.Lock()
	s.faults.delayAcks = d
	s.mu.Unlock()
}

// RejectNext rejects the next received record with code instead of applying it.
func (s *Server) RejectNext(code string) {
	s.mu.Lock()
	s.faults.rejectNext = code
	s.mu.Unlock()
}

// RejectNextHello rejects the next hello with code.
func (s *Server) RejectNextHello(code string) {
	s.mu.Lock()
	s.faults.rejectHello = code
	s.mu.Unlock()
}

// Disconnect closes the target's attached session, as a network failure would.
func (s *Server) Disconnect(targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.targetLocked(targetID)
	if err != nil {
		return err
	}
	if t.active == nil {
		return ErrNoSession
	}
	t.active.enqueue(outMsg{closeAfter: true})
	return nil
}

// Close ends every session.
func (s *Server) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
	s.mu.Lock()
	var all []*session
	for ss := range s.sessions {
		all = append(all, ss)
	}
	s.mu.Unlock()
	for _, ss := range all {
		_ = ss.conn.Close()
	}
}

// ServeHTTP serves the enrollment endpoint and the tunnel.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case protocol.EnrollPath:
		s.serveEnroll(w, r)
	case protocol.TunnelPath:
		s.serveTunnel(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req protocol.EnrollRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		http.Error(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	resp, status, err := s.enroll(&req)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) enroll(req *protocol.EnrollRequest) (*protocol.EnrollResponse, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unavailable {
		return nil, http.StatusServiceUnavailable, errors.New("control plane unavailable")
	}
	tok, err := protocol.ParseEnrollmentToken(req.Token)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	var t *target
	switch tok.Kind {
	case protocol.TokenCluster, protocol.TokenHost:
		t = s.targets[tok.ID]
		want := protocol.TargetKubernetes
		if tok.Kind == protocol.TokenHost {
			want = protocol.TargetHost
		}
		if t == nil || t.secret != tok.Secret || t.typ != want {
			s.auditLocked(AuditEntry{Target: tok.ID, Event: "enroll_rejected", Code: protocol.CodeUnauthorized})
			return nil, http.StatusUnauthorized, errors.New("invalid enrollment token")
		}
	case protocol.TokenHostGroup:
		g := s.groups[tok.ID]
		if g == nil || g.secret != tok.Secret {
			s.auditLocked(AuditEntry{Target: tok.ID, Event: "enroll_rejected", Code: protocol.CodeUnauthorized})
			return nil, http.StatusUnauthorized, errors.New("invalid enrollment token")
		}
		t = s.newTarget(protocol.TargetHost)
		s.auditLocked(AuditEntry{Target: t.id, Event: "target_created", Detail: "group " + g.id})
	}
	if t.deenrolled {
		return nil, http.StatusUnauthorized, errors.New("target de-enrolled")
	}
	if req.TargetType != t.typ {
		return nil, http.StatusBadRequest, fmt.Errorf("target type %q, token is for %q", req.TargetType, t.typ)
	}
	if req.WriterID.IsZero() {
		return nil, http.StatusBadRequest, errors.New("writer_id required")
	}
	if t.typ == protocol.TargetHost {
		if req.MachineID == "" {
			return nil, http.StatusBadRequest, errors.New("machine_id required for hosts")
		}
		if t.machineID == "" || t.pendingBinding {
			t.machineID = req.MachineID
		}
	}
	c := &credential{id: "c-" + randHex(6), secret: randHex(24), target: t.id, writer: req.WriterID, machineID: req.MachineID}
	s.creds[c.secret] = c
	s.auditLocked(AuditEntry{Target: t.id, Event: "enrolled", Writer: req.WriterID, Detail: c.id})
	return &protocol.EnrollResponse{TargetID: t.id, Credential: c.secret, CredentialID: c.id}, http.StatusOK, nil
}

func (s *Server) serveTunnel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	unavailable := s.unavailable
	s.mu.Unlock()
	if unavailable {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		http.Error(w, "bearer credential required", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	cred := s.creds[bearer]
	s.mu.Unlock()
	if cred == nil {
		s.mu.Lock()
		s.auditLocked(AuditEntry{Event: "tunnel_rejected", Code: protocol.CodeUnauthorized})
		s.mu.Unlock()
		http.Error(w, "unknown credential", http.StatusUnauthorized)
		return
	}
	conn, err := tunnel.Accept(w, r, s.opts.Conn)
	if err != nil {
		s.log.Warn("tunnel accept", "err", err)
		return
	}
	ss := newSession(s, conn, cred)
	s.mu.Lock()
	s.sessions[ss] = true
	s.mu.Unlock()
	conn.HandleBinary(ss.onFrame)
	conn.Handle(ss.handle)
	go ss.sendLoop()
	select {
	case <-conn.Done():
	case <-s.closed:
		_ = conn.Close()
	}
	s.endSession(ss)
}

func (s *Server) endSession(ss *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, ss)
	ss.closed = true
	if ss.target != nil && ss.target.active == ss {
		ss.target.active = nil
	}
}
