package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Clock abstracts time for backoff, rate limiting, and health reports.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Halt codes in addition to the hello rejection codes of SPEC 8.3.
const (
	HaltSuperseded = "superseded"
	HaltDeenrolled = "deenrolled"
)

// MaxBackoff caps the delay between connection attempts.
const MaxBackoff = 5 * time.Minute

// Options configures a Client.
type Options struct {
	Store     Store
	Transport Transport
	Hooks     Hooks
	Agent     protocol.AgentInfo
	Logger    *slog.Logger
	Clock     Clock
	// Jitter returns a random duration in [0, ceiling]; the default is uniform (full jitter).
	Jitter               func(ceiling time.Duration) time.Duration
	BackoffBase          time.Duration // default 1s
	BackoffMax           time.Duration // default and maximum 5m
	ReplayBytesPerSecond int64         // backlog replay rate limit; 0 is unlimited
	HealthInterval       time.Duration // default 60s; negative disables health reports
	CallTimeout          time.Duration // default 30s
	MaxBatchRecords      int           // default 512
	DisableCompression   bool
}

// StopError ends Run: the writer must stop writing (SPEC 8.3 rows 1, 4 to 7, supersede, de-enrollment).
type StopError struct{ Code string }

func (e *StopError) Error() string { return "writer stopped: " + e.Code }

// DivergenceError triggers a rebaseline at the committed head Head (SPEC 8.6).
type DivergenceError struct {
	Head   uint64
	Reason string
}

func (e *DivergenceError) Error() string {
	return fmt.Sprintf("divergence at committed head %d: %s", e.Head, e.Reason)
}

// RejectError is a hello rejection after which the writer keeps spooling and retries.
type RejectError struct {
	Code string
	Err  error
}

func (e *RejectError) Error() string { return "hello rejected: " + e.Err.Error() }
func (e *RejectError) Unwrap() error { return e.Err }

// Session errors.
var (
	ErrDisconnected = errors.New("connection closed")
	ErrNotConnected = errors.New("no active session")
)

// Status is a snapshot of the writer session.
type Status struct {
	Connected  bool
	SessionID  string
	Epoch      protocol.EpochID
	Registered bool
	Head       uint64
	Watermark  uint64
	// BacklogRecords and BacklogBytes count what Store.Entries(0) returns.
	BacklogRecords int
	BacklogBytes   int64
	Sessions       int
	Rebaselines    int
	LastError      string
	LastErrorCode  string
	Halted         string
	Compat         protocol.Compat
}

// Client is the writer session client.
type Client struct {
	opts     Options
	clock    Clock
	log      *slog.Logger
	instance protocol.ID

	mu     sync.Mutex
	status Status
	sess   *session
}

// New validates options and applies defaults.
func New(opts Options) (*Client, error) {
	if opts.Store == nil || opts.Transport == nil || opts.Hooks == nil {
		return nil, errors.New("client: store, transport, and hooks are required")
	}
	if opts.Clock == nil {
		opts.Clock = realClock{}
	}
	if opts.Jitter == nil {
		opts.Jitter = func(c time.Duration) time.Duration {
			if c <= 0 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(c) + 1)) //nolint:gosec // reconnect jitter needs no cryptographic randomness
		}
	}
	if opts.BackoffBase <= 0 {
		opts.BackoffBase = time.Second
	}
	if opts.BackoffMax <= 0 || opts.BackoffMax > MaxBackoff {
		opts.BackoffMax = MaxBackoff
	}
	opts.BackoffBase = min(opts.BackoffBase, opts.BackoffMax)
	if opts.HealthInterval == 0 {
		opts.HealthInterval = time.Minute
	}
	if opts.CallTimeout <= 0 {
		opts.CallTimeout = 30 * time.Second
	}
	if opts.MaxBatchRecords <= 0 {
		opts.MaxBatchRecords = 512
	}
	if opts.Agent.Protocol == 0 {
		opts.Agent.Protocol = protocol.Version
	}
	if opts.Agent.Schema == 0 {
		opts.Agent.Schema = protocol.SchemaVersion
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	instance, err := protocol.NewWriterID()
	if err != nil {
		return nil, fmt.Errorf("client: instance id: %w", err)
	}
	return &Client{opts: opts, clock: opts.Clock, log: log, instance: instance}, nil
}

// Run connects, resumes, and streams records until ctx ends or the writer must stop.
func (c *Client) Run(ctx context.Context) error {
	attempt := 0
	for {
		if code, ok := c.opts.Store.Halted(); ok {
			return &StopError{Code: code}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.ensureEpoch(); err != nil {
			c.fail(err)
			if errors.Is(err, ErrNotEnrolled) || errors.Is(err, ErrHalted) {
				return err
			}
		} else {
			established, err := c.connect(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.fail(err)
			var stop *StopError
			var div *DivergenceError
			switch {
			case errors.As(err, &stop):
				if herr := c.opts.Store.SetHalted(stop.Code); herr != nil {
					return errors.Join(err, herr)
				}
				return err
			case errors.As(err, &div):
				c.log.Warn("rebaseline after divergence", "head", div.Head, "reason", div.Reason)
				if rerr := c.rebaseline(div.Head); rerr != nil {
					c.fail(rerr)
					if errors.Is(rerr, ErrHalted) {
						return rerr
					}
				} else {
					if established {
						attempt = 0
					}
					if attempt == 0 {
						attempt++
						continue
					}
				}
			}
			if established {
				attempt = 0
			}
		}
		d := c.backoff(attempt)
		attempt++
		c.log.Warn("history session retry scheduled", "attempt", attempt, "retry_in", d)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.clock.After(d):
		}
	}
}

func (c *Client) backoff(attempt int) time.Duration {
	ceil := c.opts.BackoffBase
	for i := 0; i < attempt && ceil < c.opts.BackoffMax; i++ {
		ceil *= 2
	}
	if ceil > c.opts.BackoffMax {
		ceil = c.opts.BackoffMax
	}
	return min(max(c.opts.Jitter(ceil), 0), ceil)
}

func reasonFor(open string) protocol.CheckpointReason {
	switch open {
	case protocol.OpenRebaseline:
		return protocol.ReasonRebaseline
	case protocol.OpenWriterChange:
		return protocol.ReasonWriterChange
	}
	return protocol.ReasonInitial
}

// Prepare opens an initial epoch offline and emits its first checkpoint, so records can be appended before connecting.
func (c *Client) Prepare() error { return c.ensureEpoch() }

func (c *Client) ensureEpoch() error {
	st := c.opts.Store
	if st.Identity().TargetID == "" {
		return ErrNotEnrolled
	}
	if _, ok := st.Epoch(); !ok {
		if _, err := st.OpenEpoch(protocol.OpenInitial, nil, nil); err != nil {
			return err
		}
	}
	return st.Do(func(tx Tx) error {
		ep, ok := st.Epoch()
		if !ok {
			return ErrNoEpoch
		}
		if ep.Chain.Head > 0 {
			return nil
		}
		ct := &captureTx{tx: tx, reason: reasonFor(ep.OpenReason), epoch: ep}
		if err := c.opts.Hooks.Rebaseline(ct); err != nil {
			return fmt.Errorf("emit epoch checkpoint: %w", err)
		}
		_, err := ct.single()
		return err
	})
}

func (c *Client) rebaseline(head uint64) error {
	st := c.opts.Store
	ep, ok := st.Epoch()
	if !ok {
		return ErrNoEpoch
	}
	if err := st.DiscardAbove(head); err != nil {
		return err
	}
	prev, h := ep.ID, head
	if _, err := st.OpenEpoch(protocol.OpenRebaseline, &prev, &h); err != nil {
		return err
	}
	c.mu.Lock()
	c.status.Rebaselines++
	c.mu.Unlock()
	return c.ensureEpoch()
}

func (c *Client) connect(ctx context.Context) (bool, error) {
	conn, err := c.opts.Transport.Dial(ctx)
	if err != nil {
		if RPCErrorCode(err) == protocol.CodeUnauthorized {
			return false, &StopError{Code: protocol.CodeUnauthorized}
		}
		return false, err
	}
	defer func() {
		_ = conn.Close()
		<-conn.Done()
	}()
	s := newSession(ctx, c, conn)
	defer s.close()
	conn.Handle(s.handle)
	res, err := s.hello()
	if err != nil {
		return false, err
	}
	c.established(s, res)
	defer c.disconnected(s)
	if err := s.resume(res); err != nil {
		if cause := context.Cause(s.ctx); s.ctx.Err() != nil && cause != nil {
			return true, cause
		}
		return true, err
	}
	c.log.Info("history session established", "session", res.SessionID, "decision", res.Decision, "epoch", res.Epoch, "head", res.Head.Seq)
	return true, s.stream()
}

func (c *Client) established(s *session, res *protocol.HelloResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sess = s
	c.status.Connected = true
	c.status.SessionID = res.SessionID
	c.status.Epoch = res.Epoch
	c.status.Registered = true
	c.status.Head = res.Head.Seq
	c.status.Watermark = 0
	c.status.Compat = res.Compat
	c.status.Sessions++
	c.status.LastError, c.status.LastErrorCode = "", ""
}

func (c *Client) disconnected(s *session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == s {
		c.sess = nil
		c.status.Connected = false
		c.status.SessionID = ""
	}
}

func (c *Client) current() *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

func (c *Client) setHead(seq uint64) {
	c.mu.Lock()
	if seq > c.status.Head {
		c.status.Head = seq
	}
	c.mu.Unlock()
}

func (c *Client) setWatermark(w uint64) {
	c.mu.Lock()
	c.status.Watermark = w
	c.mu.Unlock()
}

func (c *Client) fail(err error) {
	if err == nil {
		return
	}
	code := RPCErrorCode(err)
	var stop *StopError
	var rej *RejectError
	var div *DivergenceError
	switch {
	case errors.As(err, &stop):
		code = stop.Code
	case errors.As(err, &rej):
		code = rej.Code
	case errors.As(err, &div):
		code = protocol.CodeDivergence
	}
	c.log.Warn("history session", "err", err, "code", code)
	c.mu.Lock()
	c.status.LastError, c.status.LastErrorCode = err.Error(), code
	c.mu.Unlock()
}

// Status returns a snapshot of the session and spool backlog.
func (c *Client) Status() Status {
	c.mu.Lock()
	st := c.status
	c.mu.Unlock()
	if ep, ok := c.opts.Store.Epoch(); ok {
		if ep.ID != st.Epoch {
			st.Epoch, st.Head, st.Watermark = ep.ID, 0, 0
		}
		st.Registered = ep.Registered
		if lc, ok := c.opts.Store.LastCommitted(); ok && lc.Seq > st.Head {
			st.Head = lc.Seq
		}
	}
	for _, e := range c.opts.Store.Entries(0) {
		st.BacklogRecords++
		st.BacklogBytes += int64(len(e.Bytes))
	}
	if code, ok := c.opts.Store.Halted(); ok {
		st.Halted = code
	}
	return st
}

// FetchBundle requests the assigned rule bundle over the active session.
func (c *Client) FetchBundle(ctx context.Context, have string) (*protocol.BundleFetchResult, error) {
	s := c.current()
	if s == nil {
		return nil, ErrNotConnected
	}
	var res protocol.BundleFetchResult
	p := protocol.BundleFetchParams{TargetType: c.opts.Store.Identity().TargetType, Have: have}
	if err := s.conn.Call(ctx, protocol.MethodBundleFetch, p, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Deenroll requests explicit de-enrollment; on success the credential is deleted and Run stops.
func (c *Client) Deenroll(ctx context.Context, reason string) error {
	s := c.current()
	if s == nil {
		return ErrNotConnected
	}
	if err := s.conn.Call(ctx, protocol.MethodDeenroll, protocol.DeenrollParams{Reason: reason}, nil); err != nil {
		return err
	}
	if err := c.clearCredential(); err != nil {
		return err
	}
	s.cancel(&StopError{Code: HaltDeenrolled})
	return nil
}

// Audit sends an investigation.audit notification.
func (c *Client) Audit(ctx context.Context, params any) error {
	s := c.current()
	if s == nil {
		return ErrNotConnected
	}
	return s.conn.Notify(ctx, protocol.MethodAudit, params)
}

func (c *Client) clearCredential() error {
	id := c.opts.Store.Identity()
	id.Credential, id.CredentialID = "", ""
	return c.opts.Store.SetIdentity(id)
}

type captureTx struct {
	tx        Tx
	reason    protocol.CheckpointReason
	epoch     EpochState
	committed uint64
	appended  []*Entry
}

func (t *captureTx) Append(typ protocol.RecordType, build func(env protocol.Envelope) (*protocol.Record, error)) (*Entry, error) {
	e, err := t.tx.Append(typ, build)
	if err == nil {
		t.appended = append(t.appended, e)
	}
	return e, err
}

func (t *captureTx) Reason() protocol.CheckpointReason { return t.reason }
func (t *captureTx) Epoch() EpochState                 { return t.epoch }
func (t *captureTx) Committed() uint64                 { return t.committed }

func (t *captureTx) single() (*Entry, error) {
	if len(t.appended) != 1 || t.appended[0].Type != protocol.TypeCheckpoint {
		return nil, fmt.Errorf("hook must append exactly one checkpoint, appended %d records", len(t.appended))
	}
	return t.appended[0], nil
}
