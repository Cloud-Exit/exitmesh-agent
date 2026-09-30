package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// Keepalive defaults (SPEC 9.1).
const (
	DefaultPingInterval = 20 * time.Second
	DefaultDeadAfter    = 60 * time.Second
	// DefaultReadLimit admits a 16 MiB record batch payload plus frame and compression overhead.
	DefaultReadLimit = protocol.MaxFramePayload + 1<<20
)

// Errors reported by a Conn.
var (
	ErrDead   = errors.New("tunnel: no traffic within the dead interval")
	ErrClosed = errors.New("tunnel: connection closed")
)

// ConnOptions tunes keepalive and message limits.
type ConnOptions struct {
	PingInterval time.Duration
	DeadAfter    time.Duration
	ReadLimit    int64
}

func (o ConnOptions) withDefaults() ConnOptions {
	if o.PingInterval <= 0 {
		o.PingInterval = DefaultPingInterval
	}
	if o.DeadAfter <= 0 {
		o.DeadAfter = DefaultDeadAfter
	}
	if o.ReadLimit <= 0 {
		o.ReadLimit = DefaultReadLimit
	}
	return o
}

// BinaryHandler receives binary frames in arrival order.
type BinaryHandler func(ctx context.Context, frame []byte)

type inbound struct {
	msg    *protocol.RPCMessage
	binary []byte
}

// Conn multiplexes JSON-RPC 2.0 text frames and binary record frames; notifications and frames dispatch in order once Handle is called.
type Conn struct {
	opts   ConnOptions
	ws     *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc

	nextID  atomic.Int64
	last    atomic.Int64
	handler atomic.Pointer[client.Handler]
	binary  atomic.Pointer[BinaryHandler]
	ready   chan struct{}
	readyMu sync.Once

	mu      sync.Mutex
	pending map[string]chan *protocol.RPCMessage
	queue   []inbound
	qsignal chan struct{}

	closing   chan struct{}
	done      chan struct{}
	serving   sync.WaitGroup
	closeOnce sync.Once
	err       error
}

var _ client.Conn = (*Conn)(nil)

func newConn(opts ConnOptions) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		opts: opts.withDefaults(), ctx: ctx, cancel: cancel, ready: make(chan struct{}),
		pending: map[string]chan *protocol.RPCMessage{}, qsignal: make(chan struct{}, 1),
		closing: make(chan struct{}), done: make(chan struct{}),
	}
	c.touch()
	return c
}

func (c *Conn) touch() { c.last.Store(time.Now().UnixNano()) }

func (c *Conn) pong(context.Context, []byte) { c.touch() }

func (c *Conn) start(ws *websocket.Conn) {
	c.ws = ws
	ws.SetReadLimit(c.opts.ReadLimit)
	read, dispatch := make(chan struct{}), make(chan struct{})
	go func() { defer close(read); c.readLoop() }()
	go func() { defer close(dispatch); c.dispatchLoop() }()
	go c.keepalive()
	go func() {
		<-read
		c.serving.Wait()
		<-dispatch
		close(c.done)
	}()
}

// Accept upgrades an HTTP request to a tunnel connection (control plane side).
func Accept(w http.ResponseWriter, r *http.Request, opts ConnOptions) (*Conn, error) {
	c := newConn(opts)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:   []string{protocol.TunnelSubprotocol},
		OnPongReceived: c.pong,
	})
	if err != nil {
		c.cancel()
		return nil, err
	}
	if ws.Subprotocol() != protocol.TunnelSubprotocol {
		_ = ws.Close(websocket.StatusPolicyViolation, "subprotocol "+protocol.TunnelSubprotocol+" required")
		c.cancel()
		return nil, fmt.Errorf("tunnel: client did not negotiate %s", protocol.TunnelSubprotocol)
	}
	c.start(ws)
	return c, nil
}

// Handle installs the request and notification handler and starts dispatch.
func (c *Conn) Handle(h client.Handler) {
	c.handler.Store(&h)
	c.readyMu.Do(func() { close(c.ready) })
}

// HandleBinary installs the binary frame handler; install it before Handle.
func (c *Conn) HandleBinary(h BinaryHandler) { c.binary.Store(&h) }

// Done is closed once the connection has ended and every handler invocation has returned.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns the reason the connection ended, or nil while it is open.
func (c *Conn) Err() error {
	select {
	case <-c.closing:
		return c.err
	default:
		return nil
	}
}

// Close ends the connection with a normal closure.
func (c *Conn) Close() error {
	c.fail(ErrClosed, websocket.StatusNormalClosure)
	return nil
}

func (c *Conn) fail(err error, code websocket.StatusCode) {
	c.closeOnce.Do(func() {
		c.err = err
		close(c.closing)
		c.mu.Lock()
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
		go func() {
			if code == websocket.StatusNormalClosure {
				if c.ws.Close(code, "") == nil {
					c.cancel()
					return
				}
			}
			_ = c.ws.CloseNow()
			c.cancel()
		}()
	})
}

func (c *Conn) readLoop() {
	for {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				c.fail(ErrClosed, websocket.StatusNormalClosure)
			} else {
				c.fail(fmt.Errorf("tunnel: read: %w", err), websocket.StatusInternalError)
			}
			return
		}
		c.touch()
		switch typ {
		case websocket.MessageBinary:
			c.enqueue(inbound{binary: data})
		case websocket.MessageText:
			var m protocol.RPCMessage
			if err := json.Unmarshal(data, &m); err != nil || m.JSONRPC != "2.0" {
				_ = c.write(context.Background(), protocol.RPCMessage{JSONRPC: "2.0", Error: &protocol.RPCError{Code: protocol.RPCParseError, Message: "invalid JSON-RPC message"}})
				continue
			}
			if m.Method == "" {
				c.deliver(&m)
				continue
			}
			if m.ID != nil {
				c.serving.Add(1)
				go func() { defer c.serving.Done(); c.serve(&m) }()
				continue
			}
			c.enqueue(inbound{msg: &m})
		}
	}
}

func idKey(id *json.RawMessage) string {
	if id == nil {
		return ""
	}
	return string(bytes.TrimSpace(*id))
}

func (c *Conn) deliver(m *protocol.RPCMessage) {
	c.mu.Lock()
	ch, ok := c.pending[idKey(m.ID)]
	if ok {
		delete(c.pending, idKey(m.ID))
	}
	c.mu.Unlock()
	if ok {
		ch <- m
	}
}

func (c *Conn) enqueue(in inbound) {
	c.mu.Lock()
	c.queue = append(c.queue, in)
	c.mu.Unlock()
	select {
	case c.qsignal <- struct{}{}:
	default:
	}
}

func (c *Conn) dispatchLoop() {
	select {
	case <-c.ready:
	case <-c.closing:
		return
	}
	for {
		c.mu.Lock()
		q := c.queue
		c.queue = nil
		c.mu.Unlock()
		for _, in := range q {
			if in.binary != nil {
				if h := c.binary.Load(); h != nil {
					(*h)(c.ctx, in.binary)
				}
				continue
			}
			h := c.handler.Load()
			_, _ = (*h)(c.ctx, &client.Request{Method: in.msg.Method, Params: in.msg.Params, Notification: true})
		}
		select {
		case <-c.qsignal:
		case <-c.closing:
			c.mu.Lock()
			rest := len(c.queue)
			c.mu.Unlock()
			if rest == 0 {
				return
			}
		}
	}
}

func (c *Conn) serve(m *protocol.RPCMessage) {
	select {
	case <-c.ready:
	case <-c.closing:
		return
	}
	h := c.handler.Load()
	res, err := (*h)(c.ctx, &client.Request{Method: m.Method, Params: m.Params})
	resp := protocol.RPCMessage{JSONRPC: "2.0", ID: m.ID}
	if err != nil {
		var re *protocol.RPCError
		if !errors.As(err, &re) {
			re = &protocol.RPCError{Code: protocol.RPCInternalError, Message: err.Error()}
		}
		resp.Error = re
	} else {
		b, merr := json.Marshal(res)
		if merr != nil {
			resp.Error = &protocol.RPCError{Code: protocol.RPCInternalError, Message: merr.Error()}
		} else {
			resp.Result = b
		}
	}
	_ = c.write(c.ctx, resp)
}

func (c *Conn) write(ctx context.Context, m protocol.RPCMessage) error {
	if err := c.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := c.ws.Write(ctx, websocket.MessageText, b); err != nil {
		return c.writeErr(err)
	}
	return nil
}

func (c *Conn) writeErr(err error) error {
	if e := c.Err(); e != nil {
		return e
	}
	return fmt.Errorf("tunnel: write: %w", err)
}

func params(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// Call sends a request and waits for its response. An error response is a *protocol.RPCError.
func (c *Conn) Call(ctx context.Context, method string, p, result any) error {
	raw, err := params(p)
	if err != nil {
		return err
	}
	id := json.RawMessage(strconv.FormatInt(c.nextID.Add(1), 10))
	ch := make(chan *protocol.RPCMessage, 1)
	c.mu.Lock()
	select {
	case <-c.closing:
		c.mu.Unlock()
		return c.err
	default:
	}
	c.pending[string(id)] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, string(id))
		c.mu.Unlock()
	}()
	if err := c.write(ctx, protocol.RPCMessage{JSONRPC: "2.0", ID: &id, Method: method, Params: raw}); err != nil {
		return err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return c.Err()
		}
		if resp.Error != nil {
			return resp.Error
		}
		if result != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, result)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closing:
		return c.err
	}
}

// Notify sends a notification.
func (c *Conn) Notify(ctx context.Context, method string, p any) error {
	raw, err := params(p)
	if err != nil {
		return err
	}
	return c.write(ctx, protocol.RPCMessage{JSONRPC: "2.0", Method: method, Params: raw})
}

// SendBinary sends one binary frame.
func (c *Conn) SendBinary(ctx context.Context, frame []byte) error {
	if err := c.Err(); err != nil {
		return err
	}
	if err := c.ws.Write(ctx, websocket.MessageBinary, frame); err != nil {
		return c.writeErr(err)
	}
	return nil
}

func (c *Conn) keepalive() {
	check := c.opts.PingInterval / 2
	if d := c.opts.DeadAfter / 4; d < check {
		check = d
	}
	pingT := time.NewTicker(c.opts.PingInterval)
	checkT := time.NewTicker(check)
	defer pingT.Stop()
	defer checkT.Stop()
	for {
		select {
		case <-c.closing:
			return
		case <-checkT.C:
			if time.Since(time.Unix(0, c.last.Load())) > c.opts.DeadAfter {
				c.fail(ErrDead, websocket.StatusGoingAway)
				return
			}
		case <-pingT.C:
			go func() {
				ctx, cancel := context.WithTimeout(c.ctx, c.opts.DeadAfter)
				defer cancel()
				if c.ws.Ping(ctx) == nil {
					c.touch()
				}
			}()
		}
	}
}
