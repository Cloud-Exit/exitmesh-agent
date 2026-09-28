package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
)

type sent struct {
	method string
	params json.RawMessage
}

// fakeCP is a scriptable control plane on the client.Transport interface.
type fakeCP struct {
	mu        sync.Mutex
	window    int64
	hello     func(n int, p protocol.HelloParams) (*protocol.HelloResult, error)
	frame     func(c *fakeConn, recs []*protocol.Record) bool
	dialErr   func(n int) error
	calls     map[string]func(json.RawMessage) (any, error)
	chains    map[protocol.EpochID]*protocol.Chain
	pending   map[protocol.EpochID]map[uint64]*protocol.Record
	hellos    []protocol.HelloParams
	summaries []protocol.SummaryParams
	frames    [][]*protocol.Record
	notes     []sent
	conns     []*fakeConn
	dials     int
}

func newFakeCP() *fakeCP {
	return &fakeCP{chains: map[protocol.EpochID]*protocol.Chain{}, pending: map[protocol.EpochID]map[uint64]*protocol.Record{}, calls: map[string]func(json.RawMessage) (any, error){}}
}

func (f *fakeCP) Dial(ctx context.Context) (client.Conn, error) {
	f.mu.Lock()
	f.dials++
	n := f.dials
	derr := f.dialErr
	f.mu.Unlock()
	if derr != nil {
		if err := derr(n); err != nil {
			return nil, err
		}
	}
	c := &fakeConn{cp: f, done: make(chan struct{})}
	f.mu.Lock()
	f.conns = append(f.conns, c)
	f.mu.Unlock()
	return c, nil
}

// head returns the committed head the fake holds for an epoch.
func (f *fakeCP) head(p protocol.HelloParams) protocol.ChainPoint {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.chains[p.Epoch]
	if c == nil {
		c = protocol.NewChain(p.TargetID, p.Epoch, p.WriterID)
		f.chains[p.Epoch] = c
		f.pending[p.Epoch] = map[uint64]*protocol.Record{}
	}
	return protocol.ChainPoint{Seq: c.Head, ChainHash: c.HeadHash}
}

func (f *fakeCP) acceptHello(n int, p protocol.HelloParams) (*protocol.HelloResult, error) {
	d := protocol.DecisionResume
	if p.EpochOpen != nil {
		d = protocol.DecisionOpened
	}
	return &protocol.HelloResult{Decision: d, SessionID: "s", Epoch: p.Epoch, Head: f.head(p), WindowBytes: f.window}, nil
}

// commit applies records in chain order, holding replay anchors that arrive early; it reports progress.
func (f *fakeCP) commit(recs []*protocol.Record) (protocol.AckParams, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ep protocol.EpochID
	moved := false
	for _, r := range recs {
		ep = r.Epoch
		c := f.chains[r.Epoch]
		if r.Parent != c.Head {
			f.pending[r.Epoch][r.Seq] = r
			continue
		}
		if _, err := c.Append(r); err != nil {
			panic(err)
		}
		moved = true
		for {
			p, ok := f.pending[r.Epoch][c.Head+1]
			if !ok {
				break
			}
			delete(f.pending[r.Epoch], p.Seq)
			if _, err := c.Append(p); err != nil {
				panic(err)
			}
		}
	}
	c := f.chains[ep]
	return protocol.AckParams{Epoch: ep, Seq: c.Head, ChainHash: c.HeadHash}, moved
}

func (f *fakeCP) conn(i int) *fakeConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns[i]
}

func (f *fakeCP) snapshot() ([]protocol.HelloParams, []protocol.SummaryParams, [][]*protocol.Record, []sent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]protocol.HelloParams(nil), f.hellos...), append([]protocol.SummaryParams(nil), f.summaries...),
		append([][]*protocol.Record(nil), f.frames...), append([]sent(nil), f.notes...)
}

type fakeConn struct {
	cp      *fakeCP
	mu      sync.Mutex
	handler client.Handler
	done    chan struct{}
	once    sync.Once
}

func (c *fakeConn) Call(ctx context.Context, method string, params, result any) error {
	b, err := json.Marshal(params)
	if err != nil {
		return err
	}
	f := c.cp
	var res any
	switch method {
	case protocol.MethodHello:
		var p protocol.HelloParams
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		f.mu.Lock()
		f.hellos = append(f.hellos, p)
		n := len(f.hellos)
		h := f.hello
		f.mu.Unlock()
		if h == nil {
			h = f.acceptHello
		}
		r, err := h(n, p)
		if err != nil {
			return err
		}
		res = r
	case protocol.MethodSummary:
		var p protocol.SummaryParams
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		f.mu.Lock()
		f.summaries = append(f.summaries, p)
		f.mu.Unlock()
		res = struct{}{}
	default:
		f.mu.Lock()
		fn := f.calls[method]
		f.mu.Unlock()
		if fn == nil {
			return &protocol.RPCError{Code: protocol.RPCMethodNotFound, Message: method}
		}
		if res, err = fn(b); err != nil {
			return err
		}
	}
	if result == nil {
		return nil
	}
	rb, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return json.Unmarshal(rb, result)
}

func (c *fakeConn) Notify(ctx context.Context, method string, params any) error {
	b, err := json.Marshal(params)
	if err != nil {
		return err
	}
	c.cp.mu.Lock()
	c.cp.notes = append(c.cp.notes, sent{method, b})
	c.cp.mu.Unlock()
	return nil
}

func (c *fakeConn) SendBinary(ctx context.Context, frame []byte) error {
	select {
	case <-c.done:
		return errors.New("closed")
	default:
	}
	bs, err := protocol.DecodeBatchFrame(frame)
	if err != nil {
		return err
	}
	recs := make([]*protocol.Record, len(bs))
	for i, b := range bs {
		if recs[i], err = protocol.Decode(b); err != nil {
			return err
		}
	}
	c.cp.mu.Lock()
	c.cp.frames = append(c.cp.frames, recs)
	fr := c.cp.frame
	c.cp.mu.Unlock()
	if fr != nil && !fr(c, recs) {
		return nil
	}
	if ack, moved := c.cp.commit(recs); moved {
		c.deliver(protocol.MethodAck, ack)
	}
	return nil
}

func (c *fakeConn) Handle(h client.Handler) {
	c.mu.Lock()
	c.handler = h
	c.mu.Unlock()
}

func (c *fakeConn) Done() <-chan struct{} { return c.done }

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

// deliver sends a notification to the client.
func (c *fakeConn) deliver(method string, params any) {
	c.mu.Lock()
	h := c.handler
	c.mu.Unlock()
	b, _ := json.Marshal(params)
	_, _ = h(context.Background(), &client.Request{Method: method, Params: b, Notification: true})
}

// request sends a request to the client and returns its JSON result.
func (c *fakeConn) request(method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	h := c.handler
	c.mu.Unlock()
	var b json.RawMessage
	if params != nil {
		b, _ = json.Marshal(params)
	}
	res, err := h(context.Background(), &client.Request{Method: method, Params: b})
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

type run struct {
	c      *client.Client
	cancel context.CancelFunc
	done   chan error
}

func startClient(t *testing.T, w *clienttest.Writer, cp *fakeCP, mod func(*client.Options)) *run {
	t.Helper()
	opts := client.Options{
		Store: w.Store, Transport: cp, Hooks: w, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond,
		HealthInterval: -1, Agent: protocol.AgentInfo{Version: "0.1.0", Role: "host", Platform: "linux/amd64"},
	}
	if mod != nil {
		mod(&opts)
	}
	c, err := client.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{c: c, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-r.done
		r.done <- nil
	})
	return r
}

func (r *run) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("client did not exit")
		return nil
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func newWriter(t *testing.T, machineID string) *clienttest.Writer {
	t.Helper()
	clock := clienttest.NewClock(testTime)
	s, err := client.NewMemStore(client.MemOptions{Now: clock.Now, Identity: client.Identity{
		TargetID: "t-1", TargetType: protocol.TargetHost, Credential: "cred", CredentialID: "c-1", MachineID: machineID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	w := clienttest.NewWriter(s, clock)
	c, err := client.New(client.Options{Store: s, Transport: newFakeCP(), Hooks: w})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Prepare(); err != nil {
		t.Fatal(err)
	}
	return w
}

func isDrained(w *clienttest.Writer) bool {
	ep, _ := w.Store.Epoch()
	lc, ok := w.Store.LastCommitted()
	return ok && lc.Seq == ep.Chain.Head && len(w.Store.Entries(0)) == 0
}
