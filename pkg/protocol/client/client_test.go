package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
)

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
	after  func(d time.Duration)
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	cb := c.after
	c.mu.Unlock()
	if cb != nil {
		cb(d)
	}
	ch := make(chan time.Time, 1)
	ch <- c.Now()
	return ch
}

func (c *fakeClock) slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

func TestNewValidates(t *testing.T) {
	if _, err := client.New(client.Options{}); err == nil {
		t.Fatal("missing store accepted")
	}
}

// Reconnect uses exponential backoff with full jitter from 1s to 5m and resets after a session.
func TestBackoffSchedule(t *testing.T) {
	w := newWriter(t, "m")
	cp := newFakeCP()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp.dialErr = func(n int) error {
		switch {
		case n == 13:
			return nil
		case n >= 15:
			cancel()
		}
		return fmt.Errorf("dial %d refused", n)
	}
	cp.frame = func(c *fakeConn, _ []*protocol.Record) bool {
		_ = c.Close()
		return false
	}
	clk := &fakeClock{now: testTime}
	c, err := client.New(client.Options{Store: w.Store, Transport: cp, Hooks: w, Clock: clk, Jitter: func(d time.Duration) time.Duration { return d }, HealthInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	s := time.Second
	want := []time.Duration{s, 2 * s, 4 * s, 8 * s, 16 * s, 32 * s, 64 * s, 128 * s, 256 * s, 300 * s, 300 * s, 300 * s, s, 2 * s}
	got := clk.slept()
	if len(got) != len(want) {
		t.Fatalf("sleeps %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sleep %d is %v, want %v (all %v)", i, got[i], want[i], got)
		}
	}
	if st := c.Status(); st.LastError == "" || st.Sessions != 1 {
		t.Fatalf("status %+v", st)
	}
}

func TestDefaultJitterIsBounded(t *testing.T) {
	w := newWriter(t, "m")
	cp := newFakeCP()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp.dialErr = func(n int) error {
		if n > 20 {
			cancel()
		}
		return errors.New("refused")
	}
	clk := &fakeClock{now: testTime}
	c, _ := client.New(client.Options{Store: w.Store, Transport: cp, Hooks: w, Clock: clk, BackoffBase: time.Second, BackoffMax: 4 * time.Second})
	_ = c.Run(ctx)
	for _, d := range clk.slept() {
		if d < 0 || d > 4*time.Second {
			t.Fatalf("sleep %v outside [0, 4s]", d)
		}
	}
}

func TestHelloParamsAndRegistration(t *testing.T) {
	w := newWriter(t, "m-42")
	cp := newFakeCP()
	logs := &syncLog{}
	r := startClient(t, w, cp, func(o *client.Options) { o.Logger = slog.New(slog.NewTextHandler(logs, nil)) })
	eventually(t, "drain", func() bool { return isDrained(w) })
	ep, _ := w.Store.Epoch()
	if !ep.Registered {
		t.Fatal("epoch not registered")
	}
	cp.conn(0).Close()
	eventually(t, "second hello", func() bool { h, _, _, _ := cp.snapshot(); return len(h) == 2 })
	hellos, _, _, _ := cp.snapshot()
	first, second := hellos[0], hellos[1]
	if first.EpochOpen == nil || first.EpochOpen.Reason != protocol.OpenInitial || first.LastCommitted != nil {
		t.Fatalf("first hello %+v", first)
	}
	if first.MachineID != "m-42" || first.TargetType != protocol.TargetHost || first.Agent.Protocol != protocol.Version || first.Agent.Platform != "linux/amd64" || first.Incarnation != 1 {
		t.Fatalf("first hello identity %+v", first)
	}
	lc, _ := w.Store.LastCommitted()
	if second.EpochOpen != nil || second.LastCommitted == nil || *second.LastCommitted != lc {
		t.Fatalf("second hello %+v", second)
	}
	if st := r.c.Status(); st.Epoch != ep.ID || st.Head != lc.Seq || !st.Registered {
		t.Fatalf("status %+v", st)
	}
	// Each established session is visible at info, so a recovered connection is not silent.
	eventually(t, "reconnect logged", func() bool { return strings.Count(logs.String(), "history session established") == 2 })
	// One process presents one instance on every reconnect; another process presents its own.
	if first.Instance == nil || first.Instance.IsZero() || second.Instance == nil || *second.Instance != *first.Instance {
		t.Fatalf("instances across a reconnect: %v, %v", first.Instance, second.Instance)
	}
	r.cancel()
	_ = r.wait(t)
	startClient(t, w, cp, nil)
	eventually(t, "hello of a new process", func() bool { h, _, _, _ := cp.snapshot(); return len(h) == 3 })
	hellos, _, _, _ = cp.snapshot()
	if third := hellos[2]; third.Instance == nil || *third.Instance == *first.Instance {
		t.Fatalf("a new client reused instance %v", third.Instance)
	}
}

func TestReplayOrderAnchorFirst(t *testing.T) {
	w := newWriter(t, "m")
	for i := 0; i < 20; i++ {
		if _, err := w.Apply(protocol.Create(fmt.Sprint("u", i), "Pod", "ns", "p", map[string]any{"i": i})); err != nil {
			t.Fatal(err)
		}
	}
	id, _, err := w.Fire("k")
	if err != nil {
		t.Fatal(err)
	}
	cp := newFakeCP()
	r := startClient(t, w, cp, func(o *client.Options) { o.MaxBatchRecords = 4 })
	eventually(t, "drain", func() bool { return isDrained(w) })
	if _, err := w.Apply(protocol.Update("u1", map[string]any{"i": 100})); err != nil {
		t.Fatal(err)
	}
	eventually(t, "live record", func() bool { return isDrained(w) })
	_, sums, frames, _ := cp.snapshot()
	if len(sums) != 1 || sums[0].Head != 0 {
		t.Fatalf("summaries %+v", sums)
	}
	wm := sums[0].Watermark
	if len(sums[0].Entries) != 1 || sums[0].Entries[0].FindingID != id || sums[0].Entries[0].State != protocol.LifecycleFiring {
		t.Fatalf("summary entries %+v", sums[0].Entries)
	}
	if len(frames[0]) != 1 || frames[0][0].Seq != wm || frames[0][0].Checkpoint.Reason != protocol.ReasonReplayAnchor {
		t.Fatalf("first frame is not the replay anchor alone")
	}
	next := uint64(1)
	for _, f := range frames[1:] {
		if len(f) > 4 {
			t.Fatalf("batch of %d records", len(f))
		}
		for _, rec := range f {
			if rec.Seq == wm {
				t.Fatal("anchor resent")
			}
			if next == wm {
				next++
			}
			if rec.Seq != next {
				t.Fatalf("record %d sent, expected %d", rec.Seq, next)
			}
			next++
		}
	}
	if st := r.c.Status(); st.Watermark != wm || st.BacklogRecords != 0 {
		t.Fatalf("status %+v", st)
	}
}

func TestWindowBoundsInflightBytes(t *testing.T) {
	w := newWriter(t, "m")
	cp := newFakeCP()
	pad := map[string]any{"pad": "0123456789012345678901234567890123456789"}
	if _, err := w.Apply(protocol.Create("probe", "Pod", "ns", "p", pad)); err != nil {
		t.Fatal(err)
	}
	size := int64(len(w.Store.Entries(2)[0].Bytes))
	cp.window = 3 * size
	startClient(t, w, cp, func(o *client.Options) { o.MaxBatchRecords = 1 })
	eventually(t, "initial drain", func() bool { return isDrained(w) })
	var hold sync.Mutex
	var held [][]*protocol.Record
	cp.mu.Lock()
	cp.frame = func(c *fakeConn, recs []*protocol.Record) bool {
		hold.Lock()
		defer hold.Unlock()
		held = append(held, recs)
		return false
	}
	cp.mu.Unlock()
	_, _, base, _ := cp.snapshot()
	for i := 0; i < 12; i++ {
		if _, err := w.Apply(protocol.Create(fmt.Sprint("u", i), "Pod", "ns", "p", pad)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "window fills", func() bool { _, _, f, _ := cp.snapshot(); return len(f)-len(base) >= 3 })
	time.Sleep(20 * time.Millisecond)
	var inflight int64
	for _, e := range w.Store.Entries(0) {
		if e.State == client.TransmittedUnconfirmed {
			inflight += int64(len(e.Bytes))
		}
	}
	_, _, before, _ := cp.snapshot()
	if inflight > cp.window || len(before)-len(base) != 3 {
		t.Fatalf("%d bytes in %d frames in flight, window %d", inflight, len(before)-len(base), cp.window)
	}
	hold.Lock()
	queued := held
	held = nil
	cp.mu.Lock()
	cp.frame = nil
	cp.mu.Unlock()
	hold.Unlock()
	c := cp.conn(0)
	for _, recs := range queued {
		if ack, moved := cp.commit(recs); moved {
			c.deliver(protocol.MethodAck, ack)
		}
	}
	eventually(t, "drain after acks", func() bool { return isDrained(w) })
}

func TestResumeHeadVerification(t *testing.T) {
	type setup struct {
		name     string
		prep     func(w *clienttest.Writer) protocol.ChainPoint
		diverges bool
	}
	apply := func(t *testing.T, w *clienttest.Writer, n int) {
		for i := 0; i < n; i++ {
			if _, err := w.Apply(protocol.Create(fmt.Sprintf("x%d-%d", n, i), "Pod", "", "p", nil)); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []setup{
		{name: "transmitted head with matching hash", prep: func(w *clienttest.Writer) protocol.ChainPoint {
			apply(t, w, 3)
			_ = w.Store.MarkTransmitted(1, 2, 3)
			e := w.Store.Entries(3)[0]
			return protocol.ChainPoint{Seq: 3, ChainHash: e.ChainHash}
		}},
		{name: "never transmitted head with matching hash", prep: func(w *clienttest.Writer) protocol.ChainPoint {
			apply(t, w, 3)
			e := w.Store.Entries(2)[0]
			return protocol.ChainPoint{Seq: 2, ChainHash: e.ChainHash}
		}},
		{name: "hash mismatch", diverges: true, prep: func(w *clienttest.Writer) protocol.ChainPoint {
			apply(t, w, 3)
			_ = w.Store.MarkTransmitted(1, 2)
			return protocol.ChainPoint{Seq: 2, ChainHash: protocol.Hash{9}}
		}},
		{name: "head above highest assigned", diverges: true, prep: func(w *clienttest.Writer) protocol.ChainPoint {
			apply(t, w, 2)
			return protocol.ChainPoint{Seq: 10, ChainHash: protocol.Hash{9}}
		}},
		{name: "head inside a coalesced range", diverges: true, prep: func(w *clienttest.Writer) protocol.ChainPoint {
			apply(t, w, 4)
			if n, err := w.Store.Coalesce(); err != nil || n != 4 {
				t.Fatalf("coalesce %d %v", n, err)
			}
			return protocol.ChainPoint{Seq: 3, ChainHash: protocol.Hash{9}}
		}},
		{name: "head below last committed", diverges: true, prep: func(w *clienttest.Writer) protocol.ChainPoint {
			apply(t, w, 3)
			ep, _ := w.Store.Epoch()
			e := w.Store.Entries(3)[0]
			if err := w.Store.Commit(ep.ID, 3, e.ChainHash); err != nil {
				t.Fatal(err)
			}
			_ = w.Store.MarkRegistered()
			return protocol.ChainPoint{Seq: 1, ChainHash: w.Store.Entries(0)[0].ChainHash}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWriter(t, "m")
			head := tc.prep(w)
			ep, _ := w.Store.Epoch()
			cp := newFakeCP()
			cp.hello = func(n int, p protocol.HelloParams) (*protocol.HelloResult, error) {
				if n == 1 {
					return &protocol.HelloResult{Decision: protocol.DecisionResume, Epoch: p.Epoch, Head: head}, nil
				}
				return cp.acceptHello(n, p)
			}
			cp.frame = func(*fakeConn, []*protocol.Record) bool { return false }
			r := startClient(t, w, cp, nil)
			if tc.diverges {
				eventually(t, "rebaseline", func() bool { e, _ := w.Store.Epoch(); return e.ID != ep.ID })
				eventually(t, "rebaseline hello", func() bool { h, _, _, _ := cp.snapshot(); return len(h) >= 2 })
				hellos, _, _, _ := cp.snapshot()
				open := hellos[1].EpochOpen
				if open == nil || open.Reason != protocol.OpenRebaseline || *open.PrevEpoch != ep.ID || *open.PrevHead != head.Seq {
					t.Fatalf("rebaseline hello %+v", hellos[1])
				}
				if r.c.Status().Rebaselines != 1 {
					t.Fatal("rebaseline not counted")
				}
				return
			}
			eventually(t, "replay", func() bool { _, s, _, _ := cp.snapshot(); return len(s) == 1 })
			if lc, _ := w.Store.LastCommitted(); lc != head {
				t.Fatalf("committed %+v, want %+v", lc, head)
			}
			if e, _ := w.Store.Epoch(); e.ID != ep.ID {
				t.Fatal("epoch changed")
			}
			_, sums, _, _ := cp.snapshot()
			if sums[0].Head != head.Seq {
				t.Fatalf("summary head %d", sums[0].Head)
			}
		})
	}
}

func TestHelloDivergenceRebaselinesAtLastCommitted(t *testing.T) {
	w := newWriter(t, "m")
	cp := newFakeCP()
	r := startClient(t, w, cp, nil)
	eventually(t, "drain", func() bool { return isDrained(w) })
	lc, _ := w.Store.LastCommitted()
	ep, _ := w.Store.Epoch()
	cp.mu.Lock()
	cp.hello = func(n int, p protocol.HelloParams) (*protocol.HelloResult, error) {
		if p.Epoch == ep.ID {
			return nil, &protocol.RPCError{Code: protocol.RPCForbidden, Message: "row 9", Data: &protocol.RPCErrorData{Code: protocol.CodeDivergence}}
		}
		return cp.acceptHello(n, p)
	}
	cp.mu.Unlock()
	cp.conn(0).Close()
	eventually(t, "rebaseline drained", func() bool { e, _ := w.Store.Epoch(); return e.ID != ep.ID && isDrained(w) })
	e, _ := w.Store.Epoch()
	if *e.PrevHead != lc.Seq || *e.PrevEpoch != ep.ID {
		t.Fatalf("rebaseline epoch %+v", e)
	}
	_, _, frames, _ := cp.snapshot()
	var first *protocol.Record
	for _, f := range frames {
		for _, rec := range f {
			if rec.Epoch == e.ID && rec.Seq == 1 {
				first = rec
			}
		}
	}
	if first == nil || first.Checkpoint.Reason != protocol.ReasonRebaseline || *first.Checkpoint.PrevEpoch != ep.ID || *first.Checkpoint.PrevHead != lc.Seq {
		t.Fatal("new epoch does not start with a rebaseline checkpoint naming the previous epoch")
	}
	if st := r.c.Status(); st.Epoch != e.ID {
		t.Fatalf("status epoch %s", st.Epoch)
	}
}

func TestAckAndRejectHandling(t *testing.T) {
	cases := []struct {
		name   string
		act    func(c *fakeConn, ep protocol.EpochID)
		stop   string
		rebase bool
	}{
		{name: "ack with a different chain hash", rebase: true, act: func(c *fakeConn, ep protocol.EpochID) {
			c.deliver(protocol.MethodAck, protocol.AckParams{Epoch: ep, Seq: 2, ChainHash: protocol.Hash{5}})
		}},
		{name: "reject divergence", rebase: true, act: func(c *fakeConn, ep protocol.EpochID) {
			c.deliver(protocol.MethodReject, protocol.RejectParams{Epoch: ep, Seq: 2, Code: protocol.CodeDivergence})
		}},
		{name: "reject invalid chain", rebase: true, act: func(c *fakeConn, ep protocol.EpochID) {
			c.deliver(protocol.MethodReject, protocol.RejectParams{Epoch: ep, Seq: 2, Code: protocol.ErrInvalidChain.Code})
		}},
		{name: "reject epoch closed", stop: protocol.CodeEpochClosed, act: func(c *fakeConn, ep protocol.EpochID) {
			c.deliver(protocol.MethodReject, protocol.RejectParams{Epoch: ep, Seq: 2, Code: protocol.CodeEpochClosed})
		}},
		{name: "superseded", stop: client.HaltSuperseded, act: func(c *fakeConn, ep protocol.EpochID) {
			c.deliver(protocol.MethodSuperseded, protocol.SupersededParams{SessionID: "s"})
		}},
		{name: "deenrolled", stop: client.HaltDeenrolled, act: func(c *fakeConn, ep protocol.EpochID) {
			c.deliver(protocol.MethodDeenrolled, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWriter(t, "m")
			if _, err := w.Apply(protocol.Create("a", "Pod", "", "a", nil)); err != nil {
				t.Fatal(err)
			}
			cp := newFakeCP()
			cp.frame = func(*fakeConn, []*protocol.Record) bool { return false }
			r := startClient(t, w, cp, nil)
			eventually(t, "frames", func() bool { _, _, f, _ := cp.snapshot(); return len(f) >= 2 })
			ep, _ := w.Store.Epoch()
			c := cp.conn(0)
			c.deliver(protocol.MethodAck, protocol.AckParams{Epoch: protocol.EpochID{7}, Seq: 1})
			c.deliver(protocol.MethodReject, protocol.RejectParams{Epoch: protocol.EpochID{7}, Seq: 1, Code: protocol.CodeDivergence})
			tc.act(c, ep.ID)
			if tc.stop != "" {
				var se *client.StopError
				if err := r.wait(t); !errors.As(err, &se) || se.Code != tc.stop {
					t.Fatalf("run returned %v", err)
				}
				if code, _ := w.Store.Halted(); code != tc.stop {
					t.Fatalf("halt %q", code)
				}
				if tc.stop == client.HaltDeenrolled && w.Store.Identity().Credential != "" {
					t.Fatal("credential kept")
				}
				return
			}
			eventually(t, "rebaseline", func() bool { e, _ := w.Store.Epoch(); return e.ID != ep.ID })
			e, _ := w.Store.Epoch()
			if *e.PrevEpoch != ep.ID || *e.PrevHead != 0 {
				t.Fatalf("rebaseline epoch %+v", e)
			}
		})
	}
}

func TestStopOnDialUnauthorized(t *testing.T) {
	w := newWriter(t, "m")
	cp := newFakeCP()
	cp.dialErr = func(int) error {
		return fmt.Errorf("dial: %w", &protocol.RPCError{Code: protocol.RPCUnauthorized, Message: "401", Data: &protocol.RPCErrorData{Code: protocol.CodeUnauthorized}})
	}
	r := startClient(t, w, cp, nil)
	var se *client.StopError
	if err := r.wait(t); !errors.As(err, &se) || se.Code != protocol.CodeUnauthorized {
		t.Fatalf("run returned %v", err)
	}
	if st := r.c.Status(); st.Halted != protocol.CodeUnauthorized || st.LastErrorCode != protocol.CodeUnauthorized {
		t.Fatalf("status %+v", st)
	}
	c2, _ := client.New(client.Options{Store: w.Store, Transport: cp, Hooks: w})
	if err := c2.Run(context.Background()); !errors.As(err, &se) {
		t.Fatalf("halted store ran: %v", err)
	}
}

func TestNotEnrolled(t *testing.T) {
	s, _ := client.NewMemStore(client.MemOptions{})
	w := clienttest.NewWriter(s, clienttest.NewClock(testTime))
	c, _ := client.New(client.Options{Store: s, Transport: newFakeCP(), Hooks: w})
	if err := c.Run(context.Background()); !errors.Is(err, client.ErrNotEnrolled) {
		t.Fatalf("run: %v", err)
	}
}

type badHooks struct {
	*clienttest.Writer
	appends int
}

func (b *badHooks) CaptureReplay(tx client.CaptureTx) (protocol.SummaryParams, error) {
	for i := 0; i < b.appends; i++ {
		if _, err := b.Writer.CaptureReplay(tx); err != nil {
			return protocol.SummaryParams{}, err
		}
	}
	return protocol.SummaryParams{}, nil
}

func TestCaptureMustAppendOneCheckpoint(t *testing.T) {
	for _, n := range []int{0, 2} {
		w := newWriter(t, "m")
		before, _ := w.Store.Epoch()
		cp := newFakeCP()
		r := startClient(t, w, cp, func(o *client.Options) { o.Hooks = &badHooks{Writer: w, appends: n} })
		eventually(t, "failed capture", func() bool { h, _, _, _ := cp.snapshot(); return len(h) >= 2 })
		eventually(t, "capture error reported", func() bool { st := r.c.Status(); return st.LastError != "" && st.Halted == "" })
		after, _ := w.Store.Epoch()
		if after.Chain.Head != before.Chain.Head {
			t.Fatalf("failed capture left %d records", after.Chain.Head-before.Chain.Head)
		}
		if _, s, _, _ := cp.snapshot(); len(s) != 0 {
			t.Fatal("summary sent after a failed capture")
		}
	}
}

func TestReverseChannelRequests(t *testing.T) {
	w := newWriter(t, "m")
	bundles := make(chan protocol.BundleAvailableParams, 1)
	w.OnBundle = func(p protocol.BundleAvailableParams) { bundles <- p }
	cp := newFakeCP()
	cp.calls[protocol.MethodBundleFetch] = func(b json.RawMessage) (any, error) {
		var p protocol.BundleFetchParams
		_ = json.Unmarshal(b, &p)
		return protocol.BundleFetchResult{Version: "v2", Bundle: []byte(p.TargetType + ":" + p.Have)}, nil
	}
	cp.calls[protocol.MethodDeenroll] = func(json.RawMessage) (any, error) { return struct{}{}, nil }
	r := startClient(t, w, cp, func(o *client.Options) { o.HealthInterval = 5 * time.Millisecond })
	eventually(t, "drain", func() bool { return isDrained(w) })
	c := cp.conn(0)

	res, err := c.request(protocol.MethodInitialize, map[string]any{"protocolVersion": client.MCPProtocolVersion})
	var init client.InitializeResult
	if err != nil || json.Unmarshal(res, &init) != nil || init.ProtocolVersion != client.MCPProtocolVersion || init.ServerInfo.Version != "0.1.0" {
		t.Fatalf("initialize %s %v", res, err)
	}
	if res, err := c.request(protocol.MethodPing, nil); err != nil || string(res) != "{}" {
		t.Fatalf("ping %s %v", res, err)
	}
	res, err = c.request(protocol.MethodToolsList, nil)
	var tl client.ToolsListResult
	if err != nil || json.Unmarshal(res, &tl) != nil || len(tl.Tools) != 1 || tl.Tools[0].Name != "state.query" {
		t.Fatalf("tools/list %s %v", res, err)
	}
	res, err = c.request(protocol.MethodToolsCall, client.CallToolParams{Name: "state.query"})
	var ctr client.CallToolResult
	if err != nil || json.Unmarshal(res, &ctr) != nil || ctr.IsError || len(ctr.StructuredContent) == 0 {
		t.Fatalf("tools/call %s %v", res, err)
	}
	res, _ = c.request(protocol.MethodToolsCall, client.CallToolParams{Name: "nope"})
	if json.Unmarshal(res, &ctr) != nil || !ctr.IsError || ctr.Content[0].Text == "" {
		t.Fatalf("unknown tool %s", res)
	}
	for _, bad := range []any{client.CallToolParams{}, "not an object"} {
		if _, err := c.request(protocol.MethodToolsCall, bad); client.RPCErrorCode(err) != "" || err == nil {
			t.Fatalf("invalid tools/call accepted: %v", err)
		}
	}
	var re *protocol.RPCError
	if _, err := c.request("no/such", nil); !errors.As(err, &re) || re.Code != protocol.RPCMethodNotFound {
		t.Fatalf("unknown method: %v", err)
	}
	c.deliver("notifications/initialized", nil)

	if _, err := c.request(protocol.MethodCredentialRotate, protocol.CredentialRotateParams{}); err == nil {
		t.Fatal("empty credential accepted")
	}
	res, err = c.request(protocol.MethodCredentialRotate, protocol.CredentialRotateParams{Credential: "new", CredentialID: "c-2"})
	if err != nil || string(res) != "{}" {
		t.Fatalf("rotate %s %v", res, err)
	}
	if id := w.Store.Identity(); id.Credential != "new" || id.CredentialID != "c-2" {
		t.Fatalf("identity %+v", id)
	}

	c.deliver(protocol.MethodBundleAvailable, protocol.BundleAvailableParams{Version: "v2", TargetType: protocol.TargetHost})
	select {
	case p := <-bundles:
		if p.Version != "v2" {
			t.Fatalf("bundle %+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bundle hook not called")
	}
	b, err := r.c.FetchBundle(context.Background(), "v1")
	if err != nil || string(b.Bundle) != "host:v1" {
		t.Fatalf("fetch %+v %v", b, err)
	}
	if err := r.c.Audit(context.Background(), map[string]string{"request": "r"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "health", func() bool {
		_, _, _, notes := cp.snapshot()
		n := 0
		for _, s := range notes {
			if s.method == protocol.MethodHealth {
				n++
			}
		}
		return n >= 2
	})
	if err := r.c.Deenroll(context.Background(), "uninstall"); err != nil {
		t.Fatal(err)
	}
	var se *client.StopError
	if err := r.wait(t); !errors.As(err, &se) || se.Code != client.HaltDeenrolled {
		t.Fatalf("run %v", err)
	}
	if _, err := r.c.FetchBundle(context.Background(), ""); !errors.Is(err, client.ErrNotConnected) {
		t.Fatalf("fetch after stop: %v", err)
	}
	if err := r.c.Audit(context.Background(), nil); !errors.Is(err, client.ErrNotConnected) {
		t.Fatalf("audit after stop: %v", err)
	}
	if err := r.c.Deenroll(context.Background(), ""); !errors.Is(err, client.ErrNotConnected) {
		t.Fatalf("deenroll after stop: %v", err)
	}
}

func TestToolResultShapes(t *testing.T) {
	r := client.ToolResult([]int{1, 2}, nil)
	if r.IsError || r.StructuredContent != nil || r.Content[0].Text != "[1,2]" {
		t.Fatalf("array result %+v", r)
	}
	r = client.ToolResult(func() {}, nil)
	if !r.IsError {
		t.Fatal("unencodable result not an error")
	}
	r = client.ToolResult(nil, errors.New("scope denied"))
	if !r.IsError || r.Content[0].Text != "scope denied" {
		t.Fatalf("error result %+v", r)
	}
}

type syncLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
