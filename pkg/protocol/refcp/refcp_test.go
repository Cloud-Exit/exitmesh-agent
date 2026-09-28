package refcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

type note struct {
	method string
	params json.RawMessage
}

// rawWriter drives the tunnel directly to exercise control plane checks an honest client never triggers.
type rawWriter struct {
	t      *testing.T
	h      *harness
	tid    string
	cred   string
	writer protocol.WriterID
	epoch  protocol.EpochID
	chain  *protocol.Chain
	state  *protocol.State
	conn   client.Conn
	notes  chan note
}

func (h *harness) rawWriter(targetType string) *rawWriter {
	t := h.t
	tid, tok, err := h.cp.CreateTarget(targetType)
	if err != nil {
		t.Fatal(err)
	}
	wid, _ := protocol.NewWriterID()
	res, err := tunnel.Enroll(context.Background(), h.tunnelOptions(nil), protocol.EnrollRequest{Token: tok, WriterID: wid, TargetType: targetType, MachineID: "m-1"})
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := protocol.NewEpoch(t0)
	r := &rawWriter{t: t, h: h, tid: tid, cred: res.Credential, writer: wid, epoch: ep, chain: protocol.NewChain(tid, ep, wid), state: protocol.NewState()}
	r.dial()
	return r
}

func (r *rawWriter) dial() {
	tr, err := tunnel.New(r.h.tunnelOptions(func() string { return r.cred }))
	if err != nil {
		r.t.Fatal(err)
	}
	conn, err := tr.Dial(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	r.conn, r.notes = conn, make(chan note, 64)
	notes := r.notes
	conn.Handle(func(_ context.Context, req *client.Request) (any, error) {
		notes <- note{req.Method, req.Params}
		return struct{}{}, nil
	})
	r.t.Cleanup(func() { _ = conn.Close() })
}

func (r *rawWriter) hello(inc uint64, lc *protocol.ChainPoint) (*protocol.HelloResult, error) {
	p := protocol.HelloParams{
		TargetID: r.tid, WriterID: r.writer, Incarnation: inc, Epoch: r.epoch, LastCommitted: lc, MachineID: "m-1",
		EpochOpen: &protocol.EpochOpen{Reason: protocol.OpenInitial}, Agent: protocol.AgentInfo{Protocol: 1, Schema: 1},
	}
	var res protocol.HelloResult
	err := r.conn.Call(context.Background(), protocol.MethodHello, p, &res)
	return &res, err
}

func (r *rawWriter) build(t protocol.RecordType, body func(env protocol.Envelope) *protocol.Record) *protocol.Record {
	rec := body(r.chain.Next(t, 1, uint64(t0.UnixMilli())))
	if _, err := protocol.Encode(rec); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.chain.Append(rec); err != nil {
		r.t.Fatal(err)
	}
	if err := r.state.ApplyRecord(rec); err != nil {
		r.t.Fatal(err)
	}
	return rec
}

func (r *rawWriter) checkpoint(reason protocol.CheckpointReason, st *protocol.State) *protocol.Record {
	return r.build(protocol.TypeCheckpoint, func(env protocol.Envelope) *protocol.Record {
		return &protocol.Record{Envelope: env, Checkpoint: st.Checkpoint(reason, protocol.Interval{}, nil)}
	})
}

func (r *rawWriter) delta(ops ...protocol.Op) *protocol.Record {
	return r.build(protocol.TypeDelta, func(env protocol.Envelope) *protocol.Record {
		return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: ops}}
	})
}

func (r *rawWriter) send(recs ...*protocol.Record) {
	var b [][]byte
	for _, rec := range recs {
		b = append(b, rec.Bytes())
	}
	f, err := protocol.EncodeBatchFrame(b, false)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.conn.SendBinary(context.Background(), f); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawWriter) expect(method string, v any) {
	r.t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case n := <-r.notes:
			if n.method != method {
				continue
			}
			if v != nil {
				if err := json.Unmarshal(n.params, v); err != nil {
					r.t.Fatal(err)
				}
			}
			return
		case <-timeout:
			r.t.Fatalf("no %s", method)
		}
	}
}

func TestRecordIdempotencyAndDivergence(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	r := h.rawWriter(protocol.TargetKubernetes)
	if res, err := r.hello(1, nil); err != nil || res.Decision != protocol.DecisionOpened || res.Head.Seq != 0 {
		t.Fatalf("hello %+v %v", res, err)
	}
	c1 := r.checkpoint(protocol.ReasonInitial, r.state)
	d2 := r.delta(deployment("a", 1))
	r.send(c1, d2)
	var ack protocol.AckParams
	r.expect(protocol.MethodAck, &ack)
	if ack.Seq != 2 || ack.ChainHash != r.chain.HeadHash {
		t.Fatalf("ack %+v", ack)
	}
	r.send(d2)
	r.expect(protocol.MethodAck, &ack)
	if st, _ := h.cp.Stats(r.tid); st.Duplicates != 1 || ack.Seq != 2 {
		t.Fatalf("duplicate: %+v ack %+v", st, ack)
	}
	other := &protocol.Record{Envelope: d2.Envelope, Delta: &protocol.Delta{Ops: []protocol.Op{deployment("b", 1)}}}
	if _, err := protocol.Encode(other); err != nil {
		t.Fatal(err)
	}
	r.send(other)
	var rej protocol.RejectParams
	r.expect(protocol.MethodReject, &rej)
	if rej.Code != protocol.CodeDivergence || rej.Seq != 2 {
		t.Fatalf("reject %+v", rej)
	}
	alarms := 0
	for _, e := range h.cp.Audit(r.tid) {
		if e.Alarm && e.Code == protocol.CodeDivergence {
			alarms++
		}
	}
	if alarms != 1 {
		t.Fatalf("divergence alarms %d", alarms)
	}
	gap := r.delta(deployment("c", 1))
	gap2 := r.delta(deployment("d", 1))
	r.send(gap2)
	r.expect(protocol.MethodReject, &rej)
	if rej.Code != protocol.ErrInvalidChain.Code || rej.Seq != gap2.Seq {
		t.Fatalf("gap reject %+v", rej)
	}
	r.send(gap, gap2)
	r.expect(protocol.MethodAck, &ack)
	if ack.Seq != gap2.Seq {
		t.Fatalf("ack after gap %+v", ack)
	}
	bad := r.chain.Next(protocol.TypeDelta, 1, 0)
	badRec := &protocol.Record{Envelope: bad, Delta: &protocol.Delta{Ops: []protocol.Op{protocol.Update("missing", map[string]any{"x": 1})}}}
	if _, err := protocol.Encode(badRec); err != nil {
		t.Fatal(err)
	}
	r.send(badRec)
	r.expect(protocol.MethodReject, &rej)
	if rej.Code != protocol.ErrInvalidOp.Code {
		t.Fatalf("invalid op reject %+v", rej)
	}
	if err := r.conn.SendBinary(context.Background(), []byte{0x09, 0x00}); err != nil {
		t.Fatal(err)
	}
	r.expect(protocol.MethodReject, &rej)
	if rej.Code != protocol.ErrUnsupportedField.Code {
		t.Fatalf("bad frame reject %+v", rej)
	}
}

func TestPendingReplayAnchor(t *testing.T) {
	for _, match := range []bool{true, false} {
		h := newHarness(t, refcp.Options{})
		r := h.rawWriter(protocol.TargetKubernetes)
		if _, err := r.hello(1, nil); err != nil {
			t.Fatal(err)
		}
		c1 := r.checkpoint(protocol.ReasonInitial, r.state)
		d2 := r.delta(deployment("a", 1))
		d3 := r.delta(protocol.Update("a", map[string]any{"replicas": 2}))
		st := r.state.Clone()
		if !match {
			st.Resources["ghost"] = &protocol.Resource{UID: "ghost", Kind: "Pod", Fields: map[string]any{}}
		}
		w4 := r.checkpoint(protocol.ReasonReplayAnchor, st)
		if err := r.conn.Call(context.Background(), protocol.MethodSummary, protocol.SummaryParams{Epoch: r.epoch, Watermark: 4, Entries: []protocol.SummaryEntry{}}, nil); err != nil {
			t.Fatal(err)
		}
		r.send(w4)
		waitFor(t, "pending anchor", func() bool { return len(h.epochs(r.tid)[0].Pending) == 1 })
		r.send(w4)
		r.send(c1, d2)
		var ack protocol.AckParams
		r.expect(protocol.MethodAck, &ack)
		r.expect(protocol.MethodAck, &ack)
		if ack.Seq != 2 {
			t.Fatalf("ack before anchor %+v", ack)
		}
		r.send(d3)
		r.expect(protocol.MethodAck, &ack)
		if ack.Seq != 4 || ack.ChainHash != r.chain.HeadHash {
			t.Fatalf("anchor not committed with its predecessors: %+v", ack)
		}
		b, _ := h.cp.Boundaries(r.tid)
		if match != (len(b) == 0) {
			t.Fatalf("match %v boundaries %+v", match, b)
		}
		if st, _ := h.cp.Stats(r.tid); st.Duplicates != 1 {
			t.Fatalf("stats %+v", st)
		}
	}
}

func TestSupersededSessionFrames(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	r := h.rawWriter(protocol.TargetKubernetes)
	if _, err := r.hello(1, nil); err != nil {
		t.Fatal(err)
	}
	c1 := r.checkpoint(protocol.ReasonInitial, r.state)
	r.send(c1)
	r.expect(protocol.MethodAck, nil)
	old := r.conn
	oldNotes := r.notes
	r.dial()
	if _, err := r.hello(1, nil); client.RPCErrorCode(err) != protocol.CodeIdentityConflict {
		t.Fatalf("same incarnation while attached: %v", err)
	}
	r.dial()
	res, err := r.hello(2, &protocol.ChainPoint{Seq: 1, ChainHash: r.chain.HeadHash})
	if err != nil || res.Decision != protocol.DecisionResume || res.Head.Seq != 1 {
		t.Fatalf("resume %+v %v", res, err)
	}
	var sup protocol.SupersededParams
	r.notes, r.conn = oldNotes, old
	r.expect(protocol.MethodSuperseded, &sup)
	r.send(r.delta(deployment("late", 1)))
	waitFor(t, "rejected superseded frame", func() bool { return auditCount(h.cp, r.tid, "frame_rejected", "") == 1 })
	if heads, _ := h.cp.Heads(r.tid); heads[r.epoch].Seq != 1 {
		t.Fatalf("superseded frame applied: %+v", heads)
	}
	if n := auditCount(h.cp, r.tid, "hello", protocol.CodeIdentityConflict); n != 1 {
		t.Fatalf("row 8 audits %d", n)
	}
	if _, err := r.hello(3, nil); client.RPCErrorCode(err) != protocol.CodeInvalidHello {
		t.Fatalf("second hello on a session: %v", err)
	}
}

func TestEnrollmentErrors(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, tok, _ := h.cp.CreateTarget(protocol.TargetHost)
	wid, _ := protocol.NewWriterID()
	enroll := func(req protocol.EnrollRequest) error {
		_, err := tunnel.Enroll(context.Background(), h.tunnelOptions(nil), req)
		return err
	}
	if err := enroll(protocol.EnrollRequest{Token: "emx1_h_" + tid + "_wrongsecretwrongsecret", WriterID: wid, TargetType: protocol.TargetHost, MachineID: "m"}); client.RPCErrorCode(err) != protocol.CodeUnauthorized {
		t.Fatalf("wrong secret: %v", err)
	}
	if err := enroll(protocol.EnrollRequest{Token: "garbage", WriterID: wid, TargetType: protocol.TargetHost}); client.RPCErrorCode(err) != protocol.CodeUnauthorized {
		t.Fatalf("garbage token: %v", err)
	}
	for _, req := range []protocol.EnrollRequest{
		{Token: tok, WriterID: wid, TargetType: protocol.TargetKubernetes, MachineID: "m"},
		{Token: tok, TargetType: protocol.TargetHost, MachineID: "m"},
		{Token: tok, WriterID: wid, TargetType: protocol.TargetHost},
	} {
		if err := enroll(req); err == nil || client.RPCErrorCode(err) != "" {
			t.Fatalf("invalid request accepted or misclassified: %+v %v", req, err)
		}
	}
	h.cp.SetUnavailable(true)
	if err := enroll(protocol.EnrollRequest{Token: tok, WriterID: wid, TargetType: protocol.TargetHost, MachineID: "m"}); err == nil {
		t.Fatal("enrolled while unavailable")
	}
	h.cp.SetUnavailable(false)
	resp, err := h.srv.Client().Get(h.srv.URL + protocol.EnrollPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET enroll: %d", resp.StatusCode)
	}
	resp, err = h.srv.Client().Get(h.srv.URL + protocol.TunnelPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tunnel without bearer: %d", resp.StatusCode)
	}
	if _, _, err := h.cp.CreateTarget("vm"); err == nil {
		t.Fatal("unknown target type accepted")
	}
	if err := h.cp.BindHost("nope"); !errors.Is(err, refcp.ErrUnknownTarget) {
		t.Fatalf("bind unknown: %v", err)
	}
}

func TestQueryErrors(t *testing.T) {
	h := newHarness(t, refcp.Options{})
	tid, _, w := h.target(protocol.TargetKubernetes, "")
	if _, err := h.cp.StateAt("nope", protocol.EpochID{}, 1); !errors.Is(err, refcp.ErrUnknownTarget) {
		t.Fatalf("unknown target: %v", err)
	}
	h.start(w, nil)
	h.waitDrained(w)
	ep := currentEpoch(w)
	if _, err := h.cp.StateAt(tid, protocol.EpochID{1}, 1); !errors.Is(err, refcp.ErrUnknownEpoch) {
		t.Fatalf("unknown epoch: %v", err)
	}
	if _, err := h.cp.StateHashAt(tid, ep, 99); !errors.Is(err, refcp.ErrNotCommitted) {
		t.Fatalf("above head: %v", err)
	}
	if _, err := h.cp.CallTool(context.Background(), "nope", "x", nil); !errors.Is(err, refcp.ErrUnknownTarget) {
		t.Fatalf("call unknown: %v", err)
	}
	if _, err := h.cp.RotateCredential(context.Background(), "nope"); !errors.Is(err, refcp.ErrUnknownTarget) {
		t.Fatalf("rotate unknown: %v", err)
	}
	other, _, _ := h.cp.CreateTarget(protocol.TargetKubernetes)
	if _, err := h.cp.RotateCredential(context.Background(), other); !errors.Is(err, refcp.ErrNoSession) {
		t.Fatalf("rotate detached: %v", err)
	}
	if err := h.cp.Disconnect(other); !errors.Is(err, refcp.ErrNoSession) {
		t.Fatalf("disconnect detached: %v", err)
	}
	if err := h.cp.PublishBundle(protocol.TargetKubernetes, "", nil, nil, nil); err == nil {
		t.Fatal("bundle without version accepted")
	}
	st, err := h.cp.StateAt(tid, ep, 1)
	if err != nil || !bytes.Equal([]byte(st.Hash().String()), []byte(w.StateHashes(ep)[1].String())) {
		t.Fatalf("state at 1: %v", err)
	}
}
