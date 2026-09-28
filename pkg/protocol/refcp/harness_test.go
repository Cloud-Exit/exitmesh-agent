package refcp_test

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client/clienttest"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type harness struct {
	t        *testing.T
	cp       *refcp.Server
	srv      *httptest.Server
	endpoint string
	caFile   string
	clock    *clienttest.Clock
	cpClock  *clienttest.Clock
}

func newHarness(t *testing.T, opts refcp.Options) *harness {
	t.Helper()
	h := &harness{t: t, clock: clienttest.NewClock(t0), cpClock: clienttest.NewClock(t0)}
	if opts.Now == nil {
		opts.Now = h.cpClock.Now
	}
	h.cp = refcp.New(opts)
	h.srv = httptest.NewTLSServer(h.cp)
	t.Cleanup(func() {
		h.cp.Close()
		h.srv.Close()
	})
	h.endpoint = strings.TrimPrefix(h.srv.URL, "https://")
	h.caFile = filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.srv.Certificate().Raw})
	if err := os.WriteFile(h.caFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) tunnelOptions(cred func() string) tunnel.Options {
	return tunnel.Options{Endpoint: h.endpoint, CAFile: h.caFile, Credential: cred}
}

func (h *harness) newStore(machineID string) *client.MemStore {
	h.t.Helper()
	s, err := client.NewMemStore(client.MemOptions{Now: h.clock.Now, Identity: client.Identity{MachineID: machineID}})
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func (h *harness) enroll(store *client.MemStore, token, targetType string) error {
	id := store.Identity()
	res, err := tunnel.Enroll(context.Background(), h.tunnelOptions(nil), protocol.EnrollRequest{
		Token: token, WriterID: store.WriterID(), TargetType: targetType, MachineID: id.MachineID,
		Agent: protocol.AgentInfo{Version: "0.1.0", Protocol: 1, Schema: 1, Engine: 1},
	})
	if err != nil {
		return err
	}
	id.TargetID, id.TargetType, id.Credential, id.CredentialID = res.TargetID, targetType, res.Credential, res.CredentialID
	return store.SetIdentity(id)
}

// target creates a target and one enrolled writer with its initial epoch prepared.
func (h *harness) target(targetType, machineID string) (string, string, *clienttest.Writer) {
	h.t.Helper()
	tid, tok, err := h.cp.CreateTarget(targetType)
	if err != nil {
		h.t.Fatal(err)
	}
	store := h.newStore(machineID)
	if err := h.enroll(store, tok, targetType); err != nil {
		h.t.Fatal(err)
	}
	w := clienttest.NewWriter(store, h.clock)
	h.prepare(w)
	return tid, tok, w
}

func (h *harness) prepare(w *clienttest.Writer) {
	h.t.Helper()
	c, err := h.client(w, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := c.Prepare(); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) client(w *clienttest.Writer, mod func(*client.Options)) (*client.Client, error) {
	store := w.Store
	tr, err := tunnel.New(h.tunnelOptions(func() string { return store.Identity().Credential }))
	if err != nil {
		return nil, err
	}
	opts := client.Options{
		Store: store, Transport: tr, Hooks: w, Agent: protocol.AgentInfo{Version: "0.1.0", Role: "coordinator"},
		BackoffBase: 5 * time.Millisecond, BackoffMax: 40 * time.Millisecond, HealthInterval: -1,
	}
	if mod != nil {
		mod(&opts)
	}
	return client.New(opts)
}

type proc struct {
	t      *testing.T
	w      *clienttest.Writer
	c      *client.Client
	cancel context.CancelFunc
	done   chan error
}

func (h *harness) start(w *clienttest.Writer, mod func(*client.Options)) *proc {
	h.t.Helper()
	c, err := h.client(w, mod)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &proc{t: h.t, w: w, c: c, cancel: cancel, done: make(chan error, 1)}
	go func() { p.done <- c.Run(ctx) }()
	h.t.Cleanup(func() { p.stop() })
	return p
}

func (p *proc) stop() error {
	p.cancel()
	select {
	case err := <-p.done:
		p.done <- err
		return err
	case <-time.After(10 * time.Second):
		p.t.Fatal("client did not stop")
		return nil
	}
}

// exit waits for Run to return on its own.
func (p *proc) exit() error {
	p.t.Helper()
	select {
	case err := <-p.done:
		p.done <- err
		return err
	case <-time.After(10 * time.Second):
		p.t.Fatalf("client did not exit; status %+v", p.c.Status())
		return nil
	}
}

func stopCode(err error) string {
	var se *client.StopError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(3 * time.Millisecond)
	}
}

// drained reports whether every record the writer assigned in its current epoch is committed.
func drained(w *clienttest.Writer) bool {
	ep, ok := w.Store.Epoch()
	if !ok || ep.Chain.Head == 0 {
		return false
	}
	lc, ok := w.Store.LastCommitted()
	return ok && lc.Seq == ep.Chain.Head && len(w.Store.Entries(0)) == 0
}

func (h *harness) waitDrained(w *clienttest.Writer) {
	h.t.Helper()
	waitFor(h.t, "spool drained", func() bool { return drained(w) })
}

func (h *harness) epochs(tid string) []refcp.EpochView {
	h.t.Helper()
	eps, err := h.cp.Epochs(tid)
	if err != nil {
		h.t.Fatal(err)
	}
	return eps
}

func currentEpoch(w *clienttest.Writer) protocol.EpochID {
	ep, _ := w.Store.Epoch()
	return ep.ID
}

// assertReconstruction requires reconstruction to equal the writer's state at every committed sequence outside ranges.
func assertReconstruction(t *testing.T, cp *refcp.Server, tid string, owners map[protocol.EpochID]*clienttest.Writer) {
	t.Helper()
	eps, err := cp.Epochs(tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != len(owners) {
		t.Fatalf("control plane has %d epochs, expected %d", len(eps), len(owners))
	}
	for _, ep := range eps {
		w := owners[ep.ID]
		if w == nil {
			t.Fatalf("no expected writer for epoch %s", ep.ID)
		}
		want := w.StateHashes(ep.ID)
		spans, err := cp.Unavailable(tid, ep.ID)
		if err != nil {
			t.Fatal(err)
		}
		for seq := uint64(1); seq <= ep.Head.Seq; seq++ {
			got, err := cp.StateHashAt(tid, ep.ID, seq)
			if protocol.IsUnavailable(spans, seq) {
				if !errors.Is(err, protocol.ErrUnavailable) {
					t.Fatalf("epoch %s seq %d inside a range: err %v", ep.ID, seq, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("epoch %s seq %d: %v", ep.ID, seq, err)
			}
			exp, ok := want[seq]
			if !ok {
				t.Fatalf("epoch %s seq %d committed but never assigned by the writer", ep.ID, seq)
			}
			if got != exp {
				t.Fatalf("epoch %s seq %d: reconstructed %s, writer state %s", ep.ID, seq, got, exp)
			}
			if ep.Head.Seq <= 150 || seq%7 == 0 || seq == ep.Head.Seq {
				st, err := cp.StateAt(tid, ep.ID, seq)
				if err != nil || st.Hash() != exp {
					t.Fatalf("epoch %s seq %d: StateAt %v", ep.ID, seq, err)
				}
			}
		}
	}
}

func deployment(uid string, replicas int) protocol.Op {
	return protocol.Create(uid, "apps/Deployment", "default", "web-"+uid, map[string]any{"replicas": replicas, "image": "nginx:1"})
}

func mustApply(t *testing.T, w *clienttest.Writer, ops ...protocol.Op) uint64 {
	t.Helper()
	seq, err := w.Apply(ops...)
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

func mustFire(t *testing.T, w *clienttest.Writer, key string) string {
	t.Helper()
	id, _, err := w.Fire(key)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustResolve(t *testing.T, w *clienttest.Writer, key string) {
	t.Helper()
	if _, err := w.Resolve(key); err != nil {
		t.Fatal(err)
	}
}

// workload appends n deltas touching resources, edges, and scopes.
func workload(t *testing.T, w *clienttest.Writer, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		uid := fmt.Sprintf("%s-%d", prefix, i)
		mustApply(t, w, deployment(uid, i))
		attrs := map[string]any{"w": i}
		mustApply(t, w, protocol.Update(uid, map[string]any{"replicas": i + 1}), protocol.EdgeAdd(uid, "owns", uid+"-rs", attrs))
		if i%3 == 0 {
			next := map[string]any{"w": i + 100}
			mustApply(t, w, protocol.EdgeReplace(uid, "owns", uid+"-rs", next, attrs))
			attrs = next
		}
		if i%4 == 0 {
			mustApply(t, w, protocol.EdgeRemove(uid, "owns", uid+"-rs", attrs), protocol.Delete(uid, protocol.DeleteDeleted))
		}
		w.Clock.Advance(time.Minute)
	}
}

func auditCount(cp *refcp.Server, tid, event, code string) int {
	n := 0
	for _, e := range cp.Audit(tid) {
		if e.Event == event && (code == "" || e.Code == code) {
			n++
		}
	}
	return n
}
