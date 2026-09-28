package spool

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

type stateHooks struct {
	mu sync.Mutex
	st *protocol.State
}

func (h *stateHooks) CaptureReplay(tx client.CaptureTx) (protocol.SummaryParams, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, err := client.AppendCheckpoint(tx, h.st, protocol.Interval{}, []string{"inventory"})
	if err != nil {
		return protocol.SummaryParams{}, err
	}
	return protocol.SummaryParams{Epoch: tx.Epoch().ID, Watermark: e.Seq, Head: tx.Committed(), Entries: []protocol.SummaryEntry{}}, nil
}

func (h *stateHooks) Rebaseline(tx client.CaptureTx) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := client.AppendCheckpoint(tx, h.st, protocol.Interval{}, []string{"inventory"})
	return err
}

func (h *stateHooks) BundleAvailable(protocol.BundleAvailableParams)             {}
func (h *stateHooks) Tools() []client.Tool                                       { return nil }
func (h *stateHooks) Tool(context.Context, string, json.RawMessage) (any, error) { return nil, nil }
func (h *stateHooks) Health() any                                                { return map[string]any{} }

func (h *stateHooks) apply(t *testing.T, s *Spool, ops ...protocol.Op) {
	t.Helper()
	err := s.Do(func(tx *Tx) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: ops}}, nil
		}); err != nil {
			return err
		}
		return h.st.ApplyOps(ops)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientStoreEndToEnd(t *testing.T) {
	cp := refcp.New(refcp.Options{})
	srv := httptest.NewTLSServer(cp)
	defer func() { cp.Close(); srv.Close() }()
	endpoint := strings.TrimPrefix(srv.URL, "https://")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tid, tok, err := cp.CreateTarget(protocol.TargetKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, CapacityBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	store := ClientStore{S: s}
	res, err := tunnel.Enroll(context.Background(), tunnel.Options{Endpoint: endpoint, CAFile: caFile}, protocol.EnrollRequest{
		Token: tok, WriterID: store.WriterID(), TargetType: protocol.TargetKubernetes, Agent: protocol.AgentInfo{Version: "test", Protocol: 1, Schema: 1, Engine: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIdentity(client.Identity{TargetID: res.TargetID, TargetType: protocol.TargetKubernetes, Credential: res.Credential, CredentialID: res.CredentialID}); err != nil {
		t.Fatal(err)
	}
	hooks := &stateHooks{st: protocol.NewState()}
	run := func(s *Spool) (context.CancelFunc, chan error) {
		st := ClientStore{S: s}
		tr, err := tunnel.New(tunnel.Options{Endpoint: endpoint, CAFile: caFile, Credential: func() string { return st.Identity().Credential }})
		if err != nil {
			t.Fatal(err)
		}
		c, err := client.New(client.Options{Store: st, Transport: tr, Hooks: hooks, Agent: protocol.AgentInfo{Version: "test", Role: "coordinator"},
			BackoffBase: 5 * time.Millisecond, BackoffMax: 40 * time.Millisecond, HealthInterval: -1})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Prepare(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		return cancel, done
	}
	// Records written before the first connection are replayed after it.
	cancel, done := run(s)
	hooks.apply(t, s, protocol.Create("u1", "Pod", "ns", "a", map[string]any{"phase": "Running"}))
	hooks.apply(t, s, protocol.Update("u1", map[string]any{"phase": "Failed"}), protocol.EdgeAdd("u1", "runs-on", "n1", nil))
	waitCommitted(t, s, 3)
	cancel()
	<-done
	// Restart: new incarnation, same epoch, offline appends replay on reconnect.
	ep1, _ := s.Epoch()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(Options{Dir: dir, CapacityBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hooks.apply(t, s, protocol.Create("u2", "Pod", "ns", "b", nil))
	hooks.apply(t, s, protocol.Delete("u1", protocol.DeleteDeleted))
	cancel, done = run(s)
	defer func() { cancel(); <-done }()
	ep2, _ := s.Epoch()
	if ep1.ID != ep2.ID {
		t.Fatal("restart changed the epoch")
	}
	head := waitCommitted(t, s, 6)
	h, err := cp.StateHashAt(tid, ep2.ID, head)
	if err != nil {
		t.Fatal(err)
	}
	hooks.mu.Lock()
	want := hooks.st.Hash()
	hooks.mu.Unlock()
	if h != want {
		t.Fatal("control plane state differs from writer state")
	}
}

func waitCommitted(t *testing.T, s *Spool, atLeast uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if lc, ok := s.LastCommitted(); ok && lc.Seq >= atLeast && len(s.Entries(0)) == 0 {
			return lc.Seq
		}
		time.Sleep(10 * time.Millisecond)
	}
	lc, _ := s.LastCommitted()
	t.Fatalf("committed head %d, want at least %d", lc.Seq, atLeast)
	return 0
}
