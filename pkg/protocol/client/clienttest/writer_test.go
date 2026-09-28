package clienttest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

type tx struct {
	client.Tx
	reason    protocol.CheckpointReason
	epoch     client.EpochState
	committed uint64
}

func (t tx) Reason() protocol.CheckpointReason { return t.reason }
func (t tx) Epoch() client.EpochState          { return t.epoch }
func (t tx) Committed() uint64                 { return t.committed }

func newWriter(t *testing.T) *Writer {
	t.Helper()
	clock := NewClock(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	s, err := client.NewMemStore(client.MemOptions{Now: clock.Now, Identity: client.Identity{TargetID: "t-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenEpoch(protocol.OpenInitial, nil, nil); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(s, clock)
	ep, _ := s.Epoch()
	if err := s.Do(func(t0 client.Tx) error { return w.Rebaseline(tx{Tx: t0, reason: protocol.ReasonInitial, epoch: ep}) }); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWriterModel(t *testing.T) {
	w := newWriter(t)
	ep, _ := w.Store.Epoch()
	s1, err := w.Apply(protocol.Create("a", "Pod", "ns", "a", map[string]any{"v": 1}))
	if err != nil || s1 != 2 {
		t.Fatalf("apply %d %v", s1, err)
	}
	if _, err := w.Apply(protocol.Update("missing", map[string]any{"v": 1})); !errors.Is(err, protocol.ErrInvalidOp) {
		t.Fatalf("invalid op: %v", err)
	}
	if len(w.State().Resources) != 1 {
		t.Fatal("invalid op changed the model")
	}
	id, s2, err := w.Fire("k")
	if err != nil || id != protocol.FindingID("t-1", "k", uint64(w.Clock.Now().UnixMilli())) {
		t.Fatalf("fire %s %v", id, err)
	}
	if _, _, err := w.Fire("k"); err == nil {
		t.Fatal("second firing of an open episode accepted")
	}
	w.Clock.Advance(time.Minute)
	if _, err := w.Update("k"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Resolve("k"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Resolve("k"); !errors.Is(err, ErrNoEpisode) {
		t.Fatalf("resolve closed episode: %v", err)
	}
	if _, err := w.Update("other"); !errors.Is(err, ErrNoEpisode) {
		t.Fatalf("update unknown: %v", err)
	}
	e := w.Episodes()[id]
	if e.State != protocol.LifecycleResolved || e.Count != 3 || e.LastTransition <= e.FirstSeen {
		t.Fatalf("episode %+v", e)
	}
	hashes := w.StateHashes(ep.ID)
	if len(hashes) != 5 || hashes[s2] != hashes[s1] || hashes[1] == hashes[s1] {
		t.Fatalf("state hashes %v", hashes)
	}

	var sum protocol.SummaryParams
	err = w.Store.Do(func(t0 client.Tx) error {
		cur, _ := w.Store.Epoch()
		var err error
		sum, err = w.CaptureReplay(tx{Tx: t0, reason: protocol.ReasonReplayAnchor, epoch: cur, committed: s1})
		return err
	})
	if err != nil || len(sum.Entries) != 1 || sum.Entries[0].State != protocol.LifecycleResolved {
		t.Fatalf("capture %+v %v", sum, err)
	}
	caps := w.Captures()
	if len(caps) != 1 || caps[0].Watermark != 6 || caps[0].AnchorHash != w.State().Hash() {
		t.Fatalf("captures %+v", caps)
	}

	c := w.Clone(w.Store.Reopen())
	if _, err := c.Apply(protocol.Create("b", "Pod", "ns", "b", nil)); err != nil {
		t.Fatal(err)
	}
	if len(w.State().Resources) != 1 || len(c.State().Resources) != 2 || len(w.StateHashes(ep.ID)) == len(c.StateHashes(ep.ID)) {
		t.Fatal("clone shares the model")
	}
}

func TestWriterHooks(t *testing.T) {
	w := newWriter(t)
	for _, uid := range []string{"a", "b", "c"} {
		if _, err := w.Apply(protocol.Create(uid, "Pod", "ns", uid, nil)); err != nil {
			t.Fatal(err)
		}
	}
	res, err := w.Tool(context.Background(), "state.query", json.RawMessage(`{"limit":2}`))
	q, ok := res.(StateQueryResult)
	if err != nil || !ok || len(q.Resources) != 2 || !q.Truncated {
		t.Fatalf("state.query %+v %v", res, err)
	}
	if _, err := w.Tool(context.Background(), "state.query", json.RawMessage(`[`)); err == nil {
		t.Fatal("bad arguments accepted")
	}
	if _, err := w.Tool(context.Background(), "x", nil); err == nil {
		t.Fatal("unknown tool accepted")
	}
	if len(w.Tools()) != 1 {
		t.Fatal("tools")
	}
	got := make(chan string, 1)
	w.OnBundle = func(p protocol.BundleAvailableParams) { got <- p.Version }
	w.BundleAvailable(protocol.BundleAvailableParams{Version: "v1"})
	if <-got != "v1" || len(w.Bundles()) != 1 {
		t.Fatal("bundle hook")
	}
	if h, ok := w.Health().(map[string]any); !ok || h["backlog"] != 4 {
		t.Fatalf("health %+v", w.Health())
	}
	w.AnchorMutator = func(s *protocol.State) { delete(s.Resources, "a") }
	err = w.Store.Do(func(t0 client.Tx) error {
		cur, _ := w.Store.Epoch()
		_, err := w.CaptureReplay(tx{Tx: t0, reason: protocol.ReasonReplayAnchor, epoch: cur})
		return err
	})
	if err != nil || w.Captures()[0].AnchorHash == w.State().Hash() {
		t.Fatal("anchor mutator not applied")
	}
}
