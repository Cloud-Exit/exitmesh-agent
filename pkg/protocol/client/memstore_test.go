package client_test

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

var testTime = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func newStore(t *testing.T) *client.MemStore {
	t.Helper()
	s, err := client.NewMemStore(client.MemOptions{
		Now:      func() time.Time { return testTime },
		Identity: client.Identity{TargetID: "t-1", TargetType: protocol.TargetKubernetes, Credential: "cred"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenEpoch(protocol.OpenInitial, nil, nil); err != nil {
		t.Fatal(err)
	}
	return s
}

func appendCheckpoint(t *testing.T, s client.Store, st *protocol.State) *client.Entry {
	t.Helper()
	var e *client.Entry
	err := s.Do(func(tx client.Tx) error {
		var err error
		e, err = tx.Append(protocol.TypeCheckpoint, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Checkpoint: st.Checkpoint(protocol.ReasonInitial, protocol.Interval{}, nil)}, nil
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func appendDelta(t *testing.T, s client.Store, ops ...protocol.Op) *client.Entry {
	t.Helper()
	var e *client.Entry
	err := s.Do(func(tx client.Tx) error {
		var err error
		e, err = tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: ops}}, nil
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func appendFinding(t *testing.T, s client.Store, id string) *client.Entry {
	t.Helper()
	var e *client.Entry
	err := s.Do(func(tx client.Tx) error {
		var err error
		e, err = tx.Append(protocol.TypeFinding, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Finding: &protocol.Finding{
				ID: id, DedupKey: "k-" + id, Transition: protocol.TransitionFiring, Category: "c", Severity: protocol.SeverityLow,
				Provenance: protocol.Provenance{Kind: protocol.ProvenanceRule, RuleID: "r", BundleVersion: "b"},
			}}, nil
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMemStoreAppendChain(t *testing.T) {
	s := newStore(t)
	ep, _ := s.Epoch()
	ref := protocol.NewChain("t-1", ep.ID, s.WriterID())
	st := protocol.NewState()
	e1 := appendCheckpoint(t, s, st)
	e2 := appendDelta(t, s, protocol.Create("u1", "Pod", "ns", "p", nil))
	e3 := appendFinding(t, s, "f1")
	for _, e := range []*client.Entry{e1, e2, e3} {
		r, err := protocol.Decode(e.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		ch, err := ref.Append(r)
		if err != nil || ch != e.ChainHash || r.Hash() != e.Hash || e.State != client.NeverTransmitted {
			t.Fatalf("entry %d: %v", e.Seq, err)
		}
		if r.Incarnation != 1 || r.Time != uint64(testTime.UnixMilli()) {
			t.Fatalf("envelope %+v", r.Envelope)
		}
	}
	if ep, _ := s.Epoch(); ep.Chain.Head != 3 || ep.Chain.HeadHash != ref.HeadHash {
		t.Fatalf("chain %+v", ep.Chain)
	}
	if got := s.Entries(2); len(got) != 2 || got[0].Seq != 2 {
		t.Fatalf("entries from 2: %d", len(got))
	}
	got := s.Entries(0)
	got[0].State = client.TransmittedUnconfirmed
	if s.Entries(0)[0].State != client.NeverTransmitted {
		t.Fatal("Entries returned shared state")
	}
}

func TestMemStoreAppendErrors(t *testing.T) {
	s, _ := client.NewMemStore(client.MemOptions{})
	if err := s.Do(func(tx client.Tx) error {
		_, err := tx.Append(protocol.TypeDelta, nil)
		return err
	}); !errors.Is(err, client.ErrNoEpoch) {
		t.Fatalf("append without epoch: %v", err)
	}
	if _, err := s.OpenEpoch(protocol.OpenInitial, nil, nil); !errors.Is(err, client.ErrNotEnrolled) {
		t.Fatalf("open without identity: %v", err)
	}
	s = newStore(t)
	appendCheckpoint(t, s, protocol.NewState())
	cases := map[string]func(tx client.Tx) error{
		"range": func(tx client.Tx) error {
			_, err := tx.Append(protocol.TypeRange, nil)
			return err
		},
		"type mismatch": func(tx client.Tx) error {
			_, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
				env.Type = protocol.TypeCheckpoint
				return &protocol.Record{Envelope: env, Checkpoint: protocol.NewState().Checkpoint(protocol.ReasonAnchor, protocol.Interval{}, nil)}, nil
			})
			return err
		},
		"envelope changed": func(tx client.Tx) error {
			_, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
				env.Seq++
				return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: []protocol.Op{protocol.Create("x", "Pod", "", "x", nil)}}}, nil
			})
			return err
		},
		"build error": func(tx client.Tx) error {
			_, err := tx.Append(protocol.TypeDelta, func(protocol.Envelope) (*protocol.Record, error) { return nil, errors.New("boom") })
			return err
		},
		"invalid record": func(tx client.Tx) error {
			_, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
				return &protocol.Record{Envelope: env, Delta: &protocol.Delta{}}, nil
			})
			return err
		},
	}
	for name, fn := range cases {
		if err := s.Do(fn); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if ep, _ := s.Epoch(); ep.Chain.Head != 1 {
		t.Fatalf("failed appends advanced the chain to %d", ep.Chain.Head)
	}
}

func TestMemStoreDoRollsBack(t *testing.T) {
	s := newStore(t)
	appendCheckpoint(t, s, protocol.NewState())
	before, _ := s.Epoch()
	err := s.Do(func(tx client.Tx) error {
		if _, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: []protocol.Op{protocol.Create("x", "Pod", "", "x", nil)}}}, nil
		}); err != nil {
			return err
		}
		return errors.New("abort")
	})
	if err == nil {
		t.Fatal("abort ignored")
	}
	after, _ := s.Epoch()
	if after.Chain != before.Chain || len(s.Entries(0)) != 1 {
		t.Fatalf("rollback left chain %+v and %d entries", after.Chain, len(s.Entries(0)))
	}
	e := appendDelta(t, s, protocol.Create("y", "Pod", "", "y", nil))
	if e.Seq != 2 {
		t.Fatalf("append after rollback at %d", e.Seq)
	}
}

func TestMemStoreMarkAndCommit(t *testing.T) {
	s := newStore(t)
	appendCheckpoint(t, s, protocol.NewState())
	for i := 0; i < 4; i++ {
		appendDelta(t, s, protocol.Create(fmt.Sprint("u", i), "Pod", "", "p", nil))
	}
	ep, _ := s.Epoch()
	if err := s.MarkTransmitted(1, 2, 9); !errors.Is(err, client.ErrNotSpooled) {
		t.Fatalf("mark missing: %v", err)
	}
	if s.Entries(0)[0].State != client.NeverTransmitted {
		t.Fatal("failed mark changed state")
	}
	if err := s.MarkTransmitted(1, 2); err != nil {
		t.Fatal(err)
	}
	es := s.Entries(0)
	if es[0].State != client.TransmittedUnconfirmed || es[1].State != client.TransmittedUnconfirmed || es[2].State != client.NeverTransmitted {
		t.Fatal("states after mark")
	}
	if es[0].State.String() != "transmitted_unconfirmed" || es[2].State.String() != "never_transmitted" {
		t.Fatal("state names")
	}
	if len(s.Transmitted()) != 2 {
		t.Fatalf("transmitted log %d", len(s.Transmitted()))
	}
	select {
	case <-s.Notify():
	default:
		t.Fatal("no notification after appends")
	}
	if err := s.Commit(protocol.EpochID{9}, 1, es[0].ChainHash); !errors.Is(err, client.ErrWrongEpoch) {
		t.Fatalf("wrong epoch: %v", err)
	}
	if err := s.Commit(ep.ID, 2, es[0].ChainHash); !errors.Is(err, client.ErrDivergence) {
		t.Fatalf("hash mismatch: %v", err)
	}
	if err := s.Commit(ep.ID, 7, es[0].ChainHash); !errors.Is(err, client.ErrDivergence) {
		t.Fatalf("above head: %v", err)
	}
	if err := s.Commit(ep.ID, 0, protocol.Hash{1}); !errors.Is(err, client.ErrDivergence) {
		t.Fatalf("bad genesis: %v", err)
	}
	if err := s.Commit(ep.ID, 0, protocol.Genesis("t-1", ep.ID, s.WriterID())); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	if err := s.Commit(ep.ID, 3, es[2].ChainHash); err != nil {
		t.Fatal(err)
	}
	if lc, ok := s.LastCommitted(); !ok || lc.Seq != 3 || lc.ChainHash != es[2].ChainHash {
		t.Fatalf("last committed %+v", lc)
	}
	if got := s.Entries(0); len(got) != 2 || got[0].Seq != 4 {
		t.Fatalf("entries after commit %d", len(got))
	}
	if err := s.Commit(ep.ID, 2, protocol.Hash{}); err != nil {
		t.Fatalf("commit below head: %v", err)
	}
	if err := s.Commit(ep.ID, 3, protocol.Hash{7}); !errors.Is(err, client.ErrDivergence) {
		t.Fatalf("head hash mismatch: %v", err)
	}
	if err := s.Commit(ep.ID, 3, es[2].ChainHash); err != nil {
		t.Fatalf("idempotent commit: %v", err)
	}
}

func TestMemStoreDiscardAndOpenEpoch(t *testing.T) {
	s := newStore(t)
	appendCheckpoint(t, s, protocol.NewState())
	appendDelta(t, s, protocol.Create("a", "Pod", "", "a", nil))
	appendDelta(t, s, protocol.Create("b", "Pod", "", "b", nil))
	ep, _ := s.Epoch()
	if err := s.Commit(ep.ID, 1, s.Entries(0)[0].ChainHash); err != nil {
		t.Fatal(err)
	}
	prev, head := ep.ID, uint64(2)
	if _, err := s.OpenEpoch(protocol.OpenRebaseline, &prev, &head); !errors.Is(err, client.ErrEntriesRemain) {
		t.Fatalf("open with entries above head: %v", err)
	}
	if _, err := s.OpenEpoch(protocol.OpenRebaseline, nil, nil); !errors.Is(err, client.ErrEntriesRemain) {
		t.Fatalf("open with entries and no head: %v", err)
	}
	if err := s.DiscardAbove(2); err != nil {
		t.Fatal(err)
	}
	if es := s.Entries(0); len(es) != 1 || es[0].Seq != 2 {
		t.Fatalf("after discard %d", len(es))
	}
	id, err := s.OpenEpoch(protocol.OpenRebaseline, &prev, &head)
	if err != nil {
		t.Fatal(err)
	}
	ep2, _ := s.Epoch()
	if ep2.ID != id || ep2.Registered || *ep2.PrevEpoch != prev || *ep2.PrevHead != 2 || ep2.Chain.Head != 0 || ep2.OpenReason != protocol.OpenRebaseline {
		t.Fatalf("new epoch %+v", ep2)
	}
	if _, ok := s.LastCommitted(); ok || len(s.Entries(0)) != 0 {
		t.Fatal("previous epoch state kept")
	}
	if err := s.MarkRegistered(); err != nil {
		t.Fatal(err)
	}
	if ep, _ := s.Epoch(); !ep.Registered {
		t.Fatal("not registered")
	}
}

func TestMemStoreHaltReopenIdentity(t *testing.T) {
	s := newStore(t)
	appendCheckpoint(t, s, protocol.NewState())
	if err := s.SetHalted(protocol.CodeNotOwner); err != nil {
		t.Fatal(err)
	}
	if err := s.Do(func(client.Tx) error { return nil }); !errors.Is(err, client.ErrHalted) {
		t.Fatalf("do while halted: %v", err)
	}
	r := s.Reopen()
	if r.Incarnation() != 2 || r.WriterID() != s.WriterID() {
		t.Fatalf("reopen incarnation %d", r.Incarnation())
	}
	if _, ok := r.Halted(); ok {
		t.Fatal("halt survived reopen")
	}
	appendDelta(t, r, protocol.Create("only-in-copy", "Pod", "", "x", nil))
	if len(s.Entries(0)) != 1 || len(r.Entries(0)) != 2 {
		t.Fatal("reopened store shares entries")
	}
	id := r.Identity()
	id.Credential = "rotated"
	if err := r.SetIdentity(id); err != nil {
		t.Fatal(err)
	}
	if s.Identity().Credential != "cred" || r.Identity().Credential != "rotated" {
		t.Fatal("identity shared across handles")
	}
}

func TestMemStoreCoalesce(t *testing.T) {
	s := newStore(t)
	st := protocol.NewState()
	appendCheckpoint(t, s, st)
	appendDelta(t, s, protocol.Create("a", "Pod", "", "a", map[string]any{"v": 1}), protocol.EdgeAdd("a", "e", "b", map[string]any{"w": 1}))
	ep, _ := s.Epoch()
	if err := s.MarkTransmitted(1, 2); err != nil {
		t.Fatal(err)
	}
	sent := s.Entries(2)[0]
	appendDelta(t, s, protocol.Update("a", map[string]any{"v": 2}))
	appendFinding(t, s, "f1")
	appendDelta(t, s, protocol.EdgeRemove("a", "e", "b", map[string]any{"w": 1}), protocol.Create("c", "Pod", "", "c", nil))
	appendDelta(t, s, protocol.Delete("c", protocol.DeleteDeleted))
	var anchorState *protocol.State
	{
		recs := decodeAll(t, s.Entries(0))
		var err error
		if anchorState, err = protocol.Reconstruct(recs, 6); err != nil {
			t.Fatal(err)
		}
	}
	err := s.Do(func(tx client.Tx) error {
		_, err := tx.Append(protocol.TypeCheckpoint, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Checkpoint: anchorState.Checkpoint(protocol.ReasonReplayAnchor, protocol.Interval{}, nil)}, nil
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	appendDelta(t, s, protocol.Update("a", map[string]any{"v": 3}))
	appendDelta(t, s, protocol.Update("a", map[string]any{"v": 4}))
	before := decodeAll(t, s.Entries(0))
	want, _ := protocol.Reconstruct(before, 9)

	n, err := s.Coalesce()
	if err != nil || n != 4 {
		t.Fatalf("first coalesce folded %d: %v", n, err)
	}
	n, err = s.Coalesce()
	if err != nil || n != 2 {
		t.Fatalf("second coalesce folded %d: %v", n, err)
	}
	if n, err := s.Coalesce(); err != nil || n != 0 {
		t.Fatalf("third coalesce folded %d: %v", n, err)
	}
	es := s.Entries(0)
	if len(es) != 5 || !bytes.Equal(es[1].Bytes, sent.Bytes) || es[2].Type != protocol.TypeRange || es[2].Seq != 6 || es[3].Seq != 7 || es[4].Type != protocol.TypeRange {
		t.Fatalf("entries after coalescing: %d", len(es))
	}
	after := decodeAll(t, es)
	if after[2].Range.From != 3 || len(after[2].Range.Findings) != 1 || after[2].Range.Findings[0].Seq != 4 {
		t.Fatalf("range %+v", after[2].Range)
	}
	ref := protocol.NewChain("t-1", ep.ID, s.WriterID())
	for i, r := range after {
		ch, err := ref.Append(r)
		if err != nil || ch != es[i].ChainHash {
			t.Fatalf("chain hash at %d after coalescing: %v", r.Seq, err)
		}
	}
	if ep, _ := s.Epoch(); ep.Chain.HeadHash != ref.HeadHash || ep.Chain.Head != 9 {
		t.Fatal("chain head not recomputed")
	}
	got, err := protocol.Reconstruct(after, 9)
	if err != nil || !got.Equal(want) {
		t.Fatalf("reconstruction after coalescing: %v", err)
	}
	if _, err := protocol.Reconstruct(after, 4); !errors.Is(err, protocol.ErrUnavailable) {
		t.Fatalf("range interior: %v", err)
	}
	appendDelta(t, s, protocol.Update("a", map[string]any{"v": 5}))
	if ep, _ := s.Epoch(); ep.Chain.Head != 10 {
		t.Fatal("append after coalescing")
	}
}

func decodeAll(t *testing.T, es []*client.Entry) []*protocol.Record {
	t.Helper()
	out := make([]*protocol.Record, len(es))
	for i, e := range es {
		r, err := protocol.Decode(e.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = r
	}
	return out
}

func TestMemStoreConcurrentAppends(t *testing.T) {
	s := newStore(t)
	appendCheckpoint(t, s, protocol.NewState())
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				appendDelta(t, s, protocol.Create(fmt.Sprintf("g%d-%d", g, i), "Pod", "", "p", nil))
				_ = s.Entries(0)
				_, _ = s.Coalesce()
			}
		}(g)
	}
	wg.Wait()
	recs := decodeAll(t, s.Entries(0))
	ep, _ := s.Epoch()
	ref := protocol.NewChain("t-1", ep.ID, s.WriterID())
	for _, r := range recs {
		if _, err := ref.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	st, err := protocol.Reconstruct(recs, ep.Chain.Head)
	if err != nil || len(st.Resources) != 200 || ep.Chain.Head < 2 {
		t.Fatalf("concurrent appends: %v %d", err, len(st.Resources))
	}
}
