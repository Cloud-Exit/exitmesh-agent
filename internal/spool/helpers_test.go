package spool

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const testTarget = "t-spool"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.UnixMilli(1_760_000_000_000)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// writer drives a spool the way the coordinator does, tracking the state its deltas describe.
type writer struct {
	t     testing.TB
	s     *Spool
	opts  Options
	clk   *fakeClock
	state *protocol.State
	uid   int
	tx    *Tx
}

func newWriter(t testing.TB, mutate func(*Options)) *writer {
	t.Helper()
	clk := newClock()
	opts := Options{Dir: t.TempDir(), CapacityBytes: 64 << 20, Clock: clk.Now}
	if mutate != nil {
		mutate(&opts)
	}
	w := &writer{t: t, opts: opts, clk: clk, state: protocol.NewState()}
	w.open()
	if err := w.s.SetIdentity(Identity{TargetID: testTarget, TargetType: protocol.TargetKubernetes, Credential: "c", CredentialID: "cid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.OpenEpoch(protocol.OpenInitial, nil, nil); err != nil {
		t.Fatal(err)
	}
	w.checkpoint(protocol.ReasonInitial)
	return w
}

func (w *writer) open() {
	w.t.Helper()
	s, err := Open(w.opts)
	if err != nil {
		w.t.Fatal(err)
	}
	w.s = s
	w.t.Cleanup(func() { _ = s.Close() })
}

func (w *writer) reopen() {
	w.t.Helper()
	if err := w.s.Close(); err != nil {
		w.t.Fatal(err)
	}
	w.open()
}

func (w *writer) append(t protocol.RecordType, build func(env protocol.Envelope) *protocol.Record, opts ...AppendOption) *Entry {
	w.t.Helper()
	w.clk.Advance(time.Second)
	if w.tx != nil {
		e, err := w.tx.Append(t, func(env protocol.Envelope) (*protocol.Record, error) { return build(env), nil }, opts...)
		if err != nil {
			w.t.Fatalf("append %s: %v", t, err)
		}
		return e
	}
	var e *Entry
	err := w.s.Do(func(tx *Tx) error {
		var err error
		e, err = tx.Append(t, func(env protocol.Envelope) (*protocol.Record, error) { return build(env), nil }, opts...)
		return err
	})
	if err != nil {
		w.t.Fatalf("append %s: %v", t, err)
	}
	return e
}

// batch runs f with every append inside one Do.
func (w *writer) batch(f func()) {
	w.t.Helper()
	if err := w.s.Do(func(tx *Tx) error {
		w.tx = tx
		defer func() { w.tx = nil }()
		f()
		return nil
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *writer) checkpoint(reason protocol.CheckpointReason) *Entry {
	return w.append(protocol.TypeCheckpoint, func(env protocol.Envelope) *protocol.Record {
		return &protocol.Record{Envelope: env, Checkpoint: w.state.Checkpoint(reason, protocol.Interval{Start: env.Time - 5, End: env.Time}, []string{"inventory"})}
	})
}

func (w *writer) delta(ops ...protocol.Op) *Entry {
	w.t.Helper()
	e := w.append(protocol.TypeDelta, func(env protocol.Envelope) *protocol.Record {
		return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: ops}}
	})
	if err := w.state.ApplyOps(ops); err != nil {
		w.t.Fatal(err)
	}
	return e
}

func (w *writer) finding(id string, evidence ...protocol.Evidence) *Entry {
	return w.append(protocol.TypeFinding, func(env protocol.Envelope) *protocol.Record {
		return &protocol.Record{Envelope: env, Finding: testFinding(id, env.Time, evidence)}
	})
}

func testFinding(id string, now uint64, evidence []protocol.Evidence) *protocol.Finding {
	return &protocol.Finding{
		ID: id, DedupKey: "k-" + id, Transition: protocol.TransitionFiring, Category: "workload", Severity: protocol.SeverityHigh,
		Provenance: protocol.Provenance{Kind: protocol.ProvenanceRule, RuleID: "r1", RuleVersion: 1, BundleVersion: "2026.09.1"},
		EvalTime:   now, FirstSeen: now, LastSeen: now, Count: 3, Resources: []string{"u1"},
		Evidence: append([]protocol.Evidence(nil), evidence...),
	}
}

func samples(n, textLen int, now uint64) []protocol.Evidence {
	out := make([]protocol.Evidence, n)
	for i := range out {
		out[i] = protocol.Evidence{Source: "logs:app", Time: now + uint64(i), Text: strings.Repeat(string(rune('a'+i%26)), textLen), Count: 2, Labels: map[string]string{"pod": "p"}}
	}
	return out
}

// randomDelta returns a valid delta against the writer's current state.
func (w *writer) randomDelta(rng *rand.Rand) *Entry {
	var ops []protocol.Op
	used := map[string]bool{}
	usedEdge := map[protocol.EdgeKey]bool{}
	for j := 0; j < 1+rng.Intn(3); j++ {
		switch rng.Intn(7) {
		case 0, 1:
			w.uid++
			uid := fmt.Sprintf("u%04d", w.uid)
			used[uid] = true
			ops = append(ops, protocol.Create(uid, "v1/Pod", "ns", uid, map[string]any{"v": int64(rng.Intn(3)), "w": "x"}))
		case 2, 3:
			uid := w.pick(rng, used)
			if uid == "" {
				continue
			}
			used[uid] = true
			ops = append(ops, protocol.Update(uid, map[string]any{"v": int64(rng.Intn(5)), "z": strings.Repeat("y", rng.Intn(40))}))
		case 4:
			uid := w.pick(rng, used)
			if uid == "" {
				continue
			}
			used[uid] = true
			ops = append(ops, protocol.Delete(uid, protocol.DeleteDeleted))
		case 5, 6:
			k := protocol.EdgeKey{From: fmt.Sprintf("n%d", rng.Intn(3)), Type: "owns", To: fmt.Sprintf("m%d", rng.Intn(3))}
			if usedEdge[k] {
				continue
			}
			usedEdge[k] = true
			attrs := map[string]any{"a": int64(rng.Intn(2))}
			cur, ok := w.state.Edges[k]
			switch {
			case !ok:
				ops = append(ops, protocol.EdgeAdd(k.From, k.Type, k.To, attrs))
			case rng.Intn(2) == 0:
				ops = append(ops, protocol.EdgeRemove(k.From, k.Type, k.To, protocol.CloneFields(cur)))
			default:
				ops = append(ops, protocol.EdgeReplace(k.From, k.Type, k.To, attrs, protocol.CloneFields(cur)))
			}
		}
	}
	if len(ops) == 0 {
		w.uid++
		uid := fmt.Sprintf("u%04d", w.uid)
		ops = append(ops, protocol.Create(uid, "v1/Pod", "ns", uid, map[string]any{"v": int64(1)}))
	}
	return w.delta(ops...)
}

func (w *writer) pick(rng *rand.Rand, used map[string]bool) string {
	var uids []string
	for uid := range w.state.Resources {
		if !used[uid] {
			uids = append(uids, uid)
		}
	}
	if len(uids) == 0 {
		return ""
	}
	sortStrings(uids)
	return uids[rng.Intn(len(uids))]
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func allEntries(s *Spool) []*Entry {
	var out []*Entry
	from := uint64(0)
	for {
		es := s.Entries(from)
		if len(es) == 0 {
			return out
		}
		out = append(out, es...)
		from = es[len(es)-1].Seq + 1
	}
}

func decode(t testing.TB, e *Entry) *protocol.Record {
	t.Helper()
	r, err := protocol.Decode(e.Bytes)
	if err != nil {
		t.Fatalf("decode %d: %v", e.Seq, err)
	}
	if r.Seq != e.Seq || r.Type != e.Type || r.Hash() != e.Hash {
		t.Fatalf("entry %d does not match its bytes", e.Seq)
	}
	return r
}

// replayHashes replays from the epoch start and checks every entry's chain hash.
func replayHashes(t testing.TB, s *Spool, entries []*Entry) *protocol.Replayer {
	t.Helper()
	ep, ok := s.Epoch()
	if !ok {
		t.Fatal("no epoch")
	}
	p := protocol.NewReplayer(ep.TargetID, ep.ID, s.WriterID())
	for _, e := range entries {
		h, err := p.Apply(decode(t, e))
		if err != nil {
			t.Fatalf("replay %d: %v", e.Seq, err)
		}
		if h != e.ChainHash {
			t.Fatalf("chain hash of %d: spool %s, replay %s", e.Seq, e.ChainHash, h)
		}
	}
	return p
}

// setCapacityForTarget sets capacity so that the relief target is about want bytes.
func setCapacityForTarget(s *Spool, want int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts.CapacityBytes = int64(float64(want)/(s.opts.CoalesceAt*reliefFactor)) + 1
}
