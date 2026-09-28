package spool

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func unpinAll(s *Spool) {
	s.mu.Lock()
	s.pinned, s.pinBytes = map[uint64]int64{}, 0
	s.mu.Unlock()
}

// pressureWriter spools 10 findings with four 1000-byte samples and 50 updates of one resource.
func pressureWriter(t *testing.T) *writer {
	w := newWriter(t, nil)
	w.delta(protocol.Create("u1", "v1/ConfigMap", "ns", "cm", map[string]any{"v": "x"}))
	for i := 0; i < 10; i++ {
		w.finding(fmt.Sprintf("f%d", i), samples(4, 1000, uint64(i))...)
		for j := 0; j < 5; j++ {
			w.delta(protocol.Update("u1", map[string]any{"v": strings.Repeat(string(rune('a'+j)), 200)}))
		}
	}
	return w
}

type stateHashes map[uint64]protocol.Hash

func snapshotStates(t *testing.T, w *writer) ([]*Entry, stateHashes) {
	t.Helper()
	es := allEntries(w.s)
	unpinAll(w.s)
	p := replayHashes(t, w.s, es)
	out := stateHashes{}
	for _, e := range es {
		h, err := p.StateHashAt(e.Seq)
		if err != nil {
			t.Fatal(err)
		}
		out[e.Seq] = h
	}
	return es, out
}

// checkEquivalent requires exact state at every sequence not unavailable, and unavailable interiors.
func checkEquivalent(t *testing.T, w *writer, before stateHashes, head uint64) []*Entry {
	t.Helper()
	after := allEntries(w.s)
	unpinAll(w.s)
	p := replayHashes(t, w.s, after)
	if len(p.Boundaries) != 0 {
		t.Fatalf("reconstruction boundaries %+v", p.Boundaries)
	}
	for seq := uint64(1); seq <= head; seq++ {
		got, err := p.StateHashAt(seq)
		if protocol.IsUnavailable(p.Unavailable, seq) {
			if !errors.Is(err, protocol.ErrUnavailable) {
				t.Fatalf("seq %d inside a range: %v", seq, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		if got != before[seq] {
			t.Fatalf("state at %d differs after relief", seq)
		}
	}
	return after
}

func findings(t *testing.T, es []*Entry) map[uint64]protocol.Finding {
	out := map[uint64]protocol.Finding{}
	for _, e := range es {
		r := decode(t, e)
		switch r.Type {
		case protocol.TypeFinding:
			out[r.Seq] = *r.Finding
		case protocol.TypeRange:
			for _, f := range r.Range.Findings {
				out[f.Seq] = f.Finding
			}
		}
	}
	return out
}

func TestRelieveOrder(t *testing.T) {
	t.Run("evict evidence first", func(t *testing.T) {
		w := pressureWriter(t)
		unpinAll(w.s)
		b0 := w.s.Usage().Bytes
		setCapacityForTarget(w.s, b0-500)
		rel, err := w.s.Relieve()
		if err != nil {
			t.Fatal(err)
		}
		if rel.EvidenceEvicted != 1 || rel.SamplesCompacted != 0 || rel.RecordsCoalesced != 0 || rel.Exhausted {
			t.Fatalf("relief %+v", rel)
		}
		if rel.BytesBefore != b0 || rel.BytesAfter > w.s.reliefTarget() || w.s.Usage().Bytes != rel.BytesAfter {
			t.Fatalf("relief bytes %+v", rel)
		}
		fs := findings(t, allEntries(w.s))
		oldest, next := fs[3], fs[9]
		if len(oldest.Evidence) != 1 || oldest.Evidence[0].Text == "" || oldest.Flags&protocol.FindingEvidenceTruncated == 0 {
			t.Fatalf("oldest finding evidence %+v flags %d", oldest.Evidence, oldest.Flags)
		}
		if len(next.Evidence) != 4 || next.Flags != 0 {
			t.Fatal("a later finding was evicted before it was needed")
		}
	})
	t.Run("compact samples second", func(t *testing.T) {
		w := pressureWriter(t)
		unpinAll(w.s)
		setCapacityForTarget(w.s, w.s.Usage().Bytes-10*3300-500)
		rel, err := w.s.Relieve()
		if err != nil {
			t.Fatal(err)
		}
		if rel.EvidenceEvicted != 10 || rel.SamplesCompacted < 1 || rel.SamplesCompacted > 9 || rel.RecordsCoalesced != 0 {
			t.Fatalf("relief %+v", rel)
		}
		f := findings(t, allEntries(w.s))[3]
		if len(f.Evidence) != 1 || f.Evidence[0].Text != "" || f.Evidence[0].Count != 2 || f.Evidence[0].Source != "logs:app" || f.Evidence[0].Labels != nil {
			t.Fatalf("compacted evidence %+v", f.Evidence)
		}
		if f.Flags != protocol.FindingEvidenceTruncated|protocol.FindingSamplesCompacted {
			t.Fatalf("flags %d", f.Flags)
		}
	})
	t.Run("coalesce last", func(t *testing.T) {
		w := pressureWriter(t)
		before, states := snapshotStates(t, w)
		head := before[len(before)-1].Seq
		setCapacityForTarget(w.s, w.s.Usage().Bytes-10*3300-10*1100-500)
		rel, err := w.s.Relieve()
		if err != nil {
			t.Fatal(err)
		}
		if rel.EvidenceEvicted != 10 || rel.SamplesCompacted != 10 || rel.RecordsCoalesced == 0 || len(rel.Unavailable) == 0 || rel.Exhausted {
			t.Fatalf("relief %+v", rel)
		}
		after := checkEquivalent(t, w, states, head)
		if !bytes.Equal(after[0].Bytes, before[0].Bytes) {
			t.Fatal("initial checkpoint rewritten")
		}
		fs := findings(t, after)
		if len(fs) != 10 {
			t.Fatalf("%d findings preserved", len(fs))
		}
		for seq := range fs {
			if decode(t, before[seq-1]).Type != protocol.TypeFinding {
				t.Fatalf("finding kept at wrong sequence %d", seq)
			}
		}
		for _, sp := range rel.Unavailable {
			if sp.From < 2 || sp.To >= head {
				t.Fatalf("span %+v", sp)
			}
		}
		if u := w.s.Usage(); u.RebaselineRequired || u.Bytes > w.s.reliefTarget() {
			t.Fatalf("usage %+v", u)
		}
		ep, _ := w.s.Epoch()
		if ep.Chain.HeadHash != after[len(after)-1].ChainHash {
			t.Fatal("chain head hash not recomputed")
		}
		w.delta(protocol.Update("u1", map[string]any{"v": "after"}))
		w.reopen()
		replayHashes(t, w.s, allEntries(w.s))
	})
	t.Run("rebaseline only when fully coalesced suffix exceeds capacity", func(t *testing.T) {
		w := pressureWriter(t)
		unpinAll(w.s)
		w.s.mu.Lock()
		w.s.opts.CapacityBytes = 1000
		w.s.mu.Unlock()
		rel, err := w.s.Relieve()
		if !errors.Is(err, ErrRebaselineRequired) {
			t.Fatalf("relieve: %v", err)
		}
		if rel.EvidenceEvicted != 10 || rel.SamplesCompacted != 10 || rel.RecordsCoalesced == 0 {
			t.Fatalf("steps before rebaseline %+v", rel)
		}
		if !w.s.Usage().RebaselineRequired {
			t.Fatal("usage does not report the rebaseline")
		}
		err = w.s.Do(func(tx *Tx) error {
			_, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
				return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: []protocol.Op{protocol.Delete("u1", protocol.DeleteDeleted)}}}, nil
			})
			return err
		})
		if !errors.Is(err, ErrRebaselineRequired) {
			t.Fatalf("append while over capacity: %v", err)
		}
		old, _ := w.s.Epoch()
		if err := w.s.DiscardAbove(0); err != nil {
			t.Fatal(err)
		}
		zero := uint64(0)
		if _, err := w.s.OpenEpoch(protocol.OpenRebaseline, &old.ID, &zero); err != nil {
			t.Fatal(err)
		}
		w.append(protocol.TypeCheckpoint, func(env protocol.Envelope) *protocol.Record {
			ck := w.state.Checkpoint(protocol.ReasonRebaseline, protocol.Interval{Start: env.Time, End: env.Time}, nil)
			ck.PrevEpoch, ck.PrevHead = &old.ID, &zero
			return &protocol.Record{Envelope: env, Checkpoint: ck}
		})
		if w.s.Usage().RebaselineRequired {
			t.Fatal("rebaseline flag survives the new epoch")
		}
	})
}

func TestCoalescingReconstructsExactly(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			w := newWriter(t, nil)
			var anchor uint64
			w.batch(func() {
				for i := 0; i < 400; i++ {
					switch {
					case i == 200:
						anchor = w.checkpoint(protocol.ReasonAnchor).Seq
					case rng.Intn(8) == 0:
						w.finding(fmt.Sprintf("f%d", rng.Intn(5)), samples(1+rng.Intn(3), 100, uint64(i))...)
					default:
						w.randomDelta(rng)
					}
				}
			})
			before, states := snapshotStates(t, w)
			head := before[len(before)-1].Seq
			setCapacityForTarget(w.s, w.s.Usage().Bytes/2)
			rel, err := w.s.Relieve()
			if err != nil {
				t.Fatal(err)
			}
			if rel.RecordsCoalesced == 0 || len(rel.Unavailable) == 0 {
				t.Fatalf("relief %+v", rel)
			}
			for _, sp := range rel.Unavailable {
				if sp.From <= anchor && anchor <= sp.To+1 {
					t.Fatalf("range %+v crosses the anchor checkpoint at %d", sp, anchor)
				}
			}
			after := checkEquivalent(t, w, states, head)
			for _, e := range after {
				if e.Seq == anchor && !bytes.Equal(e.Bytes, before[anchor-1].Bytes) {
					t.Fatal("anchor checkpoint rewritten")
				}
			}
			bf, af := findings(t, before), findings(t, after)
			if len(bf) != len(af) {
				t.Fatalf("findings %d before, %d after", len(bf), len(af))
			}
			for seq, f := range bf {
				g, ok := af[seq]
				if !ok || g.ID != f.ID || g.Transition != f.Transition || g.Count != f.Count {
					t.Fatalf("finding at %d not preserved", seq)
				}
			}
			ep, _ := w.s.Epoch()
			for _, sp := range rel.Unavailable {
				if err := w.s.Commit(ep.ID, sp.From, protocol.Hash{}); !errors.Is(err, ErrDivergence) || !strings.Contains(err.Error(), "inside coalesced range") {
					t.Fatalf("commit inside range %+v: %v", sp, err)
				}
			}
		})
	}
}

func TestTransmittedReplayAnchorPreserved(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	w := newWriter(t, nil)
	w.batch(func() {
		for i := 0; i < 60; i++ {
			w.randomDelta(rng)
		}
	})
	anchor := w.checkpoint(protocol.ReasonReplayAnchor)
	if err := w.s.MarkTransmitted(anchor.Seq); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		w.randomDelta(rng)
	}
	before, states := snapshotStates(t, w)
	head := before[len(before)-1].Seq
	setCapacityForTarget(w.s, w.s.Usage().Bytes*8/10)
	rel, err := w.s.Relieve()
	if err != nil {
		t.Fatal(err)
	}
	if rel.RecordsCoalesced == 0 {
		t.Fatalf("relief %+v", rel)
	}
	after := checkEquivalent(t, w, states, head)
	var got *Entry
	for _, e := range after {
		if e.Seq == anchor.Seq {
			got = e
		}
	}
	if got == nil || got.State != TransmittedUnconfirmed || !bytes.Equal(got.Bytes, anchor.Bytes) || got.Hash != anchor.Hash {
		t.Fatal("transmitted replay anchor changed")
	}
	if got.ChainHash == anchor.ChainHash {
		t.Fatal("anchor chain hash not recomputed after earlier coalescing")
	}
	ep, _ := w.s.Epoch()
	if err := w.s.Commit(ep.ID, anchor.Seq, got.ChainHash); err != nil {
		t.Fatal(err)
	}
}

func TestLostAcknowledgementUnderPressure(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	w := newWriter(t, nil)
	for i := 0; i < 9; i++ {
		w.randomDelta(rng)
	}
	sent := allEntries(w.s)
	var seqs []uint64
	for _, e := range sent {
		seqs = append(seqs, e.Seq)
	}
	if err := w.s.MarkTransmitted(seqs...); err != nil {
		t.Fatal(err)
	}
	committed := sent[len(sent)-1]
	w.batch(func() {
		for i := 0; i < 80; i++ {
			w.randomDelta(rng)
		}
	})
	unpinAll(w.s)
	setCapacityForTarget(w.s, w.s.Usage().Bytes*8/10)
	rel, err := w.s.Relieve()
	if err != nil {
		t.Fatal(err)
	}
	if rel.RecordsCoalesced == 0 {
		t.Fatalf("relief %+v", rel)
	}
	for _, sp := range rel.Unavailable {
		if sp.From <= committed.Seq {
			t.Fatalf("transmitted record coalesced: span %+v", sp)
		}
	}
	now := allEntries(w.s)
	for i, e := range sent {
		if !bytes.Equal(now[i].Bytes, e.Bytes) || now[i].State != TransmittedUnconfirmed || now[i].ChainHash != e.ChainHash {
			t.Fatalf("transmitted record %d rewritten", e.Seq)
		}
	}
	ep, _ := w.s.Epoch()
	if err := w.s.Commit(ep.ID, committed.Seq, committed.ChainHash); err != nil {
		t.Fatal(err)
	}
	left := allEntries(w.s)
	if len(left) == 0 || decode(t, left[0]).Parent != committed.Seq {
		t.Fatal("spool does not continue right after the committed head")
	}
	h, last := committed.ChainHash, committed.Seq
	for _, e := range left {
		if e.Seq <= last {
			t.Fatalf("duplicate or reordered sequence %d", e.Seq)
		}
		h = protocol.ChainHash(h, e.Hash)
		if h != e.ChainHash {
			t.Fatalf("chain hash of %d", e.Seq)
		}
		last = e.Seq
	}
}

func TestCrashAfterSendNeverCoalesced(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	w := newWriter(t, nil)
	w.batch(func() {
		for i := 0; i < 40; i++ {
			w.randomDelta(rng)
		}
	})
	sent := w.s.Entries(0)[:5]
	if err := w.s.MarkTransmitted(1, 2, 3, 4, 5); err != nil {
		t.Fatal(err)
	}
	w.reopen()
	setCapacityForTarget(w.s, w.s.Usage().Bytes*8/10)
	if _, err := w.s.Relieve(); err != nil {
		t.Fatal(err)
	}
	es := allEntries(w.s)
	for i := 0; i < 5; i++ {
		if es[i].State != TransmittedUnconfirmed || !bytes.Equal(es[i].Bytes, sent[i].Bytes) {
			t.Fatalf("record %d after crash and pressure: %s", es[i].Seq, es[i].State)
		}
	}
	if es[5].Type != protocol.TypeRange {
		t.Fatalf("never-transmitted backlog not coalesced, record %d is %s", es[5].Seq, es[5].Type)
	}
	ep, _ := w.s.Epoch()
	if err := w.s.Commit(ep.ID, 5, sent[4].ChainHash); err != nil {
		t.Fatal(err)
	}
	if es := allEntries(w.s); es[0].Seq <= 5 {
		t.Fatal("committed-head handshake did not resolve the transmitted records")
	}
}

func TestAutomaticReliefAfterAppend(t *testing.T) {
	w := newWriter(t, nil)
	for i := 0; i < 5; i++ {
		w.finding(fmt.Sprintf("f%d", i), samples(4, 500, uint64(i))...)
	}
	unpinAll(w.s)
	w.s.mu.Lock()
	w.s.opts.CapacityBytes = int64(float64(w.s.bytes+100) / w.s.opts.CoalesceAt)
	w.s.mu.Unlock()
	w.finding("f5", samples(4, 500, 5)...)
	fs := findings(t, allEntries(w.s))
	if len(fs[2].Evidence) != 1 || fs[2].Flags&protocol.FindingEvidenceTruncated == 0 {
		t.Fatal("automatic relief did not evict the oldest evidence")
	}
	if u := w.s.Usage(); u.ReliefError != nil || u.Bytes > w.s.trigger() {
		t.Fatalf("usage %+v", u)
	}
	replayHashes(t, w.s, allEntries(w.s))
}

func TestEntriesPinAgainstRewrite(t *testing.T) {
	w := newWriter(t, nil)
	for i := 0; i < 8; i++ {
		w.finding(fmt.Sprintf("f%d", i), samples(4, 500, uint64(i))...)
	}
	read := allEntries(w.s)
	setCapacityForTarget(w.s, w.s.Usage().Bytes*9/10)
	rel, err := w.s.Relieve()
	if err != nil {
		t.Fatal(err)
	}
	if rel.EvidenceEvicted != 0 || rel.RecordsCoalesced != 0 || !rel.Exhausted {
		t.Fatalf("records handed out by Entries were rewritten: %+v", rel)
	}
	if err := w.s.MarkTransmitted(read[1].Seq, read[2].Seq); err != nil {
		t.Fatal(err)
	}
	w.s.mu.Lock()
	w.s.opts.CapacityBytes = 64 << 20
	w.s.mu.Unlock()
	w.finding("f9", samples(4, 500, 9)...)
	setCapacityForTarget(w.s, w.s.Usage().Bytes-100)
	if rel, err = w.s.Relieve(); err != nil {
		t.Fatal(err)
	}
	if rel.EvidenceEvicted != 1 {
		t.Fatalf("unread record not relieved: %+v", rel)
	}
	now := allEntries(w.s)
	for i := range read {
		if !bytes.Equal(now[i].Bytes, read[i].Bytes) {
			t.Fatalf("record %d bytes changed after hand out", now[i].Seq)
		}
	}
	if f := findings(t, now)[now[len(now)-1].Seq]; len(f.Evidence) != 1 {
		t.Fatal("unread finding keeps its evidence")
	}
}

func TestSegmentCompaction(t *testing.T) {
	w := newWriter(t, func(o *Options) { o.SegmentBytes = 8 << 10 })
	for i := 0; i < 12; i++ {
		w.finding(fmt.Sprintf("f%d", i), samples(3, 1200, uint64(i))...)
		w.delta(protocol.Create(fmt.Sprintf("u%d", i), "v1/Pod", "ns", "n", nil))
	}
	before := allEntries(w.s)
	unpinAll(w.s)
	disk := w.s.Usage().DiskBytes
	for _, e := range before {
		if e.Type == protocol.TypeFinding {
			if err := w.s.MarkTransmitted(e.Seq); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	setCapacityForTarget(w.s, 20<<10)
	rel, err := w.s.Relieve()
	if err != nil {
		t.Fatal(err)
	}
	if rel.EvidenceEvicted == 0 || rel.SegmentsCompacted == 0 {
		t.Fatalf("relief %+v", rel)
	}
	u := w.s.Usage()
	if u.DiskBytes >= disk || u.DiskBytes > 2*(u.Bytes+int64(u.Records)*frameHeader)+w.opts.SegmentBytes {
		t.Fatalf("disk %d before %d, live %d", u.DiskBytes, disk, u.Bytes)
	}
	after := allEntries(w.s)
	if !bytes.Equal(after[1].Bytes, before[1].Bytes) {
		t.Fatal("transmitted record bytes changed by compaction")
	}
	replayHashes(t, w.s, after)
	w.reopen()
	replayHashes(t, w.s, allEntries(w.s))
}

func TestEvidenceStepsRewriteRangeFindings(t *testing.T) {
	w := newWriter(t, nil)
	w.batch(func() {
		for i := 0; i < 6; i++ {
			w.finding(fmt.Sprintf("f%d", i), samples(3, 400, uint64(i))...)
			w.delta(protocol.Create(fmt.Sprintf("u%d", i), "v1/Pod", "ns", "n", nil))
		}
	})
	first := allEntries(w.s)[0]
	unpinAll(w.s)
	ep, _ := w.s.Epoch()
	if err := w.s.Commit(ep.ID, 1, first.ChainHash); err != nil {
		t.Fatal(err)
	}
	oldest := w.s.Usage().Oldest
	if oldest.IsZero() || oldest.Equal(time.UnixMilli(int64(decode(t, first).Time))) {
		t.Fatalf("oldest %v", oldest)
	}
	w.s.mu.Lock()
	var rel Relief
	err := w.s.coalesce(0, &rel)
	if err == nil {
		err = w.s.rebuildChain()
	}
	w.s.mu.Unlock()
	if err != nil || rel.RecordsCoalesced != 12 {
		t.Fatalf("coalesce %+v %v", rel, err)
	}
	es := allEntries(w.s)
	unpinAll(w.s)
	if len(es) != 1 || es[0].Type != protocol.TypeRange || decode(t, es[0]).Parent != 1 {
		t.Fatalf("entries %d", len(es))
	}
	if u := w.s.Usage(); !u.Oldest.Equal(oldest) {
		t.Fatalf("oldest %v after coalescing, want %v", u.Oldest, oldest)
	}
	checkChainFrom(t, first.ChainHash, es)
	setCapacityForTarget(w.s, w.s.Usage().Bytes-100)
	if rel, err = w.s.Relieve(); err != nil || rel.EvidenceEvicted != 1 {
		t.Fatalf("relief %+v %v", rel, err)
	}
	now := allEntries(w.s)
	fs := findings(t, now)
	if len(fs) != 6 {
		t.Fatalf("findings %d", len(fs))
	}
	for seq, f := range fs {
		if len(f.Evidence) != 1 || f.Flags&protocol.FindingEvidenceTruncated == 0 {
			t.Fatalf("range finding %d evidence %d flags %d", seq, len(f.Evidence), f.Flags)
		}
	}
	checkChainFrom(t, first.ChainHash, now)
}

func checkChainFrom(t *testing.T, h protocol.Hash, es []*Entry) {
	t.Helper()
	for _, e := range es {
		if h = protocol.ChainHash(h, e.Hash); h != e.ChainHash {
			t.Fatalf("chain hash of %d", e.Seq)
		}
	}
}

func TestPinBudgetKeepsLatestBatch(t *testing.T) {
	w := newWriter(t, func(o *Options) { o.WindowBytes = 512 })
	w.batch(func() {
		for i := 0; i < 40; i++ {
			w.delta(protocol.Create(fmt.Sprintf("u%02d", i), "v1/Pod", "ns", "n", map[string]any{"pad": strings.Repeat("p", 250)}))
		}
	})
	var pages [][]*Entry
	for from := uint64(0); ; {
		es := w.s.Entries(from)
		if len(es) == 0 {
			break
		}
		pages = append(pages, es)
		from = es[len(es)-1].Seq + 1
		w.s.mu.Lock()
		over := w.s.pinBytes > 2*w.s.entriesLimit()
		w.s.mu.Unlock()
		if over {
			t.Fatal("pins exceed their budget")
		}
	}
	if len(pages) < 4 {
		t.Fatalf("pages %d", len(pages))
	}
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	for _, e := range pages[len(pages)-1] {
		if !w.s.isPinned(e.Seq) {
			t.Fatalf("latest batch record %d unpinned", e.Seq)
		}
	}
	if w.s.isPinned(pages[0][0].Seq) {
		t.Fatal("oldest pin kept past the budget")
	}
	again := pages[0]
	w.s.mu.Unlock()
	w.s.Entries(again[0].Seq)
	w.s.mu.Lock()
	if !w.s.isPinned(again[0].Seq) {
		t.Fatal("re-read batch not pinned")
	}
}
