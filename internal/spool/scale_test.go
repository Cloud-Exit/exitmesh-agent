package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// TestChainMarksAcrossLargeSpool runs lookups, commits, recovery, and relief across many chain marks.
func TestChainMarksAcrossLargeSpool(t *testing.T) {
	defer func(n int) { markEvery = n }(markEvery)
	markEvery = 16
	w := newWriter(t, nil)
	for b := 0; b < 3; b++ {
		w.batch(func() {
			for i := 0; i < 110; i++ {
				if b == 2 && i%10 == 0 {
					w.finding(fmt.Sprintf("f%d", i), samples(4, 300, uint64(i))...)
					continue
				}
				w.uid++
				w.delta(protocol.Create(fmt.Sprintf("u%05d", w.uid), "v1/Pod", "ns", "n", map[string]any{"v": int64(i)}))
			}
		})
	}
	all := allEntries(w.s)
	unpinAll(w.s)
	if len(all) != 331 || len(w.s.marks) < 20 {
		t.Fatalf("entries %d marks %d", len(all), len(w.s.marks))
	}
	replayHashes(t, w.s, all)
	check := func(from uint64) {
		t.Helper()
		got := w.s.Entries(from)
		unpinAll(w.s)
		if len(got) == 0 {
			t.Fatalf("Entries(%d) empty", from)
		}
		for _, e := range got {
			if e.ChainHash != all[e.Seq-1].ChainHash {
				t.Fatalf("Entries(%d): chain hash of %d", from, e.Seq)
			}
		}
	}
	for _, from := range []uint64{16, 17, 33, 200, 331} {
		check(from)
	}
	ep, _ := w.s.Epoch()
	if err := w.s.MarkTransmitted(1, 2, 3); err != nil {
		t.Fatal(err)
	}
	if err := w.s.Commit(ep.ID, 150, all[149].ChainHash); err != nil {
		t.Fatal(err)
	}
	check(151)
	check(250)
	w.reopen()
	check(151)
	check(310)
	if err := w.s.Commit(ep.ID, 210, all[209].ChainHash); err != nil {
		t.Fatal(err)
	}
	setCapacityForTarget(w.s, w.s.Usage().Bytes-3000)
	rel, err := w.s.Relieve()
	if err != nil || rel.EvidenceEvicted < 2 || rel.RecordsCoalesced != 0 {
		t.Fatalf("relief %+v %v", rel, err)
	}
	after := allEntries(w.s)
	unpinAll(w.s)
	if len(after) != 121 {
		t.Fatalf("entries after relief %d", len(after))
	}
	want := map[uint64]protocol.Hash{}
	h := all[209].ChainHash
	for _, e := range after {
		h = protocol.ChainHash(h, e.Hash)
		want[e.Seq] = h
		if h != e.ChainHash {
			t.Fatalf("chain hash of %d after relief", e.Seq)
		}
	}
	changed := 0
	for _, e := range after {
		if e.ChainHash != all[e.Seq-1].ChainHash {
			changed++
		}
	}
	if changed == 0 {
		t.Fatal("relief did not change any chain hash")
	}
	for _, from := range []uint64{215, 240, 300, 331} {
		got := w.s.Entries(from)
		unpinAll(w.s)
		for _, e := range got {
			if e.ChainHash != want[e.Seq] {
				t.Fatalf("Entries(%d) after relief: chain hash of %d", from, e.Seq)
			}
		}
	}
	if ep2, _ := w.s.Epoch(); ep2.Chain.HeadHash != after[len(after)-1].ChainHash {
		t.Fatal("head hash after relief")
	}
	if err := w.s.Commit(ep.ID, 300, want[300]); err != nil {
		t.Fatalf("commit after relief: %v", err)
	}
	after = allEntries(w.s)
	unpinAll(w.s)
	if err := w.s.DiscardAbove(after[0].Seq); err != nil {
		t.Fatal(err)
	}
	if got := allEntries(w.s); len(got) != 1 || got[0].ChainHash != after[0].ChainHash {
		t.Fatal("discard kept the wrong records")
	}
}

func TestAppendFramesUndo(t *testing.T) {
	dir := t.TempDir()
	ss, err := openSegments(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.close()
	first, _, err := ss.appendFrames([][]byte{appendFrame(nil, []byte("one"))})
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 70)
	locs, undo, err := ss.appendFrames([][]byte{appendFrame(nil, []byte("two")), appendFrame(nil, big), appendFrame(nil, []byte("three"))})
	if err != nil {
		t.Fatal(err)
	}
	if locs[0].seg != first[0].seg || locs[1].seg == locs[0].seg || locs[2].seg == locs[1].seg {
		t.Fatalf("rollover locations %+v", locs)
	}
	if p, err := ss.read(locs[2].seg, locs[2].off, 5); err != nil || string(p) != "three" {
		t.Fatalf("read back %q %v", p, err)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if ss.active != first[0].seg || len(ss.segs) != 1 {
		t.Fatalf("undo left active %d segments %d", ss.active, len(ss.segs))
	}
	fi, _ := os.Stat(filepath.Join(dir, segName(first[0].seg)))
	if fi.Size() != frameLen(3) {
		t.Fatalf("undo left %d bytes", fi.Size())
	}
	if _, err := ss.read(locs[1].seg, locs[1].off, 70); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("read of undone frame: %v", err)
	}
	if p, err := ss.read(first[0].seg, first[0].off, 3); err != nil || string(p) != "one" {
		t.Fatalf("earlier frame after undo %q %v", p, err)
	}
}
