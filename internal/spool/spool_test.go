package spool

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestLockDirExclusive(t *testing.T) {
	dir := t.TempDir()
	unlock, err := LockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockDir(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock in the same process: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("unlock is idempotent: %v", err)
	}
	again, err := LockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = again()
}

func TestSecondOpenLockedAndIncarnationMonotonic(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open: %v", err)
	}
	writer := s.WriterID()
	if writer.IsZero() || s.Incarnation() != 1 {
		t.Fatalf("writer %s incarnation %d", writer, s.Incarnation())
	}
	for want := uint64(2); want <= 4; want++ {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if s, err = Open(Options{Dir: dir}); err != nil {
			t.Fatal(err)
		}
		if s.Incarnation() != want || s.WriterID() != writer {
			t.Fatalf("reopen: incarnation %d writer %s, want %d %s", s.Incarnation(), s.WriterID(), want, writer)
		}
	}
	_ = s.Close()
	other, err := Open(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if other.WriterID() == writer {
		t.Fatal("a new spool must get a new writer id")
	}
}

func TestAppendEntriesChainAndNotify(t *testing.T) {
	w := newWriter(t, nil)
	select {
	case <-w.s.Notify():
	default:
		t.Fatal("append did not signal")
	}
	w.delta(protocol.Create("u1", "v1/Pod", "ns", "a", map[string]any{"v": int64(1)}))
	w.finding("f1", samples(2, 10, 1)...)
	w.delta(protocol.Update("u1", map[string]any{"v": int64(2)}))
	es := allEntries(w.s)
	if len(es) != 4 {
		t.Fatalf("entries %d", len(es))
	}
	p := replayHashes(t, w.s, es)
	ep, _ := w.s.Epoch()
	if ep.Chain.Head != 4 || ep.Chain.HeadHash != es[3].ChainHash || ep.Chain.LastCheckpoint != 1 || ep.OpenReason != protocol.OpenInitial {
		t.Fatalf("epoch chain %+v", ep.Chain)
	}
	if p.State().Hash() != w.state.Hash() {
		t.Fatal("replayed state differs from writer state")
	}
	for _, e := range es {
		if e.State != NeverTransmitted {
			t.Fatalf("record %d state %s", e.Seq, e.State)
		}
	}
	if got := w.s.Entries(3); len(got) != 2 || got[0].Seq != 3 || got[0].ChainHash != es[2].ChainHash {
		t.Fatalf("Entries(3) = %d entries", len(got))
	}
	w.reopen()
	again := allEntries(w.s)
	for i := range es {
		if !bytes.Equal(es[i].Bytes, again[i].Bytes) || es[i].ChainHash != again[i].ChainHash {
			t.Fatalf("record %d changed across reopen", es[i].Seq)
		}
	}
	w.delta(protocol.Delete("u1", protocol.DeleteDeleted))
	replayHashes(t, w.s, allEntries(w.s))
	if r := decode(t, allEntries(w.s)[4]); r.Incarnation != 2 {
		t.Fatalf("incarnation on record after restart: %d", r.Incarnation)
	}
}

func TestEntriesPaging(t *testing.T) {
	w := newWriter(t, func(o *Options) { o.WindowBytes = 256 })
	for i := 0; i < 30; i++ {
		w.delta(protocol.Create(strings.Repeat("u", 1)+string(rune('A'+i)), "v1/Pod", "ns", "n", map[string]any{"pad": strings.Repeat("p", 150)}))
	}
	first := w.s.Entries(0)
	if len(first) == 0 || len(first) >= 31 {
		t.Fatalf("first page %d entries", len(first))
	}
	all := allEntries(w.s)
	if len(all) != 31 {
		t.Fatalf("paged %d entries", len(all))
	}
	for i, e := range all {
		if e.Seq != uint64(i+1) {
			t.Fatalf("page order: %d at %d", e.Seq, i)
		}
	}
	replayHashes(t, w.s, all)
}

func segFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "segments", "*"+segSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCrashRecoveryIgnoresOrphanBodies(t *testing.T) {
	w := newWriter(t, nil)
	for i := 0; i < 4; i++ {
		w.delta(protocol.Create(string(rune('a'+i)), "v1/Pod", "ns", "n", nil))
	}
	before := allEntries(w.s)
	if err := w.s.Close(); err != nil {
		t.Fatal(err)
	}
	files := segFiles(t, w.opts.Dir)
	if len(files) != 1 {
		t.Fatalf("segments %v", files)
	}
	f, err := os.OpenFile(files[0], os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	referenced, _ := f.Seek(0, 2)
	orphan := appendFrame(nil, before[1].Bytes)
	if _, err := f.Write(append(orphan, 0, 0, 1, 9, 7)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	orphanSeg := filepath.Join(w.opts.Dir, "segments", segName(99))
	if err := os.WriteFile(orphanSeg, orphan, 0o600); err != nil {
		t.Fatal(err)
	}
	w.open()
	if w.s.Incarnation() != 2 {
		t.Fatalf("incarnation %d", w.s.Incarnation())
	}
	after := allEntries(w.s)
	if len(after) != len(before) {
		t.Fatalf("records %d after recovery, want %d", len(after), len(before))
	}
	for i := range before {
		if !bytes.Equal(before[i].Bytes, after[i].Bytes) || before[i].ChainHash != after[i].ChainHash {
			t.Fatalf("record %d changed", before[i].Seq)
		}
	}
	if _, err := os.Stat(orphanSeg); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreferenced segment kept")
	}
	if fi, err := os.Stat(files[0]); err != nil || fi.Size() != referenced {
		t.Fatalf("orphan tail not truncated: size %d, referenced %d", fi.Size(), referenced)
	}
	w.delta(protocol.Create("z", "v1/Pod", "ns", "n", nil))
	w.reopen()
	all := allEntries(w.s)
	if len(all) != len(before)+1 {
		t.Fatalf("records %d", len(all))
	}
	replayHashes(t, w.s, all)
}

func recordLoc(t *testing.T, s *Spool, seq uint64) recMeta {
	t.Helper()
	var m recMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		m, err = decodeMeta(seqKey(seq), tx.Bucket(bucketRecords).Get(seqKey(seq)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestOpenRejectsCorruptOrMissingBodies(t *testing.T) {
	t.Run("corrupt", func(t *testing.T) {
		w := newWriter(t, nil)
		w.delta(protocol.Create("a", "v1/Pod", "ns", "n", map[string]any{"v": "value"}))
		m := recordLoc(t, w.s, 2)
		_ = w.s.Close()
		path := filepath.Join(w.opts.Dir, "segments", segName(m.Seg))
		b, _ := os.ReadFile(path)
		b[m.Off+frameHeader+3] ^= 0xff
		_ = os.WriteFile(path, b, 0o600)
		for i := 0; i < 2; i++ {
			if _, err := Open(w.opts); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "record 2") {
				t.Fatalf("open %d: %v", i, err)
			}
		}
	})
	t.Run("corrupt after open", func(t *testing.T) {
		w := newWriter(t, nil)
		w.delta(protocol.Create("a", "v1/Pod", "ns", "n", nil))
		w.delta(protocol.Create("b", "v1/Pod", "ns", "n", nil))
		m := recordLoc(t, w.s, 2)
		f, _ := os.OpenFile(filepath.Join(w.opts.Dir, "segments", segName(m.Seg)), os.O_RDWR, 0)
		_, _ = f.WriteAt([]byte{0xee}, m.Off+frameHeader+2)
		_ = f.Close()
		if es := w.s.Entries(0); len(es) != 1 || es[0].Seq != 1 {
			t.Fatalf("entries past a corrupt body: %d", len(es))
		}
		if err := w.s.Err(); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Err: %v", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		w := newWriter(t, func(o *Options) { o.SegmentBytes = 1 })
		w.delta(protocol.Create("a", "v1/Pod", "ns", "n", nil))
		w.delta(protocol.Create("b", "v1/Pod", "ns", "n", nil))
		m := recordLoc(t, w.s, 2)
		_ = w.s.Close()
		_ = os.Remove(filepath.Join(w.opts.Dir, "segments", segName(m.Seg)))
		if _, err := Open(w.opts); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("open: %v", err)
		}
	})
}

func TestCommitDeletesRecordsAndSegments(t *testing.T) {
	w := newWriter(t, func(o *Options) { o.SegmentBytes = 1 })
	for i := 0; i < 9; i++ {
		w.delta(protocol.Create(string(rune('a'+i)), "v1/Pod", "ns", "n", nil))
	}
	es := allEntries(w.s)
	if n := len(segFiles(t, w.opts.Dir)); n != 10 {
		t.Fatalf("segments %d", n)
	}
	seqs := []uint64{1, 2, 3, 4, 5, 6}
	if err := w.s.MarkTransmitted(seqs...); err != nil {
		t.Fatal(err)
	}
	if u := w.s.Usage(); u.InFlightBytes == 0 {
		t.Fatal("in-flight bytes not counted")
	}
	for len(w.s.Notify()) > 0 {
		<-w.s.Notify()
	}
	ep, _ := w.s.Epoch()
	if err := w.s.Commit(ep.ID, 6, es[5].ChainHash); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.s.Notify():
	default:
		t.Fatal("commit did not signal")
	}
	left := allEntries(w.s)
	if len(left) != 4 || left[0].Seq != 7 {
		t.Fatalf("left %d entries", len(left))
	}
	if n := len(segFiles(t, w.opts.Dir)); n != 4 {
		t.Fatalf("segments after commit %d", n)
	}
	if u := w.s.Usage(); u.InFlightBytes != 0 || u.Records != 4 {
		t.Fatalf("usage %+v", u)
	}
	if lc, ok := w.s.LastCommitted(); !ok || lc.Seq != 6 || lc.ChainHash != es[5].ChainHash {
		t.Fatalf("last committed %+v", lc)
	}
	for i := range left {
		if left[i].ChainHash != es[i+6].ChainHash {
			t.Fatalf("chain hash of %d changed", left[i].Seq)
		}
	}
	w.reopen()
	if lc, ok := w.s.LastCommitted(); !ok || lc.Seq != 6 {
		t.Fatal("last committed not persisted")
	}
	if err := w.s.Commit(ep.ID, 6, es[5].ChainHash); err != nil {
		t.Fatalf("repeat commit: %v", err)
	}
	if err := w.s.Commit(ep.ID, 4, protocol.Hash{}); err != nil {
		t.Fatalf("stale commit: %v", err)
	}
	if err := w.s.Commit(ep.ID, 10, es[9].ChainHash); err != nil {
		t.Fatal(err)
	}
	if n := len(segFiles(t, w.opts.Dir)); n > 1 {
		t.Fatalf("segments after full commit %d", n)
	}
	if u := w.s.Usage(); u.Records != 0 || u.Bytes != 0 || u.DiskBytes != 0 {
		t.Fatalf("usage after full commit %+v", u)
	}
	w.delta(protocol.Create("z", "v1/Pod", "ns", "n", nil))
	e := allEntries(w.s)
	if len(e) != 1 || e[0].Seq != 11 || e[0].ChainHash != protocol.ChainHash(es[9].ChainHash, e[0].Hash) {
		t.Fatal("chain does not continue from the committed head")
	}
}

func TestCommitDivergence(t *testing.T) {
	w := newWriter(t, nil)
	for i := 0; i < 4; i++ {
		w.delta(protocol.Create(string(rune('a'+i)), "v1/Pod", "ns", "n", nil))
	}
	es := allEntries(w.s)
	ep, _ := w.s.Epoch()
	if err := w.s.Commit(ep.ID, 3, es[3].ChainHash); !errors.Is(err, ErrDivergence) {
		t.Fatalf("wrong chain hash: %v", err)
	}
	if err := w.s.Commit(ep.ID, 6, es[4].ChainHash); !errors.Is(err, ErrDivergence) {
		t.Fatalf("head above highest assigned: %v", err)
	}
	other, _ := protocol.NewEpoch(time.Now())
	if err := w.s.Commit(other, 3, es[2].ChainHash); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("other epoch: %v", err)
	}
	if n := len(allEntries(w.s)); n != 5 {
		t.Fatalf("divergence deleted records: %d left", n)
	}
	if err := w.s.Commit(ep.ID, 3, es[2].ChainHash); err != nil {
		t.Fatal(err)
	}
	if err := w.s.Commit(ep.ID, 3, es[1].ChainHash); !errors.Is(err, ErrDivergence) {
		t.Fatalf("changed hash at committed head: %v", err)
	}
}

func TestMarkTransmittedDurableAcrossRestart(t *testing.T) {
	w := newWriter(t, nil)
	w.delta(protocol.Create("a", "v1/Pod", "ns", "n", nil))
	w.delta(protocol.Create("b", "v1/Pod", "ns", "n", nil))
	if err := w.s.MarkTransmitted(1, 2, 2); err != nil {
		t.Fatal(err)
	}
	if err := w.s.MarkTransmitted(9); !errors.Is(err, ErrNotSpooled) {
		t.Fatalf("unknown sequence: %v", err)
	}
	w.reopen()
	es := allEntries(w.s)
	if es[0].State.String() != "transmitted-unconfirmed" || es[2].State.String() != "never-transmitted" {
		t.Fatalf("state names %s %s", es[0].State, es[2].State)
	}
	want := []RecordState{TransmittedUnconfirmed, TransmittedUnconfirmed, NeverTransmitted}
	for i, e := range es {
		if e.State != want[i] {
			t.Fatalf("record %d state %s after restart", e.Seq, e.State)
		}
	}
	if u := w.s.Usage(); u.InFlightBytes != int64(len(es[0].Bytes)+len(es[1].Bytes)) {
		t.Fatalf("in-flight bytes %d", u.InFlightBytes)
	}
}

func TestDiscardAboveAndRebaseline(t *testing.T) {
	t.Run("discard above committed head", func(t *testing.T) {
		w := newWriter(t, nil)
		for i := 0; i < 7; i++ {
			w.delta(protocol.Create(string(rune('a'+i)), "v1/Pod", "ns", "n", nil))
		}
		es := allEntries(w.s)
		_ = w.s.MarkTransmitted(1, 2, 3, 4, 5, 6, 7, 8)
		old, _ := w.s.Epoch()
		if err := w.s.Commit(old.ID, 4, es[3].ChainHash); err != nil {
			t.Fatal(err)
		}
		for len(w.s.Notify()) > 0 {
			<-w.s.Notify()
		}
		if err := w.s.DiscardAbove(4); err != nil {
			t.Fatal(err)
		}
		select {
		case <-w.s.Notify():
		default:
			t.Fatal("discard did not signal")
		}
		if n := len(allEntries(w.s)); n != 0 {
			t.Fatalf("%d records left", n)
		}
		err := w.s.Do(func(tx *Tx) error {
			_, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
				return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: []protocol.Op{protocol.Delete("a", protocol.DeleteDeleted)}}}, nil
			})
			return err
		})
		if !errors.Is(err, ErrEpochSealed) {
			t.Fatalf("append after discard: %v", err)
		}
		if err := w.s.Commit(old.ID, 6, es[5].ChainHash); !errors.Is(err, ErrDivergence) {
			t.Fatalf("commit above discard: %v", err)
		}
		w.reopen()
		if ep, _ := w.s.Epoch(); !ep.Sealed || ep.SealedAt != 4 || ep.Chain.Head != 8 {
			t.Fatalf("sealed state not persisted: %+v", ep)
		}
		h := uint64(4)
		id, err := w.s.OpenEpoch(protocol.OpenRebaseline, &old.ID, &h)
		if err != nil {
			t.Fatal(err)
		}
		if id == old.ID {
			t.Fatal("rebaseline reused the epoch")
		}
	})
	t.Run("divergence at committed head", func(t *testing.T) {
		w := newWriter(t, nil)
		for i := 0; i < 7; i++ {
			w.delta(protocol.Create(string(rune('a'+i)), "v1/Pod", "ns", "n", nil))
		}
		_ = w.s.MarkTransmitted(1, 2, 3, 4, 5, 6, 7, 8)
		old, _ := w.s.Epoch()
		if err := w.s.Commit(old.ID, 5, protocol.Hash{1}); !errors.Is(err, ErrDivergence) {
			t.Fatalf("commit: %v", err)
		}
		if err := w.s.DiscardAbove(5); err != nil {
			t.Fatal(err)
		}
		if n := len(allEntries(w.s)); n != 5 {
			t.Fatalf("%d records left", n)
		}
		if _, err := w.s.OpenEpoch(protocol.OpenRebaseline, nil, nil); !errors.Is(err, ErrRecordsRemain) {
			t.Fatalf("open without previous epoch: %v", err)
		}
		low := uint64(3)
		if _, err := w.s.OpenEpoch(protocol.OpenRebaseline, &old.ID, &low); !errors.Is(err, ErrRecordsRemain) {
			t.Fatalf("open below remaining records: %v", err)
		}
		h := uint64(5)
		id, err := w.s.OpenEpoch(protocol.OpenRebaseline, &old.ID, &h)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(allEntries(w.s)); n != 0 {
			t.Fatalf("%d records survive the rebaseline", n)
		}
		if _, ok := w.s.LastCommitted(); ok {
			t.Fatal("last committed carried into the new epoch")
		}
		e := w.append(protocol.TypeCheckpoint, func(env protocol.Envelope) *protocol.Record {
			ck := w.state.Checkpoint(protocol.ReasonRebaseline, protocol.Interval{Start: env.Time, End: env.Time}, nil)
			ck.PrevEpoch, ck.PrevHead = &old.ID, &h
			return &protocol.Record{Envelope: env, Checkpoint: ck}
		})
		if e.Seq != 1 {
			t.Fatalf("new epoch starts at %d", e.Seq)
		}
		w.reopen()
		ep, _ := w.s.Epoch()
		if ep.ID != id || ep.OpenReason != protocol.OpenRebaseline || ep.PrevEpoch == nil || *ep.PrevEpoch != old.ID || ep.PrevHead == nil || *ep.PrevHead != 5 || ep.Sealed || ep.Chain.Head != 1 {
			t.Fatalf("new epoch state %+v", ep)
		}
		replayHashes(t, w.s, allEntries(w.s))
	})
}

func TestWithCursorAtomicWithRecord(t *testing.T) {
	w := newWriter(t, nil)
	build := func(env protocol.Envelope) (*protocol.Record, error) {
		return &protocol.Record{Envelope: env, Finding: testFinding("n1", env.Time, nil)}, nil
	}
	boom := errors.New("boom")
	var kept *Tx
	err := w.s.Do(func(tx *Tx) error {
		kept = tx
		if _, err := tx.Append(protocol.TypeFinding, build, WithCursor("node/a", 7)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := kept.Append(protocol.TypeFinding, build); !errors.Is(err, ErrTxDone) {
		t.Fatalf("append after Do: %v", err)
	}
	if w.s.Cursor("node/a") != 0 || len(allEntries(w.s)) != 1 {
		t.Fatal("failed transaction persisted its cursor or record")
	}
	if ep, _ := w.s.Epoch(); ep.Chain.Head != 1 {
		t.Fatalf("failed transaction advanced the chain to %d", ep.Chain.Head)
	}
	err = w.s.Do(func(tx *Tx) error {
		if _, err := tx.Append(protocol.TypeFinding, build, WithCursor("node/a", 7)); err != nil {
			return err
		}
		_, err := tx.Append(protocol.TypeFinding, build, WithCursor("node/a", 8), WithCursor("node/b", 2))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	w.reopen()
	if w.s.Cursor("node/a") != 8 || w.s.Cursor("node/b") != 2 {
		t.Fatalf("cursors %d %d", w.s.Cursor("node/a"), w.s.Cursor("node/b"))
	}
	es := allEntries(w.s)
	if len(es) != 3 || es[1].Seq != 2 || es[2].Seq != 3 {
		t.Fatalf("records %d", len(es))
	}
	replayHashes(t, w.s, es)
	if err := w.s.Do(func(tx *Tx) error {
		_, err := tx.Append(protocol.TypeRange, build)
		return err
	}); err == nil {
		t.Fatal("range append accepted")
	}
}

func TestHaltPersistsUntilCleared(t *testing.T) {
	w := newWriter(t, nil)
	if err := w.s.SetHalted(protocol.CodeEpochClosed, "epoch closed by control plane"); err != nil {
		t.Fatal(err)
	}
	w.reopen()
	h, ok := w.s.Halted()
	if !ok || h.Code != protocol.CodeEpochClosed || h.Message == "" || h.At.IsZero() {
		t.Fatalf("halt %+v %v", h, ok)
	}
	if err := w.s.Do(func(*Tx) error { return nil }); !errors.Is(err, ErrHalted) {
		t.Fatalf("Do while halted: %v", err)
	}
	if _, err := w.s.OpenEpoch(protocol.OpenRebaseline, nil, nil); !errors.Is(err, ErrHalted) {
		t.Fatalf("OpenEpoch while halted: %v", err)
	}
	if err := w.s.ClearHalt(); err != nil {
		t.Fatal(err)
	}
	w.reopen()
	if _, ok := w.s.Halted(); ok {
		t.Fatal("halt survived ClearHalt")
	}
	w.delta(protocol.Create("a", "v1/Pod", "ns", "n", nil))
}

func TestIdentityAndRegistrationPersist(t *testing.T) {
	w := newWriter(t, nil)
	if err := w.s.SetIdentity(Identity{TargetID: "bad target"}); err == nil {
		t.Fatal("invalid target accepted")
	}
	id := Identity{TargetID: testTarget, TargetType: protocol.TargetKubernetes, Credential: "secret", CredentialID: "cred-1", MachineID: "m-1"}
	if err := w.s.SetIdentity(id); err != nil {
		t.Fatal(err)
	}
	if err := w.s.MarkRegistered(); err != nil {
		t.Fatal(err)
	}
	w.reopen()
	if w.s.Identity() != id {
		t.Fatalf("identity %+v", w.s.Identity())
	}
	if ep, _ := w.s.Epoch(); !ep.Registered {
		t.Fatal("registration lost")
	}
	fresh, err := Open(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.OpenEpoch(protocol.OpenInitial, nil, nil); err == nil {
		t.Fatal("epoch opened without a target id")
	}
	if err := fresh.MarkRegistered(); !errors.Is(err, ErrNoEpoch) {
		t.Fatalf("register without epoch: %v", err)
	}
}

func TestRecoverySnapshotReplacedInPlace(t *testing.T) {
	w := newWriter(t, nil)
	if _, ok, err := w.s.LoadRecoverySnapshot(); ok || err != nil {
		t.Fatalf("empty spool snapshot: %v %v", ok, err)
	}
	for _, v := range []string{"first snapshot", "second"} {
		if err := w.s.SaveRecoverySnapshot([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	w.reopen()
	b, ok, err := w.s.LoadRecoverySnapshot()
	if err != nil || !ok || string(b) != "second" {
		t.Fatalf("snapshot %q %v %v", b, ok, err)
	}
	if m, _ := filepath.Glob(filepath.Join(w.opts.Dir, "recovery.snap*")); len(m) != 1 {
		t.Fatalf("snapshot files %v", m)
	}
	path := filepath.Join(w.opts.Dir, "recovery.snap")
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(path, raw, 0o600)
	if _, _, err := w.s.LoadRecoverySnapshot(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt snapshot: %v", err)
	}
}

func TestKVBucketsDurableAndIsolated(t *testing.T) {
	w := newWriter(t, nil)
	if err := w.s.KV("alerts").Put("r1", []byte("firing")); err != nil {
		t.Fatal(err)
	}
	if err := w.s.KV("offsets").Put("r1", []byte("42")); err != nil {
		t.Fatal(err)
	}
	w.reopen()
	v, ok, err := w.s.KV("alerts").Get("r1")
	if err != nil || !ok || string(v) != "firing" {
		t.Fatalf("alerts %q %v %v", v, ok, err)
	}
	v, _, _ = w.s.KV("offsets").Get("r1")
	if string(v) != "42" {
		t.Fatalf("offsets %q", v)
	}
	st := w.s.KV("alerts")
	_ = w.s.Close()
	if _, _, err := st.Get("r1"); err == nil {
		t.Fatal("store usable after close")
	}
	if _, _, err := w.s.KV("new").Get("x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("new bucket after close: %v", err)
	}
}

func TestUsageRateAndProjectedWindow(t *testing.T) {
	w := newWriter(t, func(o *Options) { o.CapacityBytes = 1 << 20 })
	for i := 0; i < 99; i++ {
		w.delta(protocol.Create(strings.Repeat("u", 3)+string(rune('0'+i%10))+string(rune('a'+i/10)), "v1/Pod", "ns", "n", map[string]any{"pad": strings.Repeat("x", 100)}))
	}
	u := w.s.Usage()
	if u.Records != 100 || u.Capacity != 1<<20 || u.WindowBytes != DefaultWindowBytes {
		t.Fatalf("usage %+v", u)
	}
	first := allEntries(w.s)[0]
	if want := time.UnixMilli(int64(decode(t, first).Time)); !u.Oldest.Equal(want) {
		t.Fatalf("oldest %v, want %v", u.Oldest, want)
	}
	steady := float64(u.Bytes) / 100
	if d := (u.AppendRate - steady) / steady; d < -0.03 || d > 0.03 {
		t.Fatalf("rate %.1f B/s, steady %.1f B/s", u.AppendRate, steady)
	}
	if want := projectWindow(u.Capacity-u.Bytes, u.AppendRate); u.ProjectedWindow != want {
		t.Fatalf("projected %v, want %v", u.ProjectedWindow, want)
	}
	if exact := time.Duration(float64(u.Capacity-u.Bytes) / u.AppendRate * float64(time.Second)); u.ProjectedWindow != exact {
		t.Fatalf("projected %v, want free/rate %v", u.ProjectedWindow, exact)
	}
	w.clk.Advance(10 * rateTau)
	idle := w.s.Usage()
	if idle.AppendRate > u.AppendRate/1000 || idle.ProjectedWindow <= u.ProjectedWindow {
		t.Fatalf("idle rate %.3f window %v", idle.AppendRate, idle.ProjectedWindow)
	}
	if projectWindow(10, 0) != time.Duration(1<<63-1) {
		t.Fatal("zero rate must project an unbounded window")
	}
}
