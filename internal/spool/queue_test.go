package spool

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func openQueue(t *testing.T, dir string, capacity int64) *Queue {
	t.Helper()
	q, err := OpenQueue(dir, capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

func item(i int) []byte { return []byte(fmt.Sprintf("item-%04d", i)) }

func TestQueueAppendPeekAckRestart(t *testing.T) {
	dir := t.TempDir()
	q := openQueue(t, dir, 1<<20)
	if _, err := OpenQueue(dir, 1<<20); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open: %v", err)
	}
	for i := 1; i <= 5; i++ {
		seq, err := q.Append(item(i))
		if err != nil || seq != uint64(i) {
			t.Fatalf("append %d: seq %d %v", i, seq, err)
		}
	}
	all := q.Peek(0, 1<<20)
	if len(all) != 5 || all[0].Seq != 1 || !bytes.Equal(all[4].Data, item(5)) {
		t.Fatalf("peek all %v", all)
	}
	if got := q.Peek(3, 1); len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("peek bounded %v", got)
	}
	if got := q.Peek(3, 2*len(item(0))); len(got) != 2 || got[1].Seq != 4 {
		t.Fatalf("peek two %v", got)
	}
	if got := q.Peek(5, 1<<20); len(got) != 1 || got[0].Seq != 5 {
		t.Fatalf("peek from hint %v", got)
	}
	if err := q.Ack(2); err != nil {
		t.Fatal(err)
	}
	if err := q.Ack(1); err != nil {
		t.Fatalf("stale ack: %v", err)
	}
	if err := q.Ack(9); err == nil {
		t.Fatal("ack beyond the last item accepted")
	}
	if got := q.Peek(0, 1<<20); len(got) != 3 || got[0].Seq != 3 {
		t.Fatalf("peek after ack %v", got)
	}
	if u := q.Usage(); u.Items != 3 || u.Acked != 2 || u.Next != 6 || u.Capacity != 1<<20 || u.Bytes == 0 {
		t.Fatalf("usage %+v", u)
	}
	_ = q.Close()
	if _, err := q.Append(item(0)); !errors.Is(err, ErrClosed) {
		t.Fatalf("append after close: %v", err)
	}
	q = openQueue(t, dir, 1<<20)
	if got := q.Peek(0, 1<<20); len(got) != 3 || got[0].Seq != 3 || !bytes.Equal(got[0].Data, item(3)) {
		t.Fatalf("peek after restart %v", got)
	}
	if seq, _ := q.Append(item(6)); seq != 6 {
		t.Fatalf("sequence after restart %d", seq)
	}
	if err := q.Ack(6); err != nil {
		t.Fatal(err)
	}
	if u := q.Usage(); u.Items != 0 || u.Bytes != 0 {
		t.Fatalf("usage after full ack %+v", u)
	}
	_ = q.Close()
	q = openQueue(t, dir, 1<<20)
	if seq, _ := q.Append(item(7)); seq != 7 {
		t.Fatalf("sequence after full ack and restart %d", seq)
	}
}

func TestQueueSegmentsAndFull(t *testing.T) {
	dir := t.TempDir()
	q := openQueue(t, dir, 1<<20)
	payload := bytes.Repeat([]byte("x"), 2000)
	for i := 0; i < 100; i++ {
		if _, err := q.Append(payload); err != nil {
			t.Fatal(err)
		}
	}
	segs, _ := filepath.Glob(filepath.Join(dir, "*"+qSuffix))
	if len(segs) < 3 {
		t.Fatalf("segments %d", len(segs))
	}
	var seen []uint64
	for from := uint64(0); ; {
		page := q.Peek(from, 10_000)
		if len(page) == 0 {
			break
		}
		for _, it := range page {
			seen = append(seen, it.Seq)
		}
		from = page[len(page)-1].Seq + 1
	}
	if len(seen) != 100 || seen[99] != 100 {
		t.Fatalf("paged %d items", len(seen))
	}
	if err := q.Ack(50); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*"+qSuffix)); len(left) >= len(segs) {
		t.Fatal("acknowledged segments not removed")
	}
	if got := q.Peek(0, 1); len(got) != 1 || got[0].Seq != 51 {
		t.Fatalf("peek after partial ack %v", got)
	}

	small := openQueue(t, t.TempDir(), 200)
	n := 0
	for {
		_, err := small.Append(bytes.Repeat([]byte("y"), 40))
		if errors.Is(err, ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n == 0 || small.Usage().Bytes > 200 {
		t.Fatalf("appended %d, usage %+v", n, small.Usage())
	}
	if err := small.Ack(uint64(n)); err != nil {
		t.Fatal(err)
	}
	if _, err := small.Append([]byte("fits again")); err != nil {
		t.Fatalf("append after ack: %v", err)
	}
}

func TestQueueRecoversTornTail(t *testing.T) {
	dir := t.TempDir()
	q := openQueue(t, dir, 1<<20)
	for i := 1; i <= 3; i++ {
		if _, err := q.Append(item(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = q.Close()
	segs, _ := filepath.Glob(filepath.Join(dir, "*"+qSuffix))
	f, _ := os.OpenFile(segs[len(segs)-1], os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.Write([]byte{0, 0, 0, 40, 1, 2, 3, 4, 5})
	_ = f.Close()
	q = openQueue(t, dir, 1<<20)
	if got := q.Peek(0, 1<<20); len(got) != 3 {
		t.Fatalf("items after torn tail %d", len(got))
	}
	if seq, err := q.Append(item(4)); err != nil || seq != 4 {
		t.Fatalf("append after recovery: %d %v", seq, err)
	}
	if got := q.Peek(4, 1<<20); len(got) != 1 || !bytes.Equal(got[0].Data, item(4)) {
		t.Fatalf("item after recovery %v", got)
	}
	if q.Err() != nil {
		t.Fatal(q.Err())
	}
}

func TestQueueRejectsCorruption(t *testing.T) {
	t.Run("ack file", func(t *testing.T) {
		dir := t.TempDir()
		q := openQueue(t, dir, 1<<20)
		_, _ = q.Append(item(1))
		_ = q.Ack(1)
		_ = q.Close()
		_ = os.WriteFile(filepath.Join(dir, qAckName), []byte("garbage"), 0o600)
		if _, err := OpenQueue(dir, 1<<20); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("open: %v", err)
		}
	})
	t.Run("sealed segment", func(t *testing.T) {
		dir := t.TempDir()
		q := openQueue(t, dir, 1<<20)
		payload := bytes.Repeat([]byte("z"), 30_000)
		for i := 0; i < 6; i++ {
			_, _ = q.Append(payload)
		}
		_ = q.Close()
		segs, _ := filepath.Glob(filepath.Join(dir, "*"+qSuffix))
		if len(segs) < 2 {
			t.Fatalf("segments %d", len(segs))
		}
		b, _ := os.ReadFile(segs[0])
		b[20] ^= 0xff
		_ = os.WriteFile(segs[0], b, 0o600)
		if _, err := OpenQueue(dir, 1<<20); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("open: %v", err)
		}
	})
	if _, err := OpenQueue(t.TempDir(), 0); err == nil {
		t.Fatal("zero capacity accepted")
	}
}

func TestQueueIdentityPersistsWithTheQueue(t *testing.T) {
	dir := t.TempDir()
	q := openQueue(t, dir, 1<<20)
	id := q.ID()
	if len(id) != 32 {
		t.Fatalf("queue id %q", id)
	}
	_, _ = q.Append(item(1))
	_ = q.Close()
	if q = openQueue(t, dir, 1<<20); q.ID() != id {
		t.Fatalf("queue id changed across reopen: %s then %s", id, q.ID())
	}
	_ = q.Close()
	if other := openQueue(t, t.TempDir(), 1<<20); other.ID() == id {
		t.Fatal("a new queue reused an identity")
	}
	_ = os.WriteFile(filepath.Join(dir, qIDName), []byte("not hex"), 0o600)
	if _, err := OpenQueue(dir, 1<<20); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt identity: %v", err)
	}
}
