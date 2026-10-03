package spool

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// TestConcurrentWriterSessionAndRelief runs appends with automatic relief against a session
// that reads, marks, sends, and commits; the receiving chain must never diverge.
func TestConcurrentWriterSessionAndRelief(t *testing.T) {
	w := newWriter(t, func(o *Options) { o.CapacityBytes = 16 << 10; o.WindowBytes = 2 << 10 })
	w.delta(protocol.Create("r0", "v1/ConfigMap", "ns", "a", map[string]any{"v": "0"}))
	w.delta(protocol.Create("r1", "v1/ConfigMap", "ns", "b", map[string]any{"v": "0"}))
	ep, _ := w.s.Epoch()
	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i == 100 {
				close(started)
			}
			if i%10 == 0 {
				w.finding(fmt.Sprintf("f%d", i), samples(3, 300, uint64(i))...)
				continue
			}
			w.delta(protocol.Update(fmt.Sprintf("r%d", i%2), map[string]any{"v": strings.Repeat("v", 100+i%50)}))
		}
	}()
	<-started
	cp := protocol.NewReplayer(ep.TargetID, ep.ID, w.s.WriterID())
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	var next uint64
	ranges, sent := 0, 0
	for finished := false; ; {
		select {
		case <-done:
			finished = true
		default:
		}
		es := w.s.Entries(next)
		if len(es) == 0 {
			if finished {
				break
			}
			select {
			case <-w.s.Notify():
			case <-done:
			}
			continue
		}
		seqs := make([]uint64, len(es))
		for i, e := range es {
			seqs[i] = e.Seq
		}
		if err := w.s.MarkTransmitted(seqs...); err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			r, err := protocol.Decode(e.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			h, err := cp.Apply(r)
			if err != nil {
				t.Fatalf("control plane rejects %d: %v", e.Seq, err)
			}
			if h != e.ChainHash {
				t.Fatalf("chain hash of %d diverged", e.Seq)
			}
			if r.Type == protocol.TypeRange {
				ranges++
			}
			sent++
			next = e.Seq + 1
			if sent%7 == 0 {
				if err := w.s.Commit(ep.ID, e.Seq, h); err != nil {
					t.Fatalf("commit %d: %v", e.Seq, err)
				}
			}
		}
	}
	head := cp.Chain()
	if err := w.s.Commit(ep.ID, head.Head, head.HeadHash); err != nil {
		t.Fatal(err)
	}
	if ranges == 0 {
		t.Fatal("no coalescing happened under pressure")
	}
	if cp.State().Hash() != w.state.Hash() {
		t.Fatal("control plane state differs from writer state")
	}
	if u := w.s.Usage(); u.Records != 0 || u.ReliefError != nil || u.RebaselineRequired {
		t.Fatalf("usage %+v", u)
	}
}
