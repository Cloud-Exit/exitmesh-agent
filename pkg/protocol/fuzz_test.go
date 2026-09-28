package protocol

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"
)

var (
	fzTarget = "t-fuzz"
	fzEpoch  = EpochID{0x01, 0x9b, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 9}
	fzWriter = WriterID{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6}
)

// fzChain returns a valid chain of one checkpoint followed by n deltas and findings, with the state after each record.
func fzChain(t testing.TB, rng *rand.Rand, n int) ([]*Record, []*State) {
	t.Helper()
	c := NewChain(fzTarget, fzEpoch, fzWriter)
	st := NewState()
	var recs []*Record
	var states []*State
	add := func(r *Record) {
		if _, err := Encode(r); err != nil {
			t.Fatalf("encode %d: %v", r.Seq, err)
		}
		if _, err := c.Append(r); err != nil {
			t.Fatalf("append %d: %v", r.Seq, err)
		}
		if err := st.ApplyRecord(r); err != nil {
			t.Fatalf("apply %d: %v", r.Seq, err)
		}
		recs = append(recs, r)
		states = append(states, st.Clone())
	}
	add(&Record{Envelope: c.Next(TypeCheckpoint, 1, 1000), Checkpoint: st.Checkpoint(ReasonInitial, Interval{0, 1000}, nil)})
	next := 0
	for i := 0; i < n; i++ {
		now := uint64(2000 + i*1000)
		if rng.IntN(5) == 0 {
			f := &Finding{ID: FindingID(fzTarget, "k", now), DedupKey: "k", Transition: Transition(1 + rng.IntN(5)), Category: "c",
				Severity: SeverityLow, EvalTime: now, FirstSeen: now, LastSeen: now, Count: 1,
				Provenance: Provenance{Kind: ProvenanceRule, RuleID: "r", RuleVersion: 1, BundleVersion: "b"}}
			add(&Record{Envelope: c.Next(TypeFinding, 1, now), Finding: f})
			continue
		}
		d := &Delta{Ops: fzOps(rng, st, &next)}
		if rng.IntN(3) == 0 {
			d.Flags = uint64(1 + rng.IntN(3))
		}
		if rng.IntN(3) == 0 {
			d.Uncertain = &Interval{now - 10, now}
		}
		add(&Record{Envelope: c.Next(TypeDelta, 1, now), Delta: d})
	}
	return recs, states
}

func fzValue(rng *rand.Rand) any {
	switch rng.IntN(6) {
	case 0:
		return rng.IntN(100) - 50
	case 1:
		return float64(rng.IntN(64)) / 8
	case 2:
		return fmt.Sprintf("s%d", rng.IntN(9))
	case 3:
		return rng.IntN(2) == 0
	case 4:
		return []any{rng.IntN(3), "x"}
	default:
		return map[string]any{"k": rng.IntN(3)}
	}
}

func fzOps(rng *rand.Rand, st *State, next *int) []Op {
	res, edges := st.SortedResources(), st.SortedEdges()
	usedUID, usedEdge, usedScope := map[string]bool{}, map[EdgeKey]bool{}, map[string]bool{}
	keys := []string{"a", "b", "c"}
	var ops []Op
	for want := 1 + rng.IntN(4); len(ops) < want; {
		switch k := rng.IntN(9); {
		case k < 2 || len(res) == 0:
			uid := fmt.Sprintf("u%d", *next)
			*next++
			ops = append(ops, Create(uid, "Pod", "ns", uid, map[string]any{keys[rng.IntN(3)]: fzValue(rng)}))
			usedUID[uid] = true
		case k < 4:
			r := res[rng.IntN(len(res))]
			if usedUID[r.UID] {
				continue
			}
			ch := map[string]any{keys[rng.IntN(3)]: fzValue(rng)}
			if rng.IntN(2) == 0 {
				ch[keys[rng.IntN(3)]] = nil
			}
			ops = append(ops, Update(r.UID, ch))
			usedUID[r.UID] = true
		case k < 5:
			r := res[rng.IntN(len(res))]
			if usedUID[r.UID] {
				continue
			}
			ops = append(ops, Delete(r.UID, DeleteReason(1+rng.IntN(2))))
			usedUID[r.UID] = true
		case k < 7:
			if len(edges) > 0 && rng.IntN(2) == 0 {
				e := edges[rng.IntN(len(edges))]
				if usedEdge[e.Key()] {
					continue
				}
				if rng.IntN(2) == 0 {
					ops = append(ops, EdgeRemove(e.From, e.Type, e.To, CloneFields(e.Attrs)))
				} else {
					ops = append(ops, EdgeReplace(e.From, e.Type, e.To, map[string]any{"w": rng.IntN(3)}, CloneFields(e.Attrs)))
				}
				usedEdge[e.Key()] = true
				continue
			}
			key := EdgeKey{res[rng.IntN(len(res))].UID, "owns", fmt.Sprintf("u%d", rng.IntN(*next+1))}
			if _, ok := st.Edges[key]; ok || usedEdge[key] {
				continue
			}
			ops = append(ops, EdgeAdd(key.From, key.Type, key.To, map[string]any{"w": rng.IntN(3)}))
			usedEdge[key] = true
		default:
			key := []string{"s1", "s2"}[rng.IntN(2)]
			if usedScope[key] {
				continue
			}
			ops = append(ops, ScopeSet(key, ScopeStatus{State: ScopeState(rng.IntN(3))}))
			usedScope[key] = true
		}
	}
	return ops
}

func fzCheckFold(t *testing.T, run []*Record, before, after *State, prefix []*Record) *Record {
	t.Helper()
	g, err := Fold(run)
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	st := before.Clone()
	if err := st.ApplyOps(g.Ops); err != nil {
		t.Fatalf("folded ops do not apply at a-1: %v", err)
	}
	if st.Hash() != after.Hash() {
		t.Fatalf("folded ops over [%d,%d] do not reproduce the state at b", g.From, g.To)
	}
	last := run[len(run)-1]
	rr, err := NewRangeRecord(last.Envelope, g, run[0].Parent, last.Base)
	if err != nil {
		t.Fatalf("range record: %v", err)
	}
	back, err := Decode(rr.Bytes())
	if err != nil || back.Hash() != rr.Hash() {
		t.Fatalf("range record does not decode: %v", err)
	}
	p := NewReplayer(fzTarget, fzEpoch, fzWriter)
	for _, r := range append(append([]*Record{}, prefix...), back) {
		if _, err := p.Apply(r); err != nil {
			t.Fatalf("replay with range: %v", err)
		}
	}
	if p.State().Hash() != after.Hash() {
		t.Fatal("chain with range record does not reproduce the state at b")
	}
	for seq := g.From; seq < g.To; seq++ {
		if _, err := p.StateHashAt(seq); CodeOf(err) != "unavailable" {
			t.Fatalf("seq %d inside the range is available", seq)
		}
	}
	return back
}

func FuzzFold(f *testing.F) {
	for i := uint64(0); i < 24; i++ {
		f.Add(i, uint8(i*7), uint8(i*3), uint8(i*5))
	}
	f.Fuzz(func(t *testing.T, seed uint64, n, a, b uint8) {
		recs, states := fzChain(t, rand.New(rand.NewPCG(seed, 0x464f4c44)), 1+int(n%40))
		last := len(recs)
		if last < 2 {
			return
		}
		from := 2 + int(a)%(last-1)
		to := from + int(b)%(last-from+1)
		rr := fzCheckFold(t, recs[from-1:to], states[from-2], states[to-1], recs[:from-1])
		if to < last {
			to2 := to + 1 + int(b)%(last-to)
			run := append([]*Record{rr}, recs[to:to2]...)
			fzCheckFold(t, run, states[from-2], states[to2-1], recs[:from-1])
		}
	})
}

// fzBodyExtensions reports whether the record body carries extension keys, which the struct form does not keep.
func fzBodyExtensions(v any) bool {
	switch x := v.(type) {
	case map[any]any:
		for k, e := range x {
			if u, ok := k.(uint64); ok && u >= ExtensionKeyMin {
				return true
			}
			if fzBodyExtensions(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if fzBodyExtensions(e) {
				return true
			}
		}
	}
	return false
}

func FuzzDecode(f *testing.F) {
	recs, _ := fzChain(f, rand.New(rand.NewPCG(1, 2)), 12)
	for _, r := range recs {
		f.Add(r.Bytes())
	}
	g, err := Fold(recs[1:6])
	if err != nil {
		f.Fatal(err)
	}
	rr, err := NewRangeRecord(recs[5].Envelope, g, recs[0].Seq, 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(rr.Bytes())
	for _, s := range [][]byte{{}, {0xa0}, {0x81, 0x00}, {0xbf, 0xff}, {0xf9, 0x7e, 0x00}, {0xc1, 0x00}, {0xa2, 0x00, 0x01, 0x00, 0x01}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Decode(b)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatalf("rejection without a protocol code: %v", err)
			}
			return
		}
		v, err := decodeStrict(b)
		if err != nil {
			t.Fatalf("accepted record fails strict decoding: %v", err)
		}
		if re, err := Marshal(v); err != nil || !bytes.Equal(re, b) {
			t.Fatalf("accepted record does not re-encode identically")
		}
		if !bytes.Equal(r.Bytes(), b) || r.Hash() != RecordHash(b) {
			t.Fatal("record bytes or hash differ from input")
		}
		again, err := Decode(r.Bytes())
		if err != nil || again.Hash() != r.Hash() {
			t.Fatalf("decode is not stable: %v", err)
		}
		enc, err := Encode(again)
		if err != nil {
			t.Fatalf("accepted record does not encode: %v", err)
		}
		if !fzBodyExtensions(v.(map[any]any)[uint64(11)]) && !bytes.Equal(enc, b) {
			t.Fatalf("struct re-encoding differs:\n in  %x\n out %x", b, enc)
		}
		third, err := Decode(enc)
		if err != nil {
			t.Fatalf("re-encoded record rejected: %v", err)
		}
		if enc2, err := Encode(third); err != nil || !bytes.Equal(enc2, enc) {
			t.Fatalf("encoding is not stable: %v", err)
		}
	})
}
