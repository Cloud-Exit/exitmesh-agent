package main

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"

	p "github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Fold vectors.

type foldExpect struct {
	Span           [2]uint64   `json:"span"`
	RangeBody      string      `json:"range_body"`
	Ops            int         `json:"ops"`
	FindingSeqs    []uint64    `json:"finding_seqs"`
	Flags          uint64      `json:"flags"`
	Uncertain      [][2]uint64 `json:"uncertain"`
	StateBefore    string      `json:"state_before"`
	StateAfter     string      `json:"state_after"`
	RangeRecord    string      `json:"range_record"`
	RangeChainHash string      `json:"range_chain_hash"`
}

type foldVector struct {
	Name   string      `json:"name"`
	Prefix []string    `json:"prefix"`
	Run    []string    `json:"run"`
	Expect *foldExpect `json:"expect,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type foldFile struct {
	Description string       `json:"description"`
	Vectors     []foldVector `json:"vectors"`
}

func hexes(rs []*p.Record) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = hx(r.Bytes())
	}
	return out
}

func replay(rs []*p.Record) *p.Replayer {
	pr := p.NewReplayer(rs[0].TargetID, rs[0].Epoch, rs[0].Writer)
	for _, r := range rs {
		must(pr.Apply(r))
	}
	return pr
}

func foldCase(name string, prefix, run []*p.Record) foldVector {
	pr := replay(prefix)
	before := pr.State().Hash()
	headHash := pr.Chain().HeadHash
	g := must(p.Fold(run))
	last := run[len(run)-1]
	rr := must(p.NewRangeRecord(last.Envelope, g, run[0].Parent, last.Base))
	for _, r := range run {
		must(pr.Apply(r))
	}
	after := pr.State().Hash()
	st := replay(prefix).State().Clone()
	check(st.ApplyOps(g.Ops))
	if st.Hash() != after {
		panic(name + ": folded ops do not reproduce the state at b")
	}
	e := &foldExpect{
		Span: [2]uint64{g.From, g.To}, RangeBody: hx(marshal(generic(rr.Bytes())[uint64(11)])), Ops: len(g.Ops),
		FindingSeqs: []uint64{}, Flags: g.Flags, Uncertain: [][2]uint64{}, StateBefore: before.String(), StateAfter: after.String(),
		RangeRecord: hx(rr.Bytes()), RangeChainHash: p.ChainHash(headHash, rr.Hash()).String(),
	}
	for _, f := range g.Findings {
		e.FindingSeqs = append(e.FindingSeqs, f.Seq)
	}
	for _, iv := range g.Uncertain {
		e.Uncertain = append(e.Uncertain, [2]uint64{iv.Start, iv.End})
	}
	return foldVector{Name: name, Prefix: hexes(prefix), Run: hexes(run), Expect: e}
}

func foldError(name string, run []*p.Record) foldVector {
	_, err := p.Fold(run)
	if p.CodeOf(err) != "fold" {
		panic(fmt.Sprintf("%s: fold returned %v", name, err))
	}
	return foldVector{Name: name, Prefix: []string{}, Run: hexes(run), Error: "fold"}
}

func loose(seq uint64, ops ...p.Op) *p.Record {
	r := &p.Record{Envelope: deltaEnv(seq), Delta: &p.Delta{Ops: ops}}
	must(p.Encode(r))
	return r
}

func attrs(w int) map[string]any { return map[string]any{"w": w} }

func foldVectors() foldFile {
	var vs []foldVector

	st := p.NewState()
	check(st.ApplyOps([]p.Op{
		p.Create("u-exist1", "Pod", "default", "e1", map[string]any{"a": 1, "b": 2}),
		p.Create("u-exist2", "Pod", "default", "e2", nil),
		p.Create("u-exist3", "apps/Deployment", "default", "e3", map[string]any{"m": 0}),
	}))
	b := newBuilder(epochA, writerA)
	b.checkpointOf(st, p.ReasonInitial)
	b.delta(p.Create("u-new1", "Pod", "default", "n1", map[string]any{"x": 1, "y": 2}),
		p.Update("u-exist1", map[string]any{"a": 10, "b": nil}), p.Delete("u-exist2", p.DeleteDeleted))
	b.delta(p.Update("u-new1", map[string]any{"y": nil, "z": 3}), p.Update("u-exist1", map[string]any{"c": "c"}),
		p.Create("u-tmp", "Pod", "default", "tmp", map[string]any{"t": 1}))
	b.delta(p.Delete("u-tmp", p.DeleteDeleted), p.Update("u-exist3", map[string]any{"m": 1}))
	b.delta(p.Update("u-exist3", map[string]any{"m": 2}), p.Update("u-exist1", map[string]any{"a": nil}))
	b.delta(p.Delete("u-exist3", p.DeleteScopeRemoved))
	vs = append(vs, foldCase("resource table: create-update, update merge with nulls, cancel, delete reason", b.recs[:1], b.recs[1:]))

	st = p.NewState()
	check(st.ApplyOps([]p.Op{
		p.EdgeAdd("a", "owns", "e1", attrs(1)), p.EdgeAdd("a", "owns", "e2", attrs(1)), p.EdgeAdd("a", "owns", "e3", attrs(1)),
		p.EdgeAdd("a", "owns", "e4", attrs(1)), p.EdgeAdd("a", "owns", "e5", attrs(1)),
		p.ScopeSet("s1", p.ScopeStatus{State: p.ScopeComplete}),
	}))
	b = newBuilder(epochA, writerA)
	b.checkpointOf(st, p.ReasonInitial)
	b.delta(p.EdgeAdd("a", "owns", "eN", attrs(7)), p.EdgeRemove("a", "owns", "e1", attrs(1)),
		p.EdgeReplace("a", "owns", "e2", attrs(2), attrs(1)), p.EdgeReplace("a", "owns", "e3", attrs(5), attrs(1)),
		p.EdgeAdd("a", "owns", "eT", nil), p.EdgeRemove("a", "owns", "e4", attrs(1)), p.EdgeRemove("a", "owns", "e5", attrs(1)),
		p.ScopeSet("s1", p.ScopeStatus{State: p.ScopePartial, Reason: "forbidden"}))
	b.delta(p.EdgeReplace("a", "owns", "e2", attrs(1), attrs(2)), p.EdgeRemove("a", "owns", "eT", nil),
		p.EdgeAdd("a", "owns", "e4", attrs(1)), p.EdgeAdd("a", "owns", "e5", attrs(9)),
		p.ScopeSet("s1", p.ScopeStatus{State: p.ScopeUnavailable, Reason: "gone", Since: t0}), p.ScopeSet("s2", p.ScopeStatus{State: p.ScopeComplete}))
	vs = append(vs, foldCase("edge table and last scope-set wins", b.recs[:1], b.recs[1:]))

	b = newBuilder(epochA, writerA)
	b.checkpointOf(richState(), p.ReasonInitial)
	b.deltaWith(p.FlagSynthetic, &p.Interval{Start: t0, End: t0 + 10}, p.Update("uid-node-a", map[string]any{"ready": false}))
	b.finding(fullFinding(b.now))
	b.deltaWith(p.FlagMetricFacts, nil, p.Update("uid-node-a", map[string]any{"metric.cpu": 0.75}))
	b.finding(minimalFinding(b.now, p.TransitionResolved))
	b.deltaWith(0, &p.Interval{Start: t0 + 20, End: t0 + 30}, p.Update("uid-node-a", map[string]any{"ready": true}))
	vs = append(vs, foldCase("findings preserved in order, flags ORed, intervals concatenated", b.recs[:1], b.recs[1:]))
	vs = append(vs, foldCase("single delta", b.recs[:3], b.recs[3:4]))
	vs = append(vs, foldCase("only findings", b.recs[:2], b.recs[2:3]))

	b = newBuilder(epochA, writerA)
	b.checkpointOf(richState(), p.ReasonInitial)
	for i := 0; i < 6; i++ {
		b.delta(p.Update("uid-pod-web-1", map[string]any{"restarts": i + 1, fmt.Sprintf("k%d", i): i}))
	}
	r5 := rangeRecord(b, 3, 5)
	withRange := []*p.Record{b.recs[0], b.recs[1], r5, b.recs[5], b.recs[6]}
	vs = append(vs, foldCase("run starting with a range record takes its span start", withRange[:2], withRange[2:]))

	for seed := uint64(1); seed <= 6; seed++ {
		rg := &rgen{rng: rand.New(rand.NewPCG(seed, 0x454d4850))} //nolint:gosec // seeded PRNG keeps the committed vectors reproducible
		b := rg.chain(8 + int(seed)*3)
		n := len(b.recs)
		a := 2 + rg.rng.IntN(n-2)
		end := a + rg.rng.IntN(n-a+1)
		vs = append(vs, foldCase(fmt.Sprintf("random run seed %d", seed), b.recs[:a-1], b.recs[a-1:end]))
	}

	b = newBuilder(epochA, writerA)
	b.checkpointOf(richState(), p.ReasonInitial)
	b.delta(p.Update("uid-node-a", map[string]any{"x": 1}))
	b.checkpoint(p.ReasonAnchor)
	b.delta(p.Update("uid-node-a", map[string]any{"x": 2}))
	vs = append(vs, foldError("run containing a checkpoint", b.recs[1:4]))
	vs = append(vs, foldError("non-contiguous run", []*p.Record{b.recs[1], b.recs[3]}))
	vs = append(vs, foldError("empty run", nil))
	vs = append(vs, foldError("update after delete", []*p.Record{loose(2, p.Delete("u1", p.DeleteDeleted)), loose(3, p.Update("u1", map[string]any{"a": 1}))}))
	vs = append(vs, foldError("create of a uid already touched", []*p.Record{loose(2, p.Update("u1", map[string]any{"a": 1})), loose(3, p.Create("u1", "Pod", "", "u1", nil))}))
	vs = append(vs, foldError("edge-add of a present edge", []*p.Record{loose(2, p.EdgeAdd("a", "t", "b", nil)), loose(3, p.EdgeAdd("a", "t", "b", nil))}))
	vs = append(vs, foldError("edge-remove of an absent edge", []*p.Record{loose(2, p.EdgeRemove("a", "t", "b", nil)), loose(3, p.EdgeRemove("a", "t", "b", nil))}))
	vs = append(vs, foldError("edge-replace of an absent edge", []*p.Record{loose(2, p.EdgeRemove("a", "t", "b", nil)), loose(3, p.EdgeReplace("a", "t", "b", nil, nil))}))
	return foldFile{Description: "Fold of a contiguous run (SPEC 5). prefix holds the chain up to a-1.", Vectors: vs}
}

// rgen builds deterministic random valid chains.
type rgen struct {
	rng  *rand.Rand
	next int
}

func (g *rgen) value(depth int) any {
	switch g.rng.IntN(8) {
	case 0:
		return g.rng.IntN(2001) - 1000
	case 1:
		return float64(g.rng.IntN(400)-200) / 8
	case 2:
		return fmt.Sprintf("v%d", g.rng.IntN(50))
	case 3:
		return g.rng.IntN(2) == 0
	case 4:
		return []byte{byte(g.rng.IntN(256) & 0xff), byte(g.rng.IntN(256) & 0xff)}
	case 5:
		if depth < 2 {
			return []any{g.value(depth + 1), g.value(depth + 1)}
		}
		return uint64(1<<63) + g.rng.Uint64N(1000)
	case 6:
		if depth < 2 {
			return map[string]any{"k": g.value(depth + 1), "l": g.value(depth + 1)}
		}
		return "leaf"
	default:
		return g.rng.Float64()
	}
}

var fieldKeys = []string{"a", "b", "c", "metric.cpu", "spec", "status"}

func (g *rgen) fields(n int) map[string]any {
	m := map[string]any{}
	for i := 0; i < n; i++ {
		m[fieldKeys[g.rng.IntN(len(fieldKeys))]] = g.value(0)
	}
	return m
}

func (g *rgen) ops(st *p.State) []p.Op {
	res := st.SortedResources()
	edges := st.SortedEdges()
	usedUID, usedEdge, usedScope := map[string]bool{}, map[p.EdgeKey]bool{}, map[string]bool{}
	var ops []p.Op
	n := 1 + g.rng.IntN(4)
	for len(ops) < n {
		switch k := g.rng.IntN(10); {
		case k < 2 || len(res) == 0:
			uid := fmt.Sprintf("u%03d", g.next)
			g.next++
			kinds := []string{"Pod", "apps/Deployment", "host/Service"}
			ops = append(ops, p.Create(uid, kinds[g.rng.IntN(3)], []string{"", "default"}[g.rng.IntN(2)], uid, g.fields(g.rng.IntN(3))))
			usedUID[uid] = true
		case k < 5:
			r := res[g.rng.IntN(len(res))]
			if usedUID[r.UID] {
				continue
			}
			ch := g.fields(1 + g.rng.IntN(2))
			for _, f := range slices.Sorted(maps.Keys(r.Fields)) {
				if g.rng.IntN(3) == 0 {
					ch[f] = nil
				}
			}
			if len(ch) == 0 {
				continue
			}
			ops = append(ops, p.Update(r.UID, ch))
			usedUID[r.UID] = true
		case k < 6:
			r := res[g.rng.IntN(len(res))]
			if usedUID[r.UID] {
				continue
			}
			ops = append(ops, p.Delete(r.UID, p.DeleteReason(1+g.rng.Uint64N(2))))
			usedUID[r.UID] = true
		case k < 8:
			if len(edges) > 0 && g.rng.IntN(2) == 0 {
				e := edges[g.rng.IntN(len(edges))]
				if usedEdge[e.Key()] {
					continue
				}
				if g.rng.IntN(2) == 0 {
					ops = append(ops, p.EdgeRemove(e.From, e.Type, e.To, p.CloneFields(e.Attrs)))
				} else {
					ops = append(ops, p.EdgeReplace(e.From, e.Type, e.To, g.fields(g.rng.IntN(2)), p.CloneFields(e.Attrs)))
				}
				usedEdge[e.Key()] = true
				continue
			}
			key := p.EdgeKey{From: res[g.rng.IntN(len(res))].UID, Type: []string{"owns", "selects"}[g.rng.IntN(2)], To: fmt.Sprintf("u%03d", g.rng.IntN(g.next+1))}
			if _, ok := st.Edges[key]; ok || usedEdge[key] {
				continue
			}
			ops = append(ops, p.EdgeAdd(key.From, key.Type, key.To, g.fields(g.rng.IntN(2))))
			usedEdge[key] = true
		default:
			key := []string{"Pod|default", "apps/Deployment|default", "host/Service"}[g.rng.IntN(3)]
			if usedScope[key] {
				continue
			}
			s := p.ScopeStatus{State: p.ScopeState(g.rng.Uint64N(3))}
			if g.rng.IntN(2) == 0 {
				s.Reason = "forbidden"
			}
			if g.rng.IntN(2) == 0 {
				s.Since = t0 + g.rng.Uint64N(1000)
			}
			ops = append(ops, p.ScopeSet(key, s))
			usedScope[key] = true
		}
	}
	return ops
}

func (g *rgen) chain(n int) *builder {
	b := newBuilder(epochA, writerA)
	b.checkpoint(p.ReasonInitial)
	for i := 0; i < n; i++ {
		if g.rng.IntN(6) == 0 {
			b.finding(minimalFinding(b.now, p.Transition(1+g.rng.Uint64N(5))))
			continue
		}
		var flags uint64
		var unc *p.Interval
		if g.rng.IntN(4) == 0 {
			flags = 1 + g.rng.Uint64N(3)
		}
		if g.rng.IntN(4) == 0 {
			unc = &p.Interval{Start: b.now - 100, End: b.now}
		}
		b.deltaWith(flags, unc, g.ops(b.state)...)
	}
	return b
}

// Reconstruction vectors.

type seqHash struct {
	Seq       uint64 `json:"seq"`
	StateHash string `json:"state_hash"`
}

type seqChain struct {
	Seq       uint64 `json:"seq"`
	ChainHash string `json:"chain_hash"`
}

type boundaryVec struct {
	Seq      uint64 `json:"seq"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
}

type reconError struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

type reconVector struct {
	Name        string        `json:"name"`
	Records     []string      `json:"records"`
	States      []seqHash     `json:"states"`
	ChainHashes []seqChain    `json:"chain_hashes"`
	Boundaries  []boundaryVec `json:"boundaries"`
	Unavailable [][2]uint64   `json:"unavailable"`
	Error       *reconError   `json:"error"`
}

type reconFile struct {
	Description string        `json:"description"`
	Vectors     []reconVector `json:"vectors"`
}

func reconCase(name string, raw [][]byte, wantBoundaries int, wantErr string) reconVector {
	v := reconVector{Name: name, States: []seqHash{}, ChainHashes: []seqChain{}, Boundaries: []boundaryVec{}, Unavailable: [][2]uint64{}}
	var pr *p.Replayer
	for i, b := range raw {
		v.Records = append(v.Records, hx(b))
		if v.Error != nil {
			continue
		}
		r, err := p.Decode(b)
		if err == nil {
			if pr == nil {
				pr = p.NewReplayer(r.TargetID, r.Epoch, r.Writer)
			}
			var h p.Hash
			if h, err = pr.Apply(r); err == nil {
				v.ChainHashes = append(v.ChainHashes, seqChain{Seq: r.Seq, ChainHash: h.String()})
			}
		}
		if err != nil {
			v.Error = &reconError{Index: i, Code: p.CodeOf(err)}
		}
	}
	if (v.Error == nil) != (wantErr == "") || (v.Error != nil && v.Error.Code != wantErr) {
		panic(fmt.Sprintf("%s: error %+v, want %q", name, v.Error, wantErr))
	}
	if pr != nil {
		for seq := uint64(1); seq <= pr.Chain().Head; seq++ {
			h, err := pr.StateHashAt(seq)
			switch {
			case p.CodeOf(err) == "unavailable":
				v.States = append(v.States, seqHash{Seq: seq, StateHash: "unavailable"})
			case err != nil:
				panic(fmt.Sprintf("%s: seq %d: %v", name, seq, err))
			default:
				v.States = append(v.States, seqHash{Seq: seq, StateHash: h.String()})
			}
		}
		for _, bd := range pr.Boundaries {
			v.Boundaries = append(v.Boundaries, boundaryVec{Seq: bd.Seq, Expected: bd.Expected.String(), Got: bd.Got.String()})
		}
		for _, s := range pr.Unavailable {
			v.Unavailable = append(v.Unavailable, [2]uint64{s.From, s.To})
		}
	}
	if len(v.Boundaries) != wantBoundaries {
		panic(fmt.Sprintf("%s: %d boundaries, want %d", name, len(v.Boundaries), wantBoundaries))
	}
	return v
}

func rawOf(rs ...*p.Record) [][]byte {
	out := make([][]byte, len(rs))
	for i, r := range rs {
		out[i] = r.Bytes()
	}
	return out
}

func reconstructionVectors() reconFile {
	var vs []reconVector

	b := newBuilder(epochA, writerA)
	b.checkpointOf(richState(), p.ReasonInitial)
	b.delta(p.Create("u1", "Pod", "default", "p1", map[string]any{"v": 1}))
	b.delta(p.EdgeAdd("u1", "runs-on", "uid-node-a", nil))
	b.delta(p.Update("u1", map[string]any{"v": 2}))
	b.finding(minimalFinding(b.now, p.TransitionFiring))
	b.delta(p.Create("u2", "Pod", "default", "p2", nil))
	b.delta(p.Update("u1", map[string]any{"v": 3}), p.Delete("u2", p.DeleteDeleted))
	b.finding(minimalFinding(b.now, p.TransitionResolved))
	b.delta(p.ScopeSet("Pod", p.ScopeStatus{State: p.ScopeComplete}))
	good := b.checkpoint(p.ReasonAnchor)
	after := b.delta(p.Update("u1", map[string]any{"v": 4}))
	r7 := rangeRecord(b, 4, 7)
	chain := []*p.Record{b.recs[0], b.recs[1], b.recs[2], r7, b.recs[7], b.recs[8], good, after}
	vs = append(vs, reconCase("range 4..7 is unavailable inside, matching anchor", rawOf(chain...), 0, ""))

	wrong := b.state.Clone()
	check(wrong.ApplyOps([]p.Op{p.Create("ghost", "Pod", "default", "ghost", nil)}))
	mb := newBuilder(epochA, writerA)
	for _, r := range chain[:6] {
		mb.add(cloneRecord(r))
	}
	mb.state = replay(chain[:6]).State().Clone()
	bad := mb.checkpointOf(wrong, p.ReasonAnchor)
	next := mb.delta(p.Delete("ghost", p.DeleteDeleted), p.Update("u1", map[string]any{"v": 5}))
	vs = append(vs, reconCase("anchor mismatch is a boundary and its content governs from there", rawOf(append(append([]*p.Record{}, chain[:6]...), bad, next)...), 1, ""))

	rb := newBuilder(epochA, writerA)
	rb.checkpointOf(richState(), p.ReasonInitial)
	rb.delta(p.Update("uid-node-a", map[string]any{"ready": false}))
	rb.delta(p.Update("uid-node-a", map[string]any{"ready": true}))
	rb.delta(p.Update("uid-node-a", map[string]any{"cpu": 1}))
	anchorState := rb.state.Clone()
	check(anchorState.ApplyOps([]p.Op{p.Update("uid-node-a", map[string]any{"cpu": 2})}))
	replayAnchor := rb.checkpointOf(anchorState, p.ReasonReplayAnchor)
	vs = append(vs, reconCase("replay anchor mismatch and single-sequence range", rawOf(rb.recs[0], rangeRecord(rb, 2, 2), rb.recs[2], rangeRecord(rb, 4, 4), replayAnchor), 1, ""))
	vs = append(vs, reconCase("range starting at sequence 2", rawOf(rb.recs[0], rangeRecord(rb, 2, 4), replayAnchor), 1, ""))

	eb := newBuilder(epochA, writerA)
	eb.checkpointOf(richState(), p.ReasonInitial)
	eb.delta(p.Create("u1", "Pod", "default", "p1", nil))
	eb.delta(p.Update("u1", map[string]any{"a": 1}))
	eb.checkpoint(p.ReasonAnchor)
	eb.delta(p.Update("u1", map[string]any{"a": 2}))
	e := eb.recs
	vs = append(vs, reconCase("epoch starting with a delta", rawOf(e[1], e[2]), 0, "invalid_chain"))
	vs = append(vs, reconCase("parent gap", rawOf(e[0], e[1], e[3]), 0, "invalid_chain"))
	stale := cloneEnv(e[4], func(env *p.Envelope) { env.Base = 1 })
	vs = append(vs, reconCase("base not the governing checkpoint", append(rawOf(e[0], e[1], e[2], e[3]), stale), 0, "invalid_chain"))
	vs = append(vs, reconCase("record from another writer", append(rawOf(e[0], e[1]), cloneEnv(e[2], func(env *p.Envelope) { env.Writer = writerB })), 0, "invalid_chain"))
	vs = append(vs, reconCase("record from another epoch", append(rawOf(e[0], e[1]), cloneEnv(e[2], func(env *p.Envelope) { env.Epoch = epochB })), 0, "invalid_chain"))
	absent := encRecord(&p.Record{Envelope: e[2].Envelope, Delta: &p.Delta{Ops: []p.Op{p.Update("nobody", map[string]any{"a": 1})}}})
	vs = append(vs, reconCase("update of an absent uid", append(rawOf(e[0], e[1]), absent), 0, "invalid_op"))
	dupEdge := encRecord(&p.Record{Envelope: e[2].Envelope, Delta: &p.Delta{Ops: []p.Op{p.EdgeAdd("uid-deploy-web", "owns", "uid-pod-web-1", nil)}}})
	vs = append(vs, reconCase("edge-add of a present edge", append(rawOf(e[0], e[1]), dupEdge), 0, "invalid_op"))
	recreate := encRecord(&p.Record{Envelope: e[2].Envelope, Delta: &p.Delta{Ops: []p.Op{p.Create("u1", "Pod", "default", "p1", nil)}}})
	vs = append(vs, reconCase("create of a present uid", append(rawOf(e[0], e[1]), recreate), 0, "invalid_op"))
	badHash := mut(e[3].Bytes(), func(m map[any]any) { body(m)[uint64(6)] = make([]byte, 32) })
	vs = append(vs, reconCase("anchor whose content does not match its state hash", append(rawOf(e[0], e[1], e[2]), badHash, e[4].Bytes()), 0, "invalid_state_hash"))
	return reconFile{Description: "Chain replay (SPEC 6.3): per-sequence state hashes, chain hashes, boundaries, unavailable spans, first error.", Vectors: vs}
}

func cloneRecord(r *p.Record) *p.Record { return must(p.Decode(r.Bytes())) }

func cloneEnv(r *p.Record, fn func(*p.Envelope)) []byte {
	c := cloneRecord(r)
	fn(&c.Envelope)
	return encRecord(c)
}

// Identifier vectors.

type findingIDVec struct {
	TargetID  string `json:"target_id"`
	DedupKey  string `json:"dedup_key"`
	FirstSeen uint64 `json:"first_seen"`
	FindingID string `json:"finding_id"`
}

type queryHashVec struct {
	Language  string `json:"language"`
	Query     string `json:"query"`
	Source    string `json:"source"`
	QueryHash string `json:"query_hash"`
}

type genesisVec struct {
	TargetID string `json:"target_id"`
	Epoch    string `json:"epoch"`
	WriterID string `json:"writer_id"`
	Genesis  string `json:"genesis"`
}

type chainLinkVec struct {
	Prev       string `json:"prev"`
	RecordHash string `json:"record_hash"`
	ChainHash  string `json:"chain_hash"`
}

type recordHashVec struct {
	Hex        string `json:"hex"`
	RecordHash string `json:"record_hash"`
}

type namedHash struct {
	Name      string `json:"name"`
	StateHash string `json:"state_hash"`
}

type idFile struct {
	Description  string          `json:"description"`
	FindingIDs   []findingIDVec  `json:"finding_ids"`
	QueryHashes  []queryHashVec  `json:"query_hashes"`
	Genesis      []genesisVec    `json:"genesis"`
	ChainLinks   []chainLinkVec  `json:"chain_links"`
	RecordHashes []recordHashVec `json:"record_hashes"`
	StateHashes  []namedHash     `json:"state_hashes"`
}

func idVectors() idFile {
	f := idFile{Description: "Hashes and identifiers (SPEC 6.2, 7)."}
	for _, c := range []findingIDVec{
		{TargetID: target, DedupKey: "crashloop|default|web", FirstSeen: t0},
		{TargetID: "h-01.example", DedupKey: "disk|/var", FirstSeen: 0},
		{TargetID: target, DedupKey: "ü水", FirstSeen: 18446744073709551615},
		{TargetID: "a", DedupKey: "", FirstSeen: 1},
	} {
		c.FindingID = p.FindingID(c.TargetID, c.DedupKey, c.FirstSeen)
		f.FindingIDs = append(f.FindingIDs, c)
	}
	for _, c := range []queryHashVec{
		{Language: "promql", Query: "up", Source: "metrics"},
		{Language: "logql", Query: `{namespace="default"} |= "panic"`, Source: "logs"},
		{Language: "", Query: "", Source: ""},
	} {
		c.QueryHash = p.QueryHash(c.Language, c.Query, c.Source).String()
		f.QueryHashes = append(f.QueryHashes, c)
	}
	for _, c := range []struct {
		t    string
		e, w p.ID
	}{{target, epochA, writerA}, {target, epochB, writerA}, {"t-2", epochC, writerB}} {
		f.Genesis = append(f.Genesis, genesisVec{TargetID: c.t, Epoch: c.e.String(), WriterID: c.w.String(), Genesis: p.Genesis(c.t, c.e, c.w).String()})
	}
	g := p.Genesis(target, epochA, writerA)
	for _, b := range [][]byte{{}, {0xa0}, baseChain().recs[0].Bytes()} {
		rh := p.RecordHash(b)
		f.RecordHashes = append(f.RecordHashes, recordHashVec{Hex: hx(b), RecordHash: rh.String()})
		f.ChainLinks = append(f.ChainLinks, chainLinkVec{Prev: g.String(), RecordHash: rh.String(), ChainHash: p.ChainHash(g, rh).String()})
	}
	f.StateHashes = []namedHash{{Name: "empty", StateHash: p.NewState().Hash().String()}}
	return f
}

// Ownership vectors.

type ownPoint struct {
	Seq       uint64 `json:"seq"`
	ChainHash string `json:"chain_hash"`
}

type ownEpoch struct {
	ID          string     `json:"id"`
	Owner       string     `json:"owner"`
	Open        bool       `json:"open"`
	Head        ownPoint   `json:"head"`
	ChainHashes []ownPoint `json:"chain_hashes"`
}

type ownIncarnation struct {
	WriterID    string `json:"writer_id"`
	Incarnation uint64 `json:"incarnation"`
}

type ownActive struct {
	SessionID   string  `json:"session_id"`
	WriterID    string  `json:"writer_id"`
	Incarnation uint64  `json:"incarnation"`
	Instance    *string `json:"instance"`
}

type ownState struct {
	TargetType         string           `json:"target_type"`
	Revoked            bool             `json:"revoked"`
	Conflict           bool             `json:"conflict"`
	PendingBinding     bool             `json:"pending_binding"`
	EnrolledMachineID  string           `json:"enrolled_machine_id"`
	OpenEpoch          *string          `json:"open_epoch"`
	Epochs             []ownEpoch       `json:"epochs"`
	Retired            []string         `json:"retired"`
	HighestIncarnation []ownIncarnation `json:"highest_incarnation"`
	Active             *ownActive       `json:"active"`
}

type ownEpochOpen struct {
	Reason    string  `json:"reason"`
	PrevEpoch *string `json:"prev_epoch"`
	PrevHead  *uint64 `json:"prev_head"`
}

type ownHello struct {
	WriterID      string        `json:"writer_id"`
	Incarnation   uint64        `json:"incarnation"`
	Epoch         string        `json:"epoch"`
	EpochOpen     *ownEpochOpen `json:"epoch_open"`
	LastCommitted *ownPoint     `json:"last_committed"`
	MachineID     string        `json:"machine_id"`
	Instance      *string       `json:"instance"`
}

type ownExpect struct {
	Row          int     `json:"row"`
	Accept       bool    `json:"accept"`
	Code         string  `json:"code"`
	Outcome      string  `json:"outcome"`
	OpenEpoch    bool    `json:"open_epoch"`
	CloseEpoch   *string `json:"close_epoch"`
	RetireWriter *string `json:"retire_writer"`
	Supersede    bool    `json:"supersede"`
	SetConflict  bool    `json:"set_conflict"`
	ClearBinding bool    `json:"clear_binding"`
	Audit        bool    `json:"audit"`
	Alarm        bool    `json:"alarm"`
}

type ownVector struct {
	Name            string    `json:"name"`
	CredentialValid bool      `json:"credential_valid"`
	State           ownState  `json:"state"`
	Hello           ownHello  `json:"hello"`
	Expect          ownExpect `json:"expect"`
}

type ownFile struct {
	Description string      `json:"description"`
	Vectors     []ownVector `json:"vectors"`
}

func toOwnership(s ownState) *p.OwnershipState {
	st := &p.OwnershipState{
		TargetType: s.TargetType, Revoked: s.Revoked, Conflict: s.Conflict, PendingBinding: s.PendingBinding,
		EnrolledMachineID: s.EnrolledMachineID, Epochs: map[p.EpochID]*p.EpochInfo{}, Retired: map[p.WriterID]bool{},
		HighestIncarnation: map[p.WriterID]uint64{},
	}
	if s.OpenEpoch != nil {
		id := must(p.ParseID(*s.OpenEpoch))
		st.OpenEpoch = &id
	}
	chains := map[p.EpochID]map[uint64]p.Hash{}
	for _, e := range s.Epochs {
		id := must(p.ParseID(e.ID))
		st.Epochs[id] = &p.EpochInfo{ID: id, Owner: must(p.ParseID(e.Owner)), Open: e.Open, Head: p.ChainPoint{Seq: e.Head.Seq, ChainHash: must(p.ParseHash(e.Head.ChainHash))}}
		chains[id] = map[uint64]p.Hash{}
		for _, c := range e.ChainHashes {
			chains[id][c.Seq] = must(p.ParseHash(c.ChainHash))
		}
	}
	st.ChainHashAt = func(ep p.EpochID, seq uint64) (p.Hash, bool) {
		h, ok := chains[ep][seq]
		return h, ok
	}
	for _, w := range s.Retired {
		st.Retired[must(p.ParseID(w))] = true
	}
	for _, h := range s.HighestIncarnation {
		st.HighestIncarnation[must(p.ParseID(h.WriterID))] = h.Incarnation
	}
	if s.Active != nil {
		st.Active = &p.ActiveSession{SessionID: s.Active.SessionID, Writer: must(p.ParseID(s.Active.WriterID)), Incarnation: s.Active.Incarnation}
		if s.Active.Instance != nil {
			st.Active.Instance = must(p.ParseID(*s.Active.Instance))
		}
	}
	return st
}

func toHello(h ownHello) *p.HelloParams {
	out := &p.HelloParams{WriterID: must(p.ParseID(h.WriterID)), Incarnation: h.Incarnation, Epoch: must(p.ParseID(h.Epoch)), MachineID: h.MachineID}
	if h.EpochOpen != nil {
		eo := &p.EpochOpen{Reason: h.EpochOpen.Reason, PrevHead: h.EpochOpen.PrevHead}
		if h.EpochOpen.PrevEpoch != nil {
			id := must(p.ParseID(*h.EpochOpen.PrevEpoch))
			eo.PrevEpoch = &id
		}
		out.EpochOpen = eo
	}
	if h.LastCommitted != nil {
		out.LastCommitted = &p.ChainPoint{Seq: h.LastCommitted.Seq, ChainHash: must(p.ParseHash(h.LastCommitted.ChainHash))}
	}
	if h.Instance != nil {
		id := must(p.ParseID(*h.Instance))
		out.Instance = &id
	}
	return out
}

func idPtr(id *p.ID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func ownershipVectors() ownFile {
	w1, w2, w3 := writerA.String(), writerB.String(), p.WriterID{0x57, 0x43}.String()
	e1, e2, e3 := epochA.String(), epochB.String(), epochC.String()
	h5, h10 := p.RecordHash([]byte("chain 5")).String(), p.RecordHash([]byte("chain 10")).String()
	other := p.RecordHash([]byte("other")).String()
	base := func(tt string) ownState {
		return ownState{
			TargetType: tt, OpenEpoch: &e1,
			Epochs: []ownEpoch{
				{ID: e1, Owner: w1, Open: true, Head: ownPoint{Seq: 10, ChainHash: h10}, ChainHashes: []ownPoint{{Seq: 5, ChainHash: h5}, {Seq: 10, ChainHash: h10}}},
				{ID: e3, Owner: w2, Open: false, Head: ownPoint{Seq: 3, ChainHash: other}, ChainHashes: []ownPoint{}},
			},
			Retired: []string{}, HighestIncarnation: []ownIncarnation{{WriterID: w1, Incarnation: 5}},
		}
	}
	k8s, host := func() ownState { return base("kubernetes") }, func() ownState { return base("host") }
	hello := func(w string, inc uint64, ep string) ownHello {
		return ownHello{WriterID: w, Incarnation: inc, Epoch: ep}
	}
	withLC := func(h ownHello, seq uint64, ch string) ownHello {
		h.LastCommitted = &ownPoint{Seq: seq, ChainHash: ch}
		return h
	}
	withOpen := func(h ownHello, reason string, prev *string) ownHello {
		ph := uint64(10)
		h.EpochOpen = &ownEpochOpen{Reason: reason, PrevEpoch: prev, PrevHead: &ph}
		return h
	}
	mod := func(s ownState, fn func(*ownState)) ownState { fn(&s); return s }
	active := func(w string, inc uint64) *ownActive {
		return &ownActive{SessionID: "s-1", WriterID: w, Incarnation: inc}
	}
	n1, n2 := p.ID{0x4e, 0x31}.String(), p.ID{0x4e, 0x32}.String()
	activeIn := func(w string, inc uint64, n *string) *ownActive {
		a := active(w, inc)
		a.Instance = n
		return a
	}
	withInstance := func(h ownHello, n string) ownHello {
		h.Instance = &n
		return h
	}
	type c struct {
		name string
		cred bool
		st   ownState
		h    ownHello
	}
	cases := []c{
		{"invalid credential", false, k8s(), hello(w1, 5, e1)},
		{"revoked target", true, mod(k8s(), func(s *ownState) { s.Revoked = true }), hello(w1, 5, e1)},
		{"invalid credential precedes conflict", false, mod(host(), func(s *ownState) { s.Conflict = true }), hello(w1, 5, e1)},
		{"unresolved identity conflict", true, mod(host(), func(s *ownState) { s.Conflict = true }), hello(w1, 5, e1)},
		{"host machine id differs", true, mod(host(), func(s *ownState) { s.EnrolledMachineID = "m-1" }), func() ownHello { h := hello(w1, 5, e1); h.MachineID = "m-2"; return h }()},
		{"host machine id matches", true, mod(host(), func(s *ownState) { s.EnrolledMachineID = "m-1" }), func() ownHello { h := hello(w1, 5, e1); h.MachineID = "m-1"; return h }()},
		{"cluster target ignores machine id", true, mod(k8s(), func(s *ownState) { s.EnrolledMachineID = "m-1" }), hello(w1, 5, e1)},
		{"retired writer", true, mod(k8s(), func(s *ownState) { s.Retired = []string{w2} }), hello(w2, 1, e2)},
		{"retired writer precedes closed epoch", true, mod(k8s(), func(s *ownState) { s.Retired = []string{w2} }), hello(w2, 1, e3)},
		{"closed epoch", true, k8s(), hello(w2, 1, e3)},
		{"closed epoch presented by its owner of the open epoch", true, k8s(), hello(w1, 6, e3)},
		{"open epoch owned by another writer", true, k8s(), hello(w2, 1, e1)},
		{"stale incarnation", true, k8s(), hello(w1, 4, e1)},
		{"stale incarnation precedes duplicate session", true, mod(k8s(), func(s *ownState) { s.Active = active(w1, 4) }), hello(w1, 4, e1)},
		{"duplicate session with same writer and incarnation", true, mod(k8s(), func(s *ownState) { s.Active = active(w1, 5) }), hello(w1, 5, e1)},
		{"reconnect of the same process supersedes its stale session", true, mod(k8s(), func(s *ownState) { s.Active = activeIn(w1, 5, &n1) }), withInstance(withLC(hello(w1, 5, e1), 10, h10), n1)},
		{"same writer and incarnation from another instance", true, mod(k8s(), func(s *ownState) { s.Active = activeIn(w1, 5, &n1) }), withInstance(hello(w1, 5, e1), n2)},
		{"same writer and incarnation without an instance", true, mod(k8s(), func(s *ownState) { s.Active = activeIn(w1, 5, &n1) }), hello(w1, 5, e1)},
		{"instance against a session that presented none", true, mod(k8s(), func(s *ownState) { s.Active = active(w1, 5) }), withInstance(hello(w1, 5, e1), n1)},
		{"stale incarnation precedes a matching instance", true, mod(k8s(), func(s *ownState) { s.Active = activeIn(w1, 4, &n1) }), withInstance(hello(w1, 4, e1), n1)},
		{"divergent chain hash at last committed", true, k8s(), withLC(hello(w1, 6, e1), 10, other)},
		{"last committed above committed head", true, k8s(), withLC(hello(w1, 6, e1), 11, h10)},
		{"last committed at an unknown sequence", true, k8s(), withLC(hello(w1, 6, e1), 7, h10)},
		{"resume at committed head", true, k8s(), withLC(hello(w1, 6, e1), 10, h10)},
		{"resume below committed head", true, k8s(), withLC(hello(w1, 5, e1), 5, h5)},
		{"resume without last committed", true, k8s(), hello(w1, 5, e1)},
		{"resume supersedes a lower incarnation session", true, mod(k8s(), func(s *ownState) { s.Active = active(w1, 5) }), withLC(hello(w1, 6, e1), 10, h10)},
		{"resume does not supersede another writer's session", true, mod(k8s(), func(s *ownState) { s.Active = active(w3, 9) }), hello(w1, 6, e1)},
		{"resume does not supersede a higher incarnation session", true, mod(k8s(), func(s *ownState) { s.Active = active(w1, 9) }), hello(w1, 6, e1)},
		{"first epoch of a target", true, ownState{TargetType: "kubernetes", Epochs: []ownEpoch{}, Retired: []string{}, HighestIncarnation: []ownIncarnation{}}, hello(w1, 1, e1)},
		{"unknown epoch with only closed epochs", true, mod(k8s(), func(s *ownState) { s.OpenEpoch = nil; s.Epochs = s.Epochs[1:] }), hello(w1, 6, e2)},
		{"rebaseline closes the previous epoch", true, k8s(), withOpen(hello(w1, 6, e2), "rebaseline", &e1)},
		{"rebaseline supersedes the lower incarnation session", true, mod(k8s(), func(s *ownState) { s.Active = active(w1, 5) }), withOpen(hello(w1, 6, e2), "rebaseline", &e1)},
		{"rebaseline naming another previous epoch", true, k8s(), withOpen(hello(w1, 6, e2), "rebaseline", &e3)},
		{"owner opening an epoch without rebaseline", true, k8s(), withOpen(hello(w1, 6, e2), "initial", nil)},
		{"new writer on a cluster target", true, k8s(), withOpen(hello(w2, 1, e2), "writer_change", &e1)},
		{"new writer on a cluster target supersedes the active session", true, mod(k8s(), func(s *ownState) { s.Active = active(w1, 5) }), hello(w2, 1, e2)},
		{"new writer on a host target with a pending binding", true, mod(host(), func(s *ownState) { s.PendingBinding = true }), hello(w2, 1, e2)},
		{"new writer on a host target", true, host(), hello(w2, 1, e2)},
		{"incarnation equal to the highest seen", true, k8s(), withLC(hello(w1, 5, e1), 10, h10)},
	}
	var vs []ownVector
	for _, cs := range cases {
		d := p.Decide(toOwnership(cs.st), toHello(cs.h), cs.cred)
		vs = append(vs, ownVector{Name: cs.name, CredentialValid: cs.cred, State: cs.st, Hello: cs.h, Expect: ownExpect{
			Row: d.Row, Accept: d.Accept, Code: d.Code, Outcome: d.Outcome, OpenEpoch: d.OpenEpoch, CloseEpoch: idPtr(d.CloseEpoch),
			RetireWriter: idPtr(d.RetireWriter), Supersede: d.Supersede, SetConflict: d.SetConflict, ClearBinding: d.ClearBinding,
			Audit: d.Audit, Alarm: d.Alarm,
		}})
	}
	return ownFile{Description: "Ownership decision table (SPEC 8.3). chain_hashes lists the committed chain hashes known per epoch.", Vectors: vs}
}
