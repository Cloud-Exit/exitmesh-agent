package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
)

var (
	testTarget = "t-test"
	testWriter = WriterID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	testEpoch  = EpochID{0x01, 0x90, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}
)

type chainBuilder struct {
	t     testing.TB
	chain *Chain
	state *State
	recs  []*Record
	now   uint64
}

func newChainBuilder(t testing.TB) *chainBuilder {
	b := &chainBuilder{t: t, chain: NewChain(testTarget, testEpoch, testWriter), state: NewState(), now: 1_700_000_000_000}
	b.checkpoint(ReasonInitial)
	return b
}

func (b *chainBuilder) add(r *Record) *Record {
	b.t.Helper()
	if _, err := Encode(r); err != nil {
		b.t.Fatalf("encode seq %d: %v", r.Seq, err)
	}
	if _, err := b.chain.Append(r); err != nil {
		b.t.Fatalf("append seq %d: %v", r.Seq, err)
	}
	if err := b.state.ApplyRecord(r); err != nil {
		b.t.Fatalf("apply seq %d: %v", r.Seq, err)
	}
	b.recs = append(b.recs, r)
	b.now += 1000
	return r
}

func (b *chainBuilder) checkpoint(reason CheckpointReason) *Record {
	env := b.chain.Next(TypeCheckpoint, 1, b.now)
	ck := b.state.Checkpoint(reason, Interval{b.now - 10, b.now}, []string{"inventory"})
	return b.add(&Record{Envelope: env, Checkpoint: ck})
}

func (b *chainBuilder) delta(ops ...Op) *Record {
	env := b.chain.Next(TypeDelta, 1, b.now)
	return b.add(&Record{Envelope: env, Delta: &Delta{Ops: ops}})
}

func (b *chainBuilder) finding(id string, tr Transition) *Record {
	env := b.chain.Next(TypeFinding, 1, b.now)
	return b.add(&Record{Envelope: env, Finding: testFinding(id, tr, b.now)})
}

func testFinding(id string, tr Transition, now uint64) *Finding {
	return &Finding{
		ID: id, DedupKey: "k-" + id, Transition: tr, Category: "workload", Severity: SeverityHigh,
		Provenance: Provenance{Kind: ProvenanceRule, RuleID: "r1", RuleVersion: 3, BundleVersion: "2026.09.1"},
		EvalTime:   now, FirstSeen: now, LastSeen: now, Count: 1, Resources: []string{"u2", "u1"},
		Evidence: []Evidence{{Source: "logs:app", Time: now, Text: "boom", Count: 2}},
	}
}

func TestRoundTripAllTypes(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("u1", "apps/Deployment", "default", "web", map[string]any{"replicas": 3, "image": "nginx:1", "f": 1.5, "neg": -4, "list": []any{"a", int64(2)}, "m": map[string]any{"x": true}}))
	b.delta(Update("u1", map[string]any{"replicas": 4, "image": nil}), EdgeAdd("u1", "owns", "u2", map[string]any{"w": 1}), ScopeSet("apps/Deployment|default", ScopeStatus{State: ScopePartial, Reason: "forbidden", Since: 5}))
	b.finding("f1", TransitionFiring)
	b.checkpoint(ReasonAnchor)
	for _, r := range b.recs {
		got, err := Decode(r.Bytes())
		if err != nil {
			t.Fatalf("decode %s %d: %v", r.Type, r.Seq, err)
		}
		re, err := Encode(got)
		if err != nil {
			t.Fatalf("re-encode %d: %v", r.Seq, err)
		}
		if !bytes.Equal(re, r.Bytes()) {
			t.Fatalf("seq %d: re-encoding differs", r.Seq)
		}
		if got.Hash() != RecordHash(r.Bytes()) {
			t.Fatal("hash mismatch")
		}
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	b := newChainBuilder(t)
	good := b.recs[0].Bytes()
	cases := map[string][]byte{
		"trailing":         append(append([]byte(nil), good...), 0x00),
		"non-shortest int": nonShortest(good),
		"truncated":        good[:len(good)-3],
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unsorted keys: build a map encoding manually with keys 1 then 0.
	if _, err := Decode([]byte{0xa2, 0x01, 0x01, 0x00, 0x01}); err == nil {
		t.Error("unsorted map accepted")
	}
	// Duplicate keys.
	if _, err := Decode([]byte{0xa2, 0x00, 0x01, 0x00, 0x01}); err == nil {
		t.Error("duplicate key accepted")
	}
	// Indefinite length map.
	if _, err := Decode([]byte{0xbf, 0x00, 0x01, 0xff}); err == nil {
		t.Error("indefinite map accepted")
	}
	// Tag.
	if _, err := Decode([]byte{0xc1, 0x00}); err == nil {
		t.Error("tag accepted")
	}
}

func nonShortest(b []byte) []byte {
	// The envelope starts with a map header then key 0 (0x00) and value 1 (0x01).
	// Replace value 1 with the two-byte form 0x18 0x01.
	i := bytes.Index(b, []byte{0x00, 0x01})
	out := append([]byte(nil), b[:i+1]...)
	out = append(out, 0x18, 0x01)
	return append(out, b[i+2:]...)
}

func reencodeEnvelope(t *testing.T, r *Record, mutate func(m map[any]any)) []byte {
	t.Helper()
	v, err := decodeStrict(r.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[any]any)
	mutate(m)
	out, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUnknownAndExtensionKeys(t *testing.T) {
	b := newChainBuilder(t)
	r := b.delta(Create("u1", "Pod", "ns", "p", nil))
	unknown := reencodeEnvelope(t, r, func(m map[any]any) { m[uint64(12)] = "x" })
	if _, err := Decode(unknown); CodeOf(err) != "unsupported_field" {
		t.Fatalf("unknown key: got %v", err)
	}
	ext := reencodeEnvelope(t, r, func(m map[any]any) { m[uint64(1000)] = "future" })
	got, err := Decode(ext)
	if err != nil {
		t.Fatalf("extension key rejected: %v", err)
	}
	if got.Ext[1000] != "future" || !bytes.Equal(got.Bytes(), ext) {
		t.Fatal("extension key not preserved")
	}
	nullField := reencodeEnvelope(t, r, func(m map[any]any) {
		body := m[uint64(11)].(map[any]any)
		op := body[uint64(0)].([]any)[0].(map[any]any)
		op[uint64(5)] = map[any]any{"x": nil}
	})
	if _, err := Decode(nullField); err == nil {
		t.Fatal("null in create fields accepted")
	}
}

func TestEncodeRejectsBadValues(t *testing.T) {
	b := newChainBuilder(t)
	for name, v := range map[string]any{"nan": math.NaN(), "inf": math.Inf(1), "nil": nil, "chan": make(chan int)} {
		env := b.chain.Next(TypeDelta, 1, 1)
		r := &Record{Envelope: env, Delta: &Delta{Ops: []Op{Create("u9", "Pod", "", "p", map[string]any{"x": v})}}}
		if _, err := Encode(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFloatShortest(t *testing.T) {
	b, _ := Marshal(1.5)
	if !bytes.Equal(b, []byte{0xf9, 0x3e, 0x00}) {
		t.Fatalf("1.5 encoded as %x", b)
	}
	b, _ = Marshal(100000.0)
	if len(b) != 5 {
		t.Fatalf("100000.0 encoded as %x", b)
	}
}

func TestChainLinkage(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("u1", "Pod", "ns", "a", nil))
	env := b.chain.Next(TypeDelta, 1, 1)
	env.Parent = 0
	env.Seq = 1
	r := &Record{Envelope: env, Delta: &Delta{Ops: []Op{Create("u2", "Pod", "ns", "b", nil)}}}
	if _, err := Encode(r); err == nil {
		t.Fatal("delta at seq 1 accepted")
	}
	env = b.chain.Next(TypeDelta, 1, 1)
	env.Base = 5
	r = &Record{Envelope: env, Delta: &Delta{Ops: []Op{Create("u2", "Pod", "ns", "b", nil)}}}
	if _, err := Encode(r); err == nil {
		if _, err := b.chain.Check(r); err == nil {
			t.Fatal("wrong base accepted")
		}
	}
	other := *b.recs[1]
	c2 := NewChain(testTarget, testEpoch, WriterID{9})
	if _, err := c2.Check(b.recs[0]); err == nil {
		t.Fatal("foreign writer accepted")
	}
	_ = other
}

func TestFoldAcceptanceScenario(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("keep", "Pod", "ns", "keep", map[string]any{"a": 1, "b": 2}),
		Create("dying", "Pod", "ns", "dying", map[string]any{"a": 1}),
		EdgeAdd("keep", "runs-on", "node1", map[string]any{"zone": "a"}),
		EdgeAdd("keep", "mounts", "pvc1", map[string]any{"ro": false}))
	pre := b.state.Clone()
	start := len(b.recs)
	b.delta(Create("ephemeral", "Pod", "ns", "tmp", map[string]any{"x": 1}))
	b.delta(Update("keep", map[string]any{"a": 5}), Update("ephemeral", map[string]any{"x": 2}))
	b.finding("f1", TransitionFiring)
	b.delta(Update("keep", map[string]any{"a": 6, "b": nil}), Delete("ephemeral", DeleteDeleted))
	b.delta(EdgeAdd("keep", "selects", "svc1", map[string]any{"p": 80}))
	b.delta(EdgeRemove("keep", "selects", "svc1", map[string]any{"p": 80}), EdgeRemove("keep", "runs-on", "node1", map[string]any{"zone": "a"}), EdgeRemove("keep", "mounts", "pvc1", map[string]any{"ro": false}))
	b.delta(EdgeAdd("keep", "runs-on", "node1", map[string]any{"zone": "b"}), EdgeAdd("keep", "mounts", "pvc1", map[string]any{"ro": false}), Delete("dying", DeleteDeleted))
	b.finding("f1", TransitionResolved)
	run := b.recs[start:]
	g, err := Fold(run)
	if err != nil {
		t.Fatal(err)
	}
	if g.From != run[0].Seq || g.To != run[len(run)-1].Seq {
		t.Fatalf("span %d-%d", g.From, g.To)
	}
	if len(g.Findings) != 2 || g.Findings[0].Seq != run[2].Seq || g.Findings[1].Seq != run[len(run)-1].Seq {
		t.Fatalf("findings not preserved: %+v", g.Findings)
	}
	folded := pre.Clone()
	if err := folded.ApplyOps(g.Ops); err != nil {
		t.Fatal(err)
	}
	if folded.Hash() != b.state.Hash() {
		t.Fatal("fold does not reproduce state at b")
	}
	kinds := map[OpKind]int{}
	for _, op := range g.Ops {
		kinds[op.Kind]++
	}
	if kinds[OpCreate] != 0 || kinds[OpDelete] != 1 || kinds[OpUpdate] != 1 || kinds[OpEdgeReplace] != 1 || kinds[OpEdgeAdd] != 0 || kinds[OpEdgeRemove] != 0 {
		t.Fatalf("unexpected folded ops %v", kinds)
	}
	for _, op := range g.Ops {
		if op.Kind == OpUpdate {
			if v, ok := op.Fields["b"]; !ok || v != nil {
				t.Fatal("removal not preserved in folded update")
			}
		}
	}
	rr, err := NewRangeRecord(b.chain.Next(TypeDelta, 1, b.now), g, run[0].Parent, run[0].Base)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(rr.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if dec.Seq != g.To || dec.Parent != g.From-1 {
		t.Fatal("range envelope")
	}
}

func TestFoldRejectsNonContiguous(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("a", "Pod", "", "a", nil))
	b.delta(Create("b", "Pod", "", "b", nil))
	b.delta(Create("c", "Pod", "", "c", nil))
	if _, err := Fold([]*Record{b.recs[1], b.recs[3]}); err == nil {
		t.Fatal("gap accepted")
	}
	if _, err := Fold([]*Record{b.recs[0]}); err == nil {
		t.Fatal("checkpoint folded")
	}
}

// randomChain generates a valid random chain of deltas and findings over a small key space.
func randomChain(t testing.TB, rng *rand.Rand, n int) *chainBuilder {
	b := newChainBuilder(t)
	uidN := 0
	for i := 0; i < n; i++ {
		if rng.Intn(6) == 0 {
			b.finding(fmt.Sprintf("f%d", rng.Intn(3)), Transition(1+rng.Intn(4)))
			continue
		}
		var ops []Op
		used := map[string]bool{}
		usedE := map[EdgeKey]bool{}
		for j := 0; j < 1+rng.Intn(3); j++ {
			switch rng.Intn(8) {
			case 0, 1:
				uidN++
				uid := fmt.Sprintf("u%03d", uidN)
				used[uid] = true
				ops = append(ops, Create(uid, "Pod", "ns", uid, map[string]any{"v": int64(rng.Intn(3)), "w": "x"}))
			case 2, 3:
				uid := pick(rng, b.state, used)
				if uid == "" {
					continue
				}
				used[uid] = true
				ch := map[string]any{"v": int64(rng.Intn(3))}
				if rng.Intn(3) == 0 {
					ch["w"] = nil
				}
				if rng.Intn(3) == 0 {
					ch["z"] = []any{int64(rng.Intn(2))}
				}
				ops = append(ops, Update(uid, ch))
			case 4:
				uid := pick(rng, b.state, used)
				if uid == "" {
					continue
				}
				used[uid] = true
				ops = append(ops, Delete(uid, DeleteReason(1+rng.Intn(2))))
			case 5, 6:
				k := EdgeKey{fmt.Sprintf("n%d", rng.Intn(3)), "t", fmt.Sprintf("m%d", rng.Intn(3))}
				if usedE[k] {
					continue
				}
				usedE[k] = true
				attrs := map[string]any{"a": int64(rng.Intn(2))}
				cur, ok := b.state.Edges[k]
				switch {
				case !ok:
					ops = append(ops, EdgeAdd(k.From, k.Type, k.To, attrs))
				case rng.Intn(2) == 0:
					ops = append(ops, EdgeRemove(k.From, k.Type, k.To, CloneFields(cur)))
				default:
					ops = append(ops, EdgeReplace(k.From, k.Type, k.To, attrs, CloneFields(cur)))
				}
			case 7:
				ops = append(ops, ScopeSet(fmt.Sprintf("s%d", rng.Intn(2)), ScopeStatus{State: ScopeState(rng.Intn(3))}))
			}
		}
		ops = dedupScopes(ops)
		if len(ops) == 0 {
			continue
		}
		b.delta(ops...)
	}
	return b
}

func dedupScopes(ops []Op) []Op {
	seen := map[string]bool{}
	out := ops[:0]
	for _, op := range ops {
		if op.Kind == OpScopeSet {
			if seen[op.ScopeKey] {
				continue
			}
			seen[op.ScopeKey] = true
		}
		out = append(out, op)
	}
	return out
}

func pick(rng *rand.Rand, s *State, used map[string]bool) string {
	var c []string
	for uid := range s.Resources {
		if !used[uid] {
			c = append(c, uid)
		}
	}
	if len(c) == 0 {
		return ""
	}
	sortStrings(c)
	return c[rng.Intn(len(c))]
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestFoldProperty(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		b := randomChain(t, rng, 40)
		if len(b.recs) < 3 {
			continue
		}
		states := []*State{}
		st := NewState()
		for _, r := range b.recs {
			if r.Type == TypeCheckpoint {
				st = StateFromCheckpoint(r.Checkpoint)
			} else if err := st.ApplyRecord(r); err != nil {
				t.Fatal(err)
			}
			states = append(states, st.Clone())
		}
		i := 1 + rng.Intn(len(b.recs)-1)
		j := i + rng.Intn(len(b.recs)-i)
		g, err := Fold(b.recs[i : j+1])
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		got := states[i-1].Clone()
		if err := got.ApplyOps(g.Ops); err != nil {
			t.Fatalf("seed %d: apply fold: %v", seed, err)
		}
		if got.Hash() != states[j].Hash() {
			t.Fatalf("seed %d: fold of [%d,%d] diverges", seed, i, j)
		}
		// Re-fold: a range followed by more records folds again equivalently.
		if j+1 < len(b.recs) {
			rr, err := NewRangeRecord(b.recs[j].Envelope, g, b.recs[i].Parent, b.recs[i].Base)
			if err != nil {
				t.Fatalf("seed %d: range record: %v", seed, err)
			}
			k := j + 1 + rng.Intn(len(b.recs)-j-1)
			run := append([]*Record{rr}, b.recs[j+1:k+1]...)
			g2, err := Fold(run)
			if err != nil {
				t.Fatalf("seed %d: refold: %v", seed, err)
			}
			got2 := states[i-1].Clone()
			if err := got2.ApplyOps(g2.Ops); err != nil {
				t.Fatalf("seed %d: apply refold: %v", seed, err)
			}
			if got2.Hash() != states[k].Hash() || g2.From != b.recs[i].Seq {
				t.Fatalf("seed %d: refold diverges", seed)
			}
		}
	}
}

func TestReconstructWithRangeAndBoundary(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("a", "Pod", "", "a", map[string]any{"v": 1}))
	b.delta(Update("a", map[string]any{"v": 2}))
	b.delta(Update("a", map[string]any{"v": 3}))
	b.delta(Create("b", "Pod", "", "b", nil))
	full := append([]*Record(nil), b.recs...)
	g, err := Fold(full[2:4])
	if err != nil {
		t.Fatal(err)
	}
	rr, err := NewRangeRecord(full[3].Envelope, g, full[2].Parent, full[2].Base)
	if err != nil {
		t.Fatal(err)
	}
	// Re-chain the tail on the range record (bytes of seq 5 are unchanged).
	chain := []*Record{full[0], full[1], rr, full[4]}
	st, err := Reconstruct(chain, 5)
	if err != nil {
		t.Fatal(err)
	}
	if st.Hash() != b.state.Hash() {
		t.Fatal("state at 5 differs")
	}
	if _, err := Reconstruct(chain, 3); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("seq 3 should be unavailable: %v", err)
	}
	if st, err := Reconstruct(chain, 4); err != nil || st.Resources["a"].Fields["v"] != int64(3) {
		t.Fatalf("seq 4 (range end) should be exact: %v", err)
	}
	p := NewReplayer(testTarget, testEpoch, testWriter)
	for _, r := range chain {
		if _, err := p.Apply(r); err != nil {
			t.Fatal(err)
		}
	}
	// A checkpoint whose content disagrees with replayed state is a boundary.
	env := p.Chain()
	bogus := NewState()
	ck := bogus.Checkpoint(ReasonAnchor, Interval{}, nil)
	cr := &Record{Envelope: env.Next(TypeCheckpoint, 1, 1), Checkpoint: ck}
	if _, err := Encode(cr); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Apply(cr); err != nil {
		t.Fatal(err)
	}
	if len(p.Boundaries) != 1 {
		t.Fatal("boundary not reported")
	}
	if _, err := p.StateHashAt(3); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replayer should report unavailable interior")
	}
}

func TestCheckpointStateHashValidated(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("a", "Pod", "", "a", nil))
	ck := b.state.Checkpoint(ReasonAnchor, Interval{}, nil)
	ck.StateHash[0] ^= 1
	r := &Record{Envelope: b.chain.Next(TypeCheckpoint, 1, 1), Checkpoint: ck}
	if _, err := Encode(r); CodeOf(err) != "invalid_state_hash" {
		t.Fatalf("got %v", err)
	}
}

func TestDiffRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	a := randomChain(t, rng, 30).state
	c := randomChain(t, rng, 30).state
	ops := a.Diff(c, DeleteDeleted)
	got := a.Clone()
	if err := got.ApplyOps(ops); err != nil {
		t.Fatal(err)
	}
	if got.Hash() != c.Hash() {
		t.Fatal("diff does not transform state")
	}
	if len(c.Diff(c, DeleteDeleted)) != 0 {
		t.Fatal("self diff not empty")
	}
}

func TestFindingIDAndQueryHashDeterministic(t *testing.T) {
	if FindingID("t", "k", 1) != FindingID("t", "k", 1) || FindingID("t", "k", 1) == FindingID("t", "k", 2) {
		t.Fatal("finding id")
	}
	if len(FindingID("t", "k", 1)) != 32 {
		t.Fatal("finding id length")
	}
	if QueryHash("promql", "up", "live") == QueryHash("promql", "up", "lookback") {
		t.Fatal("query hash")
	}
}

func TestEpochUUIDv7(t *testing.T) {
	e1, _ := NewEpoch(time.UnixMilli(1000))
	e2, _ := NewEpoch(time.UnixMilli(2000))
	if e1[6]>>4 != 7 || e1[8]>>6 != 2 {
		t.Fatal("not uuidv7")
	}
	if bytes.Compare(e1[:6], e2[:6]) >= 0 {
		t.Fatal("not time ordered")
	}
}

func TestBatchFrame(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("a", "Pod", "", "a", nil))
	recs := [][]byte{b.recs[0].Bytes(), b.recs[1].Bytes()}
	for _, compress := range []bool{false, true} {
		f, err := EncodeBatchFrame(recs, compress)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeBatchFrame(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || !bytes.Equal(got[1], recs[1]) {
			t.Fatal("batch mismatch")
		}
	}
	if _, err := DecodeBatchFrame([]byte{0x02, 0}); err == nil {
		t.Fatal("unknown frame accepted")
	}
}

func TestEnrollmentToken(t *testing.T) {
	tok, err := ParseEnrollmentToken("emx1_c_t-123_abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := tok.TargetID(); !ok || id != "t-123" {
		t.Fatal("target id")
	}
	g, err := ParseEnrollmentToken("emx1_g_grp_1_abcdefghijklmnopqrstuvwxyz")
	if err != nil || g.ID != "grp_1" {
		t.Fatalf("group token: %v %+v", err, g)
	}
	if _, ok := g.TargetID(); ok {
		t.Fatal("group token has no target id")
	}
	for _, bad := range []string{"emtk_x", "emx1_z_t_abcdefghijklmnopqrstuv", "emx1_c_t_short", "emx1_c__abcdefghijklmnopqrstuvwxyz"} {
		if _, err := ParseEnrollmentToken(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestExportRoundTrip(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("a", "Pod", "", "a", nil))
	b.finding("f", TransitionFiring)
	var buf bytes.Buffer
	w, err := NewExportWriter(&buf, ExportHeader{TargetID: testTarget, WriterID: testWriter[:], Incarnation: 1, Epoch: testEpoch[:], AgentVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range b.recs {
		if err := w.Write(r.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	h, recs, err := ReadExport(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if h.TargetID != testTarget || len(recs) != 3 || !recs[2].Equal(b.recs[2]) {
		t.Fatal("export mismatch")
	}
}

func TestFindingCodec(t *testing.T) {
	f := testFinding("x", TransitionFiring, 5)
	b, err := EncodeFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	g, err := DecodeFinding(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := EncodeFinding(g)
	if !bytes.Equal(b, b2) || g.Resources[0] != "u1" {
		t.Fatal("finding codec mismatch")
	}
	if _, err := DecodeFinding(append(b, 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}
