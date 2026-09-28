package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/fxamacker/cbor/v2"

	p "github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const (
	target        = "t-vectors"
	t0     uint64 = 1_767_225_600_000
)

var (
	writerA = p.WriterID{0x57, 0x41, 0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0x01}
	writerB = p.WriterID{0x57, 0x42, 0x0b, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0x02}
	epochA  = p.EpochID{0x01, 0x9b, 0x77, 0x4f, 0x00, 0x00, 0x70, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a}
	epochB  = p.EpochID{0x01, 0x9b, 0x77, 0x4f, 0x10, 0x00, 0x70, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b}
	epochC  = p.EpochID{0x01, 0x9b, 0x77, 0x4f, 0x20, 0x00, 0x70, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c}
)

// builder appends valid records to one epoch and tracks the reconstructed state.
type builder struct {
	chain *p.Chain
	state *p.State
	recs  []*p.Record
	now   uint64
}

func newBuilder(ep p.EpochID, w p.WriterID) *builder {
	return &builder{chain: p.NewChain(target, ep, w), state: p.NewState(), now: t0}
}

func (b *builder) env(t p.RecordType) p.Envelope { return b.chain.Next(t, 1, b.now) }

func (b *builder) add(r *p.Record) *p.Record {
	must(p.Encode(r))
	must(b.chain.Append(r))
	if r.Type == p.TypeCheckpoint {
		b.state = p.StateFromCheckpoint(r.Checkpoint)
	} else {
		check(b.state.ApplyRecord(r))
	}
	b.recs = append(b.recs, r)
	b.now += 1000
	return r
}

func (b *builder) checkpointOf(st *p.State, reason p.CheckpointReason) *p.Record {
	ck := st.Checkpoint(reason, p.Interval{Start: b.now - 500, End: b.now}, []string{"inventory", "events"})
	return b.add(&p.Record{Envelope: b.env(p.TypeCheckpoint), Checkpoint: ck})
}

func (b *builder) checkpoint(reason p.CheckpointReason) *p.Record {
	return b.checkpointOf(b.state, reason)
}

func (b *builder) delta(ops ...p.Op) *p.Record { return b.deltaWith(0, nil, ops...) }

func (b *builder) deltaWith(flags uint64, unc *p.Interval, ops ...p.Op) *p.Record {
	return b.add(&p.Record{Envelope: b.env(p.TypeDelta), Delta: &p.Delta{Ops: ops, Flags: flags, Uncertain: unc}})
}

func (b *builder) finding(f *p.Finding) *p.Record {
	return b.add(&p.Record{Envelope: b.env(p.TypeFinding), Finding: f})
}

func richFields() map[string]any {
	return map[string]any{
		"replicas": 3, "image": "nginx:1.27", "ratio": 1.5, "neg": -42,
		"max": uint64(math.MaxUint64), "min": int64(math.MinInt64), "negzero": math.Copysign(0, -1),
		"half_subnormal": math.Ldexp(1, -24), "single_subnormal": math.Ldexp(1, -149), "pi": math.Pi,
		"single": 100000.0, "huge": 1e300, "blob": []byte{0x00, 0x01, 0xfe, 0xff}, "on": true, "off": false,
		"list":   []any{"a", 1, []any{}, map[string]any{}},
		"nested": map[string]any{"b": 1, "aa": 2, "é": "ü水"}, "": "empty key", "metric.cpu": 0.25,
	}
}

func richState() *p.State {
	st := p.NewState()
	check(st.ApplyOps([]p.Op{
		p.Create("uid-deploy-web", "apps/Deployment", "default", "web", richFields()),
		p.Create("uid-pod-web-1", "Pod", "default", "web-1", map[string]any{"phase": "Running", "restarts": 0}),
		p.Create("uid-node-a", "Node", "", "node-a", map[string]any{"ready": true}),
		p.Create("uid-host-svc", "host/Service", "", "sshd.service", map[string]any{"active": "active"}),
		p.EdgeAdd("uid-deploy-web", "owns", "uid-pod-web-1", map[string]any{"controller": true}),
		p.EdgeAdd("uid-pod-web-1", "runs-on", "uid-node-a", nil),
		p.ScopeSet("apps/Deployment|default", p.ScopeStatus{State: p.ScopeComplete}),
		p.ScopeSet("Secret|default", p.ScopeStatus{State: p.ScopeUnavailable, Reason: "forbidden", Since: t0 - 60000}),
		p.ScopeSet("Pod", p.ScopeStatus{State: p.ScopePartial, Reason: "list_failed"}),
	}))
	return st
}

func fullFinding(now uint64) *p.Finding {
	return &p.Finding{
		ID: p.FindingID(target, "crashloop|default|web", now-5000), DedupKey: "crashloop|default|web",
		Transition: p.TransitionFiring, Category: "workload", Severity: p.SeverityHigh,
		Provenance: p.Provenance{Kind: p.ProvenanceRule, RuleID: "k8s.crashloop", RuleVersion: 3, BundleVersion: "2026.09.1"},
		EvalTime:   now, FirstSeen: now - 5000, LastSeen: now, Count: 4,
		Resources: []string{"uid-pod-web-1", "uid-deploy-web"},
		Facts:     map[string]any{"restarts": 7, "reason": "CrashLoopBackOff", "ratio": 0.5},
		Evidence: []p.Evidence{
			{Source: "logs:default/web-1/app", Time: now - 100, Text: "panic: boom", Count: 3, Labels: map[string]string{"stream": "stderr"}, Truncated: true},
			{Source: "promql", Time: now - 50, Text: "kube_pod_container_status_restarts_total 7", Context: true},
		},
		Flags: p.FindingEvidenceTruncated | p.FindingLateAtWriter, Node: "node-a",
		Labels: map[string]string{"team": "web", "env": "prod"}, Summary: "web is crash looping",
		Suggestions: []p.Suggestion{{Language: "logql", Query: `{namespace="default"} |= "panic"`, Source: "logs"}, {Language: "promql", Query: "up"}},
		Coverage:    []string{"logs sampled"},
	}
}

func minimalFinding(now uint64, tr p.Transition) *p.Finding {
	return &p.Finding{
		ID: p.FindingID(target, "query|disk", now), DedupKey: "query|disk", Transition: tr, Category: "",
		Severity:   p.SeverityInfo,
		Provenance: p.Provenance{Kind: p.ProvenanceQuery, QueryHash: p.QueryHash("promql", "up", "metrics"), Requester: "user:alice"},
		EvalTime:   now, FirstSeen: now, LastSeen: now, Count: 1,
	}
}

// baseChain is a small valid chain: checkpoint, deltas, finding, anchor, delta.
func baseChain() *builder {
	b := newBuilder(epochA, writerA)
	b.checkpointOf(richState(), p.ReasonInitial)
	b.deltaWith(p.FlagSynthetic|p.FlagMetricFacts, &p.Interval{Start: t0 + 100, End: t0 + 900},
		p.Create("uid-cm", "ConfigMap", "default", "cfg", map[string]any{"ratio": 1.5, "s": "abc"}),
		p.Update("uid-deploy-web", map[string]any{"replicas": 4, "image": nil, "metric.cpu": 0.5}),
		p.Delete("uid-host-svc", p.DeleteScopeRemoved),
		p.EdgeAdd("uid-deploy-web", "selects", "uid-cm", map[string]any{"w": 1}),
		p.EdgeRemove("uid-pod-web-1", "runs-on", "uid-node-a", nil),
		p.EdgeReplace("uid-deploy-web", "owns", "uid-pod-web-1", map[string]any{"controller": false}, map[string]any{"controller": true}),
		p.ScopeSet("Pod", p.ScopeStatus{State: p.ScopeComplete}),
	)
	b.finding(fullFinding(b.now))
	b.finding(minimalFinding(b.now, p.TransitionStale))
	b.checkpoint(p.ReasonAnchor)
	b.delta(p.Update("uid-cm", map[string]any{"s": nil}))
	return b
}

type recordVector struct {
	Name       string `json:"name"`
	Hex        string `json:"hex"`
	Pad        *pad   `json:"pad,omitempty"`
	Type       string `json:"type"`
	Seq        uint64 `json:"seq"`
	RecordHash string `json:"record_hash"`
}

type chainRecord struct {
	Hex        string `json:"hex"`
	Type       string `json:"type"`
	Seq        uint64 `json:"seq"`
	RecordHash string `json:"record_hash"`
	ChainHash  string `json:"chain_hash"`
}

type chainVector struct {
	Name     string        `json:"name"`
	TargetID string        `json:"target_id"`
	Epoch    string        `json:"epoch"`
	WriterID string        `json:"writer_id"`
	Genesis  string        `json:"genesis"`
	Records  []chainRecord `json:"records"`
}

type valueVector struct {
	Name  string `json:"name"`
	Value tv     `json:"value"`
	Hex   string `json:"hex"`
}

type encodingFile struct {
	Description string         `json:"description"`
	Values      []valueVector  `json:"values"`
	Records     []recordVector `json:"records"`
	Chains      []chainVector  `json:"chains"`
}

func recVec(name, h string, pd *pad) recordVector {
	r, err := p.Decode(expand(h, pd))
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	return recordVector{Name: name, Hex: h, Pad: pd, Type: r.Type.String(), Seq: r.Seq, RecordHash: r.Hash().String()}
}

func chainVec(name string, recs []*p.Record) chainVector {
	first := recs[0]
	c := p.NewChain(first.TargetID, first.Epoch, first.Writer)
	cv := chainVector{Name: name, TargetID: first.TargetID, Epoch: first.Epoch.String(), WriterID: first.Writer.String(), Genesis: c.HeadHash.String()}
	for _, r := range recs {
		h := must(c.Append(r))
		cv.Records = append(cv.Records, chainRecord{Hex: hx(r.Bytes()), Type: r.Type.String(), Seq: r.Seq, RecordHash: r.Hash().String(), ChainHash: h.String()})
	}
	return cv
}

func valueVectors() []valueVector {
	f := func(name string, t tv) valueVector {
		return valueVector{Name: name, Value: t, Hex: hx(marshal(goValue(t, false)))}
	}
	nested := tArray(tArray(tArray(tUint(1))))
	return []valueVector{
		f("uint 0", tUint(0)), f("uint 23", tUint(23)), f("uint 24", tUint(24)), f("uint 255", tUint(255)),
		f("uint 256", tUint(256)), f("uint 65535", tUint(65535)), f("uint 65536", tUint(65536)),
		f("uint 2^32-1", tUint(math.MaxUint32)), f("uint 2^32", tUint(math.MaxUint32+1)), f("uint 2^64-1", tUint(math.MaxUint64)),
		f("nint -1", tNint("-1")), f("nint -24", tNint("-24")), f("nint -25", tNint("-25")), f("nint -256", tNint("-256")),
		f("nint -257", tNint("-257")), f("nint -2^63", tNint("-9223372036854775808")), f("nint -2^64", tNint("-18446744073709551616")),
		f("float 0", tFloat(0)), f("float -0", tFloat(math.Copysign(0, -1))), f("float 1", tFloat(1)), f("float 1.5", tFloat(1.5)),
		f("float -4", tFloat(-4)), f("float 65504 half max", tFloat(65504)), f("float 65520 single", tFloat(65520)),
		f("float 100000 single", tFloat(100000)), f("float 0.1 double", tFloat(0.1)), f("float 2^-14 half min normal", tFloat(math.Ldexp(1, -14))),
		f("float 2^-24 half min subnormal", tFloat(math.Ldexp(1, -24))), f("float 1023*2^-24 half max subnormal", tFloat(math.Ldexp(1023, -24))),
		f("float 2^-25 single", tFloat(math.Ldexp(1, -25))), f("float 2047*2^-25 single", tFloat(math.Ldexp(2047, -25))),
		f("float 2^-126 single min normal", tFloat(math.Ldexp(1, -126))), f("float 2^-149 single min subnormal", tFloat(math.Ldexp(1, -149))),
		f("float 2^-150 double", tFloat(math.Ldexp(1, -150))), f("float max single", tFloat(math.MaxFloat32)),
		f("float max single next double", tFloat(math.Nextafter(math.MaxFloat32, math.Inf(1)))), f("float max double", tFloat(math.MaxFloat64)),
		f("float min subnormal double", tFloat(math.SmallestNonzeroFloat64)), f("float 1+2^-10 half", tFloat(1+math.Ldexp(1, -10))),
		f("float 1+2^-11 single", tFloat(1+math.Ldexp(1, -11))), f("float 1+2^-23 single", tFloat(1+math.Ldexp(1, -23))),
		f("float 1+2^-24 double", tFloat(1+math.Ldexp(1, -24))), f("float 1e300", tFloat(1e300)),
		f("text empty", tText("")), f("text a", tText("a")), f("text unicode", tText("ü水\U0001F600")),
		f("text 23 bytes", tText(strings.Repeat("x", 23))), f("text 24 bytes", tText(strings.Repeat("y", 24))),
		f("text 256 bytes", tText(strings.Repeat("z", 256))),
		f("bytes empty", tBytes(nil)), f("bytes", tBytes([]byte{0, 1, 2, 0xff})),
		f("bool false", tBool(false)), f("bool true", tBool(true)), f("null", tNull()),
		f("array empty", tArray()), f("array nested", nested),
		f("array 24 elements", tArray(repeatTV(tUint(0), 24)...)),
		f("map empty", tMap()),
		f("map text keys length first", tMap([2]tv{tText("aa"), tUint(1)}, [2]tv{tText("b"), tUint(2)}, [2]tv{tText(""), tUint(3)}, [2]tv{tText("ab"), tUint(4)})),
		f("map int keys", tMap([2]tv{tUint(1000), tText("x")}, [2]tv{tUint(24), tText("y")}, [2]tv{tUint(0), tText("z")}, [2]tv{tUint(23), tText("w")})),
		f("map mixed keys", tMap([2]tv{tFloat(1.5), tUint(1)}, [2]tv{tNull(), tUint(2)}, [2]tv{tBool(true), tUint(3)}, [2]tv{tText("b"), tUint(4)},
			[2]tv{tBytes([]byte("a")), tUint(5)}, [2]tv{tNint("-1"), tUint(6)}, [2]tv{tUint(1), tUint(7)})),
	}
}

func repeatTV(t tv, n int) []tv {
	out := make([]tv, n)
	for i := range out {
		out[i] = t
	}
	return out
}

func deltaEnv(seq uint64) p.Envelope {
	return p.Envelope{Type: p.TypeDelta, TargetID: target, Epoch: epochA, Seq: seq, Writer: writerA, Incarnation: 1, Parent: seq - 1, Base: 1, Time: t0 + seq*1000, Schema: p.SchemaVersion}
}

func encRecord(r *p.Record) []byte { return must(p.Encode(r)) }

// bigTextRecord is a delta whose last encoded bytes are a text of textLen bytes 'a'.
func bigTextRecord(textLen int) []byte {
	return encRecord(&p.Record{Envelope: deltaEnv(2), Delta: &p.Delta{Ops: []p.Op{p.Create("uid-big", "ConfigMap", "default", "big", map[string]any{"x": strings.Repeat("a", textLen)})}}})
}

func bigArrayRecord(n int) []byte {
	arr := make([]any, n)
	for i := range arr {
		arr[i] = 0
	}
	return encRecord(&p.Record{Envelope: deltaEnv(2), Delta: &p.Delta{Ops: []p.Op{p.Create("uid-arr", "ConfigMap", "default", "arr", map[string]any{"x": arr})}}})
}

func nestedRecord(arrays int) []byte {
	var v any = 0
	for i := 0; i < arrays; i++ {
		v = []any{v}
	}
	env := deltaEnv(2)
	op := map[any]any{uint64(0): uint64(1), uint64(1): "uid-deep", uint64(2): "ConfigMap", uint64(3): "", uint64(4): "deep", uint64(5): map[any]any{"d": v}}
	return marshal(envMap(env, map[any]any{uint64(0): []any{op}}))
}

func envMap(e p.Envelope, body any) map[any]any {
	return map[any]any{
		uint64(0): uint64(p.Version), uint64(1): uint64(e.Type), uint64(2): e.TargetID, uint64(3): e.Epoch[:], uint64(4): e.Seq,
		uint64(5): e.Writer[:], uint64(6): e.Incarnation, uint64(7): e.Parent, uint64(8): e.Base, uint64(9): e.Time,
		uint64(10): e.Schema, uint64(11): body,
	}
}

// fixedSize returns a pad-described record of exactly size bytes ending in a text of 'a'.
func fixedSize(size int, lenDelta int) (string, *pad) {
	probe := bigTextRecord(1 << 16)
	textLen := size - (len(probe) - (1 << 16))
	b := bigTextRecord(textLen - lenDelta)
	prefix := b[:len(b)-(textLen-lenDelta)]
	if lenDelta != 0 {
		putLen32(prefix[len(prefix)-4:], textLen)
	}
	return hx(prefix), &pad{Byte: "61", Length: size}
}

func arrayPad(n int, declared int) (string, *pad) {
	b := bigArrayRecord(n)
	prefix := append([]byte(nil), b[:len(b)-n]...)
	putLen32(prefix[len(prefix)-4:], declared)
	return hx(prefix), &pad{Byte: "00", Length: len(prefix) + declared}
}

// putLen32 writes a CBOR 4-byte length, panicking on lengths it cannot carry.
func putLen32(b []byte, n int) {
	v := int64(n)
	if v < 0 || v > math.MaxUint32 {
		panic(fmt.Sprintf("length %d does not fit 32 bits", n))
	}
	binary.BigEndian.PutUint32(b, uint32(v))
}

func rangeRecord(b *builder, from, to int) *p.Record {
	run := b.recs[from-1 : to]
	g := must(p.Fold(run))
	last := run[len(run)-1]
	return must(p.NewRangeRecord(last.Envelope, g, run[0].Parent, last.Base))
}

func extensionRecords(bc *builder) []recordVector {
	d := generic(bc.recs[1].Bytes())
	d[uint64(1000)] = "future"
	d[uint64(70000)] = map[any]any{uint64(1): nil, "k": []any{int64(-1), 2.5}, cbor.ByteString("b"): true, "big": *new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 64))}
	d[uint64(11)].(map[any]any)[uint64(1000)] = map[any]any{"x": uint64(1)}
	f := generic(bc.recs[2].Bytes())
	fb := f[uint64(11)].(map[any]any)
	fb[uint64(1000)] = "finding-ext"
	fb[uint64(3)].(map[any]any)[uint64(1001)] = uint64(7)
	fb[uint64(12)].([]any)[0].(map[any]any)[uint64(1002)] = []any{}
	fb[uint64(17)].([]any)[0].(map[any]any)[uint64(1003)] = "s"
	ck := generic(bc.recs[0].Bytes())
	ck[uint64(11)].(map[any]any)[uint64(4000)] = cbor.ByteString("ck")
	return []recordVector{
		recVec("extension keys in envelope and delta body", hx(marshal(d)), nil),
		recVec("extension keys in finding body, provenance, evidence, suggestion", hx(marshal(f)), nil),
		recVec("extension key in checkpoint body", hx(marshal(ck)), nil),
	}
}

func encodingVectors() encodingFile {
	bc := baseChain()
	var recs []recordVector
	names := []string{"checkpoint initial with rich values", "delta with every op kind, flags, uncertainty", "finding rule provenance with every optional key",
		"finding query provenance minimal", "checkpoint periodic anchor", "delta update removing a field"}
	for i, r := range bc.recs {
		recs = append(recs, recVec(names[i], hx(r.Bytes()), nil))
	}
	rb := newBuilder(epochB, writerA)
	pe, ph := epochA, uint64(41)
	ck := p.NewState().Checkpoint(p.ReasonRebaseline, p.Interval{Start: t0, End: t0}, nil)
	ck.PrevEpoch, ck.PrevHead = &pe, &ph
	rb.add(&p.Record{Envelope: rb.env(p.TypeCheckpoint), Checkpoint: ck})
	recs = append(recs, recVec("checkpoint rebaseline naming the previous epoch, empty state", hx(rb.recs[0].Bytes()), nil))
	recs = append(recs, recVec("range folding a delta and two findings", hx(rangeRecord(bc, 2, 4).Bytes()), nil))
	recs = append(recs, recVec("range with only findings and no ops", hx(rangeRecord(bc, 3, 4).Bytes()), nil))
	recs = append(recs, extensionRecords(bc)...)
	recs = append(recs, recVec("nesting depth 32", hx(nestedRecord(27)), nil))
	h, pd := fixedSize(p.MaxRecordBytes, 0)
	recs = append(recs, recVec("record of exactly 4 MiB", h, pd))
	h, pd = arrayPad(p.MaxContainerSize, p.MaxContainerSize)
	recs = append(recs, recVec("array of 1048576 elements", h, pd))

	cb := newBuilder(epochC, writerB)
	cb.checkpointOf(richState(), p.ReasonWriterChange)
	cb.delta(p.Create("uid-a", "Pod", "ns", "a", map[string]any{"v": 1}))
	cb.delta(p.Update("uid-a", map[string]any{"v": 2}))
	cb.delta(p.Update("uid-a", map[string]any{"v": 3}), p.ScopeSet("Pod", p.ScopeStatus{State: p.ScopeComplete}))
	cb.finding(minimalFinding(cb.now, p.TransitionFiring))
	cb.delta(p.Delete("uid-a", p.DeleteDeleted))
	withRange := []*p.Record{cb.recs[0], cb.recs[1], rangeRecord(cb, 3, 5), cb.recs[5]}
	return encodingFile{
		Description: "Valid encodings. values: typed values and their deterministic CBOR. records: single valid records. chains: epochs with chain hashes.",
		Values:      valueVectors(),
		Records:     recs,
		Chains:      []chainVector{chainVec("checkpoint, delta, findings, anchor, delta", bc.recs), chainVec("chain with a range replacing 3..5", withRange)},
	}
}

func unhex(h string) []byte { return expand(h, nil) }

// Rejection vectors.

type rejectionVector struct {
	Name  string `json:"name"`
	Hex   string `json:"hex"`
	Pad   *pad   `json:"pad,omitempty"`
	Error string `json:"error"`
}

type rejectionFile struct {
	Description string            `json:"description"`
	Vectors     []rejectionVector `json:"vectors"`
}

type mutator func(m map[any]any)

func mut(b []byte, fn mutator) []byte {
	m := generic(b)
	fn(m)
	return marshal(m)
}

func body(m map[any]any) map[any]any { return m[uint64(11)].(map[any]any) }

func ops(m map[any]any) []any { return body(m)[uint64(0)].([]any) }

func opCreate(uid string) map[any]any {
	return map[any]any{uint64(0): uint64(1), uint64(1): uid, uint64(2): "Pod", uint64(3): "ns", uint64(4): "name", uint64(5): map[any]any{}}
}

func orderedMap(pairs [][2][]byte) []byte {
	out := marshalHeader(5, len(pairs))
	for _, pr := range pairs {
		out = append(out, pr[0]...)
		out = append(out, pr[1]...)
	}
	return out
}

func marshalHeader(major byte, n int) []byte {
	switch {
	case n < 0 || n > 255:
		panic("header length out of range")
	case n < 24:
		return []byte{major<<5 | byte(n)}
	default:
		return []byte{major<<5 | 24, byte(n)}
	}
}

func envPairs(b []byte) [][2][]byte {
	m := generic(b)
	var pairs [][2][]byte
	for k := uint64(0); k <= 11; k++ {
		pairs = append(pairs, [2][]byte{marshal(k), marshal(m[k])})
	}
	return pairs
}

func rejectionVectors() rejectionFile {
	bc := baseChain()
	ck, fd, anchor := bc.recs[0].Bytes(), bc.recs[2].Bytes(), bc.recs[4].Bytes()
	rg := rangeRecord(bc, 2, 4).Bytes()
	simple := encRecord(&p.Record{Envelope: deltaEnv(2), Delta: &p.Delta{Ops: []p.Op{p.Create("uid-x", "Pod", "ns", "x", map[string]any{"ratio": 1.5, "s": "abc"})}}})
	var vs []rejectionVector
	add := func(name string, b []byte, code string) {
		vs = append(vs, rejectionVector{Name: name, Hex: hx(b), Error: code})
	}
	withFloat := func(repl string) []byte { return replaceOnce(simple, []byte{0xf9, 0x3e, 0x00}, unhex(repl)) }
	setOp := func(fn func(op map[any]any)) []byte {
		return mut(simple, func(m map[any]any) { fn(ops(m)[0].(map[any]any)) })
	}
	setOps := func(os ...map[any]any) []byte {
		return mut(simple, func(m map[any]any) {
			a := make([]any, len(os))
			for i, o := range os {
				a[i] = o
			}
			body(m)[uint64(0)] = a
		})
	}
	setBody := func(b []byte, fn func(bd map[any]any)) []byte { return mut(b, func(m map[any]any) { fn(body(m)) }) }
	finding := func(fn func(f map[any]any)) []byte { return setBody(fd, fn) }
	rangeFinding := func(fn func(f map[any]any)) []byte {
		return setBody(rg, func(bd map[any]any) { fn(bd[uint64(2)].([]any)[0].([]any)[1].(map[any]any)) })
	}

	add("empty input", nil, "malformed")
	add("truncated record", ck[:len(ck)-1], "malformed")
	add("trailing bytes", append(append([]byte(nil), ck...), 0x00), "malformed")
	add("non-shortest integer", append([]byte{ck[0], 0x00, 0x18, 0x01}, ck[3:]...), "malformed")
	add("non-shortest text length", replaceOnce(simple, append([]byte{0x69}, "t-vectors"...), append([]byte{0x78, 0x09}, "t-vectors"...)), "malformed")
	pairs := envPairs(simple)
	pairs[0], pairs[1] = pairs[1], pairs[0]
	add("unsorted map keys", orderedMap(pairs), "malformed")
	pairs = envPairs(simple)
	add("duplicate map keys", orderedMap(append(pairs[:10:10], pairs[9], pairs[10], pairs[11])), "malformed")
	add("indefinite-length array", replaceOnce(ck, append(append([]byte{0x82, 0x66}, "events"...), append([]byte{0x69}, "inventory"...)...),
		append(append(append([]byte{0x9f, 0x66}, "events"...), append([]byte{0x69}, "inventory"...)...), 0xff)), "malformed")
	add("indefinite-length text", replaceOnce(simple, []byte{0x63, 'a', 'b', 'c'}, []byte{0x7f, 0x63, 'a', 'b', 'c', 0xff}), "malformed")
	add("tag", mut(simple, func(m map[any]any) { m[uint64(9)] = cbor.Tag{Number: 1, Content: m[uint64(9)]} }), "malformed")
	add("NaN float", withFloat("f97e00"), "malformed")
	add("infinite float", withFloat("f97c00"), "malformed")
	add("non-shortest float as single", withFloat("fa3fc00000"), "malformed")
	add("non-shortest float as double", withFloat("fb3ff8000000000000"), "malformed")
	add("undefined", withFloat("f7"), "malformed")
	add("simple value 16", withFloat("f0"), "malformed")
	add("simple value 32", withFloat("f820"), "malformed")
	add("two-byte simple value below 32", withFloat("f814"), "malformed")
	add("reserved additional information", withFloat("1c"), "malformed")
	add("invalid utf-8", replaceOnce(simple, []byte{0x63, 'a', 'b', 'c'}, []byte{0x63, 'a', 0xff, 'c'}), "malformed")
	add("utf-8 encoded surrogate", replaceOnce(simple, []byte{0x63, 'a', 'b', 'c'}, []byte{0x63, 0xed, 0xa0, 0x80}), "malformed")
	add("nesting depth 33", nestedRecord(28), "malformed")
	add("top-level array", marshal([]any{uint64(1)}), "malformed")
	add("envelope text key", mut(simple, func(m map[any]any) { m["x"] = uint64(1) }), "malformed")
	add("envelope negative key", mut(simple, func(m map[any]any) { m[int64(-1)] = uint64(1) }), "malformed")
	add("missing envelope key", mut(simple, func(m map[any]any) { delete(m, uint64(9)) }), "malformed")
	add("seq as text", mut(simple, func(m map[any]any) { m[uint64(4)] = "2" }), "malformed")
	add("epoch of 15 bytes", mut(simple, func(m map[any]any) { m[uint64(3)] = epochA[:15] }), "malformed")
	add("target_id with a space", mut(simple, func(m map[any]any) { m[uint64(2)] = "t vectors" }), "malformed")
	add("empty target_id", mut(simple, func(m map[any]any) { m[uint64(2)] = "" }), "malformed")
	add("protocol version 2", mut(simple, func(m map[any]any) { m[uint64(0)] = uint64(2) }), "unsupported_field")
	add("record type 5", mut(simple, func(m map[any]any) { m[uint64(1)] = uint64(5) }), "unsupported_field")
	add("unknown envelope key 12", mut(simple, func(m map[any]any) { m[uint64(12)] = "x" }), "unsupported_field")
	add("unknown delta body key 3", setBody(simple, func(bd map[any]any) { bd[uint64(3)] = uint64(1) }), "unsupported_field")
	add("unknown op key 12 in create", setOp(func(op map[any]any) { op[uint64(12)] = uint64(1) }), "unsupported_field")
	add("extension key in op", setOp(func(op map[any]any) { op[uint64(1000)] = uint64(1) }), "unsupported_field")
	scopeOp := map[any]any{uint64(0): uint64(7), uint64(11): "Pod", uint64(12): map[any]any{uint64(0): uint64(0), uint64(1000): "x"}}
	add("extension key in scope status inside op", setOps(scopeOp), "unsupported_field")
	add("unknown key in checkpoint scope status", setBody(ck, func(bd map[any]any) {
		bd[uint64(4)].(map[any]any)["Pod"].(map[any]any)[uint64(3)] = uint64(1)
	}), "unsupported_field")
	add("unknown suggestion key 3", finding(func(f map[any]any) { f[uint64(17)].([]any)[0].(map[any]any)[uint64(3)] = "x" }), "unsupported_field")
	add("unknown provenance key 4 in rule provenance", finding(func(f map[any]any) { f[uint64(3)].(map[any]any)[uint64(4)] = "x" }), "unsupported_field")

	add("null in create fields", setOp(func(op map[any]any) { op[uint64(5)] = map[any]any{"x": nil} }), "invalid_value")
	upd := map[any]any{uint64(0): uint64(2), uint64(1): "uid-x", uint64(5): map[any]any{"x": []any{nil}}}
	add("null inside an array in update changes", setOps(upd), "invalid_value")
	add("null inside a nested map in update changes", setOps(map[any]any{uint64(0): uint64(2), uint64(1): "uid-x", uint64(5): map[any]any{"x": map[any]any{"y": nil}}}), "invalid_value")
	add("non-text key in a nested field map", setOp(func(op map[any]any) { op[uint64(5)] = map[any]any{"x": map[any]any{uint64(1): uint64(2)}} }), "invalid_value")
	add("integer below -2^63 in fields", setOp(func(op map[any]any) {
		op[uint64(5)] = map[any]any{"x": *new(big.Int).Sub(big.NewInt(math.MinInt64), big.NewInt(1))}
	}), "invalid_value")
	add("non-text field key", setOp(func(op map[any]any) { op[uint64(5)] = map[any]any{uint64(1): uint64(2)} }), "malformed")

	envMut := func(b []byte, fields map[uint64]uint64) []byte {
		return mut(b, func(m map[any]any) {
			for k, v := range fields {
				m[k] = v
			}
		})
	}
	add("incarnation 0", envMut(simple, map[uint64]uint64{6: 0}), "invalid_chain")
	add("seq 0", envMut(ck, map[uint64]uint64{4: 0, 8: 0}), "invalid_chain")
	add("delta at seq 1", envMut(simple, map[uint64]uint64{4: 1, 7: 0}), "invalid_chain")
	add("delta seq not parent+1", envMut(simple, map[uint64]uint64{4: 3}), "invalid_chain")
	add("delta base above parent", envMut(simple, map[uint64]uint64{8: 2}), "invalid_chain")
	add("delta base 0", envMut(simple, map[uint64]uint64{8: 0}), "invalid_chain")
	add("finding seq not parent+1", envMut(fd, map[uint64]uint64{7: 1}), "invalid_chain")
	add("checkpoint base not seq", envMut(anchor, map[uint64]uint64{8: 1}), "invalid_chain")
	add("checkpoint seq not parent+1", envMut(anchor, map[uint64]uint64{7: 3}), "invalid_chain")
	add("range span mismatch: seq is not b", envMut(rg, map[uint64]uint64{4: 5}), "invalid_chain")
	add("range span mismatch: parent is not a-1", envMut(rg, map[uint64]uint64{7: 2, 8: 1}), "invalid_chain")
	add("range starting at 1", setBody(envMut(rg, map[uint64]uint64{7: 0, 8: 1}), func(bd map[any]any) { bd[uint64(1)] = []any{uint64(1), uint64(4)} }), "invalid_chain")
	add("range with a above b", setBody(envMut(rg, map[uint64]uint64{7: 4, 8: 1}), func(bd map[any]any) { bd[uint64(1)] = []any{uint64(5), uint64(4)} }), "invalid_chain")
	add("range base above parent", envMut(rg, map[uint64]uint64{8: 2}), "invalid_chain")

	add("delta without ops", setBody(simple, func(bd map[any]any) { bd[uint64(0)] = []any{} }), "invalid_op")
	add("two ops for the same uid", setOps(opCreate("uid-x"), map[any]any{uint64(0): uint64(3), uint64(1): "uid-x", uint64(6): uint64(1)}), "invalid_op")
	edge := func(kind uint64) map[any]any {
		return map[any]any{uint64(0): kind, uint64(1): "a", uint64(7): "owns", uint64(8): "b", uint64(9): map[any]any{}}
	}
	add("two ops for the same edge key", setOps(edge(4), edge(5)), "invalid_op")
	sc := func(st uint64) map[any]any {
		return map[any]any{uint64(0): uint64(7), uint64(11): "Pod", uint64(12): map[any]any{uint64(0): st}}
	}
	add("two ops for the same scope key", setOps(sc(0), sc(1)), "invalid_op")
	add("update with empty changes", setOps(map[any]any{uint64(0): uint64(2), uint64(1): "uid-x", uint64(5): map[any]any{}}), "invalid_op")
	add("delete reason 3", setOps(map[any]any{uint64(0): uint64(3), uint64(1): "uid-x", uint64(6): uint64(3)}), "invalid_op")
	add("op kind 8", setOps(map[any]any{uint64(0): uint64(8)}), "invalid_op")
	add("create with empty uid", setOp(func(op map[any]any) { op[uint64(1)] = "" }), "invalid_op")
	add("create with empty kind", setOp(func(op map[any]any) { op[uint64(2)] = "" }), "invalid_op")
	add("edge op with empty type", setOps(map[any]any{uint64(0): uint64(4), uint64(1): "a", uint64(7): "", uint64(8): "b", uint64(9): map[any]any{}}), "invalid_op")
	add("scope-set state 3", setOps(sc(3)), "invalid_op")
	add("scope-set empty key", setOps(map[any]any{uint64(0): uint64(7), uint64(11): "", uint64(12): map[any]any{uint64(0): uint64(0)}}), "invalid_op")

	add("zero delta flags present", setBody(simple, func(bd map[any]any) { bd[uint64(1)] = uint64(0) }), "malformed")
	add("delta uncertainty start after end", setBody(simple, func(bd map[any]any) { bd[uint64(2)] = []any{uint64(5), uint64(4)} }), "malformed")
	add("delta uncertainty interval of three", setBody(simple, func(bd map[any]any) { bd[uint64(2)] = []any{uint64(1), uint64(2), uint64(3)} }), "malformed")
	add("zero range flags present", setBody(rg, func(bd map[any]any) { bd[uint64(3)] = uint64(0) }), "malformed")
	add("empty range uncertainty list present", setBody(rg, func(bd map[any]any) { bd[uint64(4)] = []any{} }), "malformed")
	add("range ops not in canonical order", setBody(rg, func(bd map[any]any) {
		a := bd[uint64(0)].([]any)
		a[0], a[1] = a[1], a[0]
	}), "malformed")
	add("range finding seq outside span", setBody(rg, func(bd map[any]any) { bd[uint64(2)].([]any)[0].([]any)[0] = uint64(1) }), "malformed")
	add("range findings not ascending", setBody(rg, func(bd map[any]any) {
		a := bd[uint64(2)].([]any)
		a[0], a[1] = a[1], a[0]
	}), "malformed")
	add("range finding with empty dedup key", rangeFinding(func(f map[any]any) { f[uint64(1)] = "" }), "malformed")
	add("unsorted checkpoint resources", setBody(ck, func(bd map[any]any) {
		a := bd[uint64(2)].([]any)
		a[0], a[1] = a[1], a[0]
	}), "malformed")
	add("duplicate checkpoint resource", setBody(ck, func(bd map[any]any) {
		a := bd[uint64(2)].([]any)
		bd[uint64(2)] = append([]any{a[0]}, a...)
	}), "malformed")
	add("unsorted checkpoint edges", setBody(ck, func(bd map[any]any) {
		a := bd[uint64(3)].([]any)
		a[0], a[1] = a[1], a[0]
	}), "malformed")
	add("duplicate capability", setBody(ck, func(bd map[any]any) { bd[uint64(5)] = []any{"events", "events"} }), "malformed")
	add("unsorted capabilities", setBody(ck, func(bd map[any]any) { bd[uint64(5)] = []any{"inventory", "events"} }), "malformed")
	add("checkpoint reason 6", setBody(ck, func(bd map[any]any) { bd[uint64(0)] = uint64(6) }), "malformed")
	add("checkpoint interval start after end", setBody(ck, func(bd map[any]any) { bd[uint64(1)] = []any{uint64(2), uint64(1)} }), "malformed")
	add("previous epoch on a later checkpoint", setBody(anchor, func(bd map[any]any) { bd[uint64(7)] = epochB[:] }), "malformed")
	add("previous head on a later checkpoint", setBody(anchor, func(bd map[any]any) { bd[uint64(8)] = uint64(3) }), "malformed")
	add("empty scope reason present", setBody(ck, func(bd map[any]any) { bd[uint64(4)].(map[any]any)["Pod"].(map[any]any)[uint64(1)] = "" }), "malformed")
	add("zero scope since present", setBody(ck, func(bd map[any]any) { bd[uint64(4)].(map[any]any)["Pod"].(map[any]any)[uint64(2)] = uint64(0) }), "malformed")
	add("checkpoint scope state 3", setBody(ck, func(bd map[any]any) { bd[uint64(4)].(map[any]any)["Pod"].(map[any]any)[uint64(0)] = uint64(3) }), "malformed")
	add("checkpoint resource with empty kind", setBody(ck, func(bd map[any]any) { bd[uint64(2)].([]any)[0].([]any)[1] = "" }), "malformed")
	add("checkpoint resource of four elements", setBody(ck, func(bd map[any]any) {
		r := bd[uint64(2)].([]any)[0].([]any)
		bd[uint64(2)].([]any)[0] = r[:4]
	}), "malformed")
	add("state hash of 31 bytes", setBody(ck, func(bd map[any]any) { bd[uint64(6)] = bd[uint64(6)].([]byte)[:31] }), "malformed")

	add("unsorted finding resources", finding(func(f map[any]any) { f[uint64(10)] = []any{"b", "a"} }), "malformed")
	add("duplicate finding resources", finding(func(f map[any]any) { f[uint64(10)] = []any{"a", "a"} }), "malformed")
	add("empty finding facts present", finding(func(f map[any]any) { f[uint64(11)] = map[any]any{} }), "malformed")
	add("empty evidence list present", finding(func(f map[any]any) { f[uint64(12)] = []any{} }), "malformed")
	add("zero finding flags present", finding(func(f map[any]any) { f[uint64(13)] = uint64(0) }), "malformed")
	add("empty source node present", finding(func(f map[any]any) { f[uint64(14)] = "" }), "malformed")
	add("empty labels present", finding(func(f map[any]any) { f[uint64(15)] = map[any]any{} }), "malformed")
	add("non-text label value", finding(func(f map[any]any) { f[uint64(15)] = map[any]any{"a": uint64(1)} }), "malformed")
	add("empty summary present", finding(func(f map[any]any) { f[uint64(16)] = "" }), "malformed")
	add("empty suggestions present", finding(func(f map[any]any) { f[uint64(17)] = []any{} }), "malformed")
	add("empty coverage present", finding(func(f map[any]any) { f[uint64(18)] = []any{} }), "malformed")
	add("evidence truncated false", finding(func(f map[any]any) { f[uint64(12)].([]any)[0].(map[any]any)[uint64(5)] = false }), "malformed")
	add("evidence zero count present", finding(func(f map[any]any) { f[uint64(12)].([]any)[0].(map[any]any)[uint64(3)] = uint64(0) }), "malformed")
	add("empty suggestion source present", finding(func(f map[any]any) { f[uint64(17)].([]any)[1].(map[any]any)[uint64(2)] = "" }), "malformed")
	add("transition 6", finding(func(f map[any]any) { f[uint64(2)] = uint64(6) }), "malformed")
	add("severity 0", finding(func(f map[any]any) { f[uint64(5)] = uint64(0) }), "malformed")
	add("provenance kind 3", finding(func(f map[any]any) { f[uint64(3)] = map[any]any{uint64(0): uint64(3)} }), "malformed")
	add("query hash of 31 bytes", finding(func(f map[any]any) {
		f[uint64(3)] = map[any]any{uint64(0): uint64(2), uint64(4): make([]byte, 31), uint64(5): "user:alice"}
	}), "malformed")
	add("empty query requester", finding(func(f map[any]any) {
		f[uint64(3)] = map[any]any{uint64(0): uint64(2), uint64(4): make([]byte, 32), uint64(5): ""}
	}), "malformed")
	add("empty finding id", finding(func(f map[any]any) { f[uint64(0)] = "" }), "malformed")
	add("empty rule bundle version", finding(func(f map[any]any) { f[uint64(3)].(map[any]any)[uint64(3)] = "" }), "malformed")
	add("missing finding count", finding(func(f map[any]any) { delete(f, uint64(9)) }), "malformed")

	add("bad checkpoint state hash", setBody(ck, func(bd map[any]any) { bd[uint64(6)] = make([]byte, 32) }), "invalid_state_hash")
	add("checkpoint content changed under its state hash", setBody(anchor, func(bd map[any]any) {
		bd[uint64(5)] = []any{"events"}
		bd[uint64(2)].([]any)[0].([]any)[3] = "renamed"
	}), "invalid_state_hash")

	h, pd := fixedSize(p.MaxRecordBytes+1, 1)
	vs = append(vs, rejectionVector{Name: "record larger than 4 MiB", Hex: h, Pad: pd, Error: "too_large"})
	h, pd = arrayPad(p.MaxContainerSize, p.MaxContainerSize+1)
	vs = append(vs, rejectionVector{Name: "array of 1048577 elements", Hex: h, Pad: pd, Error: "malformed"})

	for _, v := range vs {
		_, err := p.Decode(expand(v.Hex, v.Pad))
		if got := p.CodeOf(err); got != v.Error {
			panic(fmt.Sprintf("%s: Decode returned %q (%v), vector expects %q", v.Name, got, err, v.Error))
		}
	}
	return rejectionFile{Description: "Records every reader rejects, with the rejection code.", Vectors: vs}
}
