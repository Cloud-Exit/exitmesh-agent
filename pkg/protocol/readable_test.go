package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReadable(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("u1", "Pod", "ns", "p", map[string]any{"blob": []byte{1, 2}}), EdgeAdd("u1", "runs-on", "n1", map[string]any{"a": 1}), ScopeSet("Pod|ns", ScopeStatus{State: ScopeUnavailable, Reason: "forbidden"}))
	b.delta(Update("u1", map[string]any{"blob": nil}), EdgeReplace("u1", "runs-on", "n1", map[string]any{"a": 2}, map[string]any{"a": 1}))
	b.finding("f1", TransitionFiring)
	g, err := Fold(b.recs[2:4])
	if err != nil {
		t.Fatal(err)
	}
	rr, err := NewRangeRecord(b.recs[3].Envelope, g, b.recs[2].Parent, b.recs[2].Base)
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, r := range append(b.recs, rr) {
		h := b.chain.HeadHash
		j, err := json.Marshal(Readable(r, &h))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, string(j))
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{`"type":"checkpoint"`, `"reason":"initial"`, `"op":"create"`, `"base64":"AQI="`, `"state":"unavailable"`, `"op":"edge_replace"`, `"prev_attrs":{"a":1}`, `"transition":"firing"`, `"rule_id":"r1"`, `"unavailable":[3,3]`, `"chain_hash"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("readable output lacks %s", want)
		}
	}
}
