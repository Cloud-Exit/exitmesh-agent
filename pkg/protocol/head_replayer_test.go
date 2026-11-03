package protocol

import (
	"testing"
)

func TestHeadReplayerFollowsTheChainWithoutStateHashes(t *testing.T) {
	b := newChainBuilder(t)
	b.delta(Create("a", "Pod", "", "a", map[string]any{"v": 1}))
	b.delta(Update("a", map[string]any{"v": 2}))
	b.checkpoint(ReasonAnchor)
	b.delta(Create("b", "Pod", "", "b", nil))

	p, err := NewHeadReplayerAt(b.recs[0], Genesis(testTarget, testEpoch, testWriter))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range b.recs[1:] {
		if _, err := p.Apply(r); err != nil {
			t.Fatal(err)
		}
	}
	if p.State().Hash() != b.state.Hash() {
		t.Fatal("the head replayer reached a different state")
	}
	if p.Chain().HeadHash != b.chain.HeadHash || p.Chain().Head != b.chain.Head {
		t.Fatal("the head replayer reached a different chain head")
	}
	if len(p.Boundaries) != 0 {
		t.Fatalf("boundaries %+v, want none", p.Boundaries)
	}
	if _, err := p.StateHashAt(b.chain.Head); err == nil {
		t.Fatal("a head replayer keeps no per-record state hashes")
	}

	env := p.Chain()
	ck := NewState().Checkpoint(ReasonAnchor, Interval{}, nil)
	disagreeing := &Record{Envelope: env.Next(TypeCheckpoint, 1, 1), Checkpoint: ck}
	if _, err := Encode(disagreeing); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Apply(disagreeing); err != nil {
		t.Fatal(err)
	}
	if len(p.Boundaries) != 1 {
		t.Fatal("a checkpoint that disagrees with the replayed state must still be a boundary")
	}
}
