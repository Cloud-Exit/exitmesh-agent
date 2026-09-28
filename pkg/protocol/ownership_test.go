package protocol

import "testing"

func TestDecideTable(t *testing.T) {
	w1, w2 := WriterID{1}, WriterID{2}
	e1, e2, e3 := EpochID{1}, EpochID{2}, EpochID{3}
	head := ChainPoint{Seq: 10, ChainHash: Hash{0xaa}}
	base := func(tt string) *OwnershipState {
		return &OwnershipState{
			TargetType: tt,
			OpenEpoch:  &e1,
			Epochs: map[EpochID]*EpochInfo{
				e1: {ID: e1, Owner: w1, Open: true, Head: head},
				e3: {ID: e3, Owner: w2, Open: false},
			},
			Retired:            map[WriterID]bool{},
			HighestIncarnation: map[WriterID]uint64{w1: 5},
			ChainHashAt: func(ep EpochID, seq uint64) (Hash, bool) {
				if ep == e1 && seq == 10 {
					return head.ChainHash, true
				}
				return Hash{}, false
			},
		}
	}
	hello := func(w WriterID, inc uint64, ep EpochID) *HelloParams {
		return &HelloParams{WriterID: w, Incarnation: inc, Epoch: ep}
	}
	cases := []struct {
		name  string
		st    func() *OwnershipState
		h     *HelloParams
		cred  bool
		row   int
		code  string
		setup func(*OwnershipState, *HelloParams)
	}{
		{name: "bad credential", st: func() *OwnershipState { return base(TargetKubernetes) }, h: hello(w1, 5, e1), cred: false, row: 1, code: CodeUnauthorized},
		{name: "conflict", st: func() *OwnershipState { s := base(TargetHost); s.Conflict = true; return s }, h: hello(w1, 5, e1), cred: true, row: 2, code: CodeIdentityConflict},
		{name: "machine id", st: func() *OwnershipState { s := base(TargetHost); s.EnrolledMachineID = "m1"; return s }, h: &HelloParams{WriterID: w1, Incarnation: 5, Epoch: e1, MachineID: "m2"}, cred: true, row: 3, code: CodeIdentityConflict},
		{name: "retired", st: func() *OwnershipState { s := base(TargetKubernetes); s.Retired[w2] = true; return s }, h: hello(w2, 1, e2), cred: true, row: 4, code: CodeWriterRetired},
		{name: "closed epoch", st: func() *OwnershipState { return base(TargetKubernetes) }, h: hello(w2, 1, e3), cred: true, row: 5, code: CodeEpochClosed},
		{name: "not owner", st: func() *OwnershipState { return base(TargetKubernetes) }, h: hello(w2, 1, e1), cred: true, row: 6, code: CodeNotOwner},
		{name: "stale incarnation", st: func() *OwnershipState { return base(TargetKubernetes) }, h: hello(w1, 4, e1), cred: true, row: 7, code: CodeStaleIncarnation},
		{name: "duplicate session", st: func() *OwnershipState {
			s := base(TargetKubernetes)
			s.Active = &ActiveSession{Writer: w1, Incarnation: 5}
			return s
		}, h: hello(w1, 5, e1), cred: true, row: 8, code: CodeIdentityConflict},
		{name: "divergent prefix", st: func() *OwnershipState { return base(TargetKubernetes) }, h: &HelloParams{WriterID: w1, Incarnation: 6, Epoch: e1, LastCommitted: &ChainPoint{Seq: 10, ChainHash: Hash{0xbb}}}, cred: true, row: 9, code: CodeDivergence},
		{name: "prefix beyond head", st: func() *OwnershipState { return base(TargetKubernetes) }, h: &HelloParams{WriterID: w1, Incarnation: 6, Epoch: e1, LastCommitted: &ChainPoint{Seq: 11}}, cred: true, row: 9, code: CodeDivergence},
		{name: "resume", st: func() *OwnershipState { return base(TargetKubernetes) }, h: &HelloParams{WriterID: w1, Incarnation: 6, Epoch: e1, LastCommitted: &head}, cred: true, row: 10},
		{name: "first enrollment", st: func() *OwnershipState {
			return &OwnershipState{TargetType: TargetKubernetes, Epochs: map[EpochID]*EpochInfo{}}
		}, h: hello(w1, 1, e1), cred: true, row: 11},
		{name: "rebaseline", st: func() *OwnershipState { return base(TargetKubernetes) }, h: &HelloParams{WriterID: w1, Incarnation: 6, Epoch: e2, EpochOpen: &EpochOpen{Reason: OpenRebaseline, PrevEpoch: &e1}}, cred: true, row: 12},
		{name: "owner new epoch without rebaseline", st: func() *OwnershipState { return base(TargetKubernetes) }, h: hello(w1, 6, e2), cred: true, row: 16, code: CodeInvalidHello},
		{name: "new writer cluster", st: func() *OwnershipState { return base(TargetKubernetes) }, h: hello(w2, 1, e2), cred: true, row: 13},
		{name: "new writer host bound", st: func() *OwnershipState { s := base(TargetHost); s.PendingBinding = true; return s }, h: hello(w2, 1, e2), cred: true, row: 14},
		{name: "new writer host", st: func() *OwnershipState { return base(TargetHost) }, h: hello(w2, 1, e2), cred: true, row: 15, code: CodeIdentityConflict},
	}
	for _, c := range cases {
		d := Decide(c.st(), c.h, c.cred)
		if d.Row != c.row || d.Code != c.code {
			t.Errorf("%s: got row %d code %q, want row %d code %q", c.name, d.Row, d.Code, c.row, c.code)
		}
		if (c.code == "") != d.Accept {
			t.Errorf("%s: accept=%v", c.name, d.Accept)
		}
	}
	d := Decide(base(TargetKubernetes), hello(w2, 1, e2), true)
	if d.RetireWriter == nil || *d.RetireWriter != w1 || d.CloseEpoch == nil || *d.CloseEpoch != e1 {
		t.Fatal("writer change must retire the previous owner and close its epoch")
	}
	s := base(TargetKubernetes)
	s.Active = &ActiveSession{Writer: w1, Incarnation: 5}
	if d := Decide(s, hello(w1, 6, e1), true); !d.Supersede || d.Row != 10 {
		t.Fatal("higher incarnation must supersede")
	}
}
