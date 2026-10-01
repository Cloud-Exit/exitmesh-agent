package protocol

// EpochInfo is the control plane's view of one epoch.
type EpochInfo struct {
	ID       EpochID
	Owner    WriterID
	Open     bool
	Head     ChainPoint
	ClosedAt uint64
}

// ActiveSession is the currently attached writer session of a target.
type ActiveSession struct {
	SessionID   string
	Writer      WriterID
	Incarnation uint64
	// Instance is the instance the session presented; zero when it presented none.
	Instance ID
}

// OwnershipState is the per-target ownership registry input to Decide (SPEC 8.2).
type OwnershipState struct {
	TargetType         string
	Revoked            bool
	OpenEpoch          *EpochID
	Epochs             map[EpochID]*EpochInfo
	Retired            map[WriterID]bool
	HighestIncarnation map[WriterID]uint64
	Active             *ActiveSession
	EnrolledMachineID  string
	Conflict           bool
	PendingBinding     bool
	// ChainHashAt returns the committed chain hash at seq in epoch; seq 0 is the genesis.
	ChainHashAt func(epoch EpochID, seq uint64) (Hash, bool)
}

// Decision is the outcome of the ownership decision table.
type Decision struct {
	Row          int
	Accept       bool
	Code         string
	Outcome      string
	OpenEpoch    bool
	CloseEpoch   *EpochID
	RetireWriter *WriterID
	Supersede    bool
	SetConflict  bool
	ClearBinding bool
	Audit        bool
	Alarm        bool
}

// reject builds a rejection; every rejection is audited.
func reject(row int, code string) Decision {
	return Decision{Row: row, Code: code, Audit: true}
}

// Decide evaluates the normative ownership decision table (SPEC 8.3) for a hello.
func Decide(st *OwnershipState, h *HelloParams, credentialValid bool) Decision {
	if !credentialValid || st.Revoked {
		return reject(1, CodeUnauthorized)
	}
	if st.Conflict {
		return reject(2, CodeIdentityConflict)
	}
	if st.TargetType == TargetHost && st.EnrolledMachineID != "" && h.MachineID != st.EnrolledMachineID {
		d := reject(3, CodeIdentityConflict)
		d.SetConflict, d.Alarm = true, true
		return d
	}
	if st.Retired[h.WriterID] {
		return reject(4, CodeWriterRetired)
	}
	ep, known := st.Epochs[h.Epoch]
	if known && !ep.Open {
		return reject(5, CodeEpochClosed)
	}
	if known && ep.Owner != h.WriterID {
		return reject(6, CodeNotOwner)
	}
	if hi, ok := st.HighestIncarnation[h.WriterID]; ok && h.Incarnation < hi {
		return reject(7, CodeStaleIncarnation)
	}
	reconnect := false
	if st.Active != nil && st.Active.Writer == h.WriterID && st.Active.Incarnation == h.Incarnation {
		if h.Instance == nil || h.Instance.IsZero() || st.Active.Instance != *h.Instance {
			d := reject(8, CodeIdentityConflict)
			d.Alarm = true
			return d
		}
		reconnect = true
	}
	supersede := reconnect || st.Active != nil && st.Active.Writer == h.WriterID && st.Active.Incarnation < h.Incarnation
	if known {
		if h.LastCommitted != nil {
			if h.LastCommitted.Seq > ep.Head.Seq {
				return reject(9, CodeDivergence)
			}
			if st.ChainHashAt != nil {
				if ch, ok := st.ChainHashAt(h.Epoch, h.LastCommitted.Seq); !ok || ch != h.LastCommitted.ChainHash {
					return reject(9, CodeDivergence)
				}
			}
		}
		return Decision{Row: 10, Accept: true, Outcome: DecisionResume, Supersede: supersede}
	}
	if st.OpenEpoch == nil {
		if len(st.Epochs) == 0 {
			return Decision{Row: 11, Accept: true, Outcome: DecisionOpened, OpenEpoch: true, Supersede: supersede}
		}
		return reject(16, CodeInvalidHello)
	}
	open := st.Epochs[*st.OpenEpoch]
	cur := *st.OpenEpoch
	if open.Owner == h.WriterID {
		if h.EpochOpen != nil && h.EpochOpen.Reason == OpenRebaseline && h.EpochOpen.PrevEpoch != nil && *h.EpochOpen.PrevEpoch == cur {
			return Decision{Row: 12, Accept: true, Outcome: DecisionOpened, OpenEpoch: true, CloseEpoch: &cur, Supersede: supersede, Audit: true}
		}
		return reject(16, CodeInvalidHello)
	}
	prevOwner := open.Owner
	switch {
	case st.TargetType != TargetHost:
		return Decision{Row: 13, Accept: true, Outcome: DecisionOpened, OpenEpoch: true, CloseEpoch: &cur, RetireWriter: &prevOwner, Supersede: st.Active != nil, Audit: true}
	case st.PendingBinding:
		return Decision{Row: 14, Accept: true, Outcome: DecisionOpened, OpenEpoch: true, CloseEpoch: &cur, RetireWriter: &prevOwner, ClearBinding: true, Supersede: st.Active != nil, Audit: true}
	default:
		d := reject(15, CodeIdentityConflict)
		d.SetConflict, d.Alarm = true, true
		return d
	}
}
