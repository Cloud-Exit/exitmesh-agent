package client

import (
	"errors"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// RecordState is the delivery state of a spooled record (SPEC 8.1). Committed records are deleted.
type RecordState int

const (
	NeverTransmitted RecordState = iota
	TransmittedUnconfirmed
)

func (s RecordState) String() string {
	if s == TransmittedUnconfirmed {
		return "transmitted_unconfirmed"
	}
	return "never_transmitted"
}

// Entry is one spooled record.
type Entry struct {
	Seq       uint64
	Type      protocol.RecordType
	State     RecordState
	Bytes     []byte
	Hash      protocol.Hash
	ChainHash protocol.Hash
}

// Identity is the enrolled identity persisted with the spool.
type Identity struct {
	TargetID     string
	TargetType   string
	Credential   string
	CredentialID string
	MachineID    string
}

// EpochState is the writer's current epoch.
type EpochState struct {
	ID         protocol.EpochID
	OpenReason string
	PrevEpoch  *protocol.EpochID
	PrevHead   *uint64
	Registered bool
	Chain      protocol.Chain
}

// Tx appends records under the sequence lock.
type Tx interface {
	Append(t protocol.RecordType, build func(env protocol.Envelope) (*protocol.Record, error)) (*Entry, error)
}

// Store is the durable spool used by the writer session. See the package documentation.
type Store interface {
	WriterID() protocol.WriterID
	Incarnation() uint64
	Identity() Identity
	SetIdentity(Identity) error
	Epoch() (EpochState, bool)
	OpenEpoch(reason string, prev *protocol.EpochID, prevHead *uint64) (protocol.EpochID, error)
	MarkRegistered() error
	Do(fn func(tx Tx) error) error
	Entries(fromSeq uint64) []*Entry
	MarkTransmitted(seqs ...uint64) error
	Commit(epoch protocol.EpochID, seq uint64, chainHash protocol.Hash) error
	LastCommitted() (protocol.ChainPoint, bool)
	DiscardAbove(seq uint64) error
	Notify() <-chan struct{}
	SetHalted(code string) error
	Halted() (string, bool)
}

// Store errors.
var (
	ErrDivergence    = errors.New("committed chain diverges from the spool")
	ErrHalted        = errors.New("writer halted")
	ErrNoEpoch       = errors.New("no epoch open")
	ErrNotEnrolled   = errors.New("target identity not enrolled")
	ErrNotSpooled    = errors.New("sequence not spooled")
	ErrWrongEpoch    = errors.New("epoch is not the current epoch")
	ErrEntriesRemain = errors.New("entries above the previous head remain")
)
