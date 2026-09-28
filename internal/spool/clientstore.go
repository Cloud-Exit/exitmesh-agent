package spool

import (
	"errors"
	"fmt"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// ClientStore adapts a Spool to the session client's Store interface.
type ClientStore struct{ S *Spool }

var _ client.Store = ClientStore{}

// ClientTx adapts a spool transaction to client.Tx and exposes cursor-bearing appends.
type ClientTx struct{ T *Tx }

func (a ClientTx) Append(t protocol.RecordType, build func(env protocol.Envelope) (*protocol.Record, error)) (*client.Entry, error) {
	e, err := a.T.Append(t, build)
	if err != nil {
		return nil, mapErr(err)
	}
	return toClientEntry(e), nil
}

// AppendWithCursor appends and persists an idempotency cursor atomically with the record.
func (a ClientTx) AppendWithCursor(t protocol.RecordType, build func(env protocol.Envelope) (*protocol.Record, error), key string, value uint64) (*client.Entry, error) {
	e, err := a.T.Append(t, build, WithCursor(key, value))
	if err != nil {
		return nil, mapErr(err)
	}
	return toClientEntry(e), nil
}

func toClientEntry(e *Entry) *client.Entry {
	st := client.NeverTransmitted
	if e.State == TransmittedUnconfirmed {
		st = client.TransmittedUnconfirmed
	}
	return &client.Entry{Seq: e.Seq, Type: e.Type, State: st, Bytes: e.Bytes, Hash: e.Hash, ChainHash: e.ChainHash}
}

// mapErr wraps spool sentinels so errors.Is matches the client's sentinels too.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var target error
	switch {
	case errors.Is(err, ErrDivergence):
		target = client.ErrDivergence
	case errors.Is(err, ErrHalted):
		target = client.ErrHalted
	case errors.Is(err, ErrNoEpoch), errors.Is(err, ErrEpochSealed):
		target = client.ErrNoEpoch
	case errors.Is(err, ErrNotSpooled):
		target = client.ErrNotSpooled
	case errors.Is(err, ErrEpochMismatch):
		target = client.ErrWrongEpoch
	case errors.Is(err, ErrRecordsRemain):
		target = client.ErrEntriesRemain
	default:
		return err
	}
	return fmt.Errorf("%w: %w", target, err)
}

func (a ClientStore) WriterID() protocol.WriterID { return a.S.WriterID() }
func (a ClientStore) Incarnation() uint64         { return a.S.Incarnation() }

func (a ClientStore) Identity() client.Identity {
	id := a.S.Identity()
	return client.Identity{TargetID: id.TargetID, TargetType: id.TargetType, Credential: id.Credential, CredentialID: id.CredentialID, MachineID: id.MachineID}
}

func (a ClientStore) SetIdentity(id client.Identity) error {
	return mapErr(a.S.SetIdentity(Identity{TargetID: id.TargetID, TargetType: id.TargetType, Credential: id.Credential, CredentialID: id.CredentialID, MachineID: id.MachineID}))
}

func (a ClientStore) Epoch() (client.EpochState, bool) {
	e, ok := a.S.Epoch()
	if !ok {
		return client.EpochState{}, false
	}
	return client.EpochState{ID: e.ID, OpenReason: e.OpenReason, PrevEpoch: e.PrevEpoch, PrevHead: e.PrevHead, Registered: e.Registered, Chain: e.Chain}, true
}

func (a ClientStore) OpenEpoch(reason string, prev *protocol.EpochID, prevHead *uint64) (protocol.EpochID, error) {
	id, err := a.S.OpenEpoch(reason, prev, prevHead)
	return id, mapErr(err)
}

func (a ClientStore) MarkRegistered() error { return mapErr(a.S.MarkRegistered()) }

func (a ClientStore) Do(fn func(tx client.Tx) error) error {
	return mapErr(a.S.Do(func(tx *Tx) error { return fn(ClientTx{T: tx}) }))
}

func (a ClientStore) Entries(fromSeq uint64) []*client.Entry {
	es := a.S.Entries(fromSeq)
	out := make([]*client.Entry, len(es))
	for i, e := range es {
		out[i] = toClientEntry(e)
	}
	return out
}

func (a ClientStore) MarkTransmitted(seqs ...uint64) error {
	return mapErr(a.S.MarkTransmitted(seqs...))
}

func (a ClientStore) Commit(epoch protocol.EpochID, seq uint64, chainHash protocol.Hash) error {
	return mapErr(a.S.Commit(epoch, seq, chainHash))
}

func (a ClientStore) LastCommitted() (protocol.ChainPoint, bool) { return a.S.LastCommitted() }
func (a ClientStore) DiscardAbove(seq uint64) error              { return mapErr(a.S.DiscardAbove(seq)) }
func (a ClientStore) Notify() <-chan struct{}                    { return a.S.Notify() }
func (a ClientStore) SetHalted(code string) error                { return mapErr(a.S.SetHalted(code, code)) }

func (a ClientStore) Halted() (string, bool) {
	h, ok := a.S.Halted()
	return h.Code, ok
}
