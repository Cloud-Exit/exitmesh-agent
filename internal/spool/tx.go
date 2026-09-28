package spool

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Entry is one spooled record.
type Entry struct {
	Seq       uint64
	Type      protocol.RecordType
	State     RecordState
	Bytes     []byte // exact record bytes
	Hash      protocol.Hash
	ChainHash protocol.Hash
}

// Tx appends under the sequence lock; its records and cursors persist only if Do returns nil.
type Tx struct {
	s       *Spool
	chain   protocol.Chain
	recs    []*protocol.Record
	entries []*Entry
	cursors map[string]uint64
	done    bool
}

// AppendOption modifies an append.
type AppendOption func(*appendOpts)

type appendOpts struct {
	cursors map[string]uint64
}

// WithCursor persists an idempotency cursor atomically with the record.
func WithCursor(key string, value uint64) AppendOption {
	return func(o *appendOpts) {
		if o.cursors == nil {
			o.cursors = map[string]uint64{}
		}
		o.cursors[key] = value
	}
}

// Do runs fn under the sequence lock, commits its appends durably, then relieves pressure if needed.
func (s *Spool) Do(fn func(tx *Tx) error) error {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.mu.Lock()
	err := s.writableLocked()
	chain := s.chain
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tx := &Tx{s: s, chain: chain}
	err = fn(tx)
	tx.done = true
	if err != nil {
		return err
	}
	if len(tx.recs) == 0 && len(tx.cursors) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.commitTx(tx); err != nil {
		return err
	}
	s.signal()
	if s.bytes >= s.trigger() && s.bytes >= s.nextRelief {
		_, s.lastReliefErr = s.relieveLocked()
	}
	return nil
}

// Append builds, encodes if needed, and chains the next record; range records come only from Relieve.
func (tx *Tx) Append(t protocol.RecordType, build func(env protocol.Envelope) (*protocol.Record, error), opts ...AppendOption) (*Entry, error) {
	if tx.done {
		return nil, ErrTxDone
	}
	s := tx.s
	if t == protocol.TypeRange {
		return nil, errors.New("spool: range records are created only by relief")
	}
	s.mu.Lock()
	epoch, blocked := s.epoch, s.rebaseline && s.bytes > s.opts.CapacityBytes
	s.mu.Unlock()
	if epoch == nil {
		return nil, ErrNoEpoch
	}
	if epoch.Sealed {
		return nil, ErrEpochSealed
	}
	if blocked {
		return nil, ErrRebaselineRequired
	}
	env := tx.chain.Next(t, s.incarnation, uint64(s.opts.Clock().UnixMilli()))
	rec, err := build(env)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errors.New("spool: builder returned no record")
	}
	if rec.Type != t {
		return nil, fmt.Errorf("spool: builder returned a %s record for a %s append", rec.Type, t)
	}
	if rec.Bytes() == nil {
		if _, err := protocol.Encode(rec); err != nil {
			return nil, err
		}
	}
	h, err := tx.chain.Append(rec)
	if err != nil {
		return nil, err
	}
	var o appendOpts
	for _, opt := range opts {
		opt(&o)
	}
	for k, v := range o.cursors {
		if tx.cursors == nil {
			tx.cursors = map[string]uint64{}
		}
		tx.cursors[k] = v
	}
	e := &Entry{Seq: rec.Seq, Type: rec.Type, State: NeverTransmitted, Bytes: rec.Bytes(), Hash: rec.Hash(), ChainHash: h}
	tx.recs = append(tx.recs, rec)
	tx.entries = append(tx.entries, e)
	return e, nil
}

// commitTx writes bodies and fsyncs them, then commits metadata; the caller holds seqMu and mu.
func (s *Spool) commitTx(tx *Tx) error {
	if err := s.writableLocked(); err != nil {
		return err
	}
	frames := make([][]byte, len(tx.recs))
	for i, r := range tx.recs {
		frames[i] = appendFrame(nil, r.Bytes())
	}
	var locs []loc
	undo := func() error { return nil }
	if len(frames) > 0 {
		var err error
		if locs, undo, err = s.segs.appendFrames(frames); err != nil {
			return err
		}
	}
	metas := make([]recMeta, len(tx.recs))
	var n int64
	for i, r := range tx.recs {
		metas[i] = recMeta{
			Seq: r.Seq, Type: r.Type, State: NeverTransmitted, Hash: r.Hash(),
			Seg: locs[i].seg, Off: locs[i].off, Len: uint32(len(r.Bytes())), Time: r.Time, From: r.Seq,
		}
		n += int64(len(r.Bytes()))
	}
	var epoch EpochState
	if s.epoch != nil {
		epoch = *s.epoch
		epoch.Chain = tx.chain
	}
	err := s.db.Update(func(btx *bolt.Tx) error {
		rb := btx.Bucket(bucketRecords)
		for i := range metas {
			if err := rb.Put(seqKey(metas[i].Seq), metas[i].encode()); err != nil {
				return err
			}
		}
		if len(metas) > 0 {
			if err := putJSON(btx.Bucket(bucketMeta), keyEpoch, epoch); err != nil {
				return err
			}
		}
		cb := btx.Bucket(bucketCursors)
		for k, v := range tx.cursors {
			if err := cb.Put([]byte(k), u64(v)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if uerr := undo(); uerr != nil {
			s.fault = fmt.Errorf("spool: rolling back unreferenced bodies: %w", uerr)
		}
		return err
	}
	if len(metas) > 0 {
		s.chain = tx.chain
		epoch.Chain = s.chain
		s.epoch = &epoch
		for i, m := range metas {
			s.account(m, 1)
			s.addMark(m.Seq, tx.entries[i].ChainHash)
		}
		s.rate.add(s.opts.Clock(), n)
	}
	for k, v := range tx.cursors {
		s.cursors[k] = v
	}
	return nil
}
