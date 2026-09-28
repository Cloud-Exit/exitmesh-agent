package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	bolt "go.etcd.io/bbolt"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// chainMark is a known chain hash; marks[0] is the parent of the first spooled record.
type chainMark struct {
	seq  uint64
	hash protocol.Hash
}

var markEvery = 1024

func (s *Spool) baseMark() chainMark {
	if s.committed != nil {
		return chainMark{s.committed.Seq, s.committed.ChainHash}
	}
	if s.epoch != nil {
		return chainMark{0, protocol.Genesis(s.epoch.TargetID, s.epoch.ID, s.writer)}
	}
	return chainMark{}
}

func (s *Spool) addMark(seq uint64, h protocol.Hash) {
	s.sinceMark++
	if s.sinceMark >= markEvery {
		s.marks = append(s.marks, chainMark{seq, h})
		s.sinceMark = 0
	}
}

// markBefore returns the last mark strictly below seq, or the base mark.
func (s *Spool) markBefore(seq uint64) chainMark {
	i := sort.Search(len(s.marks), func(i int) bool { return s.marks[i].seq >= seq })
	if i == 0 {
		return s.marks[0]
	}
	return s.marks[i-1]
}

// locate finds the spooled record whose span contains seq and its chain hash.
func (s *Spool) locate(seq uint64) (recMeta, protocol.Hash, bool, error) {
	mk := s.markBefore(seq)
	h := mk.hash
	var out recMeta
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		for k, v := c.Seek(seqKey(mk.seq + 1)); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			h = protocol.ChainHash(h, m.Hash)
			if m.Seq >= seq {
				if m.From <= seq {
					out, found = m, true
				}
				return nil
			}
		}
		return nil
	})
	return out, h, found, err
}

// rebuildChain recomputes every chain hash from the base after record bytes changed.
func (s *Spool) rebuildChain() error {
	base := s.baseMark()
	h := base.hash
	marks := []chainMark{base}
	since := 0
	var last uint64
	any := false
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			h = protocol.ChainHash(h, m.Hash)
			if since++; since >= markEvery {
				marks = append(marks, chainMark{m.Seq, h})
				since = 0
			}
			last, any = m.Seq, true
		}
		return nil
	})
	if err != nil {
		s.fault = fmt.Errorf("spool: chain index rebuild: %w", err)
		return s.fault
	}
	s.marks, s.sinceMark = marks, since
	if any && last == s.chain.Head {
		s.chain.HeadHash = h
		if s.epoch != nil {
			e := *s.epoch
			e.Chain = s.chain
			s.epoch = &e
		}
	}
	return nil
}

func (s *Spool) entriesLimit() int64 { return 4 * s.opts.WindowBytes }

// Entries pages spooled records from fromSeq in chain order (at most four windows, at least one) and pins them against rewrites.
func (s *Spool) Entries(fromSeq uint64) []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.count == 0 {
		return nil
	}
	limit := s.entriesLimit()
	mk := s.markBefore(fromSeq)
	h := mk.hash
	var out []*Entry
	var total int64
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		for k, v := c.Seek(seqKey(mk.seq + 1)); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			h = protocol.ChainHash(h, m.Hash)
			if m.Seq < fromSeq {
				continue
			}
			if len(out) > 0 && total+int64(m.Len) > limit {
				return nil
			}
			body, err := s.readBody(m)
			if err != nil {
				return err
			}
			out = append(out, &Entry{Seq: m.Seq, Type: m.Type, State: m.State, Bytes: body, Hash: m.Hash, ChainHash: h})
			total += int64(m.Len)
		}
		return nil
	})
	if err != nil && s.readErr == nil {
		s.readErr = err
	}
	s.pinBatch(out)
	return out
}

func (s *Spool) readBody(m recMeta) ([]byte, error) {
	body, err := s.segs.read(m.Seg, m.Off, m.Len)
	if err != nil {
		return nil, fmt.Errorf("record %d: %w", m.Seq, err)
	}
	if protocol.RecordHash(body) != m.Hash {
		return nil, fmt.Errorf("%w: record %d body does not match its hash", ErrCorrupt, m.Seq)
	}
	return body, nil
}

// pinBatch pins the never-transmitted records just handed out; older pins go first when over budget.
func (s *Spool) pinBatch(es []*Entry) {
	var add int64
	for _, e := range es {
		if _, ok := s.pinned[e.Seq]; !ok && e.State == NeverTransmitted {
			add += int64(len(e.Bytes))
		}
	}
	if s.pinBytes+add > 2*s.entriesLimit() {
		keep, kept := map[uint64]int64{}, int64(0)
		for _, e := range es {
			if n, ok := s.pinned[e.Seq]; ok {
				keep[e.Seq], kept = n, kept+n
			}
		}
		s.pinned, s.pinBytes = keep, kept
	}
	for _, e := range es {
		if _, ok := s.pinned[e.Seq]; !ok && e.State == NeverTransmitted {
			s.pinned[e.Seq] = int64(len(e.Bytes))
			s.pinBytes += int64(len(e.Bytes))
		}
	}
}

func (s *Spool) unpin(seq uint64) {
	if n, ok := s.pinned[seq]; ok {
		delete(s.pinned, seq)
		s.pinBytes -= n
	}
}

func (s *Spool) isPinned(seq uint64) bool {
	_, ok := s.pinned[seq]
	return ok
}

// MarkTransmitted durably moves records to transmitted-unconfirmed; call it before sending them.
func (s *Spool) MarkTransmitted(seqs ...uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if len(seqs) == 0 {
		return nil
	}
	var changed []recMeta
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRecords)
		for _, seq := range seqs {
			k := seqKey(seq)
			v := b.Get(k)
			if v == nil {
				return fmt.Errorf("%w: sequence %d", ErrNotSpooled, seq)
			}
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			if m.State == TransmittedUnconfirmed {
				continue
			}
			m.State = TransmittedUnconfirmed
			if err := b.Put(k, m.encode()); err != nil {
				return err
			}
			changed = append(changed, m)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, m := range changed {
		s.inflight += int64(m.Len)
		s.unpin(m.Seq)
	}
	return nil
}

// Commit deletes every record at or below a committed head, or returns ErrDivergence (SPEC 8.4 step 2).
func (s *Spool) Commit(epoch protocol.EpochID, seq uint64, chainHash protocol.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.epoch == nil {
		return ErrNoEpoch
	}
	if epoch != s.epoch.ID {
		return fmt.Errorf("%w: %s, current %s", ErrEpochMismatch, epoch, s.epoch.ID)
	}
	if seq == 0 {
		return nil
	}
	if seq > s.chain.Head {
		return fmt.Errorf("%w: committed head %d above highest assigned sequence %d", ErrDivergence, seq, s.chain.Head)
	}
	if c := s.committed; c != nil && seq <= c.Seq {
		if seq == c.Seq && chainHash != c.ChainHash {
			return fmt.Errorf("%w: chain hash at committed head %d changed", ErrDivergence, seq)
		}
		return nil
	}
	if s.epoch.Sealed && seq > s.epoch.SealedAt {
		return fmt.Errorf("%w: committed head %d above discarded suffix from %d", ErrDivergence, seq, s.epoch.SealedAt+1)
	}
	m, h, found, err := s.locate(seq)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: sequence %d missing from spool", ErrCorrupt, seq)
	}
	if m.Seq != seq {
		return fmt.Errorf("%w: committed head %d inside coalesced range [%d,%d]", ErrDivergence, seq, m.From, m.Seq)
	}
	if h != chainHash {
		return fmt.Errorf("%w: chain hash at %d is %s, control plane has %s", ErrDivergence, seq, h, chainHash)
	}
	cp := protocol.ChainPoint{Seq: seq, ChainHash: chainHash}
	var gone []recMeta
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRecords)
		c := b.Cursor()
		for k, v := c.First(); k != nil && binary.BigEndian.Uint64(k) <= seq; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			gone = append(gone, m)
		}
		for _, m := range gone {
			if err := b.Delete(seqKey(m.Seq)); err != nil {
				return err
			}
		}
		return putJSON(tx.Bucket(bucketMeta), keyCommitted, cp)
	})
	if err != nil {
		return err
	}
	s.forget(gone)
	s.committed = &cp
	marks := []chainMark{{seq, chainHash}}
	for _, mk := range s.marks {
		if mk.seq > seq {
			marks = append(marks, mk)
		}
	}
	s.marks = marks
	s.nextRelief = 0
	s.noteIO(s.segs.gc())
	s.signal()
	return nil
}

func (s *Spool) forget(gone []recMeta) {
	for _, m := range gone {
		s.account(m, -1)
		s.unpin(m.Seq)
	}
}

func (s *Spool) noteIO(err error) {
	if err != nil && s.readErr == nil {
		s.readErr = err
	}
}

// LastCommitted returns the committed head last confirmed by the control plane for the current epoch.
func (s *Spool) LastCommitted() (protocol.ChainPoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed == nil {
		return protocol.ChainPoint{}, false
	}
	return *s.committed, true
}

// DiscardAbove deletes records above seq and seals the epoch, whose sequences are never reissued (SPEC 8.6).
func (s *Spool) DiscardAbove(seq uint64) error {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.epoch == nil {
		return nil
	}
	e := *s.epoch
	e.Chain = s.chain
	if !e.Sealed || seq < e.SealedAt {
		e.SealedAt = seq
	}
	e.Sealed = true
	var gone []recMeta
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRecords)
		if seq < math.MaxUint64 {
			c := b.Cursor()
			for k, v := c.Seek(seqKey(seq + 1)); k != nil; k, v = c.Next() {
				m, err := decodeMeta(k, v)
				if err != nil {
					return err
				}
				gone = append(gone, m)
			}
			for _, m := range gone {
				if err := b.Delete(seqKey(m.Seq)); err != nil {
					return err
				}
			}
		}
		return putJSON(tx.Bucket(bucketMeta), keyEpoch, e)
	})
	if err != nil {
		return err
	}
	s.forget(gone)
	s.epoch = &e
	marks := s.marks[:1]
	for _, mk := range s.marks[1:] {
		if mk.seq <= seq {
			marks = append(marks, mk)
		}
	}
	s.marks = marks
	s.nextRelief = 0
	s.noteIO(s.segs.gc())
	s.signal()
	return nil
}

// OpenEpoch starts a fresh chain; remaining records must be at or below prevHead of prev, and are dropped.
func (s *Spool) OpenEpoch(reason string, prev *protocol.EpochID, prevHead *uint64) (protocol.EpochID, error) {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writableLocked(); err != nil {
		return protocol.EpochID{}, err
	}
	if reason == "" {
		return protocol.EpochID{}, errors.New("spool: epoch open reason required")
	}
	target := s.identity.TargetID
	if !protocol.ValidTargetID(target) {
		return protocol.EpochID{}, errors.New("spool: identity has no valid target id")
	}
	if s.epoch != nil && s.count > 0 {
		if prev == nil || prevHead == nil || *prev != s.epoch.ID {
			return protocol.EpochID{}, fmt.Errorf("%w: %d records", ErrRecordsRemain, s.count)
		}
		if last := s.lastSeq(); last > *prevHead {
			return protocol.EpochID{}, fmt.Errorf("%w: record %d above previous head %d", ErrRecordsRemain, last, *prevHead)
		}
	}
	now := s.opts.Clock()
	id, err := protocol.NewEpoch(now)
	if err != nil {
		return protocol.EpochID{}, err
	}
	e := EpochState{ID: id, TargetID: target, OpenReason: reason, OpenedAt: now.UTC(), Chain: *protocol.NewChain(target, id, s.writer)}
	if prev != nil {
		p := *prev
		e.PrevEpoch = &p
	}
	if prevHead != nil {
		h := *prevHead
		e.PrevHead = &h
	}
	var gone []recMeta
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRecords)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			gone = append(gone, m)
		}
		for _, m := range gone {
			if err := b.Delete(seqKey(m.Seq)); err != nil {
				return err
			}
		}
		mb := tx.Bucket(bucketMeta)
		if err := mb.Delete(keyCommitted); err != nil {
			return err
		}
		return putJSON(mb, keyEpoch, e)
	})
	if err != nil {
		return protocol.EpochID{}, err
	}
	s.forget(gone)
	s.epoch = &e
	s.chain = e.Chain
	s.committed = nil
	s.marks = []chainMark{s.baseMark()}
	s.sinceMark = 0
	s.pinned, s.pinBytes = map[uint64]int64{}, 0
	s.rebaseline, s.nextRelief = false, 0
	s.noteIO(s.segs.gc())
	s.signal()
	return id, nil
}

func (s *Spool) lastSeq() uint64 {
	var last uint64
	_ = s.db.View(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bucketRecords).Cursor().Last(); k != nil {
			last = binary.BigEndian.Uint64(k)
		}
		return nil
	})
	return last
}
