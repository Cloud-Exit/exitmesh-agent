package client

import (
	"fmt"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// MemOptions configures a MemStore.
type MemOptions struct {
	WriterID protocol.WriterID // zero generates a random writer ID
	Identity Identity
	Now      func() time.Time
}

type memData struct {
	writer      protocol.WriterID
	incarnation uint64
	identity    Identity
	epoch       *EpochState
	chain       *protocol.Chain
	entries     []*Entry
	committed   *protocol.ChainPoint
	transmitted map[protocol.RecordID]protocol.Hash
}

// MemStore is a goroutine-safe in-memory Store with full spool semantics, for tests.
type MemStore struct {
	seq    sync.Mutex
	mu     sync.Mutex
	d      *memData
	halted string
	notify chan struct{}
	now    func() time.Time
}

var _ Store = (*MemStore)(nil)

// NewMemStore creates a spool with incarnation 1.
func NewMemStore(opts MemOptions) (*MemStore, error) {
	w := opts.WriterID
	if w.IsZero() {
		var err error
		if w, err = protocol.NewWriterID(); err != nil {
			return nil, err
		}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	d := &memData{writer: w, incarnation: 1, identity: opts.Identity, transmitted: map[protocol.RecordID]protocol.Hash{}}
	return &MemStore{d: d, notify: make(chan struct{}, 1), now: now}, nil
}

// Reopen copies the durable state into a new handle with the next incarnation, as a restart does; halt is not copied.
func (s *MemStore) Reopen() *MemStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := *s.d
	d.incarnation++
	if s.d.epoch != nil {
		ep := *s.d.epoch
		d.epoch = &ep
		ch := *s.d.chain
		d.chain = &ch
	}
	if s.d.committed != nil {
		c := *s.d.committed
		d.committed = &c
	}
	d.entries = make([]*Entry, len(s.d.entries))
	for i, e := range s.d.entries {
		d.entries[i] = copyEntry(e)
	}
	d.transmitted = make(map[protocol.RecordID]protocol.Hash, len(s.d.transmitted))
	for k, v := range s.d.transmitted {
		d.transmitted[k] = v
	}
	return &MemStore{d: &d, notify: make(chan struct{}, 1), now: s.now}
}

func copyEntry(e *Entry) *Entry {
	c := *e
	return &c
}

func (s *MemStore) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *MemStore) WriterID() protocol.WriterID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.writer
}

func (s *MemStore) Incarnation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.incarnation
}

func (s *MemStore) Identity() Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.identity
}

func (s *MemStore) SetIdentity(id Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.identity = id
	return nil
}

func (s *MemStore) Epoch() (EpochState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.epoch == nil {
		return EpochState{}, false
	}
	ep := *s.d.epoch
	ep.Chain = *s.d.chain
	return ep, true
}

func (s *MemStore) OpenEpoch(reason string, prev *protocol.EpochID, prevHead *uint64) (protocol.EpochID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.identity.TargetID == "" {
		return protocol.EpochID{}, ErrNotEnrolled
	}
	for _, e := range s.d.entries {
		if prevHead == nil || e.Seq > *prevHead {
			return protocol.EpochID{}, fmt.Errorf("%w: seq %d", ErrEntriesRemain, e.Seq)
		}
	}
	id, err := protocol.NewEpoch(s.now())
	if err != nil {
		return id, err
	}
	ep := &EpochState{ID: id, OpenReason: reason}
	if prev != nil {
		p := *prev
		ep.PrevEpoch = &p
	}
	if prevHead != nil {
		h := *prevHead
		ep.PrevHead = &h
	}
	s.d.epoch = ep
	s.d.chain = protocol.NewChain(s.d.identity.TargetID, id, s.d.writer)
	s.d.entries = nil
	s.d.committed = nil
	return id, nil
}

func (s *MemStore) MarkRegistered() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.epoch == nil {
		return ErrNoEpoch
	}
	s.d.epoch.Registered = true
	return nil
}

type memTx struct {
	s        *MemStore
	appended int
}

// Do runs fn under the sequence lock; if fn fails, its appends are discarded.
func (s *MemStore) Do(fn func(tx Tx) error) error {
	s.seq.Lock()
	defer s.seq.Unlock()
	if code, ok := s.Halted(); ok {
		return fmt.Errorf("%w: %s", ErrHalted, code)
	}
	s.mu.Lock()
	var chain *protocol.Chain
	if s.d.chain != nil {
		c := *s.d.chain
		chain = &c
	}
	s.mu.Unlock()
	tx := &memTx{s: s}
	err := fn(tx)
	if err != nil && tx.appended > 0 {
		s.mu.Lock()
		s.d.entries = s.d.entries[:len(s.d.entries)-tx.appended]
		s.d.chain = chain
		s.mu.Unlock()
	}
	return err
}

func (t *memTx) Append(typ protocol.RecordType, build func(env protocol.Envelope) (*protocol.Record, error)) (*Entry, error) {
	s := t.s
	if typ == protocol.TypeRange {
		return nil, fmt.Errorf("%w: range records are produced by coalescing only", protocol.ErrInvalidChain)
	}
	s.mu.Lock()
	if s.halted != "" {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrHalted, s.halted)
	}
	if s.d.epoch == nil {
		s.mu.Unlock()
		return nil, ErrNoEpoch
	}
	env := s.d.chain.Next(typ, s.d.incarnation, uint64(s.now().UnixMilli()))
	s.mu.Unlock()
	rec, err := build(env)
	if err != nil {
		return nil, err
	}
	if rec.Type != typ {
		return nil, fmt.Errorf("%w: built %s, appending %s", protocol.ErrInvalidChain, rec.Type, typ)
	}
	if rec.Envelope != env {
		return nil, fmt.Errorf("%w: record envelope differs from the assigned envelope", protocol.ErrInvalidChain)
	}
	b, err := protocol.Encode(rec)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.epoch == nil || s.d.epoch.ID != env.Epoch {
		return nil, ErrWrongEpoch
	}
	ch, err := s.d.chain.Append(rec)
	if err != nil {
		return nil, err
	}
	e := &Entry{Seq: rec.Seq, Type: typ, State: NeverTransmitted, Bytes: b, Hash: rec.Hash(), ChainHash: ch}
	s.d.entries = append(s.d.entries, e)
	t.appended++
	s.signal()
	return copyEntry(e), nil
}

func (s *MemStore) Entries(fromSeq uint64) []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Entry
	for _, e := range s.d.entries {
		if e.Seq >= fromSeq {
			out = append(out, copyEntry(e))
		}
	}
	return out
}

func (s *MemStore) index(seq uint64) int {
	for i, e := range s.d.entries {
		if e.Seq == seq {
			return i
		}
	}
	return -1
}

func (s *MemStore) MarkTransmitted(seqs ...uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := make([]int, len(seqs))
	for i, seq := range seqs {
		j := s.index(seq)
		if j < 0 {
			return fmt.Errorf("%w: %d", ErrNotSpooled, seq)
		}
		idx[i] = j
	}
	for i, j := range idx {
		e := s.d.entries[j]
		e.State = TransmittedUnconfirmed
		s.d.transmitted[protocol.RecordID{TargetID: s.d.chain.TargetID, Epoch: s.d.epoch.ID, Seq: seqs[i]}] = e.Hash
	}
	return nil
}

func (s *MemStore) Commit(epoch protocol.EpochID, seq uint64, chainHash protocol.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.epoch == nil || s.d.epoch.ID != epoch {
		return ErrWrongEpoch
	}
	if c := s.d.committed; c != nil && seq <= c.Seq {
		if seq == c.Seq && chainHash != c.ChainHash {
			return fmt.Errorf("%w: chain hash at committed head %d", ErrDivergence, seq)
		}
		return nil
	}
	if seq == 0 {
		if chainHash != protocol.Genesis(s.d.chain.TargetID, epoch, s.d.writer) {
			return fmt.Errorf("%w: genesis", ErrDivergence)
		}
		return nil
	}
	j := s.index(seq)
	if j < 0 {
		return fmt.Errorf("%w: sequence %d is not a spooled record", ErrDivergence, seq)
	}
	if s.d.entries[j].ChainHash != chainHash {
		return fmt.Errorf("%w: chain hash at %d", ErrDivergence, seq)
	}
	s.d.entries = append([]*Entry(nil), s.d.entries[j+1:]...)
	s.d.committed = &protocol.ChainPoint{Seq: seq, ChainHash: chainHash}
	s.signal()
	return nil
}

func (s *MemStore) LastCommitted() (protocol.ChainPoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.committed == nil {
		return protocol.ChainPoint{}, false
	}
	return *s.d.committed, true
}

func (s *MemStore) DiscardAbove(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := s.d.entries[:0:0]
	for _, e := range s.d.entries {
		if e.Seq <= seq {
			keep = append(keep, e)
		}
	}
	s.d.entries = keep
	return nil
}

func (s *MemStore) Notify() <-chan struct{} { return s.notify }

func (s *MemStore) SetHalted(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.halted = code
	return nil
}

func (s *MemStore) Halted() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.halted, s.halted != ""
}

// Transmitted returns every record ID this spool ever marked transmitted, with its record hash.
func (s *MemStore) Transmitted() map[protocol.RecordID]protocol.Hash {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[protocol.RecordID]protocol.Hash, len(s.d.transmitted))
	for k, v := range s.d.transmitted {
		out[k] = v
	}
	return out
}

// Coalesce folds the oldest run of two or more never-transmitted non-checkpoint records into a range (SPEC 8.7).
func (s *MemStore) Coalesce() (int, error) {
	s.seq.Lock()
	defer s.seq.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	es := s.d.entries
	coalescable := func(e *Entry) bool { return e.State == NeverTransmitted && e.Type != protocol.TypeCheckpoint }
	for i := 0; i < len(es); i++ {
		if !coalescable(es[i]) {
			continue
		}
		j := i
		for j+1 < len(es) && coalescable(es[j+1]) {
			j++
		}
		if j == i {
			continue
		}
		if err := s.fold(i, j); err != nil {
			return 0, err
		}
		return j - i + 1, nil
	}
	return 0, nil
}

func (s *MemStore) fold(i, j int) error {
	es := s.d.entries
	recs := make([]*protocol.Record, 0, j-i+1)
	for _, e := range es[i : j+1] {
		r, err := protocol.Decode(e.Bytes)
		if err != nil {
			return err
		}
		recs = append(recs, r)
	}
	g, err := protocol.Fold(recs)
	if err != nil {
		return err
	}
	first, last := recs[0], recs[len(recs)-1]
	rr, err := protocol.NewRangeRecord(last.Envelope, g, first.Parent, first.Base)
	if err != nil {
		return err
	}
	prev := protocol.Genesis(s.d.chain.TargetID, s.d.epoch.ID, s.d.writer)
	switch {
	case i > 0:
		prev = es[i-1].ChainHash
	case s.d.committed != nil:
		prev = s.d.committed.ChainHash
	}
	folded := &Entry{Seq: rr.Seq, Type: protocol.TypeRange, State: NeverTransmitted, Bytes: rr.Bytes(), Hash: rr.Hash()}
	out := append(append(append([]*Entry(nil), es[:i]...), folded), es[j+1:]...)
	for k := i; k < len(out); k++ {
		c := copyEntry(out[k])
		c.ChainHash = protocol.ChainHash(prev, c.Hash)
		prev = c.ChainHash
		out[k] = c
	}
	s.d.entries = out
	s.d.chain.HeadHash = prev
	return nil
}
