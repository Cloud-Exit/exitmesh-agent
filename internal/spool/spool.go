package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Defaults applied to zero Options fields (PRD 8.2).
const (
	DefaultCapacityBytes int64   = 10 << 30
	DefaultWindowBytes   int64   = 8 << 20
	DefaultSegmentBytes  int64   = 64 << 20
	DefaultCoalesceAt    float64 = 0.90
)

var (
	ErrClosed        = errors.New("spool: closed")
	ErrHalted        = errors.New("spool: writer halted")
	ErrNoEpoch       = errors.New("spool: no open epoch")
	ErrEpochSealed   = errors.New("spool: epoch sealed by discard; open a new epoch")
	ErrEpochMismatch = errors.New("spool: not the current epoch")
	ErrRecordsRemain = errors.New("spool: records of the current epoch remain spooled")
	ErrDivergence    = errors.New("spool: divergence")
	ErrNotSpooled    = errors.New("spool: record not spooled")
	ErrTxDone        = errors.New("spool: transaction finished")
)

// Options configures a Spool.
type Options struct {
	Dir           string  // coordinator PVC mount or /var/lib/exitmesh/spool
	CapacityBytes int64   // hard budget for record bodies
	WindowBytes   int64   // transmitted-unconfirmed window
	SegmentBytes  int64   // segment file size before rollover
	CoalesceAt    float64 // fraction of capacity that triggers relief
	Clock         func() time.Time
}

func (o Options) withDefaults() Options {
	if o.CapacityBytes <= 0 {
		o.CapacityBytes = DefaultCapacityBytes
	}
	if o.WindowBytes <= 0 {
		o.WindowBytes = DefaultWindowBytes
	}
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = DefaultSegmentBytes
	}
	if o.CoalesceAt <= 0 || o.CoalesceAt > 1 {
		o.CoalesceAt = DefaultCoalesceAt
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return o
}

// Identity is the enrolled identity stored with the spool.
type Identity struct {
	TargetID     string `json:"target_id"`
	TargetType   string `json:"target_type"`
	Credential   string `json:"credential"`
	CredentialID string `json:"credential_id"`
	MachineID    string `json:"machine_id"`
}

// EpochState is the current epoch and its chain position.
type EpochState struct {
	ID         protocol.EpochID  `json:"id"`
	TargetID   string            `json:"target_id"`
	OpenReason string            `json:"open_reason"`
	PrevEpoch  *protocol.EpochID `json:"prev_epoch,omitempty"`
	PrevHead   *uint64           `json:"prev_head,omitempty"`
	Registered bool              `json:"registered"`
	OpenedAt   time.Time         `json:"opened_at"`
	Sealed     bool              `json:"sealed"` // records above SealedAt were discarded; no further appends
	SealedAt   uint64            `json:"sealed_at"`
	Chain      protocol.Chain    `json:"chain"` // Head is the highest sequence ever assigned
}

// Halt records a rejection that forbids writing until an operator clears it.
type Halt struct {
	Code    string    `json:"code"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// Usage reports spool occupancy and the projected outage window (PRD S13).
type Usage struct {
	Bytes              int64 // record body bytes, counted against Capacity
	DiskBytes          int64 // segment file bytes including superseded frames
	Capacity           int64
	Records            int
	InFlightBytes      int64 // transmitted-unconfirmed record bytes
	WindowBytes        int64
	Oldest             time.Time // emit time of the oldest spooled record, zero when empty
	AppendRate         float64   // bytes per second, exponentially weighted
	ProjectedWindow    time.Duration
	RebaselineRequired bool
	ReliefError        error // last automatic relief failure, if any
}

// Spool is the writer's durable record store; only Tx methods may be called from inside Do.
type Spool struct {
	opts   Options
	unlock func() error
	db     *bolt.DB
	segs   *segments

	writer      protocol.WriterID
	incarnation uint64

	seqMu sync.Mutex // sequence lock: appends, relief, epoch changes
	mu    sync.Mutex // state below

	closed    bool
	fault     error // blocks writes: metadata and bodies may disagree
	readErr   error // reported by Err: a body failed verification on read, or cleanup failed
	identity  Identity
	epoch     *EpochState
	chain     protocol.Chain
	committed *protocol.ChainPoint
	halt      *Halt
	cursors   map[string]uint64
	kvs       map[string]kv.Store

	marks     []chainMark
	sinceMark int
	count     int
	bytes     int64
	inflight  int64
	pinned    map[uint64]uint32
	pinBytes  int64

	rate          rateEWMA
	rebaseline    bool
	nextRelief    int64
	lastReliefErr error

	notify chan struct{}
}

// Open locks Dir, creates the writer ID once, durably increments the incarnation, and recovers.
func Open(opts Options) (*Spool, error) {
	if opts.Dir == "" {
		return nil, errors.New("spool: Options.Dir is required")
	}
	opts = opts.withDefaults()
	unlock, err := LockDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	s := &Spool{
		opts:    opts,
		unlock:  unlock,
		cursors: map[string]uint64{},
		kvs:     map[string]kv.Store{},
		pinned:  map[uint64]uint32{},
		notify:  make(chan struct{}, 1),
	}
	if err := s.open(); err != nil {
		s.release()
		return nil, err
	}
	return s, nil
}

func (s *Spool) open() error {
	db, err := kv.OpenBolt(filepath.Join(s.opts.Dir, "meta.db"))
	if err != nil {
		return err
	}
	s.db = db
	if err := s.initWriter(); err != nil {
		return err
	}
	if err := s.load(); err != nil {
		return err
	}
	if s.segs, err = openSegments(filepath.Join(s.opts.Dir, "segments"), s.opts.SegmentBytes); err != nil {
		return err
	}
	if err := s.recover(); err != nil {
		return err
	}
	if err := os.Remove(s.snapshotPath() + ".tmp"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	now := s.opts.Clock()
	s.rate = rateEWMA{start: now, last: now}
	return nil
}

func (s *Spool) release() {
	if s.segs != nil {
		_ = s.segs.close()
	}
	if s.db != nil {
		_ = s.db.Close()
	}
	_ = s.unlock()
}

func (s *Spool) initWriter() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketRecords, bucketCursors} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		m := tx.Bucket(bucketMeta)
		if v := m.Get(keyWriter); v != nil {
			if len(v) != len(s.writer) {
				return fmt.Errorf("%w: writer id", ErrCorrupt)
			}
			copy(s.writer[:], v)
		} else {
			id, err := protocol.NewWriterID()
			if err != nil {
				return err
			}
			if err := m.Put(keyWriter, id[:]); err != nil {
				return err
			}
			s.writer = id
		}
		var inc uint64
		if v := m.Get(keyIncarnation); v != nil {
			if len(v) != 8 {
				return fmt.Errorf("%w: incarnation", ErrCorrupt)
			}
			inc = binary.BigEndian.Uint64(v)
		}
		inc++
		s.incarnation = inc
		return m.Put(keyIncarnation, u64(inc))
	})
}

func (s *Spool) load() error {
	return s.db.View(func(tx *bolt.Tx) error {
		m := tx.Bucket(bucketMeta)
		if _, err := getJSON(m, keyIdentity, &s.identity); err != nil {
			return err
		}
		var e EpochState
		if ok, err := getJSON(m, keyEpoch, &e); err != nil {
			return err
		} else if ok {
			s.epoch = &e
		}
		var cp protocol.ChainPoint
		if ok, err := getJSON(m, keyCommitted, &cp); err != nil {
			return err
		} else if ok {
			s.committed = &cp
		}
		var h Halt
		if ok, err := getJSON(m, keyHalt, &h); err != nil {
			return err
		} else if ok {
			s.halt = &h
		}
		return tx.Bucket(bucketCursors).ForEach(func(k, v []byte) error {
			if len(v) != 8 {
				return fmt.Errorf("%w: cursor %q", ErrCorrupt, k)
			}
			s.cursors[string(k)] = binary.BigEndian.Uint64(v)
			return nil
		})
	})
}

// recover verifies referenced bodies, rebuilds the chain, and drops bytes no metadata references.
func (s *Spool) recover() error {
	base := s.baseMark()
	h := base.hash
	s.marks = []chainMark{base}
	s.sinceMark = 0
	fr := &frameReader{ss: s.segs}
	var last *recMeta
	prev := base.seq
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			if s.epoch == nil {
				return fmt.Errorf("%w: records without an epoch", ErrCorrupt)
			}
			if m.From != prev+1 {
				return fmt.Errorf("%w: record %d does not follow %d", ErrCorrupt, m.Seq, prev)
			}
			if _, err := fr.read(m.Seg, m.Off, m.Len); err != nil {
				return fmt.Errorf("record %d: %w", m.Seq, err)
			}
			st := s.segs.segs[m.Seg]
			if end := m.Off + frameLen(int(m.Len)); end > st.maxEnd {
				st.maxEnd = end
			}
			s.account(m, 1)
			h = protocol.ChainHash(h, m.Hash)
			s.addMark(m.Seq, h)
			prev = m.Seq
			mm := m
			last = &mm
		}
		return nil
	})
	if err != nil {
		return err
	}
	removed := false
	for _, id := range s.segs.ids() {
		st := s.segs.segs[id]
		if st.live > 0 {
			continue
		}
		_ = st.f.Close()
		if err := os.Remove(filepath.Join(s.segs.dir, segName(id))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		delete(s.segs.segs, id)
		removed = true
	}
	if ids := s.segs.ids(); len(ids) > 0 {
		id := ids[len(ids)-1]
		st := s.segs.segs[id]
		if st.size > st.maxEnd {
			if err := st.f.Truncate(st.maxEnd); err != nil {
				return err
			}
			if err := st.f.Sync(); err != nil {
				return err
			}
			st.size = st.maxEnd
		}
		s.segs.active = id
	}
	if removed {
		if err := syncDir(s.segs.dir); err != nil {
			return err
		}
	}
	if s.epoch == nil {
		return nil
	}
	e := s.epoch
	s.chain = protocol.Chain{TargetID: e.TargetID, Epoch: e.ID, Writer: s.writer, Head: e.Chain.Head, LastCheckpoint: e.Chain.LastCheckpoint}
	switch {
	case last != nil && last.Seq > e.Chain.Head:
		return fmt.Errorf("%w: record %d above chain head %d", ErrCorrupt, last.Seq, e.Chain.Head)
	case last != nil && last.Seq == e.Chain.Head:
		s.chain.HeadHash = h
	case last != nil && !e.Sealed:
		return fmt.Errorf("%w: spool ends at %d below chain head %d", ErrCorrupt, last.Seq, e.Chain.Head)
	case last == nil && s.committed != nil && s.committed.Seq == e.Chain.Head:
		s.chain.HeadHash = s.committed.ChainHash
	case last == nil && e.Chain.Head == 0:
		s.chain.HeadHash = h
	case last == nil && !e.Sealed:
		return fmt.Errorf("%w: records up to chain head %d missing", ErrCorrupt, e.Chain.Head)
	default:
		s.chain.HeadHash = h
	}
	e.Chain = s.chain
	return nil
}

func (s *Spool) account(m recMeta, sign int) {
	s.count += sign
	s.bytes += int64(sign) * int64(m.Len)
	if m.State == TransmittedUnconfirmed {
		s.inflight += int64(sign) * int64(m.Len)
	}
	if st := s.segs.segs[m.Seg]; st != nil {
		st.live += int64(sign) * frameLen(int(m.Len))
	}
}

// Close releases the spool and its lock. It must not be called from inside Do.
func (s *Spool) Close() error {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.segs.close(), s.db.Close(), s.unlock())
}

func (s *Spool) WriterID() protocol.WriterID { return s.writer }
func (s *Spool) Incarnation() uint64         { return s.incarnation }

// Err returns the first storage fault or read-side corruption seen since Open, if any.
func (s *Spool) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fault != nil {
		return s.fault
	}
	return s.readErr
}

func (s *Spool) Identity() Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identity
}

func (s *Spool) SetIdentity(id Identity) error {
	if id.TargetID != "" && !protocol.ValidTargetID(id.TargetID) {
		return fmt.Errorf("spool: invalid target id %q", id.TargetID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := s.putMeta(keyIdentity, id); err != nil {
		return err
	}
	s.identity = id
	return nil
}

// Epoch returns the current epoch, if one is open.
func (s *Spool) Epoch() (EpochState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch == nil {
		return EpochState{}, false
	}
	e := *s.epoch
	e.Chain = s.chain
	if e.PrevEpoch != nil {
		p := *e.PrevEpoch
		e.PrevEpoch = &p
	}
	if e.PrevHead != nil {
		h := *e.PrevHead
		e.PrevHead = &h
	}
	return e, true
}

// MarkRegistered records that the control plane registered the current epoch.
func (s *Spool) MarkRegistered() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.epoch == nil {
		return ErrNoEpoch
	}
	e := *s.epoch
	e.Chain = s.chain
	e.Registered = true
	if err := s.putMeta(keyEpoch, e); err != nil {
		return err
	}
	s.epoch = &e
	return nil
}

// SetHalted persists a rejection so the writer never resumes writing after restart until ClearHalt.
func (s *Spool) SetHalted(code, message string) error {
	if code == "" {
		return errors.New("spool: halt code required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	h := Halt{Code: code, Message: message, At: s.opts.Clock().UTC()}
	if err := s.putMeta(keyHalt, h); err != nil {
		return err
	}
	s.halt = &h
	return nil
}

func (s *Spool) Halted() (Halt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.halt == nil {
		return Halt{}, false
	}
	return *s.halt, true
}

// ClearHalt is the operator path that allows writing again.
func (s *Spool) ClearHalt() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Delete(keyHalt) }); err != nil {
		return err
	}
	s.halt = nil
	return nil
}

// Cursor returns an idempotency cursor persisted with WithCursor, or 0.
func (s *Spool) Cursor(key string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursors[key]
}

// KV returns a durable store over its own bucket in the spool metadata database.
func (s *Spool) KV(bucket string) kv.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.kvs[bucket]; ok {
		return st
	}
	if s.closed {
		return errStore{ErrClosed}
	}
	st, err := kv.NewBolt(s.db, kvBucketPrefix+bucket)
	if err != nil {
		return errStore{err}
	}
	s.kvs[bucket] = st
	return st
}

type errStore struct{ err error }

func (e errStore) Get(string) ([]byte, bool, error)                 { return nil, false, e.err }
func (e errStore) Put(string, []byte) error                         { return e.err }
func (e errStore) Delete(string) error                              { return e.err }
func (e errStore) ForEach(string, func(string, []byte) error) error { return e.err }
func (e errStore) Batch(map[string][]byte) error                    { return e.err }

func (s *Spool) snapshotPath() string { return filepath.Join(s.opts.Dir, "recovery.snap") }

// SaveRecoverySnapshot replaces the single local recovery snapshot in place.
func (s *Spool) SaveRecoverySnapshot(b []byte) error {
	if int64(len(b)) > math.MaxUint32 {
		return errors.New("spool: recovery snapshot too large")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return writeFileAtomic(s.snapshotPath(), appendFrame(nil, b))
}

// LoadRecoverySnapshot returns the local recovery snapshot, verified against its checksum.
func (s *Spool) LoadRecoverySnapshot() ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, ErrClosed
	}
	data, err := os.ReadFile(s.snapshotPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(data) < frameHeader {
		return nil, false, fmt.Errorf("%w: recovery snapshot truncated", ErrCorrupt)
	}
	p, err := checkFrame(data, int(binary.BigEndian.Uint32(data[0:4])))
	if err != nil {
		return nil, false, fmt.Errorf("recovery snapshot: %w", err)
	}
	return p, true, nil
}

// Usage reports occupancy, append rate, and the projected window (free capacity / rate).
func (s *Spool) Usage() Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := Usage{
		Bytes: s.bytes, Capacity: s.opts.CapacityBytes, Records: s.count,
		InFlightBytes: s.inflight, WindowBytes: s.opts.WindowBytes,
		RebaselineRequired: s.rebaseline, ReliefError: s.lastReliefErr,
	}
	if s.closed {
		return u
	}
	u.DiskBytes = s.segs.diskBytes()
	u.Oldest = s.oldestLocked()
	u.AppendRate = s.rate.rate(s.opts.Clock())
	free := u.Capacity - u.Bytes
	if free < 0 {
		free = 0
	}
	u.ProjectedWindow = projectWindow(free, u.AppendRate)
	return u
}

func projectWindow(free int64, rate float64) time.Duration {
	if rate <= 0 {
		return time.Duration(math.MaxInt64)
	}
	ns := float64(free) / rate * float64(time.Second)
	if ns >= math.MaxInt64 {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(ns)
}

func (s *Spool) oldestLocked() time.Time {
	if s.count == 0 {
		return time.Time{}
	}
	var t time.Time
	_ = s.db.View(func(tx *bolt.Tx) error {
		k, v := tx.Bucket(bucketRecords).Cursor().First()
		if k == nil {
			return nil
		}
		m, err := decodeMeta(k, v)
		if err != nil {
			return err
		}
		t = time.UnixMilli(int64(m.Time))
		return nil
	})
	return t
}

// Notify is signalled, without blocking, after appends, commits, and discards.
func (s *Spool) Notify() <-chan struct{} { return s.notify }

func (s *Spool) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *Spool) writableLocked() error {
	if s.closed {
		return ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	if s.halt != nil {
		return fmt.Errorf("%w: %s", ErrHalted, s.halt.Code)
	}
	return nil
}

func (s *Spool) putMeta(key []byte, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put(key, b) })
}

func getJSON(b *bolt.Bucket, key []byte, v any) (bool, error) {
	raw := b.Get(key)
	if raw == nil {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("%w: %s: %v", ErrCorrupt, key, err)
	}
	return true, nil
}

func putJSON(b *bolt.Bucket, key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, raw)
}

const rateTau = time.Hour

// rateEWMA normalizes a decaying byte counter by elapsed time so early estimates are unbiased.
type rateEWMA struct {
	acc   float64
	last  time.Time
	start time.Time
}

func (r *rateEWMA) add(now time.Time, n int64) {
	if dt := now.Sub(r.last).Seconds(); dt > 0 {
		r.acc *= math.Exp(-dt / rateTau.Seconds())
		r.last = now
	}
	r.acc += float64(n)
}

func (r *rateEWMA) rate(now time.Time) float64 {
	tau := rateTau.Seconds()
	el := now.Sub(r.start).Seconds()
	if el <= 0 {
		return 0
	}
	acc := r.acc
	if dt := now.Sub(r.last).Seconds(); dt > 0 {
		acc *= math.Exp(-dt / tau)
	}
	return acc / (tau * (1 - math.Exp(-el/tau)))
}
