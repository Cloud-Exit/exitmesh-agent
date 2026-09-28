package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// txn is one coordinator transaction under the spool sequence lock; head changes apply only when every append succeeded.
type txn struct {
	c       *Coordinator
	tx      *spool.Tx
	pending [][]protocol.Op
	stats   []func(*chainStats)
	after   []func()
	view    map[string]map[string]any
}

type captureTx struct {
	tx        client.Tx
	reason    protocol.CheckpointReason
	epoch     client.EpochState
	committed uint64
}

func (t captureTx) Append(typ protocol.RecordType, build func(env protocol.Envelope) (*protocol.Record, error)) (*client.Entry, error) {
	return t.tx.Append(typ, build)
}
func (t captureTx) Reason() protocol.CheckpointReason { return t.reason }
func (t captureTx) Epoch() client.EpochState          { return t.epoch }
func (t captureTx) Committed() uint64                 { return t.committed }

func reasonFor(open string) protocol.CheckpointReason {
	switch open {
	case protocol.OpenRebaseline:
		return protocol.ReasonRebaseline
	case protocol.OpenWriterChange:
		return protocol.ReasonWriterChange
	}
	return protocol.ReasonInitial
}

func (c *Coordinator) clientEpoch() (client.EpochState, bool) { return c.store.Epoch() }

// do runs fn under the spool lock; a new epoch without records first receives its opening checkpoint.
func (c *Coordinator) do(fn func(t *txn) error) error {
	return c.sp.Do(func(tx *spool.Tx) error {
		if c.headState() == nil {
			return errNotReady
		}
		t := &txn{c: c, tx: tx}
		ep, ok := c.clientEpoch()
		if !ok {
			return errNotReady
		}
		if ep.Chain.Head == 0 {
			if _, err := t.checkpoint(captureTx{tx: spool.ClientTx{T: tx}, reason: reasonFor(ep.OpenReason), epoch: ep}); err != nil {
				return err
			}
		}
		if err := fn(t); err != nil {
			return err
		}
		return t.apply()
	})
}

func (t *txn) apply() error {
	c := t.c
	if len(t.pending) > 0 {
		c.headMu.Lock()
		for _, ops := range t.pending {
			if err := c.head.ApplyOps(ops); err != nil {
				c.headMu.Unlock()
				c.fail(fmt.Errorf("coordinator: spooled delta does not apply to the chain head: %w", err))
				return err
			}
		}
		c.headVer++
		c.headMu.Unlock()
		c.kube.dirty()
	}
	for _, f := range t.after {
		f()
	}
	if len(t.stats) > 0 {
		c.statMu.Lock()
		for _, f := range t.stats {
			f(&c.stats)
		}
		c.statMu.Unlock()
	}
	return nil
}

// checkpoint appends a full checkpoint of the chain head through a capture transaction.
func (t *txn) checkpoint(ct client.CaptureTx) (*client.Entry, error) {
	c := t.c
	e, err := client.AppendCheckpoint(ct, c.headState(), c.interval(), c.caps)
	if err != nil {
		return nil, err
	}
	now := c.now()
	t.stats = append(t.stats, func(s *chainStats) {
		s.LastCheckpoint = seqTime{Seq: e.Seq, Time: now}
		s.DeltasSinceAnchor, s.LastAnchor = 0, now
	})
	return e, nil
}

func (c *Coordinator) interval() protocol.Interval {
	return protocol.Interval{Start: uint64(c.startedAt.UnixMilli()), End: uint64(c.now().UnixMilli())}
}

// delta appends a delta whose ops are applied to the head once the transaction succeeds.
func (t *txn) delta(ops []protocol.Op, flags uint64, unc *protocol.Interval, opts ...spool.AppendOption) error {
	if len(ops) == 0 {
		return nil
	}
	if err := applicable(t.c.headState(), ops); err != nil {
		return err
	}
	e, err := t.tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
		return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: ops, Flags: flags, Uncertain: unc}}, nil
	}, opts...)
	if err != nil {
		return err
	}
	t.pending = append(t.pending, ops)
	now := t.c.now()
	t.stats = append(t.stats, func(s *chainStats) {
		s.LastDelta = seqTime{Seq: e.Seq, Time: now}
		s.DeltasSinceAnchor++
	})
	return nil
}

// emit appends a finding record; it is the findings.Emit of this transaction.
func (t *txn) emit(f protocol.Finding, opts ...spool.AppendOption) (uint64, error) {
	e, err := t.tx.Append(protocol.TypeFinding, func(env protocol.Envelope) (*protocol.Record, error) {
		return &protocol.Record{Envelope: env, Finding: &f}, nil
	}, opts...)
	if err != nil {
		return 0, err
	}
	now := t.c.now()
	t.stats = append(t.stats, func(s *chainStats) { s.LastFinding = seqTime{Seq: e.Seq, Time: now} })
	return e.Seq, nil
}

var errInapplicable = errors.New("coordinator: ops do not apply to the chain head")

// applicable checks ops against a copy of only the keys they touch, which is what ApplyOps validates.
func applicable(st *protocol.State, ops []protocol.Op) error {
	mini := protocol.NewState()
	for i := range ops {
		op := &ops[i]
		switch op.Kind {
		case protocol.OpScopeSet:
			if v, ok := st.Scopes[op.ScopeKey]; ok {
				mini.Scopes[op.ScopeKey] = v
			}
		case protocol.OpEdgeAdd, protocol.OpEdgeRemove, protocol.OpEdgeReplace:
			if a, ok := st.Edges[op.EdgeKey()]; ok {
				mini.Edges[op.EdgeKey()] = a
			}
		default:
			if _, ok := st.Resources[op.UID]; ok {
				mini.Resources[op.UID] = &protocol.Resource{UID: op.UID, Fields: map[string]any{}}
			}
		}
	}
	if err := mini.ApplyOps(ops); err != nil {
		return fmt.Errorf("%w: %w", errInapplicable, err)
	}
	return nil
}

func (t *txn) emitFinding(f protocol.Finding) (uint64, error) { return t.emit(f) }

func (c *Coordinator) headState() *protocol.State {
	c.headMu.Lock()
	defer c.headMu.Unlock()
	return c.head
}

// stateView returns an immutable copy of the chain head, shared until the head changes.
func (c *Coordinator) stateView() *protocol.State {
	c.headMu.Lock()
	defer c.headMu.Unlock()
	if c.head == nil {
		return nil
	}
	if c.cache == nil || c.cacheVer != c.headVer {
		c.cache, c.cacheVer = c.head.Clone(), c.headVer
	}
	return c.cache
}

// sink receives collector ops in order; failed appends switch to resync, which later emits the net difference.
func (c *Coordinator) sink(ops []protocol.Op, synthetic bool, unc *protocol.Interval) {
	c.sinkMu.Lock()
	defer c.sinkMu.Unlock()
	if c.observed != nil {
		if err := c.observed.ApplyOps(ops); err != nil {
			c.observed = carryOver(c.observed, c.tracker.Snapshot())
		}
		c.resyncLocked()
		return
	}
	var flags uint64
	if synthetic {
		flags |= protocol.FlagSynthetic
	}
	err := c.do(func(t *txn) error { return t.delta(ops, flags, unc) })
	if err == nil {
		c.setErr("append", nil)
		c.poke()
		return
	}
	if errors.Is(err, errInapplicable) {
		c.log.Warn("collector ops diverge from the chain head; emitting the net difference", "err", err)
		c.observed, c.resyncSince = carryOver(c.stateView(), c.tracker.Snapshot()), c.now()
		c.resyncLocked()
		return
	}
	c.appendFailed(err)
	obs := c.stateView().Clone()
	if aerr := obs.ApplyOps(ops); aerr != nil {
		obs = carryOver(c.stateView(), c.tracker.Snapshot())
	}
	c.observed, c.resyncSince = obs, c.now()
	if unc != nil && protocol.UnixMilli(unc.Start).Before(c.resyncSince) {
		c.resyncSince = protocol.UnixMilli(unc.Start)
	}
}

func (c *Coordinator) appendFailed(err error) {
	c.log.Warn("append to spool failed", "err", err)
	c.setErr("append", err)
	if errors.Is(err, spool.ErrRebaselineRequired) {
		c.requestRebaseline()
	}
}

// resyncLocked emits the synthetic net difference between the chain head and the observed state.
func (c *Coordinator) resyncLocked() {
	if c.observed == nil {
		return
	}
	since := c.resyncSince
	err := c.do(func(t *txn) error {
		ops := c.headState().Diff(c.observed, protocol.DeleteDeleted)
		iv := &protocol.Interval{Start: uint64(since.UnixMilli()), End: uint64(c.now().UnixMilli())}
		return t.delta(ops, protocol.FlagSynthetic, iv)
	})
	if err != nil {
		c.appendFailed(err)
		return
	}
	c.log.Info("chain resynchronized with the observed state", "since", since)
	c.observed = nil
	c.setErr("append", nil)
}

func (c *Coordinator) resync() {
	c.sinkMu.Lock()
	defer c.sinkMu.Unlock()
	c.resyncLocked()
}

// onSynced aligns the recovered chain head with the relisted cluster, or opens the epoch with its first checkpoint.
func (c *Coordinator) onSynced(observed *protocol.State) {
	c.sinkMu.Lock()
	defer c.sinkMu.Unlock()
	defer close(c.synced)
	rec := c.recovered
	c.recovered = nil
	if c.rebaselineAtSync {
		c.setHead(observed)
		if err := c.localRebaseline("chain head could not be reconstructed from the spool"); err != nil {
			c.fail(fmt.Errorf("coordinator: rebaseline after failed recovery: %w", err))
		}
		return
	}
	if rec == nil {
		c.setHead(observed)
		if err := c.cl.Prepare(); err != nil {
			c.fail(fmt.Errorf("coordinator: open epoch: %w", err))
		}
		return
	}
	target := carryOver(rec, observed)
	c.setHead(rec)
	iv := &protocol.Interval{Start: uint64(c.recoveredAt.UnixMilli()), End: uint64(c.now().UnixMilli())}
	err := c.do(func(t *txn) error {
		return t.delta(rec.Diff(target, protocol.DeleteDeleted), protocol.FlagSynthetic, iv)
	})
	if err != nil {
		c.appendFailed(err)
		c.observed, c.resyncSince = target, c.recoveredAt
	}
}

func (c *Coordinator) setHead(st *protocol.State) {
	c.headMu.Lock()
	c.head = st
	c.headVer++
	c.headMu.Unlock()
	c.kube.dirty()
}

// carryOver keeps what a fresh relist cannot see: metric facts and resources of scopes that are not complete.
func carryOver(rec, observed *protocol.State) *protocol.State {
	out := observed.Clone()
	incomplete := func(kind, ns string) bool {
		for _, k := range []string{kind + "|", kind + "|" + ns} {
			if s, ok := out.Scopes[k]; ok && s.State != protocol.ScopeComplete {
				return true
			}
		}
		return false
	}
	for uid, r := range rec.Resources {
		cur, ok := out.Resources[uid]
		if !ok {
			if incomplete(r.Kind, r.Namespace) {
				cp := *r
				cp.Fields = protocol.CloneFields(r.Fields)
				out.Resources[uid] = &cp
				for k, a := range rec.Edges {
					if k.From == uid {
						out.Edges[k] = protocol.CloneFields(a)
					}
				}
			}
			continue
		}
		for k, v := range r.Fields {
			if isMetricField(k) {
				if _, has := cur.Fields[k]; !has {
					if cur.Fields == nil {
						cur.Fields = map[string]any{}
					}
					cur.Fields[k] = protocol.CloneValue(v)
				}
			}
		}
	}
	return out
}

func (c *Coordinator) requestRebaseline() {
	c.statMu.Lock()
	c.rebaseline = true
	c.statMu.Unlock()
	c.poke()
}

func (c *Coordinator) rebaselineWanted() bool {
	c.statMu.Lock()
	defer c.statMu.Unlock()
	return c.rebaseline
}

func (c *Coordinator) noteBoundary(reason string) {
	ep, _ := c.sp.Epoch()
	c.log.Warn("reconstruction boundary", "reason", reason, "epoch", ep.ID.String())
	c.statMu.Lock()
	defer c.statMu.Unlock()
	c.stats.Boundaries = append(c.stats.Boundaries, boundary{Time: c.now(), Epoch: ep.ID, Reason: reason})
	if len(c.stats.Boundaries) > 20 {
		c.stats.Boundaries = c.stats.Boundaries[len(c.stats.Boundaries)-20:]
	}
}

// localRebaseline closes the epoch at its committed head and starts a new one with a full checkpoint; only without a live session.
func (c *Coordinator) localRebaseline(reason string) error {
	ep, ok := c.sp.Epoch()
	if !ok {
		return nil
	}
	lc, _ := c.sp.LastCommitted()
	if err := c.sp.DiscardAbove(lc.Seq); err != nil {
		return err
	}
	prev, h := ep.ID, lc.Seq
	if _, err := c.sp.OpenEpoch(protocol.OpenRebaseline, &prev, &h); err != nil {
		return err
	}
	c.statMu.Lock()
	c.rebaseline = false
	c.statMu.Unlock()
	c.noteBoundary(reason)
	return c.do(func(*txn) error { return nil })
}

// maybeAnchor appends a periodic anchor while connected and caught up, bounded by replay cost and age.
func (c *Coordinator) maybeAnchor() {
	if c.airgap || c.cl == nil || !c.cl.Status().Connected {
		return
	}
	if u := c.sp.Usage(); u.Bytes > u.InFlightBytes {
		return
	}
	c.statMu.Lock()
	n, last := c.stats.DeltasSinceAnchor, c.stats.LastAnchor
	c.statMu.Unlock()
	if n == 0 || (n < c.t.AnchorDeltas && c.now().Sub(last) < c.t.AnchorEvery) {
		return
	}
	err := c.do(func(t *txn) error {
		ep, _ := c.clientEpoch()
		_, err := t.checkpoint(captureTx{tx: spool.ClientTx{T: t.tx}, reason: protocol.ReasonAnchor, epoch: ep})
		return err
	})
	if err != nil {
		c.appendFailed(err)
	}
}

type snapshotFile struct {
	Epoch   protocol.EpochID `json:"epoch"`
	Seq     uint64           `json:"seq"`
	SavedAt int64            `json:"saved_at"`
	Record  []byte           `json:"record"`
}

// saveSnapshot persists the chain head state at its sequence, under the spool lock.
func (c *Coordinator) saveSnapshot() (protocol.EpochID, uint64, error) {
	var ep protocol.EpochID
	var seq uint64
	err := c.sp.Do(func(*spool.Tx) error {
		e, ok := c.sp.Epoch()
		hd := c.headState()
		if !ok || e.Chain.Head == 0 || hd == nil {
			return errNotReady
		}
		ck := hd.Checkpoint(protocol.ReasonAnchor, c.interval(), c.caps)
		now := c.now()
		rec := &protocol.Record{Envelope: protocol.Envelope{
			Type: protocol.TypeCheckpoint, TargetID: c.targetID, Epoch: e.ID, Seq: e.Chain.Head, Writer: c.sp.WriterID(),
			Incarnation: c.sp.Incarnation(), Parent: e.Chain.Head - 1, Base: e.Chain.Head, Time: uint64(now.UnixMilli()), Schema: protocol.SchemaVersion,
		}, Checkpoint: ck}
		b, err := protocol.Encode(rec)
		if err != nil {
			return err
		}
		out, err := json.Marshal(snapshotFile{Epoch: e.ID, Seq: e.Chain.Head, SavedAt: now.UnixMilli(), Record: b})
		if err != nil {
			return err
		}
		if err := c.sp.SaveRecoverySnapshot(out); err != nil {
			return err
		}
		ep, seq = e.ID, e.Chain.Head
		return nil
	})
	return ep, seq, err
}

// recover rebuilds the chain head from the recovery snapshot and the spooled records above it.
func (c *Coordinator) recover() error {
	ep, ok := c.sp.Epoch()
	if !ok || ep.Chain.Head == 0 {
		return nil
	}
	st, at, err := c.replay(ep, true)
	if err != nil {
		c.log.Warn("recovery from the snapshot failed; replaying the spool alone", "err", err)
		st, at, err = c.replay(ep, false)
	}
	if err != nil {
		c.log.Error("chain head cannot be reconstructed; rebaselining", "err", err)
		c.rebaselineAtSync = true
		return nil
	}
	c.recovered, c.recoveredAt = st, at
	c.log.Info("recovered chain head", "epoch", ep.ID.String(), "seq", ep.Chain.Head, "resources", len(st.Resources))
	return nil
}

func (c *Coordinator) replay(ep spool.EpochState, useSnapshot bool) (*protocol.State, time.Time, error) {
	var st *protocol.State
	var from uint64
	var last time.Time
	if useSnapshot {
		b, ok, err := c.sp.LoadRecoverySnapshot()
		if err != nil {
			return nil, last, err
		}
		if ok {
			var sf snapshotFile
			if err := json.Unmarshal(b, &sf); err != nil {
				return nil, last, fmt.Errorf("decode recovery snapshot: %w", err)
			}
			if sf.Epoch == ep.ID && sf.Seq <= ep.Chain.Head {
				r, err := protocol.Decode(sf.Record)
				if err != nil || r.Checkpoint == nil {
					return nil, last, fmt.Errorf("decode recovery snapshot record: %w", err)
				}
				st, from, last = protocol.StateFromCheckpoint(r.Checkpoint), sf.Seq, time.UnixMilli(sf.SavedAt)
			}
		}
	}
	next, reached := from+1, from
	for {
		es := c.sp.Entries(next)
		if len(es) == 0 {
			break
		}
		for _, e := range es {
			r, err := protocol.Decode(e.Bytes)
			if err != nil {
				return nil, last, fmt.Errorf("decode spooled record %d: %w", e.Seq, err)
			}
			if t := protocol.UnixMilli(r.Time); t.After(last) {
				last = t
			}
			switch r.Type {
			case protocol.TypeCheckpoint:
				st = protocol.StateFromCheckpoint(r.Checkpoint)
			case protocol.TypeDelta, protocol.TypeRange:
				if st == nil {
					return nil, last, fmt.Errorf("record %d has no base state in the spool", e.Seq)
				}
				if r.Range != nil && r.Range.From <= reached && from > 0 {
					return nil, last, fmt.Errorf("range %d-%d spans the snapshot at %d", r.Range.From, r.Range.To, from)
				}
				if err := st.ApplyRecord(r); err != nil {
					return nil, last, fmt.Errorf("apply spooled record %d: %w", e.Seq, err)
				}
			}
			reached, next = e.Seq, e.Seq+1
		}
	}
	if st == nil || reached != ep.Chain.Head {
		return nil, last, fmt.Errorf("spool ends at %d, chain head is %d", reached, ep.Chain.Head)
	}
	return st, last, nil
}

type pendingCommit struct {
	epoch protocol.EpochID
	seq   uint64
	hash  protocol.Hash
}

// commitStore refreshes the recovery snapshot before the spool drops committed records, deferring commits while throttled.
type commitStore struct {
	spool.ClientStore
	c         *Coordinator
	mu        sync.Mutex
	snapEpoch protocol.EpochID
	snapSeq   uint64
	lastSave  time.Time
	pending   *pendingCommit
}

func (w *commitStore) covered(epoch protocol.EpochID, seq uint64) bool {
	return w.snapEpoch == epoch && w.snapSeq >= seq
}

func (w *commitStore) saveLocked() error {
	ep, seq, err := w.c.saveSnapshot()
	if err != nil {
		return err
	}
	w.snapEpoch, w.snapSeq, w.lastSave = ep, seq, w.c.now()
	return nil
}

func (w *commitStore) saveNow() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.saveLocked()
}

func (w *commitStore) commitLocked(epoch protocol.EpochID, seq uint64, hash protocol.Hash) error {
	if err := w.ClientStore.Commit(epoch, seq, hash); err != nil {
		return err
	}
	if w.pending != nil && w.pending.seq <= seq {
		w.pending = nil
	}
	w.c.afterCommit(seq)
	return nil
}

// Commit is the session's path; a pending rebaseline surfaces as a divergence so the client closes the epoch at this head.
func (w *commitStore) Commit(epoch protocol.EpochID, seq uint64, hash protocol.Hash) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.commit(epoch, seq, hash, false); err != nil {
		return err
	}
	if w.c.rebaselineWanted() {
		return fmt.Errorf("%w: spool capacity exceeded after full coalescing; rebaseline at the committed head", client.ErrDivergence)
	}
	return nil
}

func (w *commitStore) commit(epoch protocol.EpochID, seq uint64, hash protocol.Hash, force bool) error {
	if lc, ok := w.ClientStore.LastCommitted(); ok && seq <= lc.Seq {
		return w.ClientStore.Commit(epoch, seq, hash)
	}
	if !w.covered(epoch, seq) && (force || w.c.now().Sub(w.lastSave) >= w.c.t.SnapshotEvery) {
		if err := w.saveLocked(); err != nil {
			return fmt.Errorf("refresh recovery snapshot before commit: %w", err)
		}
	}
	if w.covered(epoch, seq) {
		return w.commitLocked(epoch, seq, hash)
	}
	if err := w.verify(epoch, seq, hash); err != nil {
		return err
	}
	if w.pending == nil || w.pending.epoch != epoch || w.pending.seq < seq {
		w.pending = &pendingCommit{epoch: epoch, seq: seq, hash: hash}
	}
	if w.snapEpoch == epoch && w.snapSeq > 0 {
		lc, _ := w.ClientStore.LastCommitted()
		if es := w.Entries(w.snapSeq); w.snapSeq > lc.Seq && len(es) > 0 && es[0].Seq == w.snapSeq {
			return w.commitLocked(epoch, w.snapSeq, es[0].ChainHash)
		}
	}
	return nil
}

// verify checks a deferred commit against the spool so divergence is still reported at once.
func (w *commitStore) verify(epoch protocol.EpochID, seq uint64, hash protocol.Hash) error {
	ep, ok := w.Epoch()
	if !ok || ep.ID != epoch {
		return client.ErrWrongEpoch
	}
	if seq > ep.Chain.Head {
		return fmt.Errorf("%w: commit %d above the highest assigned sequence %d", client.ErrDivergence, seq, ep.Chain.Head)
	}
	es := w.Entries(seq)
	if len(es) == 0 || es[0].Seq != seq {
		return fmt.Errorf("%w: commit %d is not a spooled record boundary", client.ErrDivergence, seq)
	}
	if es[0].ChainHash != hash {
		return fmt.Errorf("%w: chain hash at %d differs", client.ErrDivergence, seq)
	}
	return nil
}

// flush applies a deferred commit once the snapshot may be refreshed.
func (w *commitStore) flush(force bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	p := w.pending
	if p == nil {
		return
	}
	if ep, ok := w.Epoch(); !ok || ep.ID != p.epoch {
		w.pending = nil
		return
	}
	if !force && w.c.now().Sub(w.lastSave) < w.c.t.SnapshotEvery {
		return
	}
	if err := w.commit(p.epoch, p.seq, p.hash, true); err != nil {
		w.c.log.Warn("deferred commit", "seq", p.seq, "err", err)
		w.c.setErr("commit", err)
		return
	}
	w.c.setErr("commit", nil)
}

func (w *commitStore) LastCommitted() (protocol.ChainPoint, bool) {
	w.mu.Lock()
	p := w.pending
	w.mu.Unlock()
	lc, ok := w.ClientStore.LastCommitted()
	if p != nil {
		if ep, eok := w.Epoch(); eok && ep.ID == p.epoch && p.seq > lc.Seq {
			return protocol.ChainPoint{Seq: p.seq, ChainHash: p.hash}, true
		}
	}
	return lc, ok
}

func (w *commitStore) OpenEpoch(reason string, prev *protocol.EpochID, prevHead *uint64) (protocol.EpochID, error) {
	w.mu.Lock()
	w.pending = nil
	w.mu.Unlock()
	id, err := w.ClientStore.OpenEpoch(reason, prev, prevHead)
	if err == nil && reason == protocol.OpenRebaseline {
		w.c.statMu.Lock()
		w.c.rebaseline = false
		w.c.statMu.Unlock()
		w.c.noteBoundary("rebaseline: new epoch opened at committed head")
	}
	return id, err
}

func (c *Coordinator) afterCommit(seq uint64) {
	if err := c.fnd.Commit(seq); err != nil {
		c.log.Warn("prune findings", "err", err)
	}
	if err := c.nfi.Commit(seq); err != nil {
		c.log.Warn("prune node findings", "err", err)
	}
}
