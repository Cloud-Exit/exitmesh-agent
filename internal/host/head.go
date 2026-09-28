package host

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

var errNoCheckpoint = errors.New("host: the current epoch has no checkpoint yet")

// head is the normalized host state as of the spool chain head; it changes only inside spool.Do.
type head struct {
	mu        sync.Mutex
	state     *protocol.State
	lastMs    uint64
	collected [2]time.Time

	snapMu    sync.Mutex
	snapEpoch protocol.EpochID
	snapSeq   uint64
	snapOK    bool
}

func (hd *head) snapshot() *protocol.State {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	if hd.state == nil {
		return protocol.NewState()
	}
	return hd.state.Clone()
}

func (hd *head) interval() protocol.Interval {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	return protocol.Interval{Start: uint64(hd.collected[0].UnixMilli()), End: uint64(hd.collected[1].UnixMilli())}
}

// advance applies ops and returns an undo for a transaction that later fails to commit.
func (hd *head) advance(env protocol.Envelope, ops []protocol.Op) (func(), error) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	prevMs := hd.lastMs
	var prev *protocol.State
	if len(ops) > 0 {
		prev = hd.state.Clone()
		if err := hd.state.ApplyOps(ops); err != nil {
			hd.state = prev
			return nil, err
		}
	}
	hd.lastMs = env.Time
	return func() {
		hd.mu.Lock()
		defer hd.mu.Unlock()
		if prev != nil {
			hd.state = prev
		}
		hd.lastMs = prevMs
	}, nil
}

type hostTx struct {
	tx   *spool.Tx
	last *protocol.Envelope
	ops  []protocol.Op
}

func (t *hostTx) append(typ protocol.RecordType, body func(env protocol.Envelope) *protocol.Record) (*spool.Entry, error) {
	e, err := t.tx.Append(typ, func(env protocol.Envelope) (*protocol.Record, error) {
		if env.Seq <= 1 {
			return nil, errNoCheckpoint
		}
		r := body(env)
		t.last = &env
		return r, nil
	})
	if err != nil {
		t.last = nil
	}
	return e, err
}

func (t *hostTx) delta(d protocol.Delta) error {
	_, err := t.append(protocol.TypeDelta, func(env protocol.Envelope) *protocol.Record {
		dd := d
		return &protocol.Record{Envelope: env, Delta: &dd}
	})
	if err == nil {
		t.ops = append(t.ops, d.Ops...)
	}
	return err
}

func (t *hostTx) finding(f protocol.Finding) (uint64, error) {
	e, err := t.append(protocol.TypeFinding, func(env protocol.Envelope) *protocol.Record {
		ff := f
		return &protocol.Record{Envelope: env, Finding: &ff}
	})
	if err != nil {
		return 0, err
	}
	return e.Seq, nil
}

// do runs fn under the spool sequence lock and advances the head state with what it appended.
func (h *Host) do(fn func(*hostTx) error) error {
	var undo func()
	err := h.sp.Do(func(tx *spool.Tx) error {
		ht := &hostTx{tx: tx}
		if err := fn(ht); err != nil {
			return err
		}
		if ht.last == nil {
			return nil
		}
		var err error
		undo, err = h.head.advance(*ht.last, ht.ops)
		return err
	})
	if err != nil && undo != nil {
		undo()
	}
	return err
}

// recover loads the recovery snapshot and replays spooled records above it to the chain head.
func (h *Host) recover() error {
	hd := &h.head
	hd.state = protocol.NewState()
	ep, ok := h.sp.Epoch()
	if !ok {
		return nil
	}
	st, from := (*protocol.State)(nil), uint64(1)
	b, ok, err := h.sp.LoadRecoverySnapshot()
	if err != nil {
		return fmt.Errorf("host: recovery snapshot: %w", err)
	}
	if ok {
		r, err := protocol.Decode(b)
		if err != nil || r.Checkpoint == nil {
			return fmt.Errorf("host: recovery snapshot: undecodable: %w", err)
		}
		if r.Epoch == ep.ID {
			st, from, hd.lastMs = protocol.StateFromCheckpoint(r.Checkpoint), r.Seq+1, r.Time
			hd.snapEpoch, hd.snapSeq, hd.snapOK = r.Epoch, r.Seq, true
		}
	}
	for {
		es := h.sp.Entries(from)
		if len(es) == 0 {
			break
		}
		for _, e := range es {
			r, err := protocol.Decode(e.Bytes)
			if err != nil {
				return fmt.Errorf("host: recover spooled record %d: %w", e.Seq, err)
			}
			switch {
			case r.Type == protocol.TypeCheckpoint:
				st = protocol.StateFromCheckpoint(r.Checkpoint)
			case st == nil:
				return fmt.Errorf("host: recovery snapshot missing below spooled record %d of epoch %s", e.Seq, ep.ID)
			default:
				if err := st.ApplyRecord(r); err != nil {
					return fmt.Errorf("host: replay spooled record %d: %w", e.Seq, err)
				}
			}
			hd.lastMs = r.Time
			from = e.Seq + 1
		}
	}
	if st == nil {
		if ep.Chain.Head > 0 {
			return fmt.Errorf("host: recovery snapshot missing for epoch %s at head %d", ep.ID, ep.Chain.Head)
		}
		st = protocol.NewState()
	}
	hd.state = st
	return nil
}

// ensureSnapshot keeps the recovery snapshot at or above a sequence before the spool drops it.
func (h *Host) ensureSnapshot(epoch protocol.EpochID, seq uint64) error {
	hd := &h.head
	hd.snapMu.Lock()
	defer hd.snapMu.Unlock()
	if hd.snapOK && hd.snapEpoch == epoch && hd.snapSeq >= seq {
		return nil
	}
	var b []byte
	var at uint64
	err := h.sp.Do(func(*spool.Tx) error {
		ep, ok := h.sp.Epoch()
		if !ok {
			return client.ErrNoEpoch
		}
		if ep.ID != epoch || ep.Chain.Head < seq {
			return fmt.Errorf("host: commit %s/%d is not covered by the chain head %s/%d", epoch, seq, ep.ID, ep.Chain.Head)
		}
		hd.mu.Lock()
		defer hd.mu.Unlock()
		at = ep.Chain.Head
		r := &protocol.Record{
			Envelope: protocol.Envelope{
				Type: protocol.TypeCheckpoint, TargetID: h.sp.Identity().TargetID, Epoch: ep.ID, Seq: at,
				Writer: h.sp.WriterID(), Incarnation: h.sp.Incarnation(), Parent: at - 1, Base: at,
				Time: hd.lastMs, Schema: protocol.SchemaVersion,
			},
			Checkpoint: hd.state.Checkpoint(snapshotReason(at), protocol.Interval{Start: hd.lastMs, End: hd.lastMs}, nil),
		}
		var err error
		b, err = protocol.Encode(r)
		return err
	})
	if err != nil {
		return err
	}
	if err := h.sp.SaveRecoverySnapshot(b); err != nil {
		return err
	}
	hd.snapEpoch, hd.snapSeq, hd.snapOK = epoch, at, true
	return nil
}

func snapshotReason(seq uint64) protocol.CheckpointReason {
	if seq == 1 {
		return protocol.ReasonInitial
	}
	return protocol.ReasonAnchor
}

// commitStore applies commits after refreshing the recovery snapshot (architecture: recovery snapshot invariant).
type commitStore struct {
	client.Store
	h *Host
}

func (c commitStore) Commit(epoch protocol.EpochID, seq uint64, chainHash protocol.Hash) error {
	if err := c.h.ensureSnapshot(epoch, seq); err != nil {
		return err
	}
	if err := c.Store.Commit(epoch, seq, chainHash); err != nil {
		return err
	}
	if c.h.tracker != nil {
		if err := c.h.tracker.Commit(seq); err != nil {
			c.h.log.Warn("findings commit", "seq", seq, "err", err)
		}
	}
	return nil
}

func (h *Host) resetTracker() {
	h.ht = hostfacts.NewHostTracker(h.facts, h.head.snapshot(), h.clk.Now)
}

// collectState collects host facts and appends the resulting ops as a delta.
func (h *Host) collectState(ctx context.Context, first bool) error {
	start := h.clk.Now()
	res, err := h.ht.Collect(ctx)
	if err != nil {
		h.resetTracker()
		return err
	}
	end := h.clk.Now()
	h.head.mu.Lock()
	h.head.collected = [2]time.Time{start, end}
	h.head.mu.Unlock()
	h.mu.Lock()
	h.st.scopes = res.Scopes
	h.st.lastCollect = end
	h.mu.Unlock()
	if ep, ok := h.sp.Epoch(); !ok || ep.Chain.Head == 0 {
		h.head.mu.Lock()
		h.head.state = res.State
		h.head.mu.Unlock()
		return nil
	}
	if len(res.Ops) == 0 {
		return nil
	}
	d := protocol.Delta{Ops: res.Ops}
	if first {
		h.head.mu.Lock()
		since := h.head.lastMs
		h.head.mu.Unlock()
		d.Flags = protocol.FlagSynthetic
		d.Uncertain = &protocol.Interval{Start: since, End: uint64(end.UnixMilli())}
	}
	if err := h.do(func(tx *hostTx) error { return tx.delta(d) }); err != nil {
		h.resetTracker()
		return fmt.Errorf("host: append delta: %w", err)
	}
	return nil
}
