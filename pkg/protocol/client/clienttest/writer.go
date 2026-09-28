// Package clienttest provides an in-memory writer model implementing client.Hooks over a client.MemStore, for tests.
package clienttest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// Clock is a settable clock shared by a writer and its store.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock returns a clock at t.
func NewClock(t time.Time) *Clock { return &Clock{t: t} }

// Now returns the current time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Episode is one finding episode.
type Episode struct {
	ID             string
	DedupKey       string
	State          string
	FirstSeen      uint64
	LastTransition uint64
	EvalTime       uint64
	Count          uint64
	Seq            uint64
}

// Capture records one replay capture.
type Capture struct {
	Epoch      protocol.EpochID
	Watermark  uint64
	Committed  uint64
	AnchorHash protocol.Hash
	Summary    protocol.SummaryParams
}

// Writer is the writer model. Every mutation runs inside Store.Do, so captures are atomic with it.
type Writer struct {
	Store *client.MemStore
	Clock *Clock
	// AnchorMutator, when set, alters the state written into replay anchors.
	AnchorMutator func(*protocol.State)
	// OnBundle, when set, is called for every bundle.available.
	OnBundle func(protocol.BundleAvailableParams)

	mu       sync.Mutex
	state    *protocol.State
	episodes map[string]*Episode
	byID     map[string]*Episode
	touched  map[string]uint64
	hashes   map[protocol.EpochID]map[uint64]protocol.Hash
	captures []Capture
	bundles  []protocol.BundleAvailableParams
}

var _ client.Hooks = (*Writer)(nil)

// NewWriter returns an empty writer model on store.
func NewWriter(store *client.MemStore, clock *Clock) *Writer {
	return &Writer{
		Store: store, Clock: clock, state: protocol.NewState(), episodes: map[string]*Episode{},
		byID: map[string]*Episode{}, touched: map[string]uint64{}, hashes: map[protocol.EpochID]map[uint64]protocol.Hash{},
	}
}

// Clone copies the model onto store, as a restarted or forked process that rebuilt its state.
func (w *Writer) Clone(store *client.MemStore) *Writer {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := NewWriter(store, w.Clock)
	n.AnchorMutator = w.AnchorMutator
	n.state = w.state.Clone()
	for k, e := range w.episodes {
		c := *e
		n.episodes[k] = &c
	}
	for k, e := range w.byID {
		c := *e
		n.byID[k] = &c
	}
	for k, v := range w.touched {
		n.touched[k] = v
	}
	for ep, m := range w.hashes {
		n.hashes[ep] = map[uint64]protocol.Hash{}
		for s, h := range m {
			n.hashes[ep][s] = h
		}
	}
	return n
}

func (w *Writer) nowMs() uint64 { return uint64(w.Clock.Now().UnixMilli()) }

func (w *Writer) recordLocked(e *client.Entry, h protocol.Hash) {
	ep, _ := w.Store.Epoch()
	m := w.hashes[ep.ID]
	if m == nil {
		m = map[uint64]protocol.Hash{}
		w.hashes[ep.ID] = m
	}
	m[e.Seq] = h
}

// Apply appends one delta with ops and returns its sequence.
func (w *Writer) Apply(ops ...protocol.Op) (uint64, error) {
	var seq uint64
	err := w.Store.Do(func(tx client.Tx) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		next := w.state.Clone()
		if err := next.ApplyOps(ops); err != nil {
			return err
		}
		e, err := tx.Append(protocol.TypeDelta, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Delta: &protocol.Delta{Ops: ops}}, nil
		})
		if err != nil {
			return err
		}
		w.state = next
		w.recordLocked(e, next.Hash())
		seq = e.Seq
		return nil
	})
	return seq, err
}

// Fire opens a new episode for key and returns its finding ID and sequence.
func (w *Writer) Fire(key string) (string, uint64, error) {
	return w.transition(key, protocol.TransitionFiring)
}

// Update records an update transition of the open episode for key.
func (w *Writer) Update(key string) (uint64, error) {
	_, seq, err := w.transition(key, protocol.TransitionUpdate)
	return seq, err
}

// Resolve closes the open episode for key.
func (w *Writer) Resolve(key string) (uint64, error) {
	_, seq, err := w.transition(key, protocol.TransitionResolved)
	return seq, err
}

// ErrNoEpisode reports a transition for a key without an open episode.
var ErrNoEpisode = errors.New("clienttest: no open episode")

func (w *Writer) transition(key string, tr protocol.Transition) (string, uint64, error) {
	var id string
	var seq uint64
	err := w.Store.Do(func(tx client.Tx) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		now := w.nowMs()
		cur := w.episodes[key]
		next := Episode{}
		switch {
		case tr == protocol.TransitionFiring:
			if cur != nil && cur.State != protocol.LifecycleResolved {
				return fmt.Errorf("clienttest: episode for %s already open", key)
			}
			next = Episode{DedupKey: key, FirstSeen: now, Count: 1}
			next.ID = protocol.FindingID(w.Store.Identity().TargetID, key, now)
		case cur == nil || cur.State == protocol.LifecycleResolved:
			return fmt.Errorf("%w: %s", ErrNoEpisode, key)
		default:
			next = *cur
			next.Count++
		}
		next.State = lifecycle(tr)
		next.LastTransition, next.EvalTime = now, now
		e, err := tx.Append(protocol.TypeFinding, func(env protocol.Envelope) (*protocol.Record, error) {
			return &protocol.Record{Envelope: env, Finding: &protocol.Finding{
				ID: next.ID, DedupKey: key, Transition: tr, Category: "test", Severity: protocol.SeverityHigh,
				Provenance: protocol.Provenance{Kind: protocol.ProvenanceRule, RuleID: "rule-" + key, RuleVersion: 1, BundleVersion: "b1"},
				EvalTime:   now, FirstSeen: next.FirstSeen, LastSeen: now, Count: next.Count,
			}}, nil
		})
		if err != nil {
			return err
		}
		next.Seq = e.Seq
		ep := next
		w.episodes[key] = &ep
		w.byID[ep.ID] = &ep
		w.touched[ep.ID] = e.Seq
		w.recordLocked(e, w.state.Hash())
		id, seq = ep.ID, e.Seq
		return nil
	})
	return id, seq, err
}

func lifecycle(tr protocol.Transition) string {
	switch tr {
	case protocol.TransitionResolved:
		return protocol.LifecycleResolved
	case protocol.TransitionStale:
		return protocol.LifecycleStale
	}
	return protocol.LifecycleFiring
}

// CaptureReplay appends the replay anchor and returns the summary of findings touched above the committed head.
func (w *Writer) CaptureReplay(tx client.CaptureTx) (protocol.SummaryParams, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	anchor := w.state.Clone()
	if w.AnchorMutator != nil {
		w.AnchorMutator(anchor)
	}
	now := w.nowMs()
	e, err := client.AppendCheckpoint(tx, anchor, protocol.Interval{Start: now, End: now}, []string{"inventory"})
	if err != nil {
		return protocol.SummaryParams{}, err
	}
	w.recordLocked(e, anchor.Hash())
	var sum protocol.SummaryParams
	for id, seq := range w.touched {
		if seq <= tx.Committed() || seq >= e.Seq {
			continue
		}
		ep := w.byID[id]
		sum.Entries = append(sum.Entries, protocol.SummaryEntry{
			FindingID: ep.ID, DedupKey: ep.DedupKey, State: ep.State, FirstSeen: ep.FirstSeen,
			LastTransition: ep.LastTransition, EvalTime: ep.EvalTime, RuleID: "rule-" + ep.DedupKey,
			BundleVersion: "b1", Severity: protocol.SeverityHigh.String(),
		})
	}
	slices.SortFunc(sum.Entries, func(a, b protocol.SummaryEntry) int {
		if a.FindingID < b.FindingID {
			return -1
		}
		if a.FindingID > b.FindingID {
			return 1
		}
		return 0
	})
	w.captures = append(w.captures, Capture{Epoch: tx.Epoch().ID, Watermark: e.Seq, Committed: tx.Committed(), AnchorHash: anchor.Hash(), Summary: sum})
	return sum, nil
}

// Rebaseline appends the full checkpoint of a new epoch.
func (w *Writer) Rebaseline(tx client.CaptureTx) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.nowMs()
	e, err := client.AppendCheckpoint(tx, w.state, protocol.Interval{Start: now, End: now}, []string{"inventory"})
	if err != nil {
		return err
	}
	w.touched = map[string]uint64{}
	w.recordLocked(e, w.state.Hash())
	return nil
}

// BundleAvailable records the announcement.
func (w *Writer) BundleAvailable(p protocol.BundleAvailableParams) {
	w.mu.Lock()
	w.bundles = append(w.bundles, p)
	cb := w.OnBundle
	w.mu.Unlock()
	if cb != nil {
		cb(p)
	}
}

// Tools advertises state.query.
func (w *Writer) Tools() []client.Tool {
	return []client.Tool{{Name: "state.query", Description: "Resources in the current state", InputSchema: json.RawMessage(`{"type":"object"}`)}}
}

// StateQueryResult is the state.query result.
type StateQueryResult struct {
	Source    string   `json:"source"`
	Resources []string `json:"resources"`
	Truncated bool     `json:"truncated"`
}

// Tool serves state.query.
func (w *Writer) Tool(_ context.Context, name string, args json.RawMessage) (any, error) {
	if name != "state.query" {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	var p struct {
		Limit int `json:"limit"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	res := StateQueryResult{Source: "state", Resources: []string{}}
	for _, r := range w.state.SortedResources() {
		if p.Limit > 0 && len(res.Resources) == p.Limit {
			res.Truncated = true
			break
		}
		res.Resources = append(res.Resources, r.UID)
	}
	return res, nil
}

// Health reports the spool backlog.
func (w *Writer) Health() any {
	return map[string]any{"status": "ok", "backlog": len(w.Store.Entries(0))}
}

// State returns a copy of the current state.
func (w *Writer) State() *protocol.State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state.Clone()
}

// StateHashes returns the state hash at every sequence this writer assigned in epoch.
func (w *Writer) StateHashes(epoch protocol.EpochID) map[uint64]protocol.Hash {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[uint64]protocol.Hash{}
	for k, v := range w.hashes[epoch] {
		out[k] = v
	}
	return out
}

// Episodes returns every episode by finding ID.
func (w *Writer) Episodes() map[string]Episode {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]Episode{}
	for id, e := range w.byID {
		out[id] = *e
	}
	return out
}

// Captures returns every replay capture in order.
func (w *Writer) Captures() []Capture {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.captures)
}

// Bundles returns every bundle announcement received.
func (w *Writer) Bundles() []protocol.BundleAvailableParams {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.bundles)
}
