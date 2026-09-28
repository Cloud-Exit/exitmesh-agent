package hostfacts

import (
	"context"
	"fmt"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Source produces snapshots; *Collector implements it.
type Source interface {
	Collect(ctx context.Context) *Snapshot
}

// HostTracker turns successive snapshots into canonical ops against the last emitted state.
type HostTracker struct {
	src  Source
	now  func() time.Time
	prev *protocol.State
}

// Result is one tracked collection.
type Result struct {
	State  *protocol.State
	Ops    []protocol.Op
	Scopes map[string]protocol.ScopeStatus
}

// NewHostTracker diffs against base (an empty state when nil), for example the state recovered from the spool.
func NewHostTracker(src Source, base *protocol.State, now func() time.Time) *HostTracker {
	if base == nil {
		base = protocol.NewState()
	}
	if now == nil {
		now = time.Now
	}
	return &HostTracker{src: src, now: now, prev: base.Clone()}
}

// State returns a copy of the last emitted state.
func (t *HostTracker) State() *protocol.State { return t.prev.Clone() }

// Collect gathers a snapshot, carries forward what failed to collect, and returns the ops from the previous state.
func (t *HostTracker) Collect(ctx context.Context) (Result, error) {
	snap := t.src.Collect(ctx)
	next, err := t.build(snap)
	if err != nil {
		return Result{}, err
	}
	ops := t.prev.Diff(next, protocol.DeleteDeleted)
	t.prev = next
	scopes := make(map[string]protocol.ScopeStatus, len(next.Scopes))
	for k, v := range next.Scopes {
		scopes[k] = v
	}
	return Result{State: next.Clone(), Ops: ops, Scopes: scopes}, nil
}

func (t *HostTracker) build(snap *Snapshot) (*protocol.State, error) {
	next := protocol.NewState()
	for uid, r := range snap.Resources {
		f, err := protocol.NormalizeFields(r.Fields, false)
		if err != nil {
			return nil, fmt.Errorf("hostfacts: resource %s: %w", uid, err)
		}
		rc := r
		rc.Fields = f
		next.Resources[uid] = &rc
	}
	for k, a := range snap.Edges {
		if _, ok := next.Resources[k.From]; !ok {
			continue
		}
		if _, ok := next.Resources[k.To]; !ok {
			continue
		}
		next.Edges[k] = protocol.CloneFields(a)
	}
	failed := map[string]bool{}
	for _, e := range Catalog {
		st, ok := snap.Status[e.ID]
		if !ok {
			st = Status{State: protocol.ScopeUnavailable, Reason: ReasonReadFailed}
		}
		if st.State == protocol.ScopeUnavailable && (e.EdgeType == "" || st.Reason == ReasonDependency) {
			failed[e.ID] = true
		}
		since := uint64(t.now().UnixMilli())
		if p, ok := t.prev.Scopes[ScopeKey(e.ID)]; ok && p.State == st.State && p.Reason == st.Reason {
			since = p.Since
		}
		next.Scopes[ScopeKey(e.ID)] = protocol.ScopeStatus{State: st.State, Reason: st.Reason, Since: since}
	}
	t.carryForward(next, failed)
	return next, nil
}

// carryForward keeps the last known resources and edges of unavailable facts, so a collection failure is a scope status, never a deletion.
func (t *HostTracker) carryForward(next *protocol.State, failed map[string]bool) {
	for _, e := range Catalog {
		if e.EdgeType != "" || !failed[e.ID] {
			continue
		}
		for uid, r := range t.prev.Resources {
			if r.Kind != e.Kind {
				continue
			}
			cur, ok := next.Resources[uid]
			switch {
			case !ok:
				rc := *r
				rc.Fields = protocol.CloneFields(r.Fields)
				next.Resources[uid] = &rc
			case ok && !e.Whole:
				for _, f := range e.Fields {
					if v, had := r.Fields[f]; had {
						if _, has := cur.Fields[f]; !has {
							cur.Fields[f] = protocol.CloneValue(v)
						}
					}
				}
			}
		}
	}
	for _, e := range Catalog {
		if e.EdgeType == "" || !failed[e.ID] {
			continue
		}
		for k, a := range t.prev.Edges {
			if k.Type != e.EdgeType || t.prev.Resources[k.From] == nil || t.prev.Resources[k.From].Kind != e.Kind {
				continue
			}
			if _, ok := next.Edges[k]; ok {
				continue
			}
			if _, ok := next.Resources[k.From]; !ok {
				continue
			}
			if _, ok := next.Resources[k.To]; !ok {
				r := t.prev.Resources[k.To]
				if r == nil {
					continue
				}
				rc := *r
				rc.Fields = protocol.CloneFields(r.Fields)
				next.Resources[k.To] = &rc
			}
			next.Edges[k] = protocol.CloneFields(a)
		}
	}
}
