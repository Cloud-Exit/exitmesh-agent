package state

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// ScopeKey returns the scope key "<kind>|<namespace>"; the namespace is empty for cluster-wide collection.
func ScopeKey(kind, namespace string) string { return kind + "|" + namespace }

// Scope removal reason recorded on the scope status.
const ReasonScopeRemoved = "scope removed"

// TrackerOptions configures a Tracker.
type TrackerOptions struct {
	Normalizer *Normalizer
	Clock      func() time.Time
	// EventWindow is the sliding window for Warning event counts, default 1h.
	EventWindow time.Duration
	// EventInterval bounds how often event counts of one object are updated, default 5m.
	EventInterval time.Duration
}

// Tracker holds the normalized state of a cluster and turns observations into canonical ops.
type Tracker struct {
	mu    sync.Mutex
	norm  *Normalizer
	clock func() time.Time
	state *protocol.State
	g     *graph
	adj   map[string]map[protocol.EdgeKey]bool
	ev    *eventAgg
}

// NewTracker returns an empty Tracker.
func NewTracker(o TrackerOptions) *Tracker {
	if o.Normalizer == nil {
		o.Normalizer = defaultNormalizer
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.EventWindow <= 0 {
		o.EventWindow = time.Hour
	}
	if o.EventInterval <= 0 {
		o.EventInterval = 5 * time.Minute
	}
	return &Tracker{
		norm: o.Normalizer, clock: o.Clock, state: protocol.NewState(), g: newGraph(),
		adj: map[string]map[protocol.EdgeKey]bool{}, ev: newEventAgg(o.EventWindow, o.EventInterval),
	}
}

// Normalizer returns the tracker's normalizer.
func (t *Tracker) Normalizer() *Normalizer { return t.norm }

type edgeBefore struct {
	attrs   map[string]any
	present bool
}

// txn records the value of every touched key before its first change so ops are the net diff.
type txn struct {
	t       *Tracker
	res     map[string]*protocol.Resource
	reasons map[string]protocol.DeleteReason
	edges   map[protocol.EdgeKey]edgeBefore
	scopes  map[string]*protocol.ScopeStatus
}

func (t *Tracker) begin() *txn {
	return &txn{t: t, res: map[string]*protocol.Resource{}, reasons: map[string]protocol.DeleteReason{},
		edges: map[protocol.EdgeKey]edgeBefore{}, scopes: map[string]*protocol.ScopeStatus{}}
}

func (tx *txn) touchResource(uid string) {
	if _, ok := tx.res[uid]; !ok {
		tx.res[uid] = tx.t.state.Resources[uid]
	}
}

func (tx *txn) setResource(r *protocol.Resource) {
	tx.touchResource(r.UID)
	tx.t.state.Resources[r.UID] = r
}

func (tx *txn) deleteResource(uid string, reason protocol.DeleteReason) {
	tx.touchResource(uid)
	delete(tx.t.state.Resources, uid)
	tx.reasons[uid] = reason
}

func (tx *txn) setEdge(k protocol.EdgeKey, a map[string]any, present bool) {
	t := tx.t
	if _, ok := tx.edges[k]; !ok {
		cur, ok := t.state.Edges[k]
		tx.edges[k] = edgeBefore{cur, ok}
	}
	if present {
		t.state.Edges[k] = a
		for _, uid := range []string{k.From, k.To} {
			if t.adj[uid] == nil {
				t.adj[uid] = map[protocol.EdgeKey]bool{}
			}
			t.adj[uid][k] = true
		}
		return
	}
	delete(t.state.Edges, k)
	for _, uid := range []string{k.From, k.To} {
		if s := t.adj[uid]; s != nil {
			delete(s, k)
			if len(s) == 0 {
				delete(t.adj, uid)
			}
		}
	}
}

func (tx *txn) setScope(key string, st protocol.ScopeStatus) {
	cur, ok := tx.t.state.Scopes[key]
	if ok && cur.State == st.State && cur.Reason == st.Reason {
		return
	}
	if _, seen := tx.scopes[key]; !seen {
		if ok {
			c := cur
			tx.scopes[key] = &c
		} else {
			tx.scopes[key] = nil
		}
	}
	tx.t.state.Scopes[key] = st
}

func (tx *txn) commit() []protocol.Op {
	var ops []protocol.Op
	st := tx.t.state
	for uid, before := range tx.res {
		after := st.Resources[uid]
		switch {
		case before == nil && after != nil:
			ops = append(ops, protocol.Create(uid, after.Kind, after.Namespace, after.Name, protocol.CloneFields(after.Fields)))
		case before != nil && after == nil:
			ops = append(ops, protocol.Delete(uid, tx.reasons[uid]))
		case before != nil && after != nil:
			if ch := protocol.FieldChanges(before.Fields, after.Fields); len(ch) > 0 {
				ops = append(ops, protocol.Update(uid, ch))
			}
		}
	}
	for k, b := range tx.edges {
		after, ok := st.Edges[k]
		switch {
		case !b.present && ok:
			ops = append(ops, protocol.EdgeAdd(k.From, k.Type, k.To, protocol.CloneFields(after)))
		case b.present && !ok:
			ops = append(ops, protocol.EdgeRemove(k.From, k.Type, k.To, protocol.CloneFields(b.attrs)))
		case b.present && ok && !protocol.ValueEqual(b.attrs, after):
			ops = append(ops, protocol.EdgeReplace(k.From, k.Type, k.To, protocol.CloneFields(after), protocol.CloneFields(b.attrs)))
		}
	}
	for key, before := range tx.scopes {
		after := st.Scopes[key]
		if before == nil || before.State != after.State || before.Reason != after.Reason {
			ops = append(ops, protocol.ScopeSet(key, after))
		}
	}
	protocol.SortOps(ops)
	return ops
}

func (t *Tracker) syncEdges(tx *txn, uid string) {
	want := t.g.incident(uid)
	for k := range t.adj[uid] {
		if _, ok := want[k]; !ok {
			tx.setEdge(k, nil, false)
		}
	}
	for k, a := range want {
		if cur, ok := t.state.Edges[k]; !ok || !protocol.ValueEqual(cur, a) {
			tx.setEdge(k, a, true)
		}
	}
}

func isEventKind(kind string) bool { return kind == KindEvent || kind == "events.k8s.io/Event" }

func (t *Tracker) upsertLocked(tx *txn, obj *unstructured.Unstructured, now time.Time) error {
	if isEventKind(KindOf(obj)) {
		t.observeEvent(tx, obj, now)
		return nil
	}
	e, err := t.norm.normalize(obj)
	if err != nil {
		return err
	}
	uid := e.res.UID
	if old, ok := t.g.byName[keyOf(&e.res)]; ok && old != uid {
		t.removeLocked(tx, old, protocol.DeleteDeleted)
	}
	if _, existed := t.state.Resources[uid]; !existed {
		t.ev.publishCounts(uid, now)
	}
	res := e.res
	res.Fields = mergeEventFields(e.res.Fields, t.ev.fields(uid))
	tx.setResource(&res)
	t.g.put(e)
	t.syncEdges(tx, uid)
	return nil
}

func (t *Tracker) removeLocked(tx *txn, uid string, reason protocol.DeleteReason) {
	if _, ok := t.state.Resources[uid]; !ok {
		return
	}
	tx.deleteResource(uid, reason)
	for k := range t.adj[uid] {
		tx.setEdge(k, nil, false)
	}
	t.g.drop(uid)
	t.ev.forget(uid)
}

// Upsert observes obj and returns ops for the resource and every changed edge, none when unchanged.
func (t *Tracker) Upsert(obj *unstructured.Unstructured) ([]protocol.Op, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tx := t.begin()
	if err := t.upsertLocked(tx, obj, t.clock()); err != nil {
		return nil, err
	}
	return tx.commit(), nil
}

// Remove observes the deletion of obj.
func (t *Tracker) Remove(obj *unstructured.Unstructured) ([]protocol.Op, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tx := t.begin()
	kind := KindOf(obj)
	if isEventKind(kind) {
		t.ev.forgetEvent(string(obj.GetUID()))
		return nil, nil
	}
	spec := catalogByKind[kind]
	if spec == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKind, kind)
	}
	uid := string(obj.GetUID())
	if uid == "" {
		ns := ""
		if spec.Namespaced {
			ns = obj.GetNamespace()
		}
		uid = t.g.byName[objKey{kind, ns, obj.GetName()}]
	}
	t.removeLocked(tx, uid, protocol.DeleteDeleted)
	return tx.commit(), nil
}

func inScope(r *protocol.Resource, kind, namespace string) bool {
	return r.Kind == kind && (namespace == "" || r.Namespace == namespace)
}

// Reconcile diffs one scope against a fresh list and returns the ops and every UID they touch.
func (t *Tracker) Reconcile(kind, namespace string, objects []*unstructured.Unstructured) ([]protocol.Op, map[string]bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	tx := t.begin()
	var errs []error
	if isEventKind(kind) {
		keep := map[string]bool{}
		for _, o := range objects {
			keep[string(o.GetUID())] = true
			t.observeEvent(tx, o, now)
		}
		t.ev.retainEvents(namespace, keep)
	} else {
		seen := map[string]bool{}
		for _, o := range objects {
			if k := KindOf(o); k != kind {
				errs = append(errs, fmt.Errorf("state: reconcile %s: object of kind %s", kind, k))
				continue
			}
			seen[string(o.GetUID())] = true
			if err := t.upsertLocked(tx, o, now); err != nil {
				errs = append(errs, err)
			}
		}
		for uid, r := range t.state.Resources {
			if inScope(r, kind, namespace) && !seen[uid] {
				t.removeLocked(tx, uid, protocol.DeleteDeleted)
			}
		}
	}
	ops := tx.commit()
	changed := map[string]bool{}
	for i := range ops {
		switch ops[i].Kind {
		case protocol.OpCreate, protocol.OpUpdate, protocol.OpDelete:
			changed[ops[i].UID] = true
		case protocol.OpEdgeAdd, protocol.OpEdgeRemove, protocol.OpEdgeReplace:
			changed[ops[i].UID] = true
			changed[ops[i].To] = true
		}
	}
	return ops, changed, errors.Join(errs...)
}

func (t *Tracker) scopeOp(kind, namespace string, st protocol.ScopeState, reason string) []protocol.Op {
	t.mu.Lock()
	defer t.mu.Unlock()
	tx := t.begin()
	tx.setScope(ScopeKey(kind, namespace), protocol.ScopeStatus{State: st, Reason: reason, Since: uint64(t.clock().UnixMilli())})
	return tx.commit()
}

// ScopeLost marks a scope unavailable (permission loss or collection failure); resources are kept, never deleted.
func (t *Tracker) ScopeLost(kind, namespace, reason string) []protocol.Op {
	return t.scopeOp(kind, namespace, protocol.ScopeUnavailable, reason)
}

// ScopePartial marks a scope partial, for example while it is relisted.
func (t *Tracker) ScopePartial(kind, namespace, reason string) []protocol.Op {
	return t.scopeOp(kind, namespace, protocol.ScopePartial, reason)
}

// ScopeRestored marks a scope complete.
func (t *Tracker) ScopeRestored(kind, namespace string) []protocol.Op {
	return t.scopeOp(kind, namespace, protocol.ScopeComplete, "")
}

// RemoveScope deletes every resource of the scope with reason scope removed and marks the scope unavailable.
func (t *Tracker) RemoveScope(kind, namespace string) []protocol.Op {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	tx := t.begin()
	if isEventKind(kind) {
		t.ev.dropScope(namespace, func(uid string) { t.publishEvents(tx, uid, now) })
	}
	for uid, r := range t.state.Resources {
		if inScope(r, kind, namespace) {
			t.removeLocked(tx, uid, protocol.DeleteScopeRemoved)
		}
	}
	tx.setScope(ScopeKey(kind, namespace), protocol.ScopeStatus{State: protocol.ScopeUnavailable, Reason: ReasonScopeRemoved, Since: uint64(now.UnixMilli())})
	return tx.commit()
}

// FlushEvents publishes event counts that are due: changed or decayed counts whose last update is older than the interval.
func (t *Tracker) FlushEvents() []protocol.Op {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	tx := t.begin()
	for _, uid := range t.ev.due(now) {
		if _, ok := t.state.Resources[uid]; ok {
			t.publishEvents(tx, uid, now)
		}
	}
	t.ev.prune(now)
	return tx.commit()
}

// Snapshot returns a deep copy of the state for checkpoints.
func (t *Tracker) Snapshot() *protocol.State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state.Clone()
}

func (t *Tracker) observeEvent(tx *txn, obj *unstructured.Unstructured, now time.Time) {
	uid, ok := t.ev.observe(obj, now)
	if !ok {
		return
	}
	if _, tracked := t.state.Resources[uid]; tracked && t.ev.dueNow(uid, now) {
		t.publishEvents(tx, uid, now)
	}
}

func (t *Tracker) publishEvents(tx *txn, uid string, now time.Time) {
	t.ev.publishCounts(uid, now)
	r := t.state.Resources[uid]
	if r == nil {
		return
	}
	nr := *r
	nr.Fields = mergeEventFields(r.Fields, t.ev.fields(uid))
	if !protocol.ValueEqual(nr.Fields, r.Fields) {
		tx.setResource(&nr)
	}
}

const eventFieldPrefix = "events.warning."

func mergeEventFields(base, events map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(events))
	for k, v := range base {
		if !strings.HasPrefix(k, eventFieldPrefix) {
			out[k] = v
		}
	}
	for k, v := range events {
		out[k] = v
	}
	return out
}
