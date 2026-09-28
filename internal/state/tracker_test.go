package state

import (
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type harness struct {
	t       *testing.T
	tr      *Tracker
	replica *protocol.State
	now     time.Time
	seq     uint64
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, replica: protocol.NewState(), now: fixtureTime.Add(time.Hour)}
	h.tr = NewTracker(TrackerOptions{Clock: func() time.Time { return h.now }, EventWindow: time.Hour, EventInterval: 5 * time.Minute})
	return h
}

// apply encodes ops as a delta record, decodes it, applies it to the replica, and checks the replica equals the tracker.
func (h *harness) apply(ops []protocol.Op, synthetic bool) []protocol.Op {
	h.t.Helper()
	if len(ops) > 0 {
		h.seq++
		d := &protocol.Delta{Ops: ops}
		if synthetic {
			d.Flags = protocol.FlagSynthetic
			d.Uncertain = &protocol.Interval{Start: 1, End: 2}
		}
		rec := &protocol.Record{Envelope: protocol.Envelope{Type: protocol.TypeDelta, TargetID: "t1", Seq: h.seq + 1, Parent: h.seq,
			Base: 1, Incarnation: 1, Time: uint64(h.now.UnixMilli()), Schema: protocol.SchemaVersion}, Delta: d}
		b, err := protocol.Encode(rec)
		if err != nil {
			h.t.Fatalf("encode delta: %v\n%+v", err, ops)
		}
		dec, err := protocol.Decode(b)
		if err != nil {
			h.t.Fatal(err)
		}
		if err := h.replica.ApplyRecord(dec); err != nil {
			h.t.Fatalf("apply: %v\n%+v", err, ops)
		}
	}
	if snap := h.tr.Snapshot(); !snap.Equal(h.replica) {
		h.t.Fatalf("replica diverged from tracker after %+v", ops)
	}
	return ops
}

func (h *harness) upsert(u *unstructured.Unstructured) []protocol.Op {
	h.t.Helper()
	ops, err := h.tr.Upsert(u)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.apply(ops, false)
}

func (h *harness) remove(u *unstructured.Unstructured) []protocol.Op {
	h.t.Helper()
	ops, err := h.tr.Remove(u)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.apply(ops, false)
}

func (h *harness) loadAll() {
	for _, u := range fixtureObjects(h.t) {
		h.upsert(u)
	}
}

func hasEdge(st *protocol.State, from, typ, to string) bool {
	_, ok := st.Edges[protocol.EdgeKey{From: from, Type: typ, To: to}]
	return ok
}

func opKinds(ops []protocol.Op) []string {
	var out []string
	for _, o := range ops {
		out = append(out, o.Kind.String()+":"+o.UID+":"+o.EdgeType+":"+o.To+o.ScopeKey)
	}
	return out
}

func TestEveryEdgeTypeIndependentOfArrivalOrder(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	st := h.tr.Snapshot()
	for _, e := range [][3]string{
		{"dep-1", EdgeOwns, "rs-1"}, {"rs-1", EdgeOwns, "pod-1"}, {"rs-1", EdgeOwns, "pod-2"},
		{"pod-1", EdgeRunsOn, "node-1"}, {"pod-2", EdgeRunsOn, "node-2"},
		{"svc-1", EdgeSelects, "pod-1"}, {"svc-1", EdgeSelects, "pod-2"},
		{"pod-1", EdgeMounts, "pvc-1"}, {"pvc-1", EdgeBinds, "pv-1"}, {"ing-1", EdgeRoutes, "svc-1"},
		{"np-1", EdgeTargets, "pod-1"}, {"hpa-1", EdgeScales, "dep-1"}, {"pdb-1", EdgeGuards, "pod-2"},
	} {
		if !hasEdge(st, e[0], e[1], e[2]) {
			t.Fatalf("missing edge %v", e)
		}
	}
	if a := st.Edges[protocol.EdgeKey{From: "svc-1", Type: EdgeSelects, To: "pod-1"}]; dump(a) != dump(map[string]any{"ports": []any{"http"}}) {
		t.Fatalf("selects attrs %v", a)
	}
	if hasEdge(st, "svc-2", EdgeSelects, "pod-1") {
		t.Fatal("selector-less service selects pods")
	}
	for k := range st.Edges {
		if st.Resources[k.From] == nil || st.Resources[k.To] == nil {
			t.Fatalf("dangling edge %v", k)
		}
	}
	r := newHarness(t)
	objs := fixtureObjects(t)
	slices.Reverse(objs)
	for _, u := range objs {
		r.upsert(u)
	}
	if !r.tr.Snapshot().Equal(st) {
		t.Fatal("state depends on arrival order")
	}
}

func TestUnchangedObservationsProduceNoOps(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	for _, u := range fixtureObjects(t) {
		u.SetResourceVersion("99999")
		u.SetManagedFields(nil)
		if ops := h.upsert(u); len(ops) != 0 {
			t.Fatalf("unchanged %s produced %v", u.GetName(), opKinds(ops))
		}
	}
	pods := []*unstructured.Unstructured{fixtureByUID(t, "pod-1"), fixtureByUID(t, "pod-2")}
	ops, changed, err := h.tr.Reconcile(KindPod, "", pods)
	if err != nil || len(ops) != 0 || len(changed) != 0 {
		t.Fatalf("reconcile unchanged: %v %v %v", opKinds(ops), changed, err)
	}
	hb := fixtureByUID(t, "node-1")
	conds, _, _ := unstructured.NestedSlice(hb.Object, "status", "conditions")
	conds[0].(map[string]any)["lastHeartbeatTime"] = "2026-09-27T00:00:00Z"
	_ = unstructured.SetNestedSlice(hb.Object, conds, "status", "conditions")
	if ops := h.upsert(hb); len(ops) != 0 {
		t.Fatalf("heartbeat produced %v", opKinds(ops))
	}
}

func TestImageUpdateAndRelationshipChange(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	dep := fixtureByUID(t, "dep-1")
	cs, _, _ := unstructured.NestedSlice(dep.Object, "spec", "template", "spec", "containers")
	cs[0].(map[string]any)["image"] = "nginx:1.26"
	_ = unstructured.SetNestedSlice(dep.Object, cs, "spec", "template", "spec", "containers")
	ops := h.upsert(dep)
	if len(ops) != 1 || ops[0].Kind != protocol.OpUpdate || ops[0].UID != "dep-1" || dump(ops[0].Fields) != dump(map[string]any{"containers.app.image": "nginx:1.26"}) {
		t.Fatalf("image update ops %+v", ops)
	}
	pod := fixtureByUID(t, "pod-1")
	pod.SetLabels(map[string]string{"app": "other"})
	ops = h.upsert(pod)
	want := []string{
		"update:pod-1::", "edge_remove:np-1:targets:pod-1", "edge_remove:pdb-1:guards:pod-1", "edge_remove:svc-1:selects:pod-1",
	}
	if dump(opKinds(ops)) != dump(want) {
		t.Fatalf("relationship change ops %v", opKinds(ops))
	}
	if ops[0].Fields["labels.app"] != "other" {
		t.Fatalf("label change %v", ops[0].Fields)
	}
	pod.SetLabels(map[string]string{"app": "web"})
	ops = h.upsert(pod)
	if len(ops) != 4 || ops[1].Kind != protocol.OpEdgeAdd {
		t.Fatalf("relabel back %v", opKinds(ops))
	}
}

func TestSelectorEdgesFollowSelectorsAndPorts(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	svc := fixtureByUID(t, "svc-1")
	_ = unstructured.SetNestedStringMap(svc.Object, map[string]string{"app": "db"}, "spec", "selector")
	ops := h.upsert(svc)
	if dump(opKinds(ops)) != dump([]string{"edge_remove:svc-1:selects:pod-1", "edge_remove:svc-1:selects:pod-2"}) {
		t.Fatalf("selector change %v", opKinds(ops))
	}
	_ = unstructured.SetNestedStringMap(svc.Object, map[string]string{"app": "web"}, "spec", "selector")
	h.upsert(svc)
	ports, _, _ := unstructured.NestedSlice(svc.Object, "spec", "ports")
	ports[0].(map[string]any)["name"] = "https"
	_ = unstructured.SetNestedSlice(svc.Object, ports, "spec", "ports")
	ops = h.upsert(svc)
	if len(ops) != 3 || ops[0].Kind != protocol.OpUpdate || ops[1].Kind != protocol.OpEdgeReplace ||
		dump(ops[1].Attrs) != dump(map[string]any{"ports": []any{"https"}}) || dump(ops[1].PrevAttrs) != dump(map[string]any{"ports": []any{"http"}}) {
		t.Fatalf("port rename %v %+v", opKinds(ops), ops)
	}
	newPod := fixtureByUID(t, "pod-1")
	newPod.SetName("web-abc-3")
	newPod.SetUID("pod-3")
	ops = h.upsert(newPod)
	for _, e := range []string{"edge_add:pod-3:mounts:pvc-1", "edge_add:pod-3:runs-on:node-1", "edge_add:rs-1:owns:pod-3", "edge_add:svc-1:selects:pod-3"} {
		if !slices.Contains(opKinds(ops), e) {
			t.Fatalf("new pod ops %v missing %s", opKinds(ops), e)
		}
	}
	ops = h.remove(fixtureByUID(t, "node-1"))
	if !slices.Contains(opKinds(ops), "edge_remove:pod-3:runs-on:node-1") || ops[0].Kind != protocol.OpDelete {
		t.Fatalf("node removal %v", opKinds(ops))
	}
}

func TestRecreatedObjectIsDistinctIdentity(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	ops := h.remove(fixtureByUID(t, "pod-1"))
	if ops[0].Kind != protocol.OpDelete || ops[0].UID != "pod-1" || ops[0].DeleteReason != protocol.DeleteDeleted {
		t.Fatalf("delete %+v", ops[0])
	}
	re := fixtureByUID(t, "pod-1")
	re.SetUID("pod-1b")
	ops = h.upsert(re)
	if ops[0].Kind != protocol.OpCreate || ops[0].UID != "pod-1b" || ops[0].Name != "web-abc-1" {
		t.Fatalf("recreate %+v", ops[0])
	}
	missed := fixtureByUID(t, "pod-1")
	missed.SetUID("pod-1c")
	ops = h.upsert(missed)
	if !slices.Contains(opKinds(ops), "create:pod-1c::") {
		t.Fatalf("recreate without delete %v", opKinds(ops))
	}
	st := h.tr.Snapshot()
	if st.Resources["pod-1b"] != nil || st.Resources["pod-1c"] == nil || st.Resources["pod-1"] != nil {
		t.Fatal("recreation kept a stale identity")
	}
	if !slices.Contains(opKinds(ops), "delete:pod-1b::") {
		t.Fatalf("stale uid not deleted %v", opKinds(ops))
	}
}

func TestPermissionLossIsScopeStatusNotDeletion(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	h.apply(h.tr.ScopeRestored(KindPod, ""), false)
	ops := h.apply(h.tr.ScopeLost(KindPod, "", ReasonForbidden), false)
	if len(ops) != 1 || ops[0].Kind != protocol.OpScopeSet || ops[0].ScopeKey != "Pod|" || ops[0].Scope.State != protocol.ScopeUnavailable || ops[0].Scope.Reason != ReasonForbidden {
		t.Fatalf("scope lost %+v", ops)
	}
	if h.tr.Snapshot().Resources["pod-1"] == nil {
		t.Fatal("permission loss deleted resources")
	}
	h.now = h.now.Add(time.Minute)
	if ops := h.apply(h.tr.ScopeLost(KindPod, "", ReasonForbidden), false); len(ops) != 0 {
		t.Fatalf("repeated loss %v", opKinds(ops))
	}
	if ops := h.apply(h.tr.ScopePartial(KindPod, "", ReasonRelisting), false); len(ops) != 1 || ops[0].Scope.State != protocol.ScopePartial {
		t.Fatalf("partial %+v", ops)
	}
	if ops := h.apply(h.tr.ScopeRestored(KindPod, ""), false); len(ops) != 1 || ops[0].Scope.State != protocol.ScopeComplete {
		t.Fatalf("restored %+v", ops)
	}
	ops = h.apply(h.tr.RemoveScope(KindPod, ""), false)
	deletes := 0
	for _, o := range ops {
		if o.Kind == protocol.OpDelete {
			deletes++
			if o.DeleteReason != protocol.DeleteScopeRemoved {
				t.Fatalf("scope removal reason %+v", o)
			}
		}
	}
	last := ops[len(ops)-1]
	if deletes != 2 || last.Kind != protocol.OpScopeSet || last.Scope.Reason != ReasonScopeRemoved {
		t.Fatalf("remove scope %v", opKinds(ops))
	}
	if ScopeKey(KindDeployment, "shop") != "apps/Deployment|shop" {
		t.Fatal("scope key format")
	}
}

func TestReconcileAfterWatchLossHasNoGap(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	changed := fixtureByUID(t, "pod-1")
	cs, _, _ := unstructured.NestedSlice(changed.Object, "status", "containerStatuses")
	cs[0].(map[string]any)["restartCount"] = int64(5)
	_ = unstructured.SetNestedSlice(changed.Object, cs, "status", "containerStatuses")
	added := fixtureByUID(t, "pod-2")
	added.SetUID("pod-9")
	added.SetName("web-abc-9")
	ops, uids, err := h.tr.Reconcile(KindPod, "", []*unstructured.Unstructured{changed, added})
	if err != nil {
		t.Fatal(err)
	}
	h.apply(ops, true)
	kinds := opKinds(ops)
	for _, want := range []string{"update:pod-1::", "delete:pod-2::", "create:pod-9::", "edge_remove:svc-1:selects:pod-2", "edge_add:svc-1:selects:pod-9"} {
		if !slices.Contains(kinds, want) {
			t.Fatalf("reconcile ops %v missing %s", kinds, want)
		}
	}
	for _, u := range []string{"pod-1", "pod-2", "pod-9", "svc-1", "node-2"} {
		if !uids[u] {
			t.Fatalf("changed uids %v missing %s", uids, u)
		}
	}
	for _, o := range ops {
		if o.Kind == protocol.OpDelete && o.DeleteReason != protocol.DeleteDeleted {
			t.Fatalf("relist deletion reason %+v", o)
		}
	}
	other := newHarness(t)
	other.loadAll()
	ops, _, err = other.tr.Reconcile(KindPod, "elsewhere", nil)
	if err != nil || len(ops) != 0 {
		t.Fatalf("namespace-scoped reconcile touched other namespaces: %v", opKinds(ops))
	}
	if _, _, err := other.tr.Reconcile(KindPod, "", []*unstructured.Unstructured{fixtureByUID(t, "dep-1")}); err == nil {
		t.Fatal("wrong kind accepted by reconcile")
	}
}

func TestWarningEventsAggregateWithBoundedUpdates(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	ops := h.upsert(warningEvent("ev-1", "pod-1", "BackOff", 1, h.now))
	if len(ops) != 1 || dump(ops[0].Fields) != dump(map[string]any{"events.warning.BackOff": int64(1)}) {
		t.Fatalf("first warning %+v", ops)
	}
	if strings.Contains(dump(h.tr.Snapshot()), secretLiteral) {
		t.Fatal("event message leaked")
	}
	h.now = h.now.Add(time.Minute)
	if ops := h.upsert(warningEvent("ev-1", "pod-1", "BackOff", 4, h.now)); len(ops) != 0 {
		t.Fatalf("update within interval %v", opKinds(ops))
	}
	if ops := h.upsert(warningEvent("ev-2", "pod-1", "Unhealthy", 2, h.now)); len(ops) != 0 {
		t.Fatalf("new reason within interval %v", opKinds(ops))
	}
	normal := warningEvent("ev-3", "pod-1", "Pulled", 7, h.now)
	normal.Object["type"] = corev1.EventTypeNormal
	h.upsert(normal)
	if ops := h.apply(h.tr.FlushEvents(), false); len(ops) != 0 {
		t.Fatalf("flush before interval %v", opKinds(ops))
	}
	ops, _, err := h.tr.Reconcile(KindEvent, "", []*unstructured.Unstructured{warningEvent("ev-1", "pod-1", "BackOff", 4, h.now), warningEvent("ev-2", "pod-1", "Unhealthy", 2, h.now)})
	if err != nil || len(ops) != 0 {
		t.Fatalf("event relist %v %v", opKinds(ops), err)
	}
	h.now = h.now.Add(5 * time.Minute)
	ops = h.apply(h.tr.FlushEvents(), false)
	if len(ops) != 1 || dump(ops[0].Fields) != dump(map[string]any{"events.warning.BackOff": int64(4), "events.warning.Unhealthy": int64(2)}) {
		t.Fatalf("flush after interval %+v", ops)
	}
	if ops := h.apply(h.tr.FlushEvents(), false); len(ops) != 0 {
		t.Fatalf("second flush %v", opKinds(ops))
	}
	pod := fixtureByUID(t, "pod-1")
	cs, _, _ := unstructured.NestedSlice(pod.Object, "status", "containerStatuses")
	cs[0].(map[string]any)["restartCount"] = int64(9)
	_ = unstructured.SetNestedSlice(pod.Object, cs, "status", "containerStatuses")
	ops = h.upsert(pod)
	if len(ops) != 1 || len(ops[0].Fields) != 1 {
		t.Fatalf("object update disturbed event fields %+v", ops)
	}
	h.now = h.now.Add(2 * time.Hour)
	ops = h.apply(h.tr.FlushEvents(), false)
	if len(ops) != 1 || dump(ops[0].Fields) != dump(map[string]any{"events.warning.BackOff": nil, "events.warning.Unhealthy": nil}) {
		t.Fatalf("decay %+v", ops)
	}
	h.upsert(warningEvent("ev-4", "pod-new", "FailedMount", 3, h.now))
	np := fixtureByUID(t, "pod-2")
	np.SetUID("pod-new")
	np.SetName("web-abc-new")
	ops = h.upsert(np)
	if ops[0].Kind != protocol.OpCreate || ops[0].Fields["events.warning.FailedMount"] != int64(3) {
		t.Fatalf("events for later object %+v", ops[0])
	}
	old := warningEvent("ev-5", "pod-2", "BackOff", 50, h.now.Add(-3*time.Hour))
	if ops := h.upsert(old); len(ops) != 0 {
		t.Fatalf("expired event counted %v", opKinds(ops))
	}
	ops = h.apply(h.tr.RemoveScope(KindEvent, ""), false)
	if len(ops) != 2 || ops[0].Fields["events.warning.FailedMount"] != nil {
		t.Fatalf("event scope removal %+v", ops)
	}
}

func TestEventReasonsAreBounded(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	for i := 0; i < maxEventReasons+4; i++ {
		h.upsert(warningEvent("e"+string(rune('a'+i)), "pod-1", "Reason"+string(rune('A'+i)), int32(i+1), h.now))
	}
	h.now = h.now.Add(10 * time.Minute)
	h.apply(h.tr.FlushEvents(), false)
	f := h.tr.Snapshot().Resources["pod-1"].Fields
	n := 0
	for k := range f {
		if strings.HasPrefix(k, eventFieldPrefix) {
			n++
		}
	}
	if n != maxEventReasons+1 || f[eventFieldPrefix+otherReason] != int64(1+2+3+4) {
		t.Fatalf("reason cap: %d fields, other=%v", n, f[eventFieldPrefix+otherReason])
	}
}

func TestRemoveByNameAndUnsupported(t *testing.T) {
	h := newHarness(t)
	h.loadAll()
	u := fixtureByUID(t, "svc-2")
	u.SetUID("")
	ops := h.remove(u)
	if len(ops) != 1 || ops[0].Kind != protocol.OpDelete || ops[0].UID != "svc-2" {
		t.Fatalf("remove by name %v", opKinds(ops))
	}
	if ops := h.remove(u); len(ops) != 0 {
		t.Fatalf("second remove %v", opKinds(ops))
	}
	crd := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "example.com/v1", "kind": "Widget", "metadata": map[string]any{"name": "w", "uid": "w-1"}}}
	if _, err := h.tr.Remove(crd); err == nil {
		t.Fatal("unsupported remove accepted")
	}
	if _, err := h.tr.Upsert(crd); err == nil {
		t.Fatal("unsupported upsert accepted")
	}
	if ops, err := h.tr.Remove(warningEvent("ev-x", "pod-1", "BackOff", 1, h.now)); err != nil || len(ops) != 0 {
		t.Fatalf("event removal %v %v", ops, err)
	}
}
