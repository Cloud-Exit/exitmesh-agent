package engine

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func container(name string, state, last map[string]any) map[string]any {
	return map[string]any{"name": name, "state": state, "lastState": last}
}

func clusterState() *protocol.State {
	st := protocol.NewState()
	add := func(uid, kind, ns, name string, fields map[string]any) {
		st.Resources[uid] = &protocol.Resource{UID: uid, Kind: kind, Namespace: ns, Name: name, Fields: fields}
	}
	add("pod-a", "Pod", "shop", "cart-a", map[string]any{"status": map[string]any{"phase": "Running", "containerStatuses": []any{
		container("sidecar", map[string]any{"running": map[string]any{}}, map[string]any{}),
		container("app", map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}}, map[string]any{}),
	}}})
	add("pod-b", "Pod", "shop", "cart-b", map[string]any{"status": map[string]any{"phase": "Running", "containerStatuses": []any{
		container("app", map[string]any{"running": map[string]any{}}, map[string]any{"terminated": map[string]any{"reason": "OOMKilled", "exitCode": int64(137)}}),
	}}})
	add("pod-c", "Pod", "default", "ok", map[string]any{"status": map[string]any{"phase": "Running", "containerStatuses": []any{
		container("app", map[string]any{"running": map[string]any{}}, map[string]any{}),
	}}})
	add("deploy-web", "Deployment", "shop", "web", map[string]any{"spec.replicas": int64(3), "status.availableReplicas": int64(1)})
	add("deploy-api", "Deployment", "shop", "api", map[string]any{"spec.replicas": int64(2), "status.availableReplicas": uint64(2)})
	add("pvc-1", "PersistentVolumeClaim", "shop", "data", map[string]any{"status.phase": "Pending", "metadata.creationTimestamp": "2025-12-31T22:00:00Z"})
	add("pvc-2", "PersistentVolumeClaim", "shop", "fresh", map[string]any{"status.phase": "Pending", "metadata.creationTimestamp": "2025-12-31T23:59:00Z"})
	add("node-1", "Node", "", "n1", map[string]any{"status": map[string]any{"conditions": []any{
		map[string]any{"type": "MemoryPressure", "status": "False"},
		map[string]any{"type": "Ready", "status": "False", "reason": "KubeletNotReady"},
	}}})
	add("node-2", "Node", "", "n2", map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}})
	st.Edges[protocol.EdgeKey{From: "pod-a", Type: "scheduled_on", To: "node-1"}] = map[string]any{"since": "x"}
	st.Edges[protocol.EdgeKey{From: "pod-b", Type: "scheduled_on", To: "node-2"}] = nil
	st.Edges[protocol.EdgeKey{From: "pod-c", Type: "scheduled_on", To: "node-2"}] = nil
	st.Edges[protocol.EdgeKey{From: "pod-c", Type: "scheduled_on", To: "gone"}] = nil
	st.Scopes["v1/Pod"] = protocol.ScopeStatus{State: protocol.ScopeComplete}
	st.Scopes["apps/Deployment|shop"] = protocol.ScopeStatus{State: protocol.ScopeComplete}
	return st
}

type stateBox struct {
	mu sync.Mutex
	st *protocol.State
}

func (b *stateBox) get() *protocol.State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st
}

func (b *stateBox) edit(fn func(*protocol.State)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fn(b.st)
}

func insightRules() []bundle.StateRule {
	crash := stateRule("pod-crashloop", `field(r, "status.containerStatuses", []).exists(c, has(c.state.waiting) && c.state.waiting.reason == "CrashLoopBackOff")`, "Pod")
	crash.Labels = map[string]string{
		"container": `=field(r, "status.containerStatuses", []).filter(c, has(c.state.waiting) && c.state.waiting.reason == "CrashLoopBackOff")[0].name`,
		"team":      "platform",
	}
	crash.Meta.Summary = "{{ $labels.namespace }}/{{ $labels.name }} container {{ $labels.container }} is crash looping"
	oom := stateRule("pod-oomkilled", `field(r, "status.containerStatuses", []).exists(c, has(c.lastState.terminated) && c.lastState.terminated.reason == "OOMKilled")`, "Pod")
	deploy := stateRule("deployment-unavailable", `field(r, "status.availableReplicas", 0) < field(r, "spec.replicas", 1)`, "Deployment")
	deploy.For = 10 * time.Minute
	deploy.Meta.RequiredFields = []string{"spec.replicas"}
	pvc := stateRule("pvc-pending", `field(r, "status.phase", "") == "Pending" && now - timestamp(field(r, "metadata.creationTimestamp", "1970-01-01T00:00:00Z")) > duration("5m")`, "PersistentVolumeClaim")
	node := stateRule("node-not-ready", `field(r, "status.conditions", []).exists(c, c.type == "Ready" && c.status != "True")`, "Node")
	node.Labels = map[string]string{"reason": `=field(r, "status.conditions", []).filter(c, c.type == "Ready")[0].reason`}
	onBad := stateRule("pod-on-unready-node", `out(r, "scheduled_on").exists(n, field(n, "status.conditions", []).exists(c, c.type == "Ready" && c.status != "True") && n.edge.since == "x")`, "Pod")
	busy := stateRule("node-hosts-pods", `size(in(r, "scheduled_on")) >= 2 && in(r, "scheduled_on").all(p, p.kind == "Pod") && "Pod" in in(r, "scheduled_on").map(p, p.kind)`, "Node")
	return []bundle.StateRule{crash, oom, deploy, pvc, node, onBad, busy}
}

func firingKeys(evs []AlertEvent) map[string][]string {
	out := map[string][]string{}
	for _, e := range evs {
		if e.Transition == TransitionFiring {
			out[e.RuleID] = append(out[e.RuleID], e.InstanceKey)
		}
	}
	return out
}

func TestStateRulesModeledOnInsights(t *testing.T) {
	box := &stateBox{st: clusterState()}
	e, s := newTestEngine(t, Options{Role: RoleCoordinator, StateSource: box.get}, mkBundle("v1", insightRules(), nil, nil))
	eval(t, e, at(0))
	evs := s.take()
	got := firingKeys(evs)
	want := map[string][]string{
		"pod-crashloop":       {"pod-a"},
		"pod-oomkilled":       {"pod-b"},
		"pvc-pending":         {"pvc-1"},
		"node-not-ready":      {"node-1"},
		"pod-on-unready-node": {"pod-a"},
		"node-hosts-pods":     {"node-2"},
	}
	for id, keys := range want {
		if !slices.Equal(got[id], keys) {
			t.Fatalf("%s fired %v, want %v (all %v)", id, got[id], keys, got)
		}
	}
	if len(got["deployment-unavailable"]) != 0 {
		t.Fatalf("for rule fired early")
	}
	crash := only(evs, "pod-crashloop")[0]
	wantLabels := map[string]string{"kind": "Pod", "namespace": "shop", "name": "cart-a", "container": "app", "team": "platform"}
	for k, v := range wantLabels {
		if crash.Labels[k] != v {
			t.Fatalf("labels %v", crash.Labels)
		}
	}
	if crash.Summary != "shop/cart-a container app is crash looping" || !slices.Equal(crash.ResourceUIDs, []string{"pod-a"}) || crash.Class != bundle.ClassState {
		t.Fatalf("event %+v", crash)
	}
	if nr := only(evs, "node-not-ready")[0]; nr.Labels["reason"] != "KubeletNotReady" || nr.Labels["namespace"] != "" {
		t.Fatalf("node labels %v", nr.Labels)
	}
	if st := stateOf(e, "deployment-unavailable"); st.State != StateWarmingUp || st.Pending != 1 {
		t.Fatalf("deploy state %+v", st)
	}
	for i := 1; i <= 10; i++ {
		eval(t, e, at(time.Duration(i)*time.Minute))
	}
	evs = s.take()
	if dk := firingKeys(evs)["deployment-unavailable"]; !slices.Equal(dk, []string{"deploy-web"}) {
		t.Fatalf("deployment fired %v", dk)
	}
	if st := stateOf(e, "deployment-unavailable"); st.State != StateActive || st.Firing != 1 {
		t.Fatalf("deploy state %+v", st)
	}
	box.edit(func(st *protocol.State) {
		st.Resources["pod-a"].Fields["status"].(map[string]any)["containerStatuses"] = []any{container("app", map[string]any{"running": map[string]any{}}, map[string]any{})}
	})
	eval(t, e, at(11*time.Minute))
	evs = s.take()
	if got := transitions(only(evs, "pod-crashloop")); !slices.Equal(got, []string{TransitionResolved}) {
		t.Fatalf("crashloop recovery %v", got)
	}
}

func TestStateRuleIncompleteNeverResolves(t *testing.T) {
	box := &stateBox{st: clusterState()}
	deploy := insightRules()[2]
	deploy.For = 0
	e, s := newTestEngine(t, Options{Role: RoleCoordinator, StateSource: box.get}, mkBundle("v1", []bundle.StateRule{deploy}, nil, nil))
	eval(t, e, at(0))
	if got := firingKeys(s.take())["deployment-unavailable"]; !slices.Equal(got, []string{"deploy-web"}) {
		t.Fatalf("fired %v", got)
	}
	box.edit(func(st *protocol.State) { delete(st.Resources["deploy-web"].Fields, "spec.replicas") })
	eval(t, e, at(time.Minute))
	if evs := s.take(); len(evs) != 1 || evs[0].Transition != TransitionStale || !evs[0].Incomplete {
		t.Fatalf("missing required field: %+v", evs)
	}
	if st := stateOf(e, "deployment-unavailable"); st.State != StateStale || !strings.Contains(st.Reason, "incomplete") {
		t.Fatalf("state %+v", st)
	}
	box.edit(func(st *protocol.State) { st.Resources["deploy-web"].Fields["spec.replicas"] = int64(3) })
	eval(t, e, at(2*time.Minute))
	if evs := s.take(); len(evs) != 1 || evs[0].Transition != TransitionUpdate || evs[0].Incomplete {
		t.Fatalf("stale instance seen again must update, got %+v", evs)
	}
	box.edit(func(st *protocol.State) {
		st.Scopes["apps/Deployment|shop"] = protocol.ScopeStatus{State: protocol.ScopeUnavailable, Reason: "forbidden"}
	})
	eval(t, e, at(3*time.Minute))
	if evs := s.take(); len(evs) != 1 || evs[0].Transition != TransitionStale {
		t.Fatalf("unavailable scope: %+v", evs)
	}
	st := stateOf(e, "deployment-unavailable")
	if st.State != StateStale || st.Firing != 1 {
		t.Fatalf("unavailable scope state %+v", st)
	}
	box.edit(func(st *protocol.State) {
		st.Scopes["apps/Deployment|shop"] = protocol.ScopeStatus{State: protocol.ScopePartial}
		delete(st.Resources, "deploy-web")
	})
	eval(t, e, at(4*time.Minute))
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("partial scope with the resource missing resolved: %+v", evs)
	}
	box.edit(func(st *protocol.State) {
		st.Scopes["apps/Deployment|shop"] = protocol.ScopeStatus{State: protocol.ScopeComplete}
	})
	eval(t, e, at(5*time.Minute))
	if got := transitions(s.take()); !slices.Equal(got, []string{TransitionResolved}) {
		t.Fatalf("deleted resource with complete scope: %v", got)
	}
}

func TestStateSourceUnavailableMarksStale(t *testing.T) {
	var mu sync.Mutex
	st := clusterState()
	src := func() *protocol.State { mu.Lock(); defer mu.Unlock(); return st }
	e, s := newTestEngine(t, Options{Role: RoleCoordinator, StateSource: src}, mkBundle("v1", insightRules()[:1], nil, nil))
	eval(t, e, at(0))
	s.take()
	mu.Lock()
	st = nil
	mu.Unlock()
	eval(t, e, at(time.Minute))
	if evs := s.take(); len(evs) != 1 || evs[0].Transition != TransitionStale {
		t.Fatalf("got %+v", evs)
	}
	if rs := stateOf(e, "pod-crashloop"); rs.State != StateStale || rs.Reason != "state snapshot unavailable" {
		t.Fatalf("state %+v", rs)
	}
	ns, _ := newTestEngine(t, Options{Role: RoleCoordinator}, mkBundle("v1", insightRules()[:1], nil, nil))
	eval(t, ns, at(0))
	if rs := stateOf(ns, "pod-crashloop"); rs.State != StateStale {
		t.Fatalf("no source state %+v", rs)
	}
}

func TestStateRulePerResourceErrorsAreIncomplete(t *testing.T) {
	box := &stateBox{st: clusterState()}
	r := stateRule("strict", `r.fields.status.phase == "Running"`, "Pod", "Deployment")
	lbl := stateRule("label-err", `r.kind == "Deployment"`, "Deployment")
	lbl.Labels = map[string]string{"x": `=r.fields.missing.value`}
	nb := stateRule("not-bool", `field(r, "spec.replicas", 0)`, "Deployment")
	e, s := newTestEngine(t, Options{Role: RoleCoordinator, StateSource: box.get}, mkBundle("v1", []bundle.StateRule{r, lbl, nb}, nil, nil))
	eval(t, e, at(0))
	if got := firingKeys(s.take()); !slices.Equal(got["strict"], []string{"pod-a", "pod-b", "pod-c"}) || len(got["label-err"]) != 0 {
		t.Fatalf("fired %v", got)
	}
	if st := stateOf(e, "strict"); st.State != StateStale {
		t.Fatalf("strict %+v", st)
	}
	if st := stateOf(e, "label-err"); st.State != StateStale {
		t.Fatalf("label-err %+v", st)
	}
	if st := stateOf(e, "not-bool"); st.State != StateFailed || !strings.Contains(st.Reason, "want bool") {
		t.Fatalf("not-bool %+v", st)
	}
}

func TestStateRuleCostBudget(t *testing.T) {
	st := clusterState()
	items := make([]any, 5000)
	for i := range items {
		items[i] = int64(i)
	}
	st.Resources["deploy-web"].Fields["items"] = items
	r := stateRule("costly", `field(r, "items", []).map(x, x * 2).filter(x, x % 3 == 0).size() > 0`, "Deployment")
	r.Meta.Budget.MaxSamples = 1000
	cheap := stateRule("cheap", `r.name == "web"`, "Deployment")
	total := stateRule("total", `r.name != ""`, "Pod", "Deployment", "Node", "PersistentVolumeClaim")
	total.Meta.Budget.MaxSamples = 12
	e, s := newTestEngine(t, Options{Role: RoleCoordinator, StateSource: func() *protocol.State { return st }}, mkBundle("v1", []bundle.StateRule{r, cheap, total}, nil, nil))
	eval(t, e, at(0))
	if got := firingKeys(s.take()); !slices.Equal(got["cheap"], []string{"deploy-web"}) || len(got["costly"]) != 0 {
		t.Fatalf("fired %v", got)
	}
	if rs := stateOf(e, "costly"); rs.State != StateBudgetLimited || !strings.Contains(rs.Reason, "cost limit") {
		t.Fatalf("costly %+v", rs)
	}
	if rs := stateOf(e, "total"); rs.State != StateBudgetLimited || !strings.Contains(rs.Reason, "exceeds max_samples 12") {
		t.Fatalf("total %+v", rs)
	}
}

func TestDefaultScopeMatch(t *testing.T) {
	cases := []struct {
		key, kind, ns string
		want          bool
	}{
		{"apps/Deployment|shop", "Deployment", "shop", true},
		{"apps/Deployment|shop", "Deployment", "other", false},
		{"apps/Deployment", "Deployment", "any", true},
		{"Node", "Node", "", true},
		{"v1/Pod|*", "Pod", "x", true},
		{"v1/Pod|x", "Node", "x", false},
	}
	for _, c := range cases {
		if got := defaultScopeMatch(c.key, c.kind, c.ns); got != c.want {
			t.Fatalf("%+v got %v", c, got)
		}
	}
	custom := func(key, kind, ns string) bool { return key == "all" }
	st := clusterState()
	st.Scopes["all"] = protocol.ScopeStatus{State: protocol.ScopeUnavailable}
	e, s := newTestEngine(t, Options{Role: RoleCoordinator, ScopeMatch: custom, StateSource: func() *protocol.State { return st }}, mkBundle("v1", insightRules()[:1], nil, nil))
	eval(t, e, at(0))
	if evs := s.take(); len(evs) != 0 {
		t.Fatalf("custom scope match ignored: %+v", evs)
	}
}

func TestLookupField(t *testing.T) {
	f := map[string]any{"a.b": 1, "x": map[string]any{"y": map[string]any{"z": "v"}}, "s": "str"}
	for path, want := range map[string]any{"a.b": 1, "x.y.z": "v"} {
		if v, ok := lookupField(f, path); !ok || v != want {
			t.Fatalf("%s: %v %v", path, v, ok)
		}
	}
	for _, path := range []string{"x.q", "s.t", "missing", "x.y.z.w"} {
		if _, ok := lookupField(f, path); ok {
			t.Fatalf("%s found", path)
		}
	}
}
