package node

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

const promGroups = `groups:
  - name: node
    interval: 10s
    rules:
      - alert: MemHigh
        expr: container_memory_working_set_bytes{container="app"} > 800
        for: 20s
      - alert: MemNearLimit
        expr: container_memory_working_set_bytes{container!=""} / on(namespace, pod, container) kube_pod_container_resource_limits{resource="memory"} > 0.8
        for: 20s
      - alert: NodeNotReady
        expr: kube_node_status_condition{condition="Ready",status="true"} == 0
`

func promBundle(version string) map[string]string {
	return bundleFiles(version, []ruleSpec{
		{id: "mem-high", class: "promql", scope: "node", file: "prometheus/node.yaml", group: "node", alert: "MemHigh", caps: "metrics", extra: "    dedup_key: namespace, pod, container\n"},
		{id: "mem-near-limit", class: "promql", scope: "node", file: "prometheus/node.yaml", group: "node", alert: "MemNearLimit", caps: "metrics"},
		{id: "node-not-ready", class: "promql", scope: "node", file: "prometheus/node.yaml", group: "node", alert: "NodeNotReady", caps: "metrics"},
	}, map[string]string{"prometheus/node.yaml": promGroups})
}

func (h *harness) instant(expr string) promql.Vector {
	h.t.Helper()
	q, err := h.agent.prom.NewInstantQuery(context.Background(), h.agent.query, nil, expr, h.clock.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	defer q.Close()
	r := q.Exec(context.Background())
	if r.Err != nil {
		h.t.Fatal(r.Err)
	}
	v, err := r.Vector()
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

func TestPromQLRulesForSemanticsJoinAndRecovery(t *testing.T) {
	h := newHarness(t, options{caps: "metrics"})
	h.coord.setBundle(h.trust.payload(t, promBundle("v1")))
	h.coord.setKube(nodeapi.KubeUpdate{Revision: 3, Series: []nodeapi.KubeSeries{
		{Labels: map[string]string{"__name__": "kube_node_status_condition", "node": testNode, "condition": "Ready", "status": "true"}, Value: 0},
	}})
	a := h.start()
	h.waitBundle("v1")
	h.waitScrapes(2)
	h.waitFor("pod and coordinator series", func() bool {
		return len(h.instant(`kube_pod_info`)) > 0 && len(h.instant(`kube_node_status_condition`)) == 1
	})
	var pods []string
	for _, s := range h.instant(`kube_pod_info`) {
		pods = append(pods, s.Metric.Get("pod"))
	}
	slices.Sort(pods)
	if !slices.Equal(pods, []string{"chatty-1", "web-1"}) {
		t.Fatalf("node-derived pod series cover %v, want only the pods on %s", pods, testNode)
	}
	if v := h.instant(`kube_pod_container_resource_limits{pod="web-1",container="app",resource="memory"}`); len(v) != 1 || v[0].F != 1000 {
		t.Fatalf("limits series %v", v)
	}

	h.step(10 * time.Second)
	if r := h.rule("mem-high"); r.Firing != 0 || r.Pending != 1 {
		t.Fatalf("after one interval mem-high %+v, want pending", r)
	}
	h.step(10 * time.Second)
	h.step(10 * time.Second)
	for _, id := range []string{"mem-high", "mem-near-limit", "node-not-ready"} {
		if r := h.rule(id); r.Firing != 1 {
			t.Fatalf("%s %+v, want firing", id, r)
		}
	}
	h.waitDelivered()
	fs := h.coord.findings(t)
	for _, id := range []string{"mem-high", "mem-near-limit", "node-not-ready"} {
		if got := transitions(fs, id); !slices.Equal(got, []string{"firing"}) {
			t.Fatalf("%s transitions %v", id, got)
		}
	}
	for _, f := range fs {
		if f.Node != testNode || f.Provenance.BundleVersion != "v1" {
			t.Fatalf("finding provenance %+v node %q", f.Provenance, f.Node)
		}
		if f.Provenance.RuleID == "mem-near-limit" && (f.Labels["pod"] != "web-1" || f.Labels["container"] != "app") {
			t.Fatalf("join finding labels %v", f.Labels)
		}
	}

	h.kubelet.set(memFixture(100))
	h.coord.setKube(nodeapi.KubeUpdate{Revision: 4, Series: []nodeapi.KubeSeries{
		{Labels: map[string]string{"__name__": "kube_node_status_condition", "node": testNode, "condition": "Ready", "status": "true"}, Value: 1},
	}})
	h.waitScrapes(2)
	h.clock.Advance(time.Second)
	h.waitFor("coordinator series update", func() bool {
		v := h.instant(`kube_node_status_condition`)
		return len(v) == 1 && v[0].F == 1
	})
	h.step(10 * time.Second)
	h.waitDelivered()
	fs = h.coord.findings(t)
	for _, id := range []string{"mem-high", "mem-near-limit", "node-not-ready"} {
		if got := transitions(fs, id); !slices.Equal(got, []string{"firing", "resolved"}) {
			t.Fatalf("%s transitions after recovery %v", id, got)
		}
	}
	reg, ok := h.coord.lastRegister()
	if !ok || reg.Node != testNode || reg.BundleVersion != "v1" || reg.Coverage["metrics"] != coverageAvailable ||
		reg.Coverage["logs"] != "unavailable: capability disabled" || reg.QueueUsage.Capacity == 0 {
		t.Fatalf("register %+v", reg)
	}
	if st := a.Status(); st.BundleVersion != "v1" || st.TSDB.Retention <= 0 || st.Coverage["metrics.pod_targets"] != "1 up, 0 down, 0 dropped" {
		t.Fatalf("status %+v", st)
	}
	if v := h.instant(`app_requests_total{namespace="other",pod="chatty-1"}`); len(v) != 1 || v[0].F != 5 {
		t.Fatalf("annotated pod target series %v", v)
	}
}

const clusterGroups = `groups:
  - name: cluster
    interval: 10s
    rules:
      - alert: ClusterMemory
        expr: sum(max_over_time(container_memory_working_set_bytes{container="app"}[1m])) > 100
`

func TestClusterRulePartsPushedAsSeries(t *testing.T) {
	h := newHarness(t, options{caps: "metrics"})
	h.coord.setBundle(h.trust.payload(t, bundleFiles("c1", []ruleSpec{
		{id: "cluster-mem", class: "promql", scope: "cluster", file: "prometheus/cluster.yaml", group: "cluster", alert: "ClusterMemory", caps: "metrics"},
	}, map[string]string{"prometheus/cluster.yaml": clusterGroups})))
	h.start()
	h.waitBundle("c1")
	h.waitScrapes(2)
	h.step(10 * time.Second)
	h.waitDelivered()
	var parts []*nodeapi.Part
	for _, it := range h.coord.received(nodeapi.KindSeries) {
		if it.Part.RuleID == "cluster-mem" && len(it.Part.Samples) > 0 {
			parts = append(parts, it.Part)
		}
	}
	if len(parts) == 0 {
		t.Fatal("no cluster rule part pushed")
	}
	p := parts[len(parts)-1]
	if p.BundleVersion != "c1" || p.Samples[0].Value != 900 {
		t.Fatalf("part %+v", p)
	}
	if fs := h.coord.findings(t); len(fs) != 0 {
		t.Fatalf("node evaluated the outer cluster aggregation: %d findings", len(fs))
	}
}
