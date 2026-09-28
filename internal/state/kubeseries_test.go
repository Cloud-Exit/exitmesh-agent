package state

import (
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func seriesIndex(s []Series) map[string]float64 {
	out := map[string]float64{}
	for _, x := range s {
		out[x.Labels.String()] = x.Value
	}
	return out
}

func fixtureState(t *testing.T) *Tracker {
	h := newHarness(t)
	h.loadAll()
	return h.tr
}

func TestKubeSeriesSemantics(t *testing.T) {
	tr := fixtureState(t)
	series := KubeSeries(tr.Snapshot(), 1000)
	idx := seriesIndex(series)
	want := map[string]float64{
		`{__name__="kube_pod_info", created_by_kind="ReplicaSet", created_by_name="web-abc", host_ip="10.0.0.1", host_network="false", namespace="shop", node="node-a", pod="web-abc-1", pod_ip="10.1.0.1", priority_class="high", uid="pod-1"}`:                         1,
		`{__name__="kube_pod_status_phase", namespace="shop", phase="Running", pod="web-abc-1", uid="pod-1"}`:                                                                                                                                                            1,
		`{__name__="kube_pod_status_phase", namespace="shop", phase="Pending", pod="web-abc-1", uid="pod-1"}`:                                                                                                                                                            0,
		`{__name__="kube_pod_status_ready", condition="true", namespace="shop", pod="web-abc-1", uid="pod-1"}`:                                                                                                                                                           1,
		`{__name__="kube_pod_status_ready", condition="false", namespace="shop", pod="web-abc-2", uid="pod-2"}`:                                                                                                                                                          1,
		`{__name__="kube_pod_container_info", container="app", image="nginx:1.25", image_id="docker.io/library/nginx@sha256:2222", image_spec="nginx:1.25", namespace="shop", pod="web-abc-1", uid="pod-1"}`:                                                             1,
		`{__name__="kube_pod_container_status_restarts_total", container="app", namespace="shop", pod="web-abc-1", uid="pod-1"}`:                                                                                                                                         2,
		`{__name__="kube_pod_container_status_waiting_reason", container="app", namespace="shop", pod="web-abc-2", reason="CrashLoopBackOff", uid="pod-2"}`:                                                                                                              1,
		`{__name__="kube_pod_container_status_last_terminated_reason", container="app", namespace="shop", pod="web-abc-1", reason="OOMKilled", uid="pod-1"}`:                                                                                                             1,
		`{__name__="kube_pod_container_resource_requests", container="app", namespace="shop", node="node-a", pod="web-abc-1", resource="cpu", uid="pod-1", unit="core"}`:                                                                                                 0.25,
		`{__name__="kube_pod_container_resource_requests", container="app", namespace="shop", node="node-a", pod="web-abc-1", resource="memory", uid="pod-1", unit="byte"}`:                                                                                              128 << 20,
		`{__name__="kube_pod_container_resource_limits", container="app", namespace="shop", node="node-a", pod="web-abc-1", resource="nvidia_com_gpu", uid="pod-1", unit="integer"}`:                                                                                     1,
		`{__name__="kube_pod_owner", namespace="shop", owner_is_controller="true", owner_kind="ReplicaSet", owner_name="web-abc", pod="web-abc-1", uid="pod-1"}`:                                                                                                         1,
		`{__name__="kube_node_info", container_runtime_version="containerd://2.0.0", internal_ip="10.0.0.1", kernel_version="6.8.0", kubelet_version="v1.34.1", node="node-a", os_image="Ubuntu 24.04", pod_cidr="10.1.0.0/24", provider_id="aws:///eu-west-1a/i-0abc"}`: 1,
		`{__name__="kube_node_status_condition", condition="Ready", node="node-a", status="true"}`:                                                                                                                                                                       1,
		`{__name__="kube_node_status_condition", condition="Ready", node="node-a", status="unknown"}`:                                                                                                                                                                    0,
		`{__name__="kube_node_status_capacity", node="node-a", resource="cpu", unit="core"}`:                                                                                                                                                                             4,
		`{__name__="kube_node_status_allocatable", node="node-a", resource="ephemeral_storage", unit="byte"}`:                                                                                                                                                            90 << 30,
		`{__name__="kube_node_status_capacity", node="node-a", resource="pods", unit="integer"}`:                                                                                                                                                                         110,
		`{__name__="kube_node_spec_unschedulable", node="node-a"}`:                                                                                                                                                                                                       0,
		`{__name__="kube_deployment_spec_replicas", deployment="web", namespace="shop"}`:                                                                                                                                                                                 3,
		`{__name__="kube_deployment_status_replicas_available", deployment="web", namespace="shop"}`:                                                                                                                                                                     2,
		`{__name__="kube_deployment_status_replicas_unavailable", deployment="web", namespace="shop"}`:                                                                                                                                                                   1,
		`{__name__="kube_statefulset_replicas", namespace="shop", statefulset="db"}`:                                                                                                                                                                                     1,
		`{__name__="kube_statefulset_status_replicas_ready", namespace="shop", statefulset="db"}`:                                                                                                                                                                        1,
		`{__name__="kube_daemonset_status_desired_number_scheduled", daemonset="agent", namespace="shop"}`:                                                                                                                                                               2,
		`{__name__="kube_daemonset_status_number_ready", daemonset="agent", namespace="shop"}`:                                                                                                                                                                           1,
		`{__name__="kube_job_status_failed", job_name="migrate", namespace="shop"}`:                                                                                                                                                                                      2,
		`{__name__="kube_persistentvolumeclaim_status_phase", namespace="shop", persistentvolumeclaim="data", phase="Bound"}`:                                                                                                                                            1,
		`{__name__="kube_persistentvolumeclaim_status_phase", namespace="shop", persistentvolumeclaim="data", phase="Lost"}`:                                                                                                                                             0,
		`{__name__="kube_persistentvolumeclaim_resource_requests_storage_bytes", namespace="shop", persistentvolumeclaim="data"}`:                                                                                                                                        10 << 30,
		`{__name__="kube_persistentvolumeclaim_info", namespace="shop", persistentvolumeclaim="data", storageclass="fast", volumemode="Filesystem", volumename="pv-data"}`:                                                                                               1,
	}
	for k, v := range want {
		got, ok := idx[k]
		if !ok || got != v {
			t.Errorf("series %s = %v (present %v), want %v", k, got, ok, v)
		}
	}
	subset := PublishedSubset()
	specs := map[string]SeriesSpec{}
	for _, s := range KubeSeriesCatalog() {
		specs[s.Name] = s
	}
	produced := map[string]bool{}
	for _, s := range series {
		name := s.Labels.Get(model.MetricNameLabel)
		produced[name] = true
		if !subset[name] || s.T != 1000 {
			t.Fatalf("series %s outside the subset or wrong time", s.Labels)
		}
		s.Labels.Range(func(l labels.Label) {
			if l.Name != model.MetricNameLabel && !slices.Contains(specs[name].Labels, l.Name) {
				t.Fatalf("series %s has undocumented label %s", name, l.Name)
			}
			if l.Value == "" {
				t.Fatalf("empty label %s", l.Name)
			}
		})
	}
	for name := range subset {
		if !produced[name] {
			t.Errorf("published series %s never produced", name)
		}
	}
	if len(subset) != len(kubeSeriesSpecs) || !subset["kube_pod_container_resource_limits"] || subset["kube_pod_created"] {
		t.Fatal("published subset map")
	}
}

func TestKubePodOwnerWithoutOwners(t *testing.T) {
	p := fixtureByUID(t, "pod-1")
	p.SetOwnerReferences(nil)
	series, err := PodSeriesFromPods(nil, []*unstructured.Unstructured{p}, 5)
	if err != nil {
		t.Fatal(err)
	}
	idx := seriesIndex(series)
	if idx[`{__name__="kube_pod_owner", namespace="shop", owner_is_controller="<none>", owner_kind="<none>", owner_name="<none>", pod="web-abc-1", uid="pod-1"}`] != 1 {
		t.Fatalf("owner none series missing: %v", idx)
	}
	if _, err := PodSeriesFromPods(nil, []*unstructured.Unstructured{fixtureByUID(t, "dep-1")}, 5); err == nil {
		t.Fatal("non-pod accepted")
	}
}

func podScoped(s []Series) []Series {
	var out []Series
	for _, x := range s {
		if strings.HasPrefix(x.Labels.Get(model.MetricNameLabel), "kube_pod_") {
			out = append(out, x)
		}
	}
	return out
}

func TestNodeScopedSubsetAndNodeDerivedParity(t *testing.T) {
	tr := fixtureState(t)
	all := KubeSeries(tr.Snapshot(), 42)
	scoped := NodeScoped(all, "node-a")
	for _, s := range scoped {
		name := s.Labels.Get(model.MetricNameLabel)
		switch {
		case strings.HasPrefix(name, "kube_pod_"):
			if s.Labels.Get("uid") != "pod-1" {
				t.Fatalf("pod series of another node: %s", s.Labels)
			}
		case strings.HasPrefix(name, "kube_node_"):
			if s.Labels.Get("node") != "node-a" {
				t.Fatalf("node series of another node: %s", s.Labels)
			}
		default:
			t.Fatalf("non node-scoped series %s", s.Labels)
		}
	}
	hasNode := false
	for _, s := range scoped {
		hasNode = hasNode || s.Labels.Get(model.MetricNameLabel) == "kube_node_info"
	}
	if !hasNode || len(NodeScoped(all, "node-z")) != 0 {
		t.Fatal("node scoping")
	}
	for _, node := range []string{"node-a", "node-b"} {
		var pods []*unstructured.Unstructured
		for _, u := range fixtureObjects(t) {
			if KindOf(u) == KindPod {
				if n, _, _ := unstructured.NestedString(u.Object, "spec", "nodeName"); n == node {
					pods = append(pods, u)
				}
			}
		}
		derived, err := PodSeriesFromPods(tr.Normalizer(), pods, 42)
		if err != nil {
			t.Fatal(err)
		}
		coord := podScoped(NodeScoped(all, node))
		if len(derived) == 0 || len(derived) != len(coord) {
			t.Fatalf("%s: derived %d series, coordinator %d", node, len(derived), len(coord))
		}
		for i := range derived {
			if labels.Compare(derived[i].Labels, coord[i].Labels) != 0 || derived[i].Value != coord[i].Value || derived[i].T != coord[i].T {
				t.Fatalf("%s: parity mismatch %s=%v vs %s=%v", node, derived[i].Labels, derived[i].Value, coord[i].Labels, coord[i].Value)
			}
		}
	}
}
