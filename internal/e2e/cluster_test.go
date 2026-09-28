package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/cloud-exit/exitmesh-agent/internal/state"
)

const (
	ns        = "shop"
	nodeA     = "node-a"
	nodeB     = "node-b"
	memLimit  = 256 << 20
	kubeToken = "kubelet-token"
	cpuBase   = 1000.0
	// cpuJump over the 5m rate window contributes about 0.6 cores per node against a threshold of 1.
	cpuJump = 180.0
)

var depGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

// podOf names the pod scheduled on each node.
var podOf = map[string]struct{ name, uid string }{nodeA: {"web-1", "pod-1"}, nodeB: {"web-2", "pod-2"}}

func typedObjects() []runtime.Object {
	rep := int32(2)
	ctrl := true
	tmpl := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web", "pod-template-hash": "7d9f"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app", Image: "nginx:1.27", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: *resource.NewQuantity(memLimit, resource.BinarySI)}}},
			{Name: "sidecar", Image: "busybox:1.36"},
		}}}
	objs := []runtime.Object{
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns, UID: "dep-web", ResourceVersion: "1", Generation: 1, Labels: map[string]string{"app": "web"}},
			Spec:       appsv1.DeploymentSpec{Replicas: &rep, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Template: tmpl},
			Status:     appsv1.DeploymentStatus{Replicas: 2, AvailableReplicas: 2, ReadyReplicas: 2, UpdatedReplicas: 2, ObservedGeneration: 1},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: "web-7d9f", Namespace: ns, UID: "rs-web", ResourceVersion: "1", Labels: map[string]string{"app": "web"},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: "dep-web", Controller: &ctrl}}},
			Spec:   appsv1.ReplicaSetSpec{Replicas: &rep, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Template: tmpl},
			Status: appsv1.ReplicaSetStatus{Replicas: 2, ReadyReplicas: 2, AvailableReplicas: 2},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns, UID: "svc-web", ResourceVersion: "1"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Name: "http", Port: 80}}},
		},
	}
	for _, n := range []string{nodeA, nodeB} {
		objs = append(objs, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: n, UID: types.UID("uid-" + n), ResourceVersion: "1"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Capacity: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("8Gi")}},
		})
		p := podOf[n]
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: ns, UID: types.UID(p.uid), ResourceVersion: "1", Labels: tmpl.Labels,
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-7d9f", UID: "rs-web", Controller: &ctrl}}},
			Spec:   *tmpl.Spec.DeepCopy(),
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1", HostIP: "10.1.0.1"},
		}
		pod.Spec.NodeName = n
		for _, c := range pod.Spec.Containers {
			pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{Name: c.Name, Ready: true, Image: c.Image})
		}
		objs = append(objs, pod)
	}
	return objs
}

// cluster is one set of fake objects served to the coordinator (dynamic, metadata, discovery) and to node agents (typed).
type cluster struct {
	dyn  *dynamicfake.FakeDynamicClient
	meta *metadatafake.FakeMetadataClient
	disc *discoveryfake.FakeDiscovery
	kube *kubefake.Clientset
	objs []runtime.Object
}

func toUnstructured(t testing.TB, obj runtime.Object) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{Object: m}
	switch obj.(type) {
	case *appsv1.Deployment:
		u.SetAPIVersion("apps/v1")
		u.SetKind("Deployment")
	case *appsv1.ReplicaSet:
		u.SetAPIVersion("apps/v1")
		u.SetKind("ReplicaSet")
	case *corev1.Service:
		u.SetAPIVersion("v1")
		u.SetKind("Service")
	case *corev1.Node:
		u.SetAPIVersion("v1")
		u.SetKind("Node")
	case *corev1.Pod:
		u.SetAPIVersion("v1")
		u.SetKind("Pod")
	}
	return u
}

func newCluster(t testing.TB) *cluster {
	listKinds := map[schema.GroupVersionResource]string{}
	for _, s := range state.Catalog() {
		listKinds[s.GVR] = s.APIKind + "List"
	}
	c := &cluster{objs: typedObjects(), disc: &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{}}}
	var us []runtime.Object
	for _, o := range c.objs {
		us = append(us, toUnstructured(t, o))
	}
	c.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, us...)
	ms := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(ms); err != nil {
		t.Fatal(err)
	}
	c.meta = metadatafake.NewSimpleMetadataClient(ms)
	byGV := map[string]*metav1.APIResourceList{}
	for _, s := range state.Catalog() {
		gv := s.GVR.GroupVersion().String()
		if byGV[gv] == nil {
			byGV[gv] = &metav1.APIResourceList{GroupVersion: gv}
			c.disc.Resources = append(c.disc.Resources, byGV[gv])
		}
		byGV[gv].APIResources = append(byGV[gv].APIResources, metav1.APIResource{Name: s.GVR.Resource, Kind: s.APIKind, Namespaced: s.Namespaced, Verbs: metav1.Verbs{"get", "list", "watch"}})
	}
	c.kube = kubefake.NewClientset(c.objs...)
	return c
}

// setDeploymentImage updates the deployment's pod template in both fakes, as an API server update would.
func (c *cluster) setDeploymentImage(t testing.TB, image string) {
	t.Helper()
	d, err := c.kube.AppsV1().Deployments(ns).Get(t.Context(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	d = d.DeepCopy()
	d.Spec.Template.Spec.Containers[0].Image = image
	d.Generation++
	d.ResourceVersion = fmt.Sprint(time.Now().UnixNano())
	if _, err := c.kube.AppsV1().Deployments(ns).Update(t.Context(), d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.dyn.Tracker().Update(depGVR, toUnstructured(t, d), ns); err != nil {
		t.Fatal(err)
	}
}

// kubelet serves kubelet and cadvisor metrics for one node behind bearer authentication.
type kubelet struct {
	mu      sync.Mutex
	pod     string
	mem     float64
	cpuInc  bool
	scrapes int
	srv     *httptest.Server
}

func newKubelet(t testing.TB, pod string, cpuInc bool) *kubelet {
	k := &kubelet{pod: pod, mem: memLimit / 2, cpuInc: cpuInc}
	k.srv = httptest.NewTLSServer(k)
	t.Cleanup(k.srv.Close)
	return k
}

func (k *kubelet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+kubeToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if r.URL.Path != "/metrics/cadvisor" {
		_, _ = w.Write([]byte("# TYPE kubelet_running_pods gauge\nkubelet_running_pods 1\n"))
		return
	}
	k.mu.Lock()
	k.scrapes++
	cpu := cpuBase
	if k.cpuInc && k.scrapes > 1 {
		cpu += cpuJump
	}
	lbl := fmt.Sprintf(`container="app",namespace=%q,pod=%q,id="/kubepods/%s/app"`, ns, k.pod, k.pod)
	body := fmt.Sprintf("# TYPE container_memory_working_set_bytes gauge\ncontainer_memory_working_set_bytes{%s} %g\n"+
		"# TYPE container_cpu_usage_seconds_total counter\ncontainer_cpu_usage_seconds_total{%s} %g\n", lbl, k.mem, lbl, cpu)
	k.mu.Unlock()
	_, _ = w.Write([]byte(body))
}

func (k *kubelet) setMem(v float64) {
	k.mu.Lock()
	k.mem = v
	k.mu.Unlock()
}

func (k *kubelet) startCPU() {
	k.mu.Lock()
	k.cpuInc = true
	k.mu.Unlock()
}

func (k *kubelet) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.scrapes
}
