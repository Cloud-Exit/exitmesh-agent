package state

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func typedU(t *testing.T, obj runtime.Object, apiVersion, kind string) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	return u
}

func TestHostPortsAndNodePorts(t *testing.T) {
	n, _ := NewNormalizer(Options{})
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "proxy", Image: "envoy:1", Ports: []corev1.ContainerPort{
		{Name: "https", ContainerPort: 8443, HostPort: 443},
		{ContainerPort: 9901, HostPort: 9901, HostIP: "127.0.0.1", Protocol: corev1.ProtocolUDP},
		{Name: "metrics", ContainerPort: 9100},
	}}}}}
	pod.Name, pod.Namespace, pod.UID = "edge-1", "shop", "pod-edge"
	r, _, err := n.Normalize(typedU(t, pod, "v1", "Pod"))
	if err != nil {
		t.Fatal(err)
	}
	if got := dump(r.Fields["containers.proxy.hostPorts"]); got != dump([]any{"127.0.0.1:9901/UDP->9901", "https:443/TCP->8443"}) {
		t.Fatalf("hostPorts %s", got)
	}
	svc := &corev1.Service{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: map[string]string{"app": "edge"}, Ports: []corev1.ServicePort{
		{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080), NodePort: 30080},
		{Port: 53, Protocol: corev1.ProtocolUDP, NodePort: 30053},
		{Name: "internal", Port: 9000},
	}}}
	svc.Name, svc.Namespace, svc.UID = "edge", "shop", "svc-edge"
	r, _, err = n.Normalize(typedU(t, svc, "v1", "Service"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Fields["type"] != "NodePort" || dump(r.Fields["nodePorts"]) != dump([]any{"30053/UDP", "http:30080/TCP"}) {
		t.Fatalf("service fields %v", r.Fields)
	}
	svc.Spec.Type, svc.Spec.Ports = corev1.ServiceTypeClusterIP, svc.Spec.Ports[2:]
	if r, _, _ = n.Normalize(typedU(t, svc, "v1", "Service")); r.Fields["nodePorts"] != nil {
		t.Fatalf("ClusterIP service exported nodePorts %v", r.Fields)
	}
}

func routeObject(kind, name, uid string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": "shop", "uid": uid},
		"spec":     spec,
	}}
	if kind == "TLSRoute" {
		u.SetAPIVersion("gateway.networking.k8s.io/v1alpha2")
	}
	return u
}

func TestGatewayRoutesProjectRoutesEdges(t *testing.T) {
	n, _ := NewNormalizer(Options{})
	for _, k := range []struct{ kind, res string }{{"Gateway", "gateways"}, {"HTTPRoute", "httproutes"}, {"TLSRoute", "tlsroutes"}} {
		n.registerCustom(schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: k.res}, k.kind, true)
	}
	gw := routeObject("Gateway", "public", "gw-1", map[string]any{"gatewayClassName": "envoy", "listeners": []any{map[string]any{"name": "https", "port": int64(443), "protocol": "HTTPS"}}})
	gw.SetNamespace("infra")
	http := routeObject("HTTPRoute", "web", "hr-1", map[string]any{
		"parentRefs": []any{map[string]any{"name": "public", "namespace": "infra", "sectionName": "https"}, map[string]any{"group": "", "kind": "Service", "name": "mesh"}},
		"hostnames":  []any{"shop.example.com", "www.shop.example.com"},
		"rules": []any{
			map[string]any{
				"backendRefs": []any{map[string]any{"name": "web", "port": int64(80), "weight": int64(90)}, map[string]any{"name": "api", "namespace": "other", "port": int64(8080)}},
				"filters":     []any{map[string]any{"type": "RequestHeaderModifier", "requestHeaderModifier": map[string]any{"set": []any{map[string]any{"name": "Authorization", "value": "Bearer private-value-sentinel"}}}}},
			},
			map[string]any{"backendRefs": []any{map[string]any{"group": "example.com", "kind": "Bucket", "name": "static"}}},
		},
	})
	tls := routeObject("TLSRoute", "db", "tr-1", map[string]any{
		"parentRefs": []any{map[string]any{"name": "public", "namespace": "infra"}},
		"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "web", "port": int64(443)}}}},
	})
	web := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 80}}}}
	web.Name, web.Namespace, web.UID = "web", "shop", "svc-web"
	api := &corev1.Service{Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}}}
	api.Name, api.Namespace, api.UID = "api", "other", "svc-api"
	objs := []*unstructured.Unstructured{gw, http, tls, typedU(t, web, "v1", "Service"), typedU(t, api, "v1", "Service")}
	want := map[protocol.EdgeKey]string{
		{From: "gw-1", Type: EdgeRoutes, To: "hr-1"}:    `{}`,
		{From: "gw-1", Type: EdgeRoutes, To: "tr-1"}:    `{}`,
		{From: "hr-1", Type: EdgeRoutes, To: "svc-web"}: `{"ports":["80"]}`,
		{From: "hr-1", Type: EdgeRoutes, To: "svc-api"}: `{"ports":["8080"]}`,
		{From: "tr-1", Type: EdgeRoutes, To: "svc-web"}: `{"ports":["443"]}`,
	}
	for _, order := range [][]int{{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}} {
		tr := NewTracker(TrackerOptions{Normalizer: n})
		for _, i := range order {
			if _, err := tr.Upsert(objs[i].DeepCopy()); err != nil {
				t.Fatal(err)
			}
		}
		st := tr.Snapshot()
		got := map[protocol.EdgeKey]string{}
		for k, v := range st.Edges {
			if k.Type == EdgeRoutes {
				b, _ := json.Marshal(v)
				got[k] = string(b)
			}
		}
		if dump(got) != dump(want) {
			t.Fatalf("routes edges %v, want %v", got, want)
		}
		hr := st.Resources["hr-1"].Fields
		if dump(hr["parentRefs"]) != dump([]any{"Gateway:infra/public#https", "Service:shop/mesh"}) ||
			dump(hr["backends"]) != dump([]any{"Bucket.example.com:shop/static", "other/api:8080", "web:80"}) ||
			dump(hr["hostnames"]) != dump([]any{"shop.example.com", "www.shop.example.com"}) {
			t.Fatalf("HTTPRoute fields %v", hr)
		}
		if f := st.Resources["tr-1"].Fields; dump(f["parentRefs"]) != dump([]any{"Gateway:infra/public"}) || dump(f["backends"]) != dump([]any{"web:443"}) {
			t.Fatalf("TLSRoute fields %v", f)
		}
		b, _ := json.Marshal(st.Resources)
		if strings.Contains(string(b), "sentinel") {
			t.Fatal("route filter values entered state")
		}
		if _, err := tr.Remove(typedU(t, web, "v1", "Service")); err != nil {
			t.Fatal(err)
		}
		for k := range tr.Snapshot().Edges {
			if k.To == "svc-web" {
				t.Fatalf("edge %v outlived its Service", k)
			}
		}
		changed := http.DeepCopy()
		_ = unstructured.SetNestedSlice(changed.Object, []any{map[string]any{"name": "public", "namespace": "elsewhere"}}, "spec", "parentRefs")
		if _, err := tr.Upsert(changed); err != nil {
			t.Fatal(err)
		}
		if _, ok := tr.Snapshot().Edges[protocol.EdgeKey{From: "gw-1", Type: EdgeRoutes, To: "hr-1"}]; ok {
			t.Fatal("reparented route kept its Gateway edge")
		}
	}
	u := http.DeepCopy()
	Transform(n, KindOf(u))(u)
	b, _ := json.Marshal(u)
	if strings.Contains(string(b), "sentinel") || strings.Contains(string(b), "filters") {
		t.Fatalf("route filters survived the cache transform: %s", b)
	}
	if refs, _, _ := unstructured.NestedSlice(u.Object, "spec", "rules"); len(refs) != 2 {
		t.Fatalf("route backend references dropped by the cache transform: %s", b)
	}
}
