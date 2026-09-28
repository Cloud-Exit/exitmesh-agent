package state

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func allFieldsNormalizer(t testing.TB) *Normalizer {
	t.Helper()
	var sel []string
	for _, s := range catalog {
		for _, fd := range s.Fields {
			if !fd.Default {
				sel = append(sel, s.Kind+":"+fd.Path)
			}
		}
	}
	n, err := NewNormalizer(Options{Fields: sel})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func dump(v any) string { return fmt.Sprintf("%#v", v) }

func mustNormalize(t testing.TB, n *Normalizer, u *unstructured.Unstructured) protocol.Resource {
	t.Helper()
	r, _, err := n.Normalize(u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNormalizeEveryKindExcludesSensitiveAndChurn(t *testing.T) {
	seen := map[string]bool{}
	for _, u := range fixtureObjects(t) {
		r := mustNormalize(t, defaultNormalizer, u)
		seen[r.Kind] = true
		spec := catalogByKind[r.Kind]
		if r.UID != string(u.GetUID()) || r.Name != u.GetName() {
			t.Fatalf("identity %+v", r)
		}
		if spec.Namespaced != (r.Namespace != "") {
			t.Fatalf("%s namespace %q", r.Kind, r.Namespace)
		}
		for k, v := range r.Fields {
			matched := false
			for _, fd := range spec.Fields {
				if PathPattern(fd.Path).MatchString(k) {
					matched = true
					if !fd.Default {
						t.Fatalf("%s: non-default field %s exported without selection", r.Kind, k)
					}
				}
			}
			if !matched {
				t.Fatalf("%s: field %s not in catalog", r.Kind, k)
			}
			if v == nil {
				t.Fatalf("%s: null field %s", r.Kind, k)
			}
		}
		text := dump(r.Fields)
		for _, bad := range []string{"managedFields", "resourceVersion", "12345", secretLiteral, secretCMValue, "hunter2",
			"payments-internal", "example.com/owner", "last-applied", "kubelet is posting", "lastHeartbeat", "Deployment does not have",
			"back-off", "healthz", "arn:aws:kms", "s3cr3t", "free text", "oom\""} {
			if strings.Contains(text, bad) {
				t.Fatalf("%s leaked %q in %s", r.Kind, bad, text)
			}
		}
		if _, err := protocol.NormalizeFields(r.Fields, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range catalog {
		if !s.Aggregated && !seen[s.Kind] {
			t.Fatalf("no fixture for %s", s.Kind)
		}
	}
}

func TestNormalizeValues(t *testing.T) {
	get := func(uid string) map[string]any {
		return mustNormalize(t, defaultNormalizer, fixtureByUID(t, uid)).Fields
	}
	pod := get("pod-1")
	want := map[string]any{
		"phase": "Running", "nodeName": "node-a", "ready": true, "hostNetwork": false, "qosClass": "Burstable",
		"labels.app": "web", "owners.ReplicaSet.web-abc": true, "conditions.Ready.status": "True",
		"conditions.PodScheduled.reason": "Scheduled",
		"containers.app.image":           "nginx:1.25", "containers.app.imageID": "docker.io/library/nginx@sha256:2222",
		"containers.app.restarts": int64(2), "containers.app.state": "running",
		"containers.app.lastTerminatedReason": "OOMKilled", "containers.app.lastTerminatedExitCode": int64(137),
		"containers.app.requests.cpu": 0.25, "containers.app.requests.memory": float64(128 << 20),
		"containers.app.requests.nvidia.com/gpu": float64(1), "containers.app.limits.cpu": float64(1),
		"initContainers.init.terminatedReason": "Completed", "initContainers.init.terminatedExitCode": int64(0),
		"created": fixtureTime.UnixMilli(), "serviceAccountName": "web", "priorityClassName": "high",
	}
	for k, v := range want {
		if !protocol.ValueEqual(pod[k], v) {
			t.Fatalf("pod %s = %#v, want %#v", k, pod[k], v)
		}
	}
	list := func(f map[string]any, k string) string { return dump(f[k]) }
	if got := list(pod, "containers.app.envRefs"); !strings.Contains(got, "API_TOKEN=secret:web-secret/token") ||
		!strings.Contains(got, "MODE=configMap:web-config/mode") || strings.Contains(got, "DB_PASSWORD") {
		t.Fatalf("envRefs %s", got)
	}
	if got := list(pod, "refs.claims"); got != dump([]any{"data", "web-abc-1-scratch"}) {
		t.Fatalf("claims %s", got)
	}
	if got := list(pod, "refs.secrets"); got != dump([]any{"init-secret", "regcred", "tls", "web-env-secret", "web-secret"}) {
		t.Fatalf("secrets %s", got)
	}
	if got := list(pod, "containers.app.ports"); got != dump([]any{"9090/UDP", "http:8080/TCP"}) {
		t.Fatalf("ports %s", got)
	}
	for _, k := range []string{"containers.app.args", "containers.app.command", "conditions.example.com/gate.status", "labels.team", "labels.pod-template-hash"} {
		if _, ok := pod[k]; ok {
			t.Fatalf("pod exports %s", k)
		}
	}
	waiting := get("pod-2")
	if waiting["containers.app.waitingReason"] != "CrashLoopBackOff" || waiting["ready"] != false {
		t.Fatalf("waiting pod %v", waiting)
	}
	node := get("node-1")
	for k, v := range map[string]any{
		"capacity.cpu": float64(4), "allocatable.cpu": 3.8, "capacity.memory": float64(16 << 30), "kubeletVersion": "v1.34.1",
		"zone": "eu-west-1a", "region": "eu-west-1", "labels.node-role.kubernetes.io/worker": "", "labels.topology.kubernetes.io/zone": "eu-west-1a",
		"conditions.Ready.status": "True", "conditions.Ready.reason": "KubeletReady", "internalIP": "10.0.0.1", "unschedulable": false,
	} {
		if !protocol.ValueEqual(node[k], v) {
			t.Fatalf("node %s = %#v, want %#v", k, node[k], v)
		}
	}
	if _, ok := node["labels.kubernetes.io/hostname"]; ok {
		t.Fatal("non-allowlisted node label exported")
	}
	if dump(node["taints"]) != dump([]any{"dedicated=gpu:NoSchedule"}) {
		t.Fatalf("taints %v", node["taints"])
	}
	dep := get("dep-1")
	if dep["replicas"] != int64(3) || dep["unavailableReplicas"] != int64(1) || dep["conditions.Available.status"] != "False" || dep["containers.app.image"] != "nginx:1.25" {
		t.Fatalf("deployment %v", dep)
	}
	svc := get("svc-1")
	if svc["hasSelector"] != true || dump(svc["ports"]) != dump([]any{"http:80/TCP->http"}) {
		t.Fatalf("service %v", svc)
	}
	if _, ok := svc["selector"]; ok {
		t.Fatal("service selector exported without selection")
	}
	ing := get("ing-1")
	if dump(ing["backends"]) != dump([]any{"web:http"}) || dump(ing["hosts"]) != dump([]any{"shop.example.com"}) || ing["tls"] != true {
		t.Fatalf("ingress %v", ing)
	}
	np := get("np-1")
	if np["podSelector"] != "app=web" || dump(np["policyTypes"]) != dump([]any{"Ingress"}) || np["ingressRules"] != int64(1) {
		t.Fatalf("netpol %v", np)
	}
	pv := get("pv-1")
	if pv["nodeAffinity"] != "kubernetes.io/hostname in (node-a)" || pv["driver"] != "local" || pv["claim"] != "shop/data" {
		t.Fatalf("pv %v", pv)
	}
	pvc := get("pvc-1")
	if pvc["requests.storage"] != float64(10<<30) || pvc["volumeName"] != "pv-data" || pvc["phase"] != "Bound" {
		t.Fatalf("pvc %v", pvc)
	}
	sc := get("sc-1")
	if sc["isDefault"] != true || sc["provisioner"] != "ebs.csi.aws.com" {
		t.Fatalf("storageclass %v", sc)
	}
	hpa := get("hpa-1")
	if hpa["target.kind"] != KindDeployment || hpa["target.name"] != "web" || hpa["minReplicas"] != int64(2) {
		t.Fatalf("hpa %v", hpa)
	}
	pdb := get("pdb-1")
	if pdb["selector"] != "app in (web)" || pdb["minAvailable"] != "1" || pdb["maxUnavailable"] != "50%" {
		t.Fatalf("pdb %v", pdb)
	}
	cm := get("cm-1")
	if _, ok := cm["keys"]; ok {
		t.Fatalf("configmap keys exported by default: %v", cm)
	}
}

func TestCatalogFieldsAllProducedWhenSelected(t *testing.T) {
	n := allFieldsNormalizer(t)
	n.annotations = []string{"example.com/*"}
	emitted := map[string][]string{}
	for _, u := range fixtureObjects(t) {
		if len(u.GetOwnerReferences()) == 0 {
			u.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Owner", Name: "o", UID: "o-1"}})
		}
		r := mustNormalize(t, n, u)
		for k := range r.Fields {
			emitted[r.Kind] = append(emitted[r.Kind], k)
		}
	}
	for _, s := range catalog {
		if s.Aggregated {
			continue
		}
		for _, fd := range s.Fields {
			if fd.Path == "terminating" {
				continue
			}
			re := PathPattern(fd.Path)
			found := false
			for _, k := range emitted[s.Kind] {
				if re.MatchString(k) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: catalog field %s is never produced", s.Kind, fd.Path)
			}
		}
	}
	del := fixtureByUID(t, "pod-1")
	del.SetDeletionTimestamp(&fixtureTime)
	if r := mustNormalize(t, n, del); r.Fields["terminating"] != true {
		t.Fatal("terminating not produced")
	}
}

func TestSelectedFreeTextIsRedacted(t *testing.T) {
	n, err := NewNormalizer(Options{Fields: []string{
		"apps/Deployment:containers.<container>.args", "apps/Deployment:containers.<container>.command",
		"Service:externalName", "storage.k8s.io/StorageClass:parameters.<key>", "ConfigMap:keys",
	}})
	if err != nil {
		t.Fatal(err)
	}
	dep := mustNormalize(t, n, fixtureByUID(t, "dep-1")).Fields
	args := dump(dep["containers.app.args"])
	if !strings.Contains(args, "postgres://admin:<redacted>@db:5432/app") || strings.Contains(args, "hunter2") || !strings.Contains(args, "--verbose") {
		t.Fatalf("args %s", args)
	}
	if dump(dep["containers.app.command"]) != dump([]any{"/app/server"}) {
		t.Fatalf("command %v", dep["containers.app.command"])
	}
	if _, ok := dep["initContainers.init.args"]; ok {
		t.Fatal("unselected init args exported")
	}
	ext := mustNormalize(t, n, fixtureByUID(t, "svc-2")).Fields
	if ext["externalName"] != "https://user:<redacted>@payments.example.com" {
		t.Fatalf("externalName %v", ext["externalName"])
	}
	sc := mustNormalize(t, n, fixtureByUID(t, "sc-1")).Fields
	if sc["parameters.type"] != "gp3" || sc["parameters.kmsKeyId"] != "arn:aws:kms:key/abc" {
		t.Fatalf("parameters %v", sc)
	}
	cm := mustNormalize(t, n, fixtureByUID(t, "cm-1")).Fields
	if dump(cm["keys"]) != dump([]any{"cert.der", "db.password", "mode"}) || strings.Contains(dump(cm), secretCMValue) || strings.Contains(dump(cm), "prod") {
		t.Fatalf("configmap %v", cm)
	}
}

func TestAllowlists(t *testing.T) {
	n, err := NewNormalizer(Options{LabelAllowlist: []string{"team", "pod-*"}, AnnotationAllowlist: []string{"example.com/*"}})
	if err != nil {
		t.Fatal(err)
	}
	u := fixtureByUID(t, "pod-1")
	ann := u.GetAnnotations()
	ann["example.com/api-token"] = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	u.SetAnnotations(ann)
	f := mustNormalize(t, n, u).Fields
	if f["labels.team"] != "payments-internal" || f["labels.pod-template-hash"] != "abc" || f["annotations.example.com/owner"] != "alice" {
		t.Fatalf("allowlisted %v", f)
	}
	if f["annotations.example.com/api-token"] != "<redacted>" {
		t.Fatalf("secret annotation %v", f["annotations.example.com/api-token"])
	}
	if _, ok := f["labels.app"]; ok {
		t.Fatal("label outside the configured allowlist exported")
	}
	if _, ok := f["annotations.kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Fatal("annotation outside the allowlist exported")
	}
}

func TestOwnerEdgesAndErrors(t *testing.T) {
	_, edges, err := Normalize(fixtureByUID(t, "pod-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].From != "rs-1" || edges[0].To != "pod-1" || edges[0].Type != EdgeOwns || edges[0].Attrs["controller"] != true {
		t.Fatalf("edges %+v", edges)
	}
	crd := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "example.com/v1", "kind": "Widget",
		"metadata": map[string]any{"name": "w", "namespace": "shop", "uid": "w-1"}}}
	if _, _, err := Normalize(crd); !errors.Is(err, ErrUnsupportedKind) {
		t.Fatalf("crd: %v", err)
	}
	if _, _, err := Normalize(warningEvent("e1", "pod-1", "BackOff", 1, fixtureTime.Time)); !errors.Is(err, ErrAggregatedKind) {
		t.Fatalf("event: %v", err)
	}
	noUID := fixtureByUID(t, "pod-1")
	noUID.SetUID("")
	if _, _, err := Normalize(noUID); err == nil {
		t.Fatal("object without uid accepted")
	}
	if _, err := NewNormalizer(Options{Fields: []string{"Pod:nope"}}); err == nil {
		t.Fatal("unknown field accepted")
	}
	if KindOf(fixtureByUID(t, "dep-1")) != KindDeployment || KindOf(fixtureByUID(t, "pod-1")) != KindPod {
		t.Fatal("kind strings")
	}
}
