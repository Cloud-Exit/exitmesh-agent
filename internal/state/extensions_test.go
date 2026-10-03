package state

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func extensionObject(kind, name, uid string) *unstructured.Unstructured {
	group, k, ok := strings.Cut(kind, "/")
	version := "v1"
	if !ok {
		k, group = group, ""
	} else {
		version = group + "/v1"
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": version, "kind": k, "metadata": map[string]any{"name": name, "namespace": "shop", "uid": uid}}}
}

func TestSecretValuesNeverEnterStateAndHelmMetadataSurvives(t *testing.T) {
	n, _ := NewNormalizer(Options{AnnotationAllowlist: []string{"*"}})
	u := extensionObject(KindSecret, "sh.helm.release.v1.demo.v4", "sec")
	u.Object["data"] = map[string]any{"password": "private-value-sentinel", "release": "encoded-release-sentinel"}
	u.Object["stringData"] = map[string]any{"password": "private-value-sentinel"}
	u.SetAnnotations(map[string]string{"copied": "private-value-sentinel"})
	u.SetLabels(map[string]string{"owner": "helm", "name": "demo", "version": "4", "status": "failed"})
	tr := NewTracker(TrackerOptions{Normalizer: n})
	if _, err := tr.Upsert(u); err != nil {
		t.Fatal(err)
	}
	r := tr.Snapshot().Resources["sec"]
	if r.Fields["helm.name"] != "demo" || r.Fields["helm.status"] != "failed" {
		t.Fatalf("missing release metadata: %v", r.Fields)
	}
	b, _ := json.Marshal(tr.Snapshot())
	if strings.Contains(string(b), "sentinel") || strings.Contains(string(b), "annotations.copied") {
		t.Fatal("Secret payload entered state")
	}
	pm := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"copied": "private-value-sentinel"}}}
	Transform(n, KindSecret)(pm)
	if len(pm.Annotations) != 0 {
		t.Fatal("Secret annotations survived metadata transform")
	}
	Transform(n, KindSecret)(u)
	b, _ = json.Marshal(u)
	if strings.Contains(string(b), "sentinel") || u.Object["data"] != nil || u.Object["stringData"] != nil {
		t.Fatal("Secret payload survived cache transform")
	}
}

func TestExternalSecretConditionsAndDependencyEdges(t *testing.T) {
	n, _ := NewNormalizer(Options{})
	gvr := schema.GroupVersionResource{Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets"}
	n.registerCustom(gvr, "ExternalSecret", true)
	u := extensionObject("external-secrets.io/ExternalSecret", "db-creds", "ext")
	u.SetGeneration(4)
	u.Object["spec"] = map[string]any{"target": map[string]any{"name": "db"}, "secretStoreRef": map[string]any{"name": "vault", "kind": "SecretStore"}, "data": []any{map[string]any{"literal": "private-value-sentinel"}}}
	u.Object["status"] = map[string]any{"observedGeneration": int64(3), "credentials": "private-value-sentinel", "conditions": []any{map[string]any{"type": "Ready", "status": "False", "reason": "SecretSyncedError", "observedGeneration": int64(3), "message": "private-value-sentinel"}}}
	dep := extensionObject(KindDeployment, "web", "dep")
	dep.Object["spec"] = map[string]any{}
	_ = unstructured.SetNestedSlice(dep.Object, []any{map[string]any{"name": "web", "image": "web:v1", "envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "db"}}}}}, "spec", "template", "spec", "containers")
	secret := extensionObject(KindSecret, "db", "sec")
	for _, order := range [][]*unstructured.Unstructured{{u, dep, secret}, {secret, dep, u}} {
		tr := NewTracker(TrackerOptions{Normalizer: n})
		for _, obj := range order {
			if _, err := tr.Upsert(obj); err != nil {
				t.Fatal(err)
			}
		}
		st := tr.Snapshot()
		r := st.Resources["ext"]
		if r.Fields["conditions.Ready.status"] != "False" || r.Fields["targetSecret"] != "db" || r.Fields["conditions.Ready.observedGeneration"] == nil {
			t.Fatalf("missing custom health fields: %v", r.Fields)
		}
		for _, edge := range []protocol.EdgeKey{{From: "dep", Type: EdgeUsesSecret, To: "sec"}, {From: "ext", Type: EdgeProducesSecret, To: "sec"}, {From: "dep", Type: EdgeNeedsSecretSync, To: "ext"}} {
			if _, ok := st.Edges[edge]; !ok {
				t.Fatalf("missing edge %v", edge)
			}
		}
		b, _ := json.Marshal(st)
		if strings.Contains(string(b), "sentinel") {
			t.Fatal("custom payload leaked")
		}
		if _, err := tr.Remove(secret); err != nil {
			t.Fatal(err)
		}
		if len(tr.Snapshot().Edges) != 1 || tr.Snapshot().Resources["ext"].Fields["targetSecret"] != "db" {
			t.Fatal("deletion lost unresolved dependency or retained stale edge")
		}
		changed := u.DeepCopy()
		_ = unstructured.SetNestedField(changed.Object, "other", "spec", "target", "name")
		if _, err := tr.Upsert(changed); err != nil {
			t.Fatal(err)
		}
		if len(tr.Snapshot().Edges) != 0 {
			t.Fatal("retargeted ExternalSecret retained stale dependency")
		}
	}
	Transform(n, KindOf(u))(u)
	b, _ := json.Marshal(u)
	if strings.Contains(string(b), "sentinel") {
		t.Fatal("custom payload survived cache transform")
	}
}

func TestSecretCollectionUsesOnlyMetadata(t *testing.T) {
	e := newTestEnv(t, nil)
	e.dyn.PrependReactor("*", "secrets", func(clienttesting.Action) (bool, runtime.Object, error) {
		t.Error("full Secret API used")
		return true, nil, nil
	})
	tr := NewTracker(TrackerOptions{})
	c, err := NewCollector(CollectorOptions{Dynamic: e.dyn, Metadata: e.meta, Tracker: tr, Resources: []string{"secrets"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case <-c.Synced():
	case <-time.After(5 * time.Second):
		t.Fatal("Secret metadata scope did not synchronize")
	}
	if len(e.meta.Actions()) == 0 {
		t.Fatal("metadata API not used")
	}
}

func TestCustomDiscoveryAddsAndRemovesScopes(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "widgets"}
	crd := extensionObject(KindCRD, "widgets.example.com", "crd")
	crd.SetNamespace("")
	crd.Object["spec"] = map[string]any{"group": "example.com", "scope": "Namespaced", "names": map[string]any{"kind": "Widget", "plural": "widgets"}, "versions": []any{map[string]any{"name": "v1", "served": true, "storage": true}}}
	widget := extensionObject("example.com/Widget", "one", "widget")
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{catalogByKind[KindCRD].GVR: "CustomResourceDefinitionList", gvr: "WidgetList"}, crd, widget)
	var forbidden atomic.Bool
	dyn.PrependReactor("list", "customresourcedefinitions", func(clienttesting.Action) (bool, runtime.Object, error) {
		if forbidden.Load() {
			return true, nil, apierrors.NewForbidden(catalogByKind[KindCRD].GVR.GroupResource(), "", errors.New("denied"))
		}
		return false, nil, nil
	})
	ticks := make(chan struct{}, 4)
	tr := NewTracker(TrackerOptions{})
	c := &Collector{o: CollectorOptions{Dynamic: dyn, Tracker: tr, Clock: time.Now, RetryBase: time.Millisecond, RetryMax: time.Second, Wait: func(ctx context.Context, _ time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-ticks:
			return true
		}
	}}, log: slog.New(&logRecorder{}), exclude: map[string]bool{}, pending: 1, syncedCh: make(chan struct{}), disc: map[string]discEntry{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { c.discoverCustom(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case <-c.Synced():
	case <-time.After(5 * time.Second):
		t.Fatal("custom discovery did not synchronize")
	}
	if tr.Snapshot().Resources["widget"] == nil {
		t.Fatal("default custom resource missing")
	}
	forbidden.Store(true)
	ticks <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	for tr.Snapshot().Scopes["inventory.exitmesh.io/CustomResourceDiscovery|"].State != protocol.ScopeUnavailable {
		if time.Now().After(deadline) {
			t.Fatal("discovery permission failure not reported")
		}
		time.Sleep(time.Millisecond)
	}
	if tr.Snapshot().Resources["widget"] == nil {
		t.Fatal("discovery failure deleted custom resources")
	}
	forbidden.Store(false)
	if err := dyn.Resource(catalogByKind[KindCRD].GVR).Delete(ctx, crd.GetName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	ticks <- struct{}{}
	deadline = time.Now().Add(5 * time.Second)
	for tr.Snapshot().Resources["widget"] != nil {
		if time.Now().After(deadline) {
			t.Fatal("removed CRD left resource behind")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := dyn.Resource(catalogByKind[KindCRD].GVR).Create(ctx, crd, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ticks <- struct{}{}
	deadline = time.Now().Add(5 * time.Second)
	for tr.Snapshot().Resources["widget"] == nil {
		if time.Now().After(deadline) {
			t.Fatal("newly installed CRD was not discovered")
		}
		time.Sleep(time.Millisecond)
	}
}

func extensionFixtures(t testing.TB) []*unstructured.Unstructured {
	t.Helper()
	secret := extensionObject(KindSecret, "demo", "helm-secret")
	cm := extensionObject(KindConfigMap, "demo", "helm-configmap")
	crd := extensionObject(KindCRD, "widgets.example.com", "widget-crd")
	crd.SetNamespace("")
	for _, u := range []*unstructured.Unstructured{secret, cm, crd} {
		u.SetCreationTimestamp(fixtureTime)
		u.SetLabels(map[string]string{"app": "web", "owner": "helm", "name": "demo", "version": "1", "status": "deployed"})
		u.SetAnnotations(map[string]string{"example.com/owner": "alice"})
	}
	crd.SetGeneration(1)
	crd.Object["spec"] = map[string]any{"group": "example.com", "scope": "Namespaced", "names": map[string]any{"kind": "Widget", "plural": "widgets"}, "versions": []any{map[string]any{"name": "v1", "served": true, "storage": true}}}
	crd.Object["status"] = map[string]any{"observedGeneration": int64(1), "conditions": []any{map[string]any{"type": "Established", "status": "True", "reason": "Accepted", "observedGeneration": int64(1)}}}
	return []*unstructured.Unstructured{secret, cm, crd}
}

func TestSecretHTTPNegotiationIsMetadataOnly(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(strconv.FormatBool(denied), func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/v1/secrets" || !strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata") {
					t.Error("Secret request did not demand metadata")
				}
				for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
					if !strings.Contains(part, "as=PartialObjectMetadata") {
						t.Error("Secret request permits a full-object fallback")
					}
				}
				if denied {
					w.WriteHeader(http.StatusNotAcceptable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadataList","metadata":{"resourceVersion":"1"},"items":[{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{"name":"demo","namespace":"shop","uid":"secret-1","labels":{"owner":"helm","name":"demo","version":"2","status":"failed"}}}]}`))
			}))
			defer srv.Close()
			mc, err := NewMetadataClient(&rest.Config{Host: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			n, _ := NewNormalizer(Options{})
			c := &Collector{o: CollectorOptions{Metadata: mc}, exclude: map[string]bool{}}
			sc := &scope{kind: KindSecret, spec: catalogByKind[KindSecret], metaOnly: true, tf: Transform(n, KindSecret)}
			obj, err := c.list(context.Background(), sc, metav1.ListOptions{})
			if denied {
				if err == nil || calls != 1 {
					t.Fatal("metadata negotiation failure did not fail closed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			list := obj.(*metav1.PartialObjectMetadataList)
			u := c.prepare(sc, &list.Items[0], true)
			r, _, err := n.Normalize(u)
			if err != nil {
				t.Fatal(err)
			}
			if r.Fields["helm.status"] != "failed" {
				t.Fatal("release status lost in metadata collection")
			}
		})
	}
}

func TestHelmRevisionLifecycle(t *testing.T) {
	tr := NewTracker(TrackerOptions{})
	for _, kind := range []string{KindSecret, KindConfigMap} {
		u := extensionObject(kind, "demo.v2", kind+"-release")
		for _, status := range []string{"pending-install", "deployed", "pending-upgrade", "failed", "superseded", "uninstalled"} {
			u.SetLabels(map[string]string{"owner": "helm", "name": "demo", "version": "2", "status": status})
			ops, err := tr.Upsert(u)
			if err != nil {
				t.Fatal(err)
			}
			if len(ops) == 0 || tr.Snapshot().Resources[string(u.GetUID())].Fields["helm.status"] != status {
				t.Fatal("release status transition lost")
			}
		}
		if _, err := tr.Remove(u); err != nil {
			t.Fatal(err)
		}
		if tr.Snapshot().Resources[string(u.GetUID())] != nil {
			t.Fatal("removed Helm revision still present")
		}
	}
}
