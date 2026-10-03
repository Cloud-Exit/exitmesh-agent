package state

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func extensionObject(kind, name, uid string) *unstructured.Unstructured {
	group, k, ok := strings.Cut(kind, "/")
	version := "v1"
	if !ok {
		k = group
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
	b, err := json.Marshal(tr.Snapshot().Resources)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sentinel") || strings.Contains(string(b), "annotations.copied") {
		t.Fatal("Secret payload entered state")
	}
	pm := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"copied": "private-value-sentinel"}}}
	Transform(n, KindSecret)(pm)
	if len(pm.Annotations) != 0 {
		t.Fatal("Secret annotations survived metadata transform")
	}
	Transform(n, KindSecret)(u)
	b, err = json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
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
		b, err := json.Marshal(st.Resources)
		if err != nil {
			t.Fatal(err)
		}
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
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
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

func customFixture() (*unstructured.Unstructured, *unstructured.Unstructured, schema.GroupVersionResource) {
	gvr := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "widgets"}
	crd := extensionObject(KindCRD, "widgets.example.com", "crd")
	crd.SetNamespace("")
	crd.Object["spec"] = map[string]any{"group": "example.com", "scope": "Namespaced", "names": map[string]any{"kind": "Widget", "plural": "widgets"}, "versions": []any{map[string]any{"name": "v1", "served": true, "storage": true}}}
	return crd, extensionObject("example.com/Widget", "one", "widget"), gvr
}

func customClient(crd, widget *unstructured.Unstructured, gvr schema.GroupVersionResource) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{catalogByKind[KindCRD].GVR: "CustomResourceDefinitionList", gvr: "WidgetList", catalogByKind[KindPod].GVR: "PodList"}, crd, widget)
}

func TestCustomDiscoveryAddsAndRemovesScopes(t *testing.T) {
	crd, widget, gvr := customFixture()
	dyn := customClient(crd, widget, gvr)
	tr := NewTracker(TrackerOptions{})
	c, cancel, done := startCollector(t, CollectorOptions{Dynamic: dyn, Tracker: tr, Resources: []string{"pods"}, Logger: slog.New(&logRecorder{})})
	defer func() { cancel(); <-done }()
	eventually(t, "custom resource with explicit built-in resources", func() bool { return tr.Snapshot().Resources["widget"] != nil })
	listCount := func() int {
		n := 0
		for _, a := range dyn.Actions() {
			if a.GetVerb() == "list" && a.GetResource().Resource == "customresourcedefinitions" {
				n++
			}
		}
		return n
	}
	before := listCount()
	c.fail(c.crdScope, apierrors.NewForbidden(catalogByKind[KindCRD].GVR.GroupResource(), "", errors.New("denied")))
	eventually(t, "discovery unavailable", func() bool {
		return tr.Snapshot().Scopes["inventory.exitmesh.io/CustomResourceDiscovery|"].State == protocol.ScopeUnavailable
	})
	if tr.Snapshot().Resources["widget"] == nil {
		t.Fatal("discovery failure deleted resources")
	}
	c.replace(c.crdScope, []any{crd.DeepCopy()})
	eventually(t, "discovery restored", func() bool {
		return tr.Snapshot().Scopes["inventory.exitmesh.io/CustomResourceDiscovery|"].State == protocol.ScopeComplete
	})
	if err := dyn.Resource(catalogByKind[KindCRD].GVR).Delete(context.Background(), crd.GetName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "CRD deletion", func() bool { return tr.Snapshot().Resources["widget"] == nil })
	if _, err := dyn.Resource(catalogByKind[KindCRD].GVR).Create(context.Background(), crd, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "CRD reinstallation", func() bool { return tr.Snapshot().Resources["widget"] != nil })
	if listCount() != before {
		t.Fatal("discovery performed additional CRD lists")
	}
}

func TestCustomDiscoveryDisabledIndependently(t *testing.T) {
	crd, widget, gvr := customFixture()
	dyn := customClient(crd, widget, gvr)
	disabled := false
	c, cancel, done := startCollector(t, CollectorOptions{Dynamic: dyn, Tracker: NewTracker(TrackerOptions{}), Resources: []string{"pods", KindCRD}, CustomResources: config.CustomResources{Enabled: &disabled}, Logger: slog.New(&logRecorder{})})
	cancel()
	<-done
	if c.discoveryWake != nil || c.discoveryStatus != nil {
		t.Fatal("disabled discovery started")
	}
	for _, a := range dyn.Actions() {
		if a.GetResource() == gvr {
			t.Fatal("disabled discovery read custom instances")
		}
	}
}

func TestCustomDiscoveryDoesNotGateInitialSync(t *testing.T) {
	crd, widget, gvr := customFixture()
	dyn := customClient(crd, widget, gvr)
	blocked := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	env := newTestEnv(t, nil)
	env.disc.Resources = append(env.disc.Resources, &metav1.APIResourceList{GroupVersion: gvr.GroupVersion().String(), APIResources: []metav1.APIResource{{Name: gvr.Resource, Kind: "Widget", Namespaced: true}}})
	slow := delayedDiscovery{DiscoveryInterface: env.disc, gv: gvr.GroupVersion().String(), started: started, blocked: blocked, once: &once}
	c, err := NewCollector(CollectorOptions{Dynamic: dyn, Discovery: slow, Tracker: NewTracker(TrackerOptions{}), Resources: []string{"pods"}, Logger: slog.New(&logRecorder{})})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	defer func() { close(blocked); cancel(); <-done }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("custom list never started")
	}
	select {
	case <-c.Synced():
	case <-time.After(time.Second):
		t.Fatal("custom list delayed built-in synchronization")
	}
}

func TestCustomDiscoveryFiltersAndBudgets(t *testing.T) {
	crd, _, _ := customFixture()
	c, err := NewCollector(CollectorOptions{Dynamic: customClient(crd, extensionObject("example.com/Widget", "one", "widget"), schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "widgets"}), Tracker: NewTracker(TrackerOptions{}), Resources: []string{"pods"}, Namespaces: []string{"a", "b", "excluded"}, ExcludeNamespaces: []string{"excluded"}, CustomResources: config.CustomResources{MaxKinds: 2, MaxScopes: 2, Include: []string{"example.com/*"}, Exclude: []string{"example.com/Skip"}}, Logger: slog.New(&logRecorder{})})
	if err != nil {
		t.Fatal(err)
	}
	c.crdScope.state = protocol.ScopeComplete
	for _, kind := range []string{"Alpha", "Beta", "Skip"} {
		u := crd.DeepCopy()
		_ = unstructured.SetNestedField(u.Object, kind, "spec", "names", "kind")
		c.crds[kind] = customSpec(u)
	}
	specs, ready := c.desiredCustom(nil)
	if !ready || len(specs) != 1 || specs["example.com/Alpha"] == nil {
		t.Fatal("scope cap or deterministic selection failed")
	}
	if c.discoveryStatus.state != protocol.ScopePartial {
		t.Fatal("limit not reported as partial coverage")
	}
	c.o.CustomResources.MaxScopes = 10
	c.o.CustomResources.MaxKinds = 1
	specs, _ = c.desiredCustom(nil)
	if len(specs) != 1 {
		t.Fatal("kind cap not enforced")
	}
	c.o.CustomResources.MaxKinds = 10
	specs, _ = c.desiredCustom(nil)
	if len(specs) != 2 || specs["example.com/Skip"] != nil {
		t.Fatal("exclude filter not honored")
	}
	c.o.CustomResources.Include = []string{"alphas.other.io"}
	specs, _ = c.desiredCustom(nil)
	if len(specs) != 0 {
		t.Fatal("include filter not honored")
	}
}

func TestCustomDiscoveryPreservesRunningKindsAtCapacity(t *testing.T) {
	for _, limits := range []struct {
		name          string
		kinds, scopes int
	}{{"kinds", 1, 10}, {"scopes", 10, 2}} {
		t.Run(limits.name, func(t *testing.T) {
			crd, obj, gvr := customFixture()
			c, err := NewCollector(CollectorOptions{Dynamic: customClient(crd, obj, gvr), Tracker: NewTracker(TrackerOptions{}), Resources: []string{"pods"}, Namespaces: []string{"a", "b"}, CustomResources: config.CustomResources{MaxKinds: limits.kinds, MaxScopes: limits.scopes}, Logger: slog.New(&logRecorder{})})
			if err != nil {
				t.Fatal(err)
			}
			c.crdScope.state = protocol.ScopeComplete
			beta := customSpec(crd)
			beta.Kind = "example.com/Beta"
			c.crds["beta"] = beta
			selected, _ := c.desiredCustom(nil)
			if selected[beta.Kind] == nil {
				t.Fatal("initial kind not selected")
			}
			workers := map[string]*customWorker{beta.Kind: {version: beta.GVR}}
			alpha := *beta
			alpha.Kind = "example.com/Alpha"
			c.crds["alpha"] = &alpha
			for range 3 {
				selected, _ = c.desiredCustom(workers)
				if len(selected) != 1 || selected[beta.Kind] == nil {
					t.Fatal("new kind displaced running inventory")
				}
				if c.discoveryStatus.state != protocol.ScopePartial {
					t.Fatal("omitted kind not reported")
				}
			}
			delete(c.crds, "alpha")
			selected, _ = c.desiredCustom(workers)
			if selected[beta.Kind] == nil || c.discoveryStatus.state != protocol.ScopeComplete {
				t.Fatal("removing waiting kind disrupted coverage")
			}
			c.crds["alpha"] = &alpha
			delete(c.crds, "beta")
			selected, _ = c.desiredCustom(workers)
			if len(selected) != 1 || selected[alpha.Kind] == nil {
				t.Fatal("vacated slot not filled")
			}
			c.crds["beta"] = beta
			c.o.CustomResources.Exclude = []string{beta.Kind}
			selected, _ = c.desiredCustom(workers)
			if len(selected) != 1 || selected[alpha.Kind] == nil {
				t.Fatal("running kind bypassed exclusion")
			}
		})
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
	for _, watching := range []bool{false, true} {
		for _, denied := range []bool{false, true} {
			t.Run("watch="+strconv.FormatBool(watching)+"/denied="+strconv.FormatBool(denied), func(t *testing.T) {
				var calls atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					want := "PartialObjectMetadataList"
					if watching {
						want = "PartialObjectMetadata"
					}
					if (r.URL.Query().Get("watch") == "true") != watching {
						t.Error("wrong request verb")
					}
					for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
						_, params, err := mime.ParseMediaType(strings.TrimSpace(part))
						if err != nil || params["as"] != want || params["g"] != "meta.k8s.io" {
							t.Errorf("invalid metadata negotiation: %s", part)
							w.WriteHeader(http.StatusNotAcceptable)
							return
						}
					}
					if denied {
						w.WriteHeader(http.StatusNotAcceptable)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					obj := `{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{"name":"demo","namespace":"shop","uid":"secret-1","labels":{"owner":"helm","name":"demo","version":"2","status":"failed"}}}`
					if watching {
						_, _ = w.Write([]byte(`{"type":"ADDED","object":` + obj + "}\n"))
					} else {
						_, _ = w.Write([]byte(`{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadataList","metadata":{"resourceVersion":"1"},"items":[` + obj + `]}`))
					}
				}))
				defer srv.Close()
				mc, err := NewMetadataClient(&rest.Config{Host: srv.URL})
				if err != nil {
					t.Fatal(err)
				}
				n, _ := NewNormalizer(Options{})
				c := &Collector{o: CollectorOptions{Metadata: mc}, exclude: map[string]bool{}}
				sc := &scope{kind: KindSecret, spec: catalogByKind[KindSecret], metaOnly: true, tf: Transform(n, KindSecret)}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var obj any
				if watching {
					stream, e := c.watch(ctx, sc, metav1.ListOptions{})
					err = e
					if err == nil {
						defer stream.Stop()
						select {
						case event := <-stream.ResultChan():
							obj = event.Object
						case <-ctx.Done():
							t.Fatal("no metadata watch event")
						}
					}
				} else {
					list, e := c.list(ctx, sc, metav1.ListOptions{})
					err = e
					if err == nil {
						obj = &list.(*metav1.PartialObjectMetadataList).Items[0]
					}
				}
				if denied {
					if err == nil || calls.Load() != 1 {
						t.Fatal("metadata failure did not fail closed")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				u := c.prepare(sc, obj, true)
				if u == nil {
					t.Fatal("metadata response not decoded")
				}
				r, _, err := n.Normalize(u)
				if err != nil {
					t.Fatal(err)
				}
				if r.Fields["helm.status"] != "failed" {
					t.Fatal("release metadata lost")
				}
			})
		}
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

type delayedDiscovery struct {
	discovery.DiscoveryInterface
	gv      string
	started chan struct{}
	blocked chan struct{}
	once    *sync.Once
}

func (d delayedDiscovery) ServerResourcesForGroupVersion(gv string) (*metav1.APIResourceList, error) {
	if gv == d.gv {
		d.once.Do(func() { close(d.started) })
		<-d.blocked
	}
	return d.DiscoveryInterface.ServerResourcesForGroupVersion(gv)
}
