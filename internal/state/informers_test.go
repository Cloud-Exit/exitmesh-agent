package state

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type testEnv struct {
	dyn  *dynamicfake.FakeDynamicClient
	meta *metadatafake.FakeMetadataClient
	disc *discoveryfake.FakeDiscovery
}

func partialMeta(t testing.TB, u *unstructured.Unstructured) *metav1.PartialObjectMetadata {
	var cm corev1.ConfigMap
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &cm); err != nil {
		t.Fatal(err)
	}
	return &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: cm.ObjectMeta}
}

func newTestEnv(t testing.TB, objs []*unstructured.Unstructured, skipGV ...string) *testEnv {
	listKinds := map[schema.GroupVersionResource]string{}
	for _, s := range catalog {
		listKinds[s.GVR] = s.APIKind + "List"
	}
	var dynObjs, metaObjs []runtime.Object
	for _, o := range objs {
		dynObjs = append(dynObjs, o.DeepCopy())
		if KindOf(o) == KindConfigMap {
			metaObjs = append(metaObjs, partialMeta(t, o))
		}
	}
	mscheme := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(mscheme); err != nil {
		t.Fatal(err)
	}
	e := &testEnv{
		dyn:  dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, dynObjs...),
		meta: metadatafake.NewSimpleMetadataClient(mscheme, metaObjs...),
		disc: &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{}},
	}
	byGV := map[string]*metav1.APIResourceList{}
	for _, s := range catalog {
		gv := s.GVR.GroupVersion().String()
		if slices.Contains(skipGV, gv) {
			continue
		}
		if byGV[gv] == nil {
			byGV[gv] = &metav1.APIResourceList{GroupVersion: gv}
			e.disc.Resources = append(e.disc.Resources, byGV[gv])
		}
		byGV[gv].APIResources = append(byGV[gv].APIResources, metav1.APIResource{Name: s.GVR.Resource, Kind: s.APIKind, Namespaced: s.Namespaced,
			Verbs: metav1.Verbs{"get", "list", "watch"}})
	}
	return e
}

func (e *testEnv) actions() []clienttesting.Action {
	var out []clienttesting.Action
	out = append(out, e.dyn.Actions()...)
	out = append(out, e.meta.Actions()...)
	return append(out, e.disc.Actions()...)
}

type batch struct {
	ops       []protocol.Op
	synthetic bool
	uncertain *protocol.Interval
}

type recorder struct {
	mu      sync.Mutex
	base    *protocol.State
	batches []batch
}

func (r *recorder) sink(ops []protocol.Op, synthetic bool, iv *protocol.Interval) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, batch{ops, synthetic, iv})
}

func (r *recorder) synced(st *protocol.State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.base = st
}

func (r *recorder) find(pred func(batch) bool) (batch, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.batches {
		if pred(b) {
			return b, true
		}
	}
	return batch{}, false
}

func (r *recorder) replay(t *testing.T) *protocol.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.base.Clone()
	for _, b := range r.batches {
		if err := st.ApplyOps(b.ops); err != nil {
			t.Fatalf("chain gap: %v in %v", err, opKinds(b.ops))
		}
	}
	return st
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type logRecorder struct {
	mu   sync.Mutex
	recs []string
}

func (l *logRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (l *logRecorder) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Level.String() + " " + r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	l.mu.Lock()
	l.recs = append(l.recs, b.String())
	l.mu.Unlock()
	return nil
}
func (l *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logRecorder) WithGroup(string) slog.Handler      { return l }

func (l *logRecorder) count(sub ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.recs {
		all := true
		for _, s := range sub {
			all = all && strings.Contains(r, s)
		}
		if all {
			n++
		}
	}
	return n
}

func hasOp(ops []protocol.Op, want string) bool { return slices.Contains(opKinds(ops), want) }

func assertReadOnly(t *testing.T, e *testEnv) {
	t.Helper()
	for _, a := range e.actions() {
		switch a.GetVerb() {
		case "get", "list", "watch":
		default:
			t.Fatalf("write verb %s on %s", a.GetVerb(), a.GetResource())
		}
		if r := a.GetResource().Resource; r == "secrets" || strings.Contains(r, "accessreview") || strings.Contains(r, "tokenreview") {
			t.Fatalf("forbidden resource %s", r)
		}
	}
}

func startCollector(t *testing.T, o CollectorOptions) (*Collector, context.CancelFunc, chan struct{}) {
	t.Helper()
	c, err := NewCollector(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	select {
	case <-c.Synced():
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("collector did not sync")
	}
	return c, cancel, done
}

var (
	podGVR  = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	depGVR  = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	cmGVR   = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	fastRef = &wait.Backoff{Duration: 5 * time.Millisecond, Cap: 5 * time.Millisecond, Factor: 1, Steps: 1 << 20}
)

func TestCollectorSyncsAndFollowsChanges(t *testing.T) {
	objs := append(fixtureObjects(t), warningEvent("ev-1", "pod-1", "BackOff", 3, time.Now()))
	env := newTestEnv(t, objs)
	rec := &recorder{}
	tr := NewTracker(TrackerOptions{})
	_, cancel, done := startCollector(t, CollectorOptions{Dynamic: env.dyn, Metadata: env.meta, Discovery: env.disc, Tracker: tr,
		Sink: rec.sink, OnSynced: rec.synced, Logger: slog.New(&logRecorder{}), ReflectorBackoff: fastRef, FlushInterval: 10 * time.Millisecond})
	defer func() { cancel(); <-done }()
	base := rec.base
	for _, o := range objs[:len(objs)-1] {
		if base.Resources[string(o.GetUID())] == nil {
			t.Fatalf("synced state misses %s", o.GetUID())
		}
	}
	for _, s := range catalog {
		if st, ok := base.Scopes[ScopeKey(s.Kind, "")]; !ok || st.State != protocol.ScopeComplete {
			t.Fatalf("scope %s = %+v", s.Kind, st)
		}
	}
	if len(base.Scopes) != len(catalog) {
		t.Fatalf("scopes %v", base.Scopes)
	}
	cm := base.Resources["cm-1"]
	if cm == nil || cm.Fields["labels.app"] != "web" || cm.Fields["keys"] != nil {
		t.Fatalf("metadata-only configmap %+v", cm)
	}
	if base.Resources["pod-1"].Fields["events.warning.BackOff"] != int64(3) {
		t.Fatalf("event aggregation %v", base.Resources["pod-1"].Fields)
	}
	if !hasEdge(base, "svc-1", EdgeSelects, "pod-1") || !hasEdge(base, "pod-1", EdgeRunsOn, "node-1") {
		t.Fatal("edges missing after sync")
	}
	dep := fixtureByUID(t, "dep-1")
	cs, _, _ := unstructured.NestedSlice(dep.Object, "spec", "template", "spec", "containers")
	cs[0].(map[string]any)["image"] = "nginx:1.27"
	_ = unstructured.SetNestedSlice(dep.Object, cs, "spec", "template", "spec", "containers")
	if err := env.dyn.Tracker().Update(depGVR, dep, "shop"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "image update", func() bool {
		_, ok := rec.find(func(b batch) bool {
			return len(b.ops) == 1 && b.ops[0].UID == "dep-1" && b.ops[0].Fields["containers.app.image"] == "nginx:1.27"
		})
		return ok
	})
	if err := env.dyn.Tracker().Delete(podGVR, "shop", "web-abc-2"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "pod deletion", func() bool {
		_, ok := rec.find(func(b batch) bool {
			return hasOp(b.ops, "delete:pod-2::") && hasOp(b.ops, "edge_remove:svc-1:selects:pod-2")
		})
		return ok
	})
	added := fixtureByUID(t, "pod-1")
	added.SetUID("pod-7")
	added.SetName("web-abc-7")
	if err := env.dyn.Tracker().Create(podGVR, added, "shop"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "pod creation", func() bool {
		_, ok := rec.find(func(b batch) bool {
			return hasOp(b.ops, "create:pod-7::") && hasOp(b.ops, "edge_add:pod-7:runs-on:node-1")
		})
		return ok
	})
	if err := env.dyn.Tracker().Delete(schema.GroupVersionResource{Version: "v1", Resource: "events"}, "shop", "ev-1"); err != nil {
		t.Fatal(err)
	}
	pm := partialMeta(t, fixtureByUID(t, "cm-1"))
	pm.Labels["app"] = "web2"
	if err := env.meta.Tracker().Update(cmGVR, pm, "shop"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "configmap metadata update", func() bool {
		_, ok := rec.find(func(b batch) bool { return hasOp(b.ops, "update:cm-1::") })
		return ok
	})
	cancel()
	<-done
	if got := rec.replay(t); !got.Equal(tr.Snapshot()) {
		t.Fatal("sink chain does not reconstruct tracker state")
	}
	assertReadOnly(t, env)
	for _, a := range env.dyn.Actions() {
		if a.GetResource().Resource == "configmaps" {
			t.Fatal("configmaps read through the full dynamic client")
		}
	}
	metaVerbs := map[string]bool{}
	for _, a := range env.meta.Actions() {
		if a.GetResource().Resource != "configmaps" {
			t.Fatalf("metadata client used for %s", a.GetResource())
		}
		metaVerbs[a.GetVerb()] = true
	}
	if !metaVerbs["list"] || !metaVerbs["watch"] {
		t.Fatalf("metadata informer verbs %v", metaVerbs)
	}
}

func TestCollectorConfigMapKeysUseStrippedFullInformer(t *testing.T) {
	env := newTestEnv(t, fixtureObjects(t))
	n, err := NewNormalizer(Options{Fields: []string{"ConfigMap:keys"}})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	tr := NewTracker(TrackerOptions{Normalizer: n})
	_, cancel, done := startCollector(t, CollectorOptions{Dynamic: env.dyn, Discovery: env.disc, Tracker: tr, Resources: []string{"configmaps"},
		Sink: rec.sink, OnSynced: rec.synced, Logger: slog.New(&logRecorder{}), ReflectorBackoff: fastRef})
	cancel()
	<-done
	cm := rec.base.Resources["cm-1"]
	if cm == nil || dump(cm.Fields["keys"]) != dump([]any{"cert.der", "db.password", "mode"}) || strings.Contains(dump(rec.base), secretCMValue) {
		t.Fatalf("configmap keys %+v", cm)
	}
	if len(env.meta.Actions()) != 0 {
		t.Fatal("metadata client used although keys were selected")
	}
}

func TestCollectorWatchLossRelistAndPermissionLoss(t *testing.T) {
	env := newTestEnv(t, fixtureObjects(t))
	var forbid atomic.Bool
	var lists atomic.Int32
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rbac revoked"))
	env.dyn.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		lists.Add(1)
		if forbid.Load() {
			return true, nil, forbidden
		}
		return false, nil, nil
	})
	watchers := make(chan *watch.FakeWatcher, 16)
	env.dyn.PrependWatchReactor("pods", func(clienttesting.Action) (bool, watch.Interface, error) {
		w := watch.NewFake()
		watchers <- w
		return true, w, nil
	})
	var failedProbes atomic.Int32
	logs := &logRecorder{}
	rec := &recorder{}
	tr := NewTracker(TrackerOptions{})
	_, cancel, done := startCollector(t, CollectorOptions{Dynamic: env.dyn, Discovery: env.disc, Tracker: tr,
		Resources: []string{"pods", "nodes", "services", "persistentvolumeclaims"}, Sink: rec.sink, OnSynced: rec.synced,
		Logger: slog.New(logs), ReflectorBackoff: fastRef, RetryBase: time.Second, FlushInterval: time.Hour,
		Wait: func(ctx context.Context, d time.Duration) bool {
			if d == time.Hour {
				<-ctx.Done()
				return false
			}
			if failedProbes.Add(1) >= 3 {
				forbid.Store(false)
			}
			select {
			case <-ctx.Done():
				return false
			case <-time.After(5 * time.Millisecond):
				return true
			}
		}})
	defer func() { cancel(); <-done }()
	w1 := <-watchers
	pod1 := fixtureByUID(t, "pod-1")
	cs, _, _ := unstructured.NestedSlice(pod1.Object, "status", "containerStatuses")
	cs[0].(map[string]any)["restartCount"] = int64(7)
	_ = unstructured.SetNestedSlice(pod1.Object, cs, "status", "containerStatuses")
	pod9 := fixtureByUID(t, "pod-2")
	pod9.SetUID("pod-9")
	pod9.SetName("web-abc-9")
	tk := env.dyn.Tracker()
	if err := tk.Update(podGVR, pod1, "shop"); err != nil {
		t.Fatal(err)
	}
	if err := tk.Delete(podGVR, "shop", "web-abc-2"); err != nil {
		t.Fatal(err)
	}
	if err := tk.Create(podGVR, pod9, "shop"); err != nil {
		t.Fatal(err)
	}
	before := uint64(time.Now().UnixMilli())
	w1.Error(&metav1.Status{Status: metav1.StatusFailure, Code: 410, Reason: metav1.StatusReasonExpired, Message: "too old resource version"})
	var relist batch
	eventually(t, "synthetic relist", func() bool {
		var ok bool
		relist, ok = rec.find(func(b batch) bool { return b.synthetic })
		return ok
	})
	for _, want := range []string{"update:pod-1::", "delete:pod-2::", "create:pod-9::", "edge_add:svc-1:selects:pod-9", "scope_set:::Pod|"} {
		if !hasOp(relist.ops, want) {
			t.Fatalf("relist ops %v missing %s", opKinds(relist.ops), want)
		}
	}
	if iv := relist.uncertain; iv == nil || iv.Start > before || iv.End < before || iv.Start > iv.End {
		t.Fatalf("uncertainty interval %+v around %d", relist.uncertain, before)
	}
	if _, ok := rec.find(func(b batch) bool {
		return !b.synthetic && len(b.ops) == 1 && b.ops[0].Kind == protocol.OpScopeSet && b.ops[0].Scope.Reason == ReasonRelisting
	}); !ok {
		t.Fatal("relist window not marked partial")
	}
	w2 := <-watchers
	forbid.Store(true)
	w2.Error(&metav1.Status{Status: metav1.StatusFailure, Code: 410, Reason: metav1.StatusReasonExpired})
	eventually(t, "scope lost", func() bool {
		_, ok := rec.find(func(b batch) bool {
			return hasOp(b.ops, "scope_set:::Pod|") && b.ops[0].Scope.Reason == ReasonForbidden
		})
		return ok
	})
	eventually(t, "scope restored", func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		last := rec.batches[len(rec.batches)-1]
		return last.synthetic && last.ops[len(last.ops)-1].Scope.State == protocol.ScopeComplete && tr.Snapshot().Scopes["Pod|"].State == protocol.ScopeComplete
	})
	rec.mu.Lock()
	for _, b := range rec.batches {
		for _, o := range b.ops {
			if o.Kind == protocol.OpDelete && o.UID != "pod-2" {
				t.Fatalf("permission loss deleted %s", o.UID)
			}
		}
	}
	rec.mu.Unlock()
	cancel()
	<-done
	if n := logs.count("scope unavailable", "Pod|", "forbidden"); n != 1 {
		t.Fatalf("forbidden reported %d times: %v", n, logs.recs)
	}
	if failedProbes.Load() < 3 {
		t.Fatalf("expected repeated forbidden probes, got %d", failedProbes.Load())
	}
	got := rec.replay(t)
	if !got.Equal(tr.Snapshot()) {
		t.Fatal("chain has a gap")
	}
	if got.Resources["pod-9"] == nil || got.Resources["pod-2"] != nil || got.Resources["pod-1"].Fields["containers.app.restarts"] != int64(7) {
		t.Fatal("relisted state wrong")
	}
	assertReadOnly(t, env)
}

func TestCollectorForbiddenReportsOnceAndBacksOff(t *testing.T) {
	env := newTestEnv(t, fixtureObjects(t), "autoscaling/v2")
	env.dyn.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("denied"))
	})
	var mu sync.Mutex
	var waits []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &logRecorder{}
	rec := &recorder{}
	var c *Collector
	var err error
	c, err = NewCollector(CollectorOptions{Dynamic: env.dyn, Discovery: env.disc, Tracker: NewTracker(TrackerOptions{}),
		Resources: []string{"pods", "deployments", "horizontalpodautoscalers", "widgets.example.com"}, Sink: rec.sink, OnSynced: rec.synced,
		Logger: slog.New(logs), RetryBase: time.Second, RetryMax: 4 * time.Second, FlushInterval: time.Hour, ReflectorBackoff: fastRef,
		Wait: func(ctx context.Context, d time.Duration) bool {
			if d == time.Hour {
				<-ctx.Done()
				return false
			}
			select {
			case <-c.Synced():
			case <-ctx.Done():
				return false
			}
			mu.Lock()
			defer mu.Unlock()
			waits = append(waits, d)
			if len(waits) >= 12 {
				cancel()
				return false
			}
			return true
		}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	<-done
	podLists := 0
	for _, a := range env.dyn.Actions() {
		if a.GetVerb() == "list" && a.GetResource().Resource == "pods" {
			podLists++
		}
		if a.GetResource().Resource == "horizontalpodautoscalers" {
			t.Fatal("listed a resource the API server does not serve")
		}
	}
	if podLists > 7 {
		t.Fatalf("forbidden list retried %d times", podLists)
	}
	mu.Lock()
	var pods []time.Duration
	for _, d := range waits {
		if d <= 4*time.Second {
			pods = append(pods, d)
		}
	}
	mu.Unlock()
	counts := map[time.Duration]int{}
	for _, d := range pods {
		counts[d]++
	}
	if counts[time.Second] > 2 || counts[2*time.Second] > 2 || counts[4*time.Second] < 6 || len(pods) != len(waits) {
		t.Fatalf("backoff not exponential up to the cap for two failing scopes: %v", pods)
	}
	if n := logs.count("scope unavailable", "Pod|", "forbidden"); n != 1 {
		t.Fatalf("forbidden reported %d times", n)
	}
	if n := logs.count("scope unavailable", "HorizontalPodAutoscaler|", "not served"); n != 1 {
		t.Fatalf("not served reported %d times", n)
	}
	if logs.count("widgets.example.com") != 1 {
		t.Fatal("unsupported resource not reported")
	}
	st := rec.base
	if s := st.Scopes["Pod|"]; s.State != protocol.ScopeUnavailable || s.Reason != ReasonForbidden {
		t.Fatalf("pod scope %+v", s)
	}
	if s := st.Scopes["apps/Deployment|"]; s.State != protocol.ScopeComplete || st.Resources["dep-1"] == nil {
		t.Fatalf("deployment scope %+v", s)
	}
	for _, b := range rec.batches {
		for _, o := range b.ops {
			if o.Kind == protocol.OpScopeSet {
				t.Fatalf("repeated failure emitted %+v", o)
			}
		}
	}
	cov := c.Coverage()
	if len(cov.Unsupported) != 1 || cov.Unsupported[0] != "widgets.example.com" || len(cov.Scopes) != 3 {
		t.Fatalf("coverage %+v", cov)
	}
	for _, s := range cov.Scopes {
		if s.Key == "Pod|" && (s.State != protocol.ScopeUnavailable || s.Attempts < 2 || s.Reason != ReasonForbidden) {
			t.Fatalf("pod coverage %+v", s)
		}
	}
	assertReadOnly(t, env)
}

func TestCollectorNamespaceProfileAndExcludes(t *testing.T) {
	env := newTestEnv(t, fixtureObjects(t))
	env.dyn.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "", errors.New("namespace profile"))
	})
	rec := &recorder{}
	_, cancel, done := startCollector(t, CollectorOptions{Dynamic: env.dyn, Discovery: env.disc, Tracker: NewTracker(TrackerOptions{}),
		Namespaces: []string{"shop", "other"}, ExcludeNamespaces: []string{"other"}, Resources: []string{"pods", "nodes"},
		Sink: rec.sink, OnSynced: rec.synced, Logger: slog.New(&logRecorder{}), ReflectorBackoff: fastRef, FlushInterval: time.Hour})
	cancel()
	<-done
	st := rec.base
	if st.Scopes["Pod|shop"].State != protocol.ScopeComplete || st.Scopes["Node|"].State != protocol.ScopeUnavailable || len(st.Scopes) != 2 {
		t.Fatalf("scopes %+v", st.Scopes)
	}
	if st.Resources["pod-1"] == nil || st.Resources["node-1"] != nil {
		t.Fatal("namespace profile resources")
	}
	for _, a := range env.dyn.Actions() {
		if a.GetResource().Resource == "pods" && a.GetNamespace() != "shop" {
			t.Fatalf("pods listed outside the profile: %q", a.GetNamespace())
		}
	}
	env2 := newTestEnv(t, fixtureObjects(t))
	rec2 := &recorder{}
	_, cancel2, done2 := startCollector(t, CollectorOptions{Dynamic: env2.dyn, Discovery: env2.disc, Tracker: NewTracker(TrackerOptions{}),
		ExcludeNamespaces: []string{"shop"}, Resources: []string{"pods", "namespaces", "nodes"},
		Sink: rec2.sink, OnSynced: rec2.synced, Logger: slog.New(&logRecorder{}), ReflectorBackoff: fastRef, FlushInterval: time.Hour})
	cancel2()
	<-done2
	if rec2.base.Resources["pod-1"] != nil || rec2.base.Resources["ns-1"] != nil || rec2.base.Resources["node-1"] == nil {
		t.Fatal("excluded namespace collected")
	}
	if _, err := NewCollector(CollectorOptions{Dynamic: env2.dyn, Tracker: NewTracker(TrackerOptions{}), Namespaces: []string{"x"}, ExcludeNamespaces: []string{"x"}}); err == nil {
		t.Fatal("fully excluded profile accepted")
	}
	if _, err := NewCollector(CollectorOptions{Dynamic: env2.dyn, Tracker: NewTracker(TrackerOptions{}), Resources: []string{"configmaps"}}); err == nil {
		t.Fatal("metadata-only configmaps without a metadata client accepted")
	}
}

func TestTransformStripsBeforeCaching(t *testing.T) {
	for _, n := range []*Normalizer{defaultNormalizer, allFieldsNormalizer(t)} {
		for _, u := range append(fixtureObjects(t), warningEvent("ev-1", "pod-1", "BackOff", 1, time.Now())) {
			kind := KindOf(u)
			cp := u.DeepCopy()
			out, err := Transform(n, kind)(cp)
			if err != nil {
				t.Fatal(err)
			}
			s := dump(out.(*unstructured.Unstructured).Object)
			for _, bad := range []string{"managedFields", "last-applied", secretLiteral, secretCMValue, "kubelet is posting", "lastHeartbeatTime",
				"healthz", "free text", "nginx:1.25\"}, SizeBytes", "Back-off restarting", "example.com/owner"} {
				if strings.Contains(s, bad) {
					t.Fatalf("%s transform kept %q", kind, bad)
				}
			}
			if kind == KindEvent {
				continue
			}
			want, _, err := n.Normalize(u)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := n.Normalize(cp)
			if err != nil {
				t.Fatal(err)
			}
			if !protocol.ValueEqual(want.Fields, got.Fields) {
				t.Fatalf("%s: transform changed normalized fields\n%v\n%v", kind, want.Fields, got.Fields)
			}
		}
	}
	pm := partialMeta(t, fixtureByUID(t, "cm-1"))
	out, _ := Transform(defaultNormalizer, KindConfigMap)(pm)
	if p := out.(*metav1.PartialObjectMetadata); len(p.ManagedFields) != 0 || len(p.Annotations) != 0 {
		t.Fatalf("partial metadata not stripped %+v", p.ObjectMeta)
	}
	sc := fixtureByUID(t, "sc-1")
	_, _ = Transform(defaultNormalizer, KindStorageCls)(sc)
	if sc.GetAnnotations()[defaultClassAnnotation] != "true" {
		t.Fatal("default class annotation stripped")
	}
	if _, ok := sc.Object["parameters"]; ok {
		t.Fatal("unselected storage class parameters kept")
	}
}

func TestCollectorCollectionFailureIsScopeStatus(t *testing.T) {
	env := newTestEnv(t, append(fixtureObjects(t), warningEvent("ev-1", "pod-1", "BackOff", 1, time.Now())))
	var fail atomic.Bool
	env.dyn.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
		if fail.CompareAndSwap(true, false) {
			return true, nil, apierrors.NewInternalError(errors.New("etcd timeout"))
		}
		return false, nil, nil
	})
	watchers := make(chan *watch.FakeWatcher, 16)
	env.dyn.PrependWatchReactor("pods", func(clienttesting.Action) (bool, watch.Interface, error) {
		w := watch.NewFake()
		watchers <- w
		return true, w, nil
	})
	logs := &logRecorder{}
	rec := &recorder{}
	tr := NewTracker(TrackerOptions{EventInterval: 50 * time.Millisecond})
	_, cancel, done := startCollector(t, CollectorOptions{Dynamic: env.dyn, Discovery: env.disc, Tracker: tr,
		Resources: []string{"pods", "events"}, Sink: rec.sink, OnSynced: rec.synced, Logger: slog.New(logs),
		ReflectorBackoff: fastRef, FlushInterval: 10 * time.Millisecond})
	defer func() { cancel(); <-done }()
	ev := warningEvent("ev-1", "pod-1", "BackOff", 6, time.Now())
	if err := env.dyn.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "events"}, ev, "shop"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "event count update", func() bool {
		_, ok := rec.find(func(b batch) bool { return len(b.ops) == 1 && b.ops[0].Fields["events.warning.BackOff"] == int64(6) })
		return ok
	})
	w1 := <-watchers
	fail.Store(true)
	w1.Error(&metav1.Status{Status: metav1.StatusFailure, Code: 410, Reason: metav1.StatusReasonExpired})
	eventually(t, "collection failure", func() bool {
		_, ok := rec.find(func(b batch) bool {
			return len(b.ops) == 1 && b.ops[0].Scope.State == protocol.ScopeUnavailable && b.ops[0].Scope.Reason == ReasonCollectionFailed
		})
		return ok
	})
	eventually(t, "recovery", func() bool {
		_, ok := rec.find(func(b batch) bool {
			return b.synthetic && hasOp(b.ops, "scope_set:::Pod|") && b.ops[len(b.ops)-1].Scope.State == protocol.ScopeComplete
		})
		return ok
	})
	cancel()
	<-done
	for _, b := range rec.batches {
		for _, o := range b.ops {
			if o.Kind == protocol.OpDelete {
				t.Fatalf("collection failure deleted %s", o.UID)
			}
		}
	}
	if n := logs.count("scope unavailable", "Pod|", ReasonCollectionFailed); n != 1 {
		t.Fatalf("collection failure reported %d times", n)
	}
	if !rec.replay(t).Equal(tr.Snapshot()) {
		t.Fatal("chain has a gap")
	}
}

func TestScopeStoreExposesTransformForWatchList(t *testing.T) {
	var store cache.TransformingStore = &scopeStore{sc: &scope{tf: Transform(defaultNormalizer, KindPod)}}
	u := fixtureByUID(t, "pod-1")
	if _, err := store.Transformer()(u); err != nil || u.GetManagedFields() != nil {
		t.Fatal("store transform does not strip")
	}
	if store.Resync() != nil {
		t.Fatal("resync")
	}
}
