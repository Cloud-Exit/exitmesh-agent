package state

import (
	"context"
	"errors"
	"log/slog"
	"path"
	"sort"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/cache"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Sink receives ops in state order; synthetic relist ops carry the interval where transients may be missed.
type Sink func(ops []protocol.Op, synthetic bool, uncertain *protocol.Interval)

// Scope failure reasons recorded on scope status.
const (
	ReasonForbidden        = "forbidden"
	ReasonUnauthorized     = "unauthorized"
	ReasonNotServed        = "not served"
	ReasonCollectionFailed = "collection failed"
	ReasonRelisting        = "relisting"
)

var errNotServed = errors.New("state: resource not served by the API server")

// CollectorOptions configures a Collector.
type CollectorOptions struct {
	Dynamic   dynamic.Interface
	Metadata  metadata.Interface
	Discovery discovery.DiscoveryInterface
	Tracker   *Tracker
	Sink      Sink
	// OnSynced receives the state once every scope finished its first attempt; ops before it are not sent to Sink.
	OnSynced func(st *protocol.State)
	// Namespaces selects the namespace profile; empty collects cluster-wide.
	Namespaces        []string
	ExcludeNamespaces []string
	// Resources lists configured resource names; empty selects every catalog kind.
	Resources       []string
	CustomResources config.CustomResources
	Logger          *slog.Logger
	Clock           func() time.Time
	// RetryBase and RetryMax bound the exponential backoff after access failures, default 30s and 30m.
	RetryBase, RetryMax time.Duration
	// FlushInterval is the event count flush period, default 30s.
	FlushInterval time.Duration
	// Wait sleeps for d or until ctx is done, reporting whether to continue; default uses a timer.
	Wait             func(ctx context.Context, d time.Duration) bool
	ReflectorBackoff *wait.Backoff
}

// ScopeReport is the collection status of one scope.
type ScopeReport struct {
	Key       string
	Kind      string
	Namespace string
	State     protocol.ScopeState
	Reason    string
	Attempts  int
}

// Coverage summarizes collection: every scope and the configured resources that are not supported.
type Coverage struct {
	Scopes      []ScopeReport
	Unsupported []string
}

type scope struct {
	kind, ns string
	spec     *KindSpec
	metaOnly bool
	tf       cache.TransformFunc

	mu          sync.Mutex
	state       protocol.ScopeState
	reason      string
	attempts    int
	backoff     time.Duration
	firstDone   bool
	retired     bool
	background  bool
	listedOnce  bool
	listing     bool
	lastHealthy time.Time
	accessErr   error
}

type discEntry struct {
	at   time.Time
	list *metav1.APIResourceList
	err  error
}

// Collector runs read-only list and watch loops for every permitted scope and feeds the Tracker.
type Collector struct {
	o               CollectorOptions
	log             *slog.Logger
	mu              sync.Mutex
	scopes          []*scope
	exclude         map[string]bool
	unsupported     []string
	synced          bool
	syncedCh        chan struct{}
	pending         int
	discMu          sync.Mutex
	disc            map[string]discEntry
	discoveryStatus *scope
	discoveryWake   chan struct{}
	crds            map[string]*KindSpec
	crdScope        *scope
}

// NewCollector validates o and prepares the scopes.
func NewCollector(o CollectorOptions) (*Collector, error) {
	if o.Tracker == nil || o.Dynamic == nil {
		return nil, errors.New("state: collector requires a tracker and a dynamic client")
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.RetryBase <= 0 {
		o.RetryBase = 30 * time.Second
	}
	if o.RetryMax < o.RetryBase {
		o.RetryMax = max(30*time.Minute, o.RetryBase)
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = 30 * time.Second
	}
	if o.Wait == nil {
		o.Wait = sleepCtx
	}
	log := o.Logger
	if log == nil {
		log = slog.New(redact.NewHandler(slog.Default().Handler(), nil))
	}
	c := &Collector{o: o, log: log, exclude: map[string]bool{}, syncedCh: make(chan struct{}), disc: map[string]discEntry{}}
	for _, ns := range o.ExcludeNamespaces {
		c.exclude[ns] = true
	}
	var namespaces []string
	for _, ns := range sortedUnique(o.Namespaces) {
		if !c.exclude[ns] {
			namespaces = append(namespaces, ns)
		}
	}
	if len(o.Namespaces) > 0 && len(namespaces) == 0 {
		return nil, errors.New("state: every configured namespace is excluded")
	}
	if o.CustomResources.MaxKinds == 0 {
		o.CustomResources.MaxKinds = 100
	}
	if o.CustomResources.MaxScopes == 0 {
		o.CustomResources.MaxScopes = 256
	}
	if o.CustomResources.MaxKinds < 1 || o.CustomResources.MaxScopes < 1 {
		return nil, errors.New("state: custom-resource limits must be positive")
	}
	for _, patterns := range [][]string{o.CustomResources.Include, o.CustomResources.Exclude} {
		for _, p := range patterns {
			if _, err := path.Match(p, ""); err != nil {
				return nil, errors.New("state: invalid custom-resource pattern")
			}
		}
	}
	c.o = o
	kinds, unsupported := ResolveKinds(o.Resources)
	if o.CustomResources.Active() {
		if !contains(kinds, KindCRD) {
			kinds = append(kinds, KindCRD)
		}
		c.discoveryWake = make(chan struct{}, 1)
		c.crds = map[string]*KindSpec{}
		c.discoveryStatus = &scope{kind: "inventory.exitmesh.io/CustomResourceDiscovery", state: protocol.ScopePartial, reason: "waiting for CRD inventory"}
		c.o.Tracker.ScopePartial(c.discoveryStatus.kind, "", c.discoveryStatus.reason)
	}
	c.unsupported = unsupported
	norm := o.Tracker.Normalizer()
	for _, kind := range kinds {
		spec := catalogByKind[kind]
		metaOnly := spec.MetadataOnly && !norm.Selected(kind, "keys")
		if metaOnly && o.Metadata == nil {
			return nil, errors.New("state: collecting metadata requires a metadata client")
		}
		nss := []string{""}
		if spec.Namespaced && len(namespaces) > 0 {
			nss = namespaces
		}
		for _, ns := range nss {
			sc := &scope{kind: kind, ns: ns, spec: spec, metaOnly: metaOnly, tf: Transform(norm, kind)}
			if kind == KindCRD && o.CustomResources.Active() {
				sc.background = true
				sc.state = protocol.ScopePartial
				sc.reason = "initial collection"
				c.crdScope = sc
			} else {
				c.pending++
			}
			c.scopes = append(c.scopes, sc)
		}
	}

	return c, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Synced is closed once every scope finished its first attempt and OnSynced ran.
func (c *Collector) Synced() <-chan struct{} { return c.syncedCh }

// Coverage reports the status of every scope.
func (c *Collector) Coverage() Coverage {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := Coverage{Unsupported: append([]string(nil), c.unsupported...)}
	scopes := c.scopes
	if c.discoveryStatus != nil {
		scopes = append(append([]*scope(nil), scopes...), c.discoveryStatus)
	}
	for _, sc := range scopes {
		if sc.retired {
			continue
		}
		sc.mu.Lock()
		out.Scopes = append(out.Scopes, ScopeReport{Key: ScopeKey(sc.kind, sc.ns), Kind: sc.kind, Namespace: sc.ns,
			State: sc.state, Reason: sc.reason, Attempts: sc.attempts})
		sc.mu.Unlock()
	}
	sort.Slice(out.Scopes, func(i, j int) bool { return out.Scopes[i].Key < out.Scopes[j].Key })
	return out
}

// Run collects until ctx is done.
func (c *Collector) Run(ctx context.Context) error {
	if len(c.unsupported) > 0 {
		c.log.Warn("state: configured resources are not supported and are not exported", "resources", c.unsupported)
	}
	c.mu.Lock()
	if c.pending == 0 && !c.synced {
		c.markSyncedLocked()
	}
	c.mu.Unlock()
	var wg sync.WaitGroup
	initial := append([]*scope(nil), c.scopes...)
	if c.o.CustomResources.Active() {
		wg.Add(1)
		go func() { defer wg.Done(); c.discoverCustom(ctx) }()
	}
	for _, sc := range initial {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runScope(ctx, sc)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.flushLoop(ctx)
	}()
	wg.Wait()
	return nil
}

func (c *Collector) flushLoop(ctx context.Context) {
	for c.o.Wait(ctx, c.o.FlushInterval) {
		c.mu.Lock()
		if c.synced {
			c.emit(c.o.Tracker.FlushEvents(), false, nil)
		}
		c.mu.Unlock()
	}
}

func (c *Collector) runScope(ctx context.Context, sc *scope) {
	for ctx.Err() == nil {
		err := c.probe(ctx, sc)
		if err == nil {
			err = c.watchScope(ctx, sc)
		}
		if ctx.Err() != nil {
			return
		}
		c.fail(sc, err)
		if !c.o.Wait(ctx, sc.nextBackoff(c.o.RetryBase, c.o.RetryMax)) {
			return
		}
	}
}

func (sc *scope) nextBackoff(base, maxD time.Duration) time.Duration {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.backoff < base {
		sc.backoff = base
	}
	d := sc.backoff
	sc.backoff = min(sc.backoff*2, maxD)
	return d
}

func accessError(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || apierrors.IsNotFound(err) ||
		apierrors.IsMethodNotSupported(err) || errors.Is(err, errNotServed)
}

func reasonFor(err error) string {
	switch {
	case apierrors.IsForbidden(err):
		return ReasonForbidden
	case apierrors.IsUnauthorized(err):
		return ReasonUnauthorized
	case errors.Is(err, errNotServed), apierrors.IsNotFound(err), apierrors.IsMethodNotSupported(err):
		return ReasonNotServed
	}
	return ReasonCollectionFailed
}

func (c *Collector) served(sc *scope) error {
	if c.o.Discovery == nil {
		return nil
	}
	gv := sc.spec.GVR.GroupVersion().String()
	now := c.o.Clock()
	c.discMu.Lock()
	ent, ok := c.disc[gv]
	c.discMu.Unlock()
	if !ok || now.Sub(ent.at) >= c.o.RetryBase {
		list, err := c.o.Discovery.ServerResourcesForGroupVersion(gv)
		ent = discEntry{at: now, list: list, err: err}
		c.discMu.Lock()
		c.disc[gv] = ent
		c.discMu.Unlock()
	}
	if ent.err != nil {
		if apierrors.IsNotFound(ent.err) {
			return errNotServed
		}
		return nil
	}
	for _, r := range ent.list.APIResources {
		if r.Name == sc.spec.GVR.Resource {
			return nil
		}
	}
	return errNotServed
}

func (c *Collector) probe(ctx context.Context, sc *scope) error {
	sc.mu.Lock()
	sc.attempts++
	sc.mu.Unlock()
	if err := c.served(sc); err != nil {
		return err
	}
	_, err := c.list(ctx, sc, metav1.ListOptions{Limit: 1})
	return err
}

func (c *Collector) list(ctx context.Context, sc *scope, opts metav1.ListOptions) (runtime.Object, error) {
	if sc.metaOnly {
		l, err := c.o.Metadata.Resource(sc.spec.GVR).Namespace(sc.ns).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		return l, nil
	}
	l, err := c.o.Dynamic.Resource(sc.spec.GVR).Namespace(sc.ns).List(ctx, opts)
	if err != nil {
		return nil, err
	}
	if sc.kind == KindSecret {
		for i := range l.Items {
			c.o.Tracker.Normalizer().strip(KindSecret, &l.Items[i])
		}
	}
	return l, nil
}

func (c *Collector) watch(ctx context.Context, sc *scope, opts metav1.ListOptions) (watch.Interface, error) {
	if sc.metaOnly {
		return c.o.Metadata.Resource(sc.spec.GVR).Namespace(sc.ns).Watch(ctx, opts)
	}
	w, err := c.o.Dynamic.Resource(sc.spec.GVR).Namespace(sc.ns).Watch(ctx, opts)
	if err != nil || sc.kind != KindSecret {
		return w, err
	}
	return watch.Filter(w, func(ev watch.Event) (watch.Event, bool) {
		if u, ok := ev.Object.(*unstructured.Unstructured); ok {
			// The projection replaces Object without mutating a shared watch input.
			safe := &unstructured.Unstructured{Object: u.Object}
			c.o.Tracker.Normalizer().strip(KindSecret, safe)
			if ev.Type == watch.Bookmark && u.GetAnnotations()["k8s.io/initial-events-end"] == "true" {
				safe.SetAnnotations(map[string]string{"k8s.io/initial-events-end": "true"})
			}
			ev.Object = safe
		}
		return ev, true
	}), nil
}

func (sc *scope) setAccessErr(err error) {
	sc.mu.Lock()
	sc.accessErr = err
	sc.mu.Unlock()
}

// getAccessErr lets a reflector that races its cancellation stop without another API call (PRD A7).
func (sc *scope) getAccessErr() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.accessErr
}

func (sc *scope) markHealthy(t time.Time) {
	sc.mu.Lock()
	if !sc.listing {
		sc.lastHealthy = t
	}
	sc.mu.Unlock()
}

func (c *Collector) watchScope(ctx context.Context, sc *scope) error {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sc.setAccessErr(nil)
	lw := &cache.ListWatch{
		ListWithContextFunc: func(lctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			if err := sc.getAccessErr(); err != nil {
				return nil, err
			}
			c.beginList(sc)
			obj, err := c.list(lctx, sc, opts)
			if err != nil {
				c.listFailed(sc, err, cancel)
			}
			return obj, err
		},
		WatchFuncWithContext: func(wctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			if err := sc.getAccessErr(); err != nil {
				return nil, err
			}
			if opts.SendInitialEvents != nil && *opts.SendInitialEvents {
				c.beginList(sc)
			}
			w, err := c.watch(wctx, sc, opts)
			if err != nil {
				if accessError(err) {
					sc.setAccessErr(err)
					cancel()
				}
				return nil, err
			}
			sc.markHealthy(c.o.Clock())
			return newTrackedWatch(w, sc, c.o.Clock), nil
		},
	}
	var client any = c.o.Dynamic
	var expected any = &unstructured.Unstructured{Object: map[string]any{"apiVersion": sc.spec.GVR.GroupVersion().String(), "kind": sc.spec.APIKind}}
	if sc.metaOnly {
		client, expected = c.o.Metadata, &metav1.PartialObjectMetadata{}
	}
	r := cache.NewReflectorWithOptions(cache.ToListWatcherWithWatchListSemantics(lw, client), expected, &scopeStore{c: c, sc: sc},
		cache.ReflectorOptions{Name: ScopeKey(sc.kind, sc.ns), Backoff: c.o.ReflectorBackoff})
	r.RunWithContext(rctx)
	if ctx.Err() != nil {
		return nil
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.accessErr == nil {
		return errors.New("state: watch stopped")
	}
	return sc.accessErr
}

func (c *Collector) beginList(sc *scope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sc.mu.Lock()
	sc.listing = true
	relist := sc.listedOnce
	sc.mu.Unlock()
	if relist {
		c.emit(c.o.Tracker.ScopePartial(sc.kind, sc.ns, ReasonRelisting), false, nil)
	}
}

func (c *Collector) listFailed(sc *scope, err error, cancel context.CancelFunc) {
	if accessError(err) {
		sc.setAccessErr(err)
		cancel()
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emit(c.o.Tracker.ScopeLost(sc.kind, sc.ns, ReasonCollectionFailed), false, nil)
	c.report(sc, protocol.ScopeUnavailable, ReasonCollectionFailed, err)
}

func (c *Collector) fail(sc *scope, err error) {
	reason := reasonFor(err)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emit(c.o.Tracker.ScopeLost(sc.kind, sc.ns, reason), false, nil)
	c.report(sc, protocol.ScopeUnavailable, reason, err)
	c.firstAttemptLocked(sc)
}

// report logs a scope status transition once; repeated failures with the same reason stay silent.
func (c *Collector) report(sc *scope, st protocol.ScopeState, reason string, err error) {
	defer c.wakeDiscovery(sc)
	sc.mu.Lock()
	changed := sc.state != st || sc.reason != reason
	sc.state, sc.reason = st, reason
	sc.mu.Unlock()
	if !changed {
		return
	}
	key := ScopeKey(sc.kind, sc.ns)
	if st == protocol.ScopeComplete {
		c.log.Info("state: scope collected", "scope", key)
		return
	}
	c.log.Warn("state: scope unavailable, backing off", "scope", key, "reason", reason, "error", err)
}

func (c *Collector) firstAttemptLocked(sc *scope) {
	sc.mu.Lock()
	first := !sc.firstDone
	sc.firstDone = true
	sc.mu.Unlock()
	if first && !sc.background {
		c.pending--
		if c.pending == 0 && !c.synced {
			c.markSyncedLocked()
		}
	}
}

func (c *Collector) markSyncedLocked() {
	c.synced = true
	if c.o.OnSynced != nil {
		c.o.OnSynced(c.o.Tracker.Snapshot())
	}
	close(c.syncedCh)
}

func (c *Collector) emit(ops []protocol.Op, synthetic bool, uncertain *protocol.Interval) {
	if !c.synced || len(ops) == 0 || c.o.Sink == nil {
		return
	}
	c.o.Sink(ops, synthetic, uncertain)
}

func (c *Collector) toUnstructured(sc *scope, obj any) *unstructured.Unstructured {
	switch o := obj.(type) {
	case cache.DeletedFinalStateUnknown:
		return c.toUnstructured(sc, o.Obj)
	case *unstructured.Unstructured:
		return o
	case *metav1.PartialObjectMetadata:
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
		if err != nil {
			return nil
		}
		u := &unstructured.Unstructured{Object: m}
		u.SetAPIVersion(sc.spec.GVR.GroupVersion().String())
		u.SetKind(sc.spec.APIKind)
		return u
	}
	return nil
}

func (c *Collector) excluded(sc *scope, u *unstructured.Unstructured) bool {
	ns := u.GetNamespace()
	if sc.kind == KindNamespace {
		ns = u.GetName()
	}
	return c.exclude[ns]
}

func (c *Collector) prepare(sc *scope, obj any, transform bool) *unstructured.Unstructured {
	u := c.toUnstructured(sc, obj)
	if u == nil {
		return nil
	}
	if transform {
		if _, err := sc.tf(u); err != nil {
			return nil
		}
	}
	if c.excluded(sc, u) {
		return nil
	}
	return u
}

func (c *Collector) observe(sc *scope, obj any, deleted bool) {
	u := c.prepare(sc, obj, !deleted)
	if u == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if sc.retired {
		return
	}
	var ops []protocol.Op
	var err error
	if deleted {
		ops, err = c.o.Tracker.Remove(u)
	} else {
		ops, err = c.o.Tracker.Upsert(u)
	}
	if err != nil {
		c.log.Debug("state: observation skipped", "scope", ScopeKey(sc.kind, sc.ns), "error", err)
		return
	}
	if sc == c.crdScope {
		if deleted {
			delete(c.crds, u.GetName())
		} else {
			c.crds[u.GetName()] = customSpec(u)
		}
		c.wakeDiscovery(sc)
	}
	c.emit(ops, false, nil)
}

func (c *Collector) replace(sc *scope, list []any) {
	objs := make([]*unstructured.Unstructured, 0, len(list))
	for _, o := range list {
		if u := c.prepare(sc, o, true); u != nil {
			objs = append(objs, u)
		}
	}
	now := c.o.Clock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if sc.retired {
		return
	}
	sc.mu.Lock()
	relist, start := sc.listedOnce, sc.lastHealthy
	sc.listedOnce, sc.listing, sc.lastHealthy, sc.backoff = true, false, now, 0
	sc.mu.Unlock()
	if sc == c.crdScope {
		c.crds = map[string]*KindSpec{}
		for _, u := range objs {
			c.crds[u.GetName()] = customSpec(u)
		}
	}
	ops, _, err := c.o.Tracker.Reconcile(sc.kind, sc.ns, objs)
	if err != nil {
		c.log.Debug("state: relist skipped objects", "scope", ScopeKey(sc.kind, sc.ns), "error", err)
	}
	ops = append(ops, c.o.Tracker.ScopeRestored(sc.kind, sc.ns)...)
	protocol.SortOps(ops)
	c.report(sc, protocol.ScopeComplete, "", nil)
	if relist {
		c.emit(ops, true, &protocol.Interval{Start: uint64(start.UnixMilli()), End: uint64(now.UnixMilli())})
	} else {
		c.emit(ops, false, nil)
	}
	c.firstAttemptLocked(sc)
}

type scopeStore struct {
	c  *Collector
	sc *scope
}

func (s *scopeStore) Add(obj any) error    { s.c.observe(s.sc, obj, false); return nil }
func (s *scopeStore) Update(obj any) error { s.c.observe(s.sc, obj, false); return nil }
func (s *scopeStore) Delete(obj any) error { s.c.observe(s.sc, obj, true); return nil }
func (s *scopeStore) Replace(list []any, _ string) error {
	s.c.replace(s.sc, list)
	return nil
}
func (s *scopeStore) Resync() error                    { return nil }
func (s *scopeStore) Transformer() cache.TransformFunc { return s.sc.tf }

// trackedWatch forwards a watch and records when it last delivered, so a relist knows its uncertainty start.
type trackedWatch struct {
	inner watch.Interface
	out   chan watch.Event
	done  chan struct{}
	once  sync.Once
}

func newTrackedWatch(w watch.Interface, sc *scope, clock func() time.Time) *trackedWatch {
	t := &trackedWatch{inner: w, out: make(chan watch.Event), done: make(chan struct{})}
	go func() {
		defer close(t.out)
		lastErr := false
		for {
			select {
			case ev, ok := <-w.ResultChan():
				if !ok {
					if !lastErr {
						sc.markHealthy(clock())
					}
					return
				}
				lastErr = ev.Type == watch.Error
				if !lastErr {
					sc.markHealthy(clock())
				}
				select {
				case t.out <- ev:
				case <-t.done:
					return
				}
			case <-t.done:
				return
			}
		}
	}()
	return t
}

func (t *trackedWatch) Stop() {
	t.once.Do(func() {
		close(t.done)
		t.inner.Stop()
	})
}

func (t *trackedWatch) ResultChan() <-chan watch.Event { return t.out }

var conditionTimeFields = []string{"message", "lastHeartbeatTime", "lastProbeTime", "lastTransitionTime", "lastUpdateTime"}

// Transform returns the informer transform that strips unexported and sensitive fields before caching.
func Transform(n *Normalizer, kind string) cache.TransformFunc {
	return func(obj any) (any, error) {
		switch o := obj.(type) {
		case *unstructured.Unstructured:
			n.strip(kind, o)
		case *metav1.PartialObjectMetadata:
			if kind == KindSecret {
				o.Annotations = nil
				labels := map[string]string{}
				for k, v := range o.Labels {
					if n.labelAllowed(k) || contains([]string{"owner", "name", "version", "status"}, k) {
						labels[k] = n.red.KeyValue(k, v)
					}
				}
				o.Labels = labels
			}
			o.ManagedFields = nil
			o.Annotations = n.keptAnnotations(kind, o.Annotations)
		}
		return obj, nil
	}
}

func (n *Normalizer) keptAnnotations(kind string, in map[string]string) map[string]string {
	var out map[string]string
	for k, v := range in {
		if n.annotationAllowed(k) || (kind == KindStorageCls && (k == defaultClassAnnotation || k == betaDefaultClassAnnotation)) {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

func nestedMap(obj map[string]any, fields ...string) map[string]any {
	v, ok, _ := unstructured.NestedFieldNoCopy(obj, fields...)
	if !ok {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func nestedList(obj map[string]any, fields ...string) []any {
	v, ok, _ := unstructured.NestedFieldNoCopy(obj, fields...)
	if !ok {
		return nil
	}
	l, _ := v.([]any)
	return l
}

func eachMap(list []any, fn func(map[string]any)) {
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			fn(m)
		}
	}
}

func (n *Normalizer) strip(kind string, u *unstructured.Unstructured) {
	if kind == KindSecret || kind == KindCRD || catalogByKind[kind] == nil {
		n.stripExtension(kind, u)
		return
	}
	o := u.Object
	unstructured.RemoveNestedField(o, "metadata", "managedFields")
	if ann := u.GetAnnotations(); len(ann) > 0 {
		if kept := n.keptAnnotations(kind, ann); len(kept) > 0 {
			u.SetAnnotations(kept)
		} else {
			unstructured.RemoveNestedField(o, "metadata", "annotations")
		}
	}
	eachMap(nestedList(o, "status", "conditions"), func(c map[string]any) {
		for _, k := range conditionTimeFields {
			delete(c, k)
		}
	})
	unstructured.RemoveNestedField(o, "status", "message")
	switch kind {
	case KindPod:
		n.stripPodSpec(kind, nestedMap(o, "spec"))
		for _, k := range []string{"containerStatuses", "initContainerStatuses"} {
			eachMap(nestedList(o, "status", k), func(s map[string]any) {
				for _, st := range []string{"state", "lastState"} {
					for _, phase := range []string{"waiting", "terminated", "running"} {
						unstructured.RemoveNestedField(s, st, phase, "message")
					}
				}
			})
		}
		unstructured.RemoveNestedField(o, "status", "ephemeralContainerStatuses")
	case KindDeployment, KindReplicaSet, KindStatefulSet, KindDaemonSet, KindJob:
		n.stripPodSpec(kind, nestedMap(o, "spec", "template", "spec"))
	case KindCronJob:
		n.stripPodSpec(kind, nestedMap(o, "spec", "jobTemplate", "spec", "template", "spec"))
	case KindNode:
		for _, k := range []string{"images", "volumesInUse", "volumesAttached", "config"} {
			unstructured.RemoveNestedField(o, "status", k)
		}
	case KindConfigMap:
		for _, k := range []string{"data", "binaryData"} {
			m := nestedMap(o, k)
			for key := range m {
				m[key] = ""
			}
		}
	case KindStorageCls:
		if !n.Selected(kind, "parameters.<key>") {
			unstructured.RemoveNestedField(o, "parameters")
		}
	case KindEvent:
		for _, k := range []string{"message", "note"} {
			unstructured.RemoveNestedField(o, k)
		}
	}
}

func (n *Normalizer) stripPodSpec(kind string, spec map[string]any) {
	if spec == nil {
		return
	}
	delete(spec, "ephemeralContainers")
	for _, group := range []string{"containers", "initContainers"} {
		eachMap(nestedList(spec, group), func(c map[string]any) {
			eachMap(nestedList(c, "env"), func(e map[string]any) { delete(e, "value") })
			for _, k := range []string{"livenessProbe", "readinessProbe", "startupProbe", "lifecycle"} {
				delete(c, k)
			}
			for _, k := range []string{"command", "args"} {
				if !n.Selected(kind, group+".<container>."+k) {
					delete(c, k)
				}
			}
		})
	}
}
