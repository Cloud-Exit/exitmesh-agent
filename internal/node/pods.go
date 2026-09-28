package node

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/scrape"
)

const (
	sourcePods        = "pods"
	sourceCoordinator = "coordinator"
)

// podWatch keeps the pods scheduled on this node, from a spec.nodeName field-selected list and watch.
type podWatch struct {
	client   kubernetes.Interface
	node     string
	onChange func()

	mu    sync.RWMutex
	pods  map[string]*corev1.Pod
	known map[string]map[string]string
	ready atomic.Bool
}

func newPodWatch(c kubernetes.Interface, node string, onChange func()) *podWatch {
	return &podWatch{client: c, node: node, onChange: onChange, pods: map[string]*corev1.Pod{}, known: map[string]map[string]string{}}
}

func (w *podWatch) run(ctx context.Context) {
	sel := fields.OneTermEqualSelector("spec.nodeName", w.node).String()
	f := informers.NewSharedInformerFactoryWithOptions(w.client, 0, informers.WithTweakListOptions(func(o *metav1.ListOptions) {
		o.FieldSelector = sel
	}))
	inf := f.Core().V1().Pods().Informer()
	_ = inf.SetTransform(func(obj any) (any, error) {
		if p, ok := obj.(*corev1.Pod); ok {
			p.ManagedFields = nil
		}
		return obj, nil
	})
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.upsert,
		UpdateFunc: func(_, obj any) { w.upsert(obj) },
		DeleteFunc: w.remove,
	})
	f.Start(ctx.Done())
	if cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		w.ready.Store(true)
		w.onChange()
	}
	<-ctx.Done()
	f.Shutdown()
}

func (w *podWatch) synced() bool { return w.ready.Load() }

func (w *podWatch) upsert(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	if p.Spec.NodeName != w.node {
		w.remove(obj)
		return
	}
	w.mu.Lock()
	w.pods[string(p.UID)] = p
	w.known[string(p.UID)] = workloadLabels(p)
	w.mu.Unlock()
	w.onChange()
}

func (w *podWatch) remove(obj any) {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	w.mu.Lock()
	_, had := w.pods[string(p.UID)]
	delete(w.pods, string(p.UID))
	delete(w.known, string(p.UID))
	w.mu.Unlock()
	if had {
		w.onChange()
	}
}

// enrich returns workload labels; the tailer keeps the last known labels after the pod leaves the watch.
func (w *podWatch) enrich(_, _, uid, _ string) map[string]string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if l, ok := w.known[uid]; ok {
		return l
	}
	return nil
}

// resolve maps a rule's Pod resource labels to the UID of a pod on this node, like the coordinator does from its state.
func (w *podWatch) resolve(kind, namespace, name string) (string, bool) {
	if kind != state.KindPod {
		return "", false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	for uid, p := range w.pods {
		if p.Namespace == namespace && p.Name == name {
			return uid, true
		}
	}
	return "", false
}

func (w *podWatch) snapshot() []*corev1.Pod {
	w.mu.RLock()
	out := make([]*corev1.Pod, 0, len(w.pods))
	for _, p := range w.pods {
		out = append(out, p)
	}
	w.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// workloadLabels names the owning workload, resolving a ReplicaSet to its Deployment by the template hash.
func workloadLabels(p *corev1.Pod) map[string]string {
	out := map[string]string{}
	ref := metav1.GetControllerOf(p)
	if ref == nil {
		return out
	}
	kind, name := ref.Kind, ref.Name
	if h := p.Labels["pod-template-hash"]; kind == "ReplicaSet" && h != "" && strings.HasSuffix(name, "-"+h) {
		kind, name = "Deployment", strings.TrimSuffix(name, "-"+h)
	}
	out["workload_kind"], out["workload"] = kind, name
	return out
}

type kubeState struct {
	changed chan struct{}
	mu      sync.Mutex
	latest  *nodeapi.KubeUpdate
}

func (a *Agent) onPods() { a.signal(a.kubeChanged()) }

func (a *Agent) kubeChanged() chan struct{} {
	a.kube.mu.Lock()
	defer a.kube.mu.Unlock()
	if a.kube.changed == nil {
		a.kube.changed = make(chan struct{}, 1)
	}
	return a.kube.changed
}

// kubeLoop rebuilds scrape targets and the node-derived and coordinator-pushed kube_* series.
func (a *Agent) kubeLoop(ctx context.Context) {
	changed := a.kubeChanged()
	t := time.NewTicker(a.t.KubeRefresh)
	defer t.Stop()
	for {
		a.refreshKube()
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-t.C:
		}
	}
}

func (a *Agent) refreshKube() {
	pods := a.pods.snapshot()
	now := a.clock()
	if a.scraper != nil {
		targets := scrape.KubeletTargets(a.kubeletHost, a.kubeletPort, scrape.KubeletOptions{
			Node: a.node, TokenFile: a.deps.KubeletTokenFile, CAFile: a.deps.KubeletCAFile,
			InsecureSkipVerify: a.cfg.Node.KubeletTLS == "skip",
		})
		sp := make([]scrape.Pod, 0, len(pods))
		for _, p := range pods {
			sp = append(sp, scrapePod(p))
		}
		a.scraper.Sync(append(targets, scrape.PodTargets(sp)...))
	}
	us := make([]*unstructured.Unstructured, 0, len(pods))
	for _, p := range pods {
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p)
		if err != nil {
			a.log.Warn("pod not converted", "namespace", p.Namespace, "pod", p.Name, "err", err)
			continue
		}
		u := &unstructured.Unstructured{Object: m}
		u.SetAPIVersion("v1")
		u.SetKind("Pod")
		us = append(us, u)
	}
	if a.pods.synced() {
		series, err := state.PodSeriesFromPods(a.norm, us, now.UnixMilli())
		if err != nil {
			a.log.Warn("pod series not derived", "err", err)
		} else {
			out := make([]engine.Series, 0, len(series))
			for _, s := range series {
				out = append(out, engine.Series{Labels: s.Labels, Samples: []engine.Sample{{T: now.UnixMilli(), F: s.Value}}})
			}
			a.mem.Replace(sourcePods, out)
		}
	}
	a.kube.mu.Lock()
	up := a.kube.latest
	a.kube.mu.Unlock()
	if up != nil {
		out := make([]engine.Series, 0, len(up.Series))
		for _, s := range up.Series {
			if s.Labels[labels.MetricName] == "" {
				continue
			}
			out = append(out, engine.Series{Labels: labels.FromMap(s.Labels), Samples: []engine.Sample{{T: now.UnixMilli(), F: s.Value}}})
		}
		a.mem.Replace(sourceCoordinator, out)
	}
}

func scrapePod(p *corev1.Pod) scrape.Pod {
	sp := scrape.Pod{Namespace: p.Namespace, Name: p.Name, UID: string(p.UID), Node: p.Spec.NodeName, IP: p.Status.PodIP, Phase: string(p.Status.Phase), Annotations: p.Annotations}
	for _, c := range p.Spec.Containers {
		for _, port := range c.Ports {
			sp.Ports = append(sp.Ports, scrape.PodPort{Container: c.Name, Port: int(port.ContainerPort), Protocol: string(port.Protocol)})
		}
	}
	return sp
}

// kubePoll long-polls the coordinator for kube_node_* and other non-pod series of this node.
func (a *Agent) kubePoll(ctx context.Context) {
	back := a.t.RetryMin
	var since uint64
	for ctx.Err() == nil {
		up, err := a.client.WaitKube(ctx, since)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Debug("kube series poll failed", "err", err)
			if !sleepCtx(ctx, back) {
				return
			}
			back = min(2*back, a.t.RetryMax)
			continue
		}
		back = a.t.RetryMin
		if up == nil {
			continue
		}
		since = up.Revision
		a.kube.mu.Lock()
		a.kube.latest = up
		a.kube.mu.Unlock()
		a.signal(a.kubeChanged())
	}
}
