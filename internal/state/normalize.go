package state

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// ErrUnsupportedKind reports an object whose kind is not in the catalog; it is reported, never exported.
var ErrUnsupportedKind = errors.New("state: unsupported kind")

// ErrAggregatedKind reports an object that is aggregated onto other resources instead of exported.
var ErrAggregatedKind = errors.New("state: kind is aggregated, not exported")

// Options configures a Normalizer.
type Options struct {
	// LabelAllowlist and AnnotationAllowlist hold exact keys or prefixes ending in "*"; nil selects the defaults.
	LabelAllowlist      []string
	AnnotationAllowlist []string
	// Fields selects non-default catalog fields as "<kind>:<path>", for example "Pod:containers.<container>.args".
	Fields   []string
	Redactor *redact.Redactor
}

// OptionsFromConfig derives normalizer options from the Kubernetes configuration section.
func OptionsFromConfig(k config.Kubernetes, r *redact.Redactor) Options {
	return Options{LabelAllowlist: k.LabelAllowlist, AnnotationAllowlist: k.AnnotationAllowlist, Redactor: r}
}

// Normalizer turns Kubernetes objects into normalized resources using the field catalog.
type Normalizer struct {
	customMu    sync.RWMutex
	custom      map[string]*KindSpec
	labels      []string
	annotations []string
	selected    map[string]bool
	red         *redact.Redactor
}

// NewNormalizer validates o and builds a Normalizer.
func NewNormalizer(o Options) (*Normalizer, error) {
	n := &Normalizer{labels: o.LabelAllowlist, annotations: o.AnnotationAllowlist, selected: map[string]bool{}, red: o.Redactor}
	if n.labels == nil {
		n.labels = DefaultLabelAllowlist
	}
	if n.annotations == nil {
		n.annotations = DefaultAnnotationAllowlist
	}
	if n.red == nil {
		n.red = redact.Default()
	}
	for _, sel := range o.Fields {
		kind, path, ok := strings.Cut(sel, ":")
		spec := n.kindSpec(kind)
		if !ok || spec == nil || spec.byPath[path] == nil {
			return nil, fmt.Errorf("state: unknown catalog field %q", sel)
		}
		n.selected[sel] = true
	}
	return n, nil
}

var defaultNormalizer, _ = NewNormalizer(Options{})

// Normalize normalizes obj with the default options.
func Normalize(obj *unstructured.Unstructured) (protocol.Resource, []protocol.Edge, error) {
	return defaultNormalizer.Normalize(obj)
}

// Selected reports whether a catalog field is exported: default-on or deliberately selected.
func (n *Normalizer) Selected(kind, path string) bool {
	spec := n.kindSpec(kind)
	if spec == nil {
		return false
	}
	fd := spec.byPath[path]
	return fd != nil && (fd.Default || n.selected[kind+":"+path])
}

// Normalize returns the normalized resource and its owner edges (owner uid -> child uid).
func (n *Normalizer) Normalize(obj *unstructured.Unstructured) (protocol.Resource, []protocol.Edge, error) {
	e, err := n.normalize(obj)
	if err != nil {
		return protocol.Resource{}, nil, err
	}
	var edges []protocol.Edge
	for _, o := range e.owners {
		edges = append(edges, protocol.Edge{From: o.uid, Type: EdgeOwns, To: e.res.UID, Attrs: map[string]any{"controller": o.controller}})
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].Key().Less(edges[j].Key()) })
	return e.res, edges, nil
}

// KindOf returns the protocol kind of obj.
func KindOf(obj *unstructured.Unstructured) string {
	gvk := obj.GroupVersionKind()
	return ProtocolKind(gvk.Group, gvk.Kind)
}

type ownerRef struct {
	uid        string
	controller bool
}

type objKey struct{ kind, ns, name string }

// entry is the internal record of a resource: exported fields plus link data that is never exported.
type entry struct {
	res        protocol.Resource
	owners     []ownerRef
	labels     map[string]string
	sel        klabels.Selector
	selAttrs   map[string]any
	nodeName   string
	claims     []string
	volumeName string
	backends   map[string][]string
	target     *objKey
}

type emitter struct {
	n    *Normalizer
	spec *KindSpec
	out  map[string]any
	err  error
}

func (em *emitter) set(path, key string, v any) {
	fd := em.spec.byPath[path]
	if fd == nil {
		if em.err == nil {
			em.err = fmt.Errorf("state: %s field %s is not in the catalog", em.spec.Kind, path)
		}
		return
	}
	if !fd.Default && !em.n.selected[em.spec.Kind+":"+path] {
		return
	}
	switch x := v.(type) {
	case nil:
		return
	case string:
		if x == "" && fd.Redaction != RedactAllowlist {
			return
		}
		if fd.Redaction == RedactText {
			x = em.n.red.String(x)
		}
		v = strings.ToValidUTF8(x, "�")
	case []string:
		if len(x) == 0 {
			return
		}
		arr := make([]any, len(x))
		for i, s := range x {
			if fd.Redaction == RedactText {
				s = em.n.red.String(s)
			}
			arr[i] = strings.ToValidUTF8(s, "�")
		}
		v = arr
	case int32:
		v = int64(x)
	case int:
		v = int64(x)
	}
	em.out[key] = v
}

func (em *emitter) put(path string, v any) { em.set(path, path, v) }

func (em *emitter) putPtr32(path string, p *int32) {
	if p != nil {
		em.put(path, int64(*p))
	}
}

func (n *Normalizer) normalize(obj *unstructured.Unstructured) (*entry, error) {
	kind := KindOf(obj)
	spec := n.kindSpec(kind)
	if spec == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKind, kind)
	}
	if kind == KindSecret || kind == KindCRD || catalogByKind[kind] == nil {
		obj = obj.DeepCopy()
		n.stripExtension(kind, obj)
	}
	if spec.Aggregated {
		return nil, fmt.Errorf("%w: %s", ErrAggregatedKind, kind)
	}
	uid := string(obj.GetUID())
	if uid == "" || obj.GetName() == "" {
		return nil, fmt.Errorf("state: %s object without uid or name", kind)
	}
	e := &entry{res: protocol.Resource{UID: uid, Kind: kind, Name: obj.GetName()}}
	if spec.Namespaced {
		e.res.Namespace = obj.GetNamespace()
	}
	em := &emitter{n: n, spec: spec, out: map[string]any{}}
	n.common(em, obj, e)
	var err error
	switch kind {
	case KindNamespace:
		err = n.namespace(em, obj)
	case KindNode:
		err = n.node(em, obj)
	case KindPod:
		err = n.pod(em, obj, e)
	case KindDeployment:
		err = n.deployment(em, obj)
	case KindReplicaSet:
		err = n.replicaSet(em, obj)
	case KindStatefulSet:
		err = n.statefulSet(em, obj)
	case KindDaemonSet:
		err = n.daemonSet(em, obj)
	case KindJob:
		err = n.job(em, obj)
	case KindCronJob:
		err = n.cronJob(em, obj)
	case KindService:
		err = n.service(em, obj, e)
	case KindIngress:
		err = n.ingress(em, obj, e)
	case KindNetPol:
		err = n.networkPolicy(em, obj, e)
	case KindPVC:
		err = n.pvc(em, obj, e)
	case KindPV:
		err = n.pv(em, obj)
	case KindStorageCls:
		err = n.storageClass(em, obj)
	case KindSecret:
		n.helm(em, obj)
	case KindConfigMap:
		err = n.configMap(em, obj)
		n.helm(em, obj)
	case KindHPA:
		err = n.hpa(em, obj, e)
	case KindPDB:
		err = n.pdb(em, obj, e)
	default:
		n.extension(em, obj)
	}
	if err == nil {
		err = em.err
	}
	if err != nil {
		return nil, fmt.Errorf("state: normalize %s %s/%s: %w", kind, obj.GetNamespace(), obj.GetName(), err)
	}
	fields, err := protocol.NormalizeFields(em.out, false)
	if err != nil {
		return nil, err
	}
	e.res.Fields = fields
	return e, nil
}

func allowed(patterns []string, key string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(key, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if p == key {
			return true
		}
	}
	return false
}

func (n *Normalizer) labelAllowed(k string) bool      { return allowed(n.labels, k) }
func (n *Normalizer) annotationAllowed(k string) bool { return allowed(n.annotations, k) }

func (n *Normalizer) common(em *emitter, obj *unstructured.Unstructured, e *entry) {
	if ts := obj.GetCreationTimestamp(); !ts.IsZero() {
		em.put("created", ts.UnixMilli())
	}
	if obj.GetDeletionTimestamp() != nil {
		em.put("terminating", true)
	}
	for k, v := range obj.GetLabels() {
		if n.labelAllowed(k) {
			em.set("labels.<key>", "labels."+k, n.red.KeyValue(k, v))
		}
	}
	for k, v := range obj.GetAnnotations() {
		if n.annotationAllowed(k) {
			em.set("annotations.<key>", "annotations."+k, n.red.KeyValue(k, v))
		}
	}
	for _, o := range obj.GetOwnerReferences() {
		ctrl := o.Controller != nil && *o.Controller
		if o.Kind != "" && o.Name != "" && !strings.Contains(o.Kind, ".") {
			em.set("owners.<kind>.<name>", "owners."+o.Kind+"."+o.Name, ctrl)
		}
		if o.UID != "" {
			e.owners = append(e.owners, ownerRef{uid: string(o.UID), controller: ctrl})
		}
	}
	sort.Slice(e.owners, func(i, j int) bool { return e.owners[i].uid < e.owners[j].uid })
}

func convert(obj *unstructured.Unstructured, out any) error {
	return runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, out)
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	s := append([]string(nil), in...)
	sort.Strings(s)
	out := s[:1]
	for _, x := range s[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

func quantityValue(name corev1.ResourceName, q resource.Quantity) float64 {
	if name == corev1.ResourceCPU {
		return float64(q.MilliValue()) / 1000
	}
	return float64(q.Value())
}

func (em *emitter) resources(path, prefix string, rl corev1.ResourceList) {
	for name, q := range rl {
		em.set(path, prefix+string(name), quantityValue(name, q))
	}
}

var conditionTypeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,62}$`)

const maxConditions = 32

// conditions reads status.conditions generically; types nil admits any simple type name.
func (em *emitter) conditions(obj *unstructured.Unstructured, types []string) {
	list, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	count := 0
	for _, c := range list {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		t, _ := m["type"].(string)
		if !conditionTypeRe.MatchString(t) || (types != nil && !contains(types, t)) || count >= maxConditions {
			continue
		}
		count++
		st, _ := m["status"].(string)
		rs, _ := m["reason"].(string)
		em.set("conditions.<type>.status", "conditions."+t+".status", st)
		em.set("conditions.<type>.reason", "conditions."+t+".reason", rs)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (n *Normalizer) namespace(em *emitter, obj *unstructured.Unstructured) error {
	var ns corev1.Namespace
	if err := convert(obj, &ns); err != nil {
		return err
	}
	em.put("phase", string(ns.Status.Phase))
	return nil
}

func taintString(t corev1.Taint) string {
	s := t.Key
	if t.Value != "" {
		s += "=" + t.Value
	}
	return s + ":" + string(t.Effect)
}

func (n *Normalizer) node(em *emitter, obj *unstructured.Unstructured) error {
	var nd corev1.Node
	if err := convert(obj, &nd); err != nil {
		return err
	}
	em.resources("capacity.<resource>", "capacity.", nd.Status.Capacity)
	em.resources("allocatable.<resource>", "allocatable.", nd.Status.Allocatable)
	var taints []string
	for _, t := range nd.Spec.Taints {
		taints = append(taints, taintString(t))
	}
	em.put("taints", sortedUnique(taints))
	em.put("unschedulable", nd.Spec.Unschedulable)
	info := nd.Status.NodeInfo
	em.put("kubeletVersion", info.KubeletVersion)
	em.put("containerRuntimeVersion", info.ContainerRuntimeVersion)
	em.put("osImage", info.OSImage)
	em.put("kernelVersion", info.KernelVersion)
	em.put("architecture", info.Architecture)
	em.put("operatingSystem", info.OperatingSystem)
	em.put("providerID", nd.Spec.ProviderID)
	em.put("podCIDR", nd.Spec.PodCIDR)
	for _, a := range nd.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			em.put("internalIP", a.Address)
			break
		}
	}
	em.put("zone", firstLabel(nd.Labels, corev1.LabelTopologyZone, corev1.LabelFailureDomainBetaZone))
	em.put("region", firstLabel(nd.Labels, corev1.LabelTopologyRegion, corev1.LabelFailureDomainBetaRegion))
	em.conditions(obj, nil)
	return nil
}

func firstLabel(l map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := l[k]; v != "" {
			return v
		}
	}
	return ""
}

func portString(name string, port int32, proto corev1.Protocol) string {
	if proto == "" {
		proto = corev1.ProtocolTCP
	}
	s := strconv.Itoa(int(port)) + "/" + string(proto)
	if name != "" {
		s = name + ":" + s
	}
	return s
}

// podSpec emits template or pod spec fields and returns the referenced claim names.
func (n *Normalizer) podSpec(em *emitter, spec *corev1.PodSpec, podName string) []string {
	var cms, secrets, claims []string
	for _, group := range []struct {
		key  string
		list []corev1.Container
	}{{"containers", spec.Containers}, {"initContainers", spec.InitContainers}} {
		p := group.key + ".<container>."
		for _, c := range group.list {
			b := group.key + "." + c.Name + "."
			em.set(p+"image", b+"image", c.Image)
			em.resources(p+"requests.<resource>", b+"requests.", c.Resources.Requests)
			em.resources(p+"limits.<resource>", b+"limits.", c.Resources.Limits)
			var ports []string
			for _, pt := range c.Ports {
				ports = append(ports, portString(pt.Name, pt.ContainerPort, pt.Protocol))
			}
			em.set(p+"ports", b+"ports", sortedUnique(ports))
			var refs []string
			for _, ev := range c.Env {
				vf := ev.ValueFrom
				switch {
				case vf == nil:
				case vf.ConfigMapKeyRef != nil:
					refs = append(refs, ev.Name+"=configMap:"+vf.ConfigMapKeyRef.Name+"/"+vf.ConfigMapKeyRef.Key)
					cms = append(cms, vf.ConfigMapKeyRef.Name)
				case vf.SecretKeyRef != nil:
					refs = append(refs, ev.Name+"=secret:"+vf.SecretKeyRef.Name+"/"+vf.SecretKeyRef.Key)
					secrets = append(secrets, vf.SecretKeyRef.Name)
				case vf.FieldRef != nil:
					refs = append(refs, ev.Name+"=field:"+vf.FieldRef.FieldPath)
				case vf.ResourceFieldRef != nil:
					refs = append(refs, ev.Name+"=resource:"+vf.ResourceFieldRef.Resource)
				}
			}
			em.set(p+"envRefs", b+"envRefs", sortedUnique(refs))
			var from []string
			for _, ef := range c.EnvFrom {
				if ef.ConfigMapRef != nil {
					from = append(from, "configMap:"+ef.ConfigMapRef.Name)
					cms = append(cms, ef.ConfigMapRef.Name)
				}
				if ef.SecretRef != nil {
					from = append(from, "secret:"+ef.SecretRef.Name)
					secrets = append(secrets, ef.SecretRef.Name)
				}
			}
			em.set(p+"envFrom", b+"envFrom", sortedUnique(from))
			em.set(p+"command", b+"command", c.Command)
			em.set(p+"args", b+"args", c.Args)
		}
	}
	for _, v := range spec.Volumes {
		switch {
		case v.ConfigMap != nil:
			cms = append(cms, v.ConfigMap.Name)
		case v.Secret != nil:
			secrets = append(secrets, v.Secret.SecretName)
		case v.PersistentVolumeClaim != nil:
			claims = append(claims, v.PersistentVolumeClaim.ClaimName)
		case v.Ephemeral != nil && podName != "":
			claims = append(claims, podName+"-"+v.Name)
		case v.Projected != nil:
			for _, src := range v.Projected.Sources {
				if src.ConfigMap != nil {
					cms = append(cms, src.ConfigMap.Name)
				}
				if src.Secret != nil {
					secrets = append(secrets, src.Secret.Name)
				}
			}
		}
	}
	for _, s := range spec.ImagePullSecrets {
		secrets = append(secrets, s.Name)
	}
	em.put("serviceAccountName", spec.ServiceAccountName)
	em.put("refs.configMaps", sortedUnique(nonEmpty(cms)))
	em.put("refs.secrets", sortedUnique(nonEmpty(secrets)))
	claims = sortedUnique(nonEmpty(claims))
	em.put("refs.claims", claims)
	return claims
}

func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containerState(s corev1.ContainerState) string {
	switch {
	case s.Running != nil:
		return "running"
	case s.Terminated != nil:
		return "terminated"
	case s.Waiting != nil:
		return "waiting"
	}
	return ""
}

func (n *Normalizer) containerStatuses(em *emitter, group string, list []corev1.ContainerStatus) {
	p := group + ".<container>."
	for _, s := range list {
		b := group + "." + s.Name + "."
		em.set(p+"imageID", b+"imageID", s.ImageID)
		em.set(p+"ready", b+"ready", s.Ready)
		em.set(p+"restarts", b+"restarts", s.RestartCount)
		em.set(p+"state", b+"state", containerState(s.State))
		if w := s.State.Waiting; w != nil {
			em.set(p+"waitingReason", b+"waitingReason", w.Reason)
		}
		if t := s.State.Terminated; t != nil {
			em.set(p+"terminatedReason", b+"terminatedReason", t.Reason)
			em.set(p+"terminatedExitCode", b+"terminatedExitCode", t.ExitCode)
		}
		if t := s.LastTerminationState.Terminated; t != nil {
			em.set(p+"lastTerminatedReason", b+"lastTerminatedReason", t.Reason)
			em.set(p+"lastTerminatedExitCode", b+"lastTerminatedExitCode", t.ExitCode)
		}
	}
}

func (n *Normalizer) pod(em *emitter, obj *unstructured.Unstructured, e *entry) error {
	var p corev1.Pod
	if err := convert(obj, &p); err != nil {
		return err
	}
	e.claims = n.podSpec(em, &p.Spec, p.Name)
	e.nodeName = p.Spec.NodeName
	e.labels = p.Labels
	em.put("phase", string(p.Status.Phase))
	em.put("reason", p.Status.Reason)
	em.put("nodeName", p.Spec.NodeName)
	em.put("hostIP", p.Status.HostIP)
	em.put("podIP", p.Status.PodIP)
	em.put("qosClass", string(p.Status.QOSClass))
	em.put("priorityClassName", p.Spec.PriorityClassName)
	em.put("hostNetwork", p.Spec.HostNetwork)
	ready := false
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			ready = c.Status == corev1.ConditionTrue
		}
	}
	em.put("ready", ready)
	em.conditions(obj, podConditionTypes)
	n.containerStatuses(em, "containers", p.Status.ContainerStatuses)
	n.containerStatuses(em, "initContainers", p.Status.InitContainerStatuses)
	return nil
}

func replicas(p *int32) int64 {
	if p == nil {
		return 1
	}
	return int64(*p)
}

func (em *emitter) generations(meta metav1.ObjectMeta, observed int64) {
	em.put("generation", meta.Generation)
	em.put("observedGeneration", observed)
}

func (n *Normalizer) deployment(em *emitter, obj *unstructured.Unstructured) error {
	var d appsv1.Deployment
	if err := convert(obj, &d); err != nil {
		return err
	}
	em.put("replicas", replicas(d.Spec.Replicas))
	em.put("paused", d.Spec.Paused)
	em.put("strategy", string(d.Spec.Strategy.Type))
	st := d.Status
	em.put("statusReplicas", st.Replicas)
	em.put("readyReplicas", st.ReadyReplicas)
	em.put("availableReplicas", st.AvailableReplicas)
	em.put("updatedReplicas", st.UpdatedReplicas)
	em.put("unavailableReplicas", st.UnavailableReplicas)
	em.generations(d.ObjectMeta, st.ObservedGeneration)
	em.conditions(obj, deployConditionTypes)
	n.podSpec(em, &d.Spec.Template.Spec, "")
	return nil
}

func (n *Normalizer) replicaSet(em *emitter, obj *unstructured.Unstructured) error {
	var r appsv1.ReplicaSet
	if err := convert(obj, &r); err != nil {
		return err
	}
	em.put("replicas", replicas(r.Spec.Replicas))
	em.put("statusReplicas", r.Status.Replicas)
	em.put("readyReplicas", r.Status.ReadyReplicas)
	em.put("availableReplicas", r.Status.AvailableReplicas)
	em.generations(r.ObjectMeta, r.Status.ObservedGeneration)
	em.conditions(obj, rsConditionTypes)
	n.podSpec(em, &r.Spec.Template.Spec, "")
	return nil
}

func (n *Normalizer) statefulSet(em *emitter, obj *unstructured.Unstructured) error {
	var s appsv1.StatefulSet
	if err := convert(obj, &s); err != nil {
		return err
	}
	em.put("replicas", replicas(s.Spec.Replicas))
	em.put("serviceName", s.Spec.ServiceName)
	em.put("podManagementPolicy", string(s.Spec.PodManagementPolicy))
	em.put("updateStrategy", string(s.Spec.UpdateStrategy.Type))
	st := s.Status
	em.put("statusReplicas", st.Replicas)
	em.put("readyReplicas", st.ReadyReplicas)
	em.put("availableReplicas", st.AvailableReplicas)
	em.put("currentReplicas", st.CurrentReplicas)
	em.put("updatedReplicas", st.UpdatedReplicas)
	em.put("currentRevision", st.CurrentRevision)
	em.put("updateRevision", st.UpdateRevision)
	em.generations(s.ObjectMeta, st.ObservedGeneration)
	n.podSpec(em, &s.Spec.Template.Spec, "")
	return nil
}

func (n *Normalizer) daemonSet(em *emitter, obj *unstructured.Unstructured) error {
	var d appsv1.DaemonSet
	if err := convert(obj, &d); err != nil {
		return err
	}
	em.put("updateStrategy", string(d.Spec.UpdateStrategy.Type))
	st := d.Status
	em.put("desiredNumberScheduled", st.DesiredNumberScheduled)
	em.put("currentNumberScheduled", st.CurrentNumberScheduled)
	em.put("numberReady", st.NumberReady)
	em.put("numberAvailable", st.NumberAvailable)
	em.put("numberUnavailable", st.NumberUnavailable)
	em.put("numberMisscheduled", st.NumberMisscheduled)
	em.put("updatedNumberScheduled", st.UpdatedNumberScheduled)
	em.generations(d.ObjectMeta, st.ObservedGeneration)
	n.podSpec(em, &d.Spec.Template.Spec, "")
	return nil
}

func (n *Normalizer) job(em *emitter, obj *unstructured.Unstructured) error {
	var j batchv1.Job
	if err := convert(obj, &j); err != nil {
		return err
	}
	em.putPtr32("completions", j.Spec.Completions)
	em.putPtr32("parallelism", j.Spec.Parallelism)
	em.putPtr32("backoffLimit", j.Spec.BackoffLimit)
	em.put("suspend", j.Spec.Suspend != nil && *j.Spec.Suspend)
	if j.Spec.CompletionMode != nil {
		em.put("completionMode", string(*j.Spec.CompletionMode))
	}
	em.put("active", j.Status.Active)
	em.put("succeeded", j.Status.Succeeded)
	em.put("failed", j.Status.Failed)
	em.conditions(obj, jobConditionTypes)
	n.podSpec(em, &j.Spec.Template.Spec, "")
	return nil
}

func (n *Normalizer) cronJob(em *emitter, obj *unstructured.Unstructured) error {
	var c batchv1.CronJob
	if err := convert(obj, &c); err != nil {
		return err
	}
	em.put("schedule", c.Spec.Schedule)
	if c.Spec.TimeZone != nil {
		em.put("timeZone", *c.Spec.TimeZone)
	}
	em.put("suspend", c.Spec.Suspend != nil && *c.Spec.Suspend)
	em.put("concurrencyPolicy", string(c.Spec.ConcurrencyPolicy))
	em.put("active", len(c.Status.Active))
	if t := c.Status.LastScheduleTime; t != nil {
		em.put("lastScheduleTime", t.UnixMilli())
	}
	if t := c.Status.LastSuccessfulTime; t != nil {
		em.put("lastSuccessfulTime", t.UnixMilli())
	}
	n.podSpec(em, &c.Spec.JobTemplate.Spec.Template.Spec, "")
	return nil
}

func selectorString(s klabels.Selector) string {
	if s.Empty() {
		return "*"
	}
	return s.String()
}

func (n *Normalizer) service(em *emitter, obj *unstructured.Unstructured, e *entry) error {
	var s corev1.Service
	if err := convert(obj, &s); err != nil {
		return err
	}
	em.put("type", string(s.Spec.Type))
	em.put("clusterIP", s.Spec.ClusterIP)
	var ports, names []string
	for _, p := range s.Spec.Ports {
		ports = append(ports, portString(p.Name, p.Port, p.Protocol)+"->"+p.TargetPort.String())
		if p.Name != "" {
			names = append(names, p.Name)
		} else {
			names = append(names, portString("", p.Port, p.Protocol))
		}
	}
	em.put("ports", sortedUnique(ports))
	em.put("hasSelector", len(s.Spec.Selector) > 0)
	if len(s.Spec.Selector) > 0 {
		if sel, err := klabels.ValidatedSelectorFromSet(s.Spec.Selector); err == nil {
			e.sel = sel
			em.put("selector", selectorString(sel))
		}
	}
	e.selAttrs = map[string]any{}
	if names = sortedUnique(names); len(names) > 0 {
		arr := make([]any, len(names))
		for i, x := range names {
			arr[i] = x
		}
		e.selAttrs["ports"] = arr
	}
	em.put("sessionAffinity", string(s.Spec.SessionAffinity))
	em.put("externalTrafficPolicy", string(s.Spec.ExternalTrafficPolicy))
	if s.Spec.InternalTrafficPolicy != nil {
		em.put("internalTrafficPolicy", string(*s.Spec.InternalTrafficPolicy))
	}
	em.put("externalName", s.Spec.ExternalName)
	em.put("loadBalancerIngress", lbIngress(s.Status.LoadBalancer.Ingress))
	return nil
}

func lbIngress(in []corev1.LoadBalancerIngress) []string {
	var out []string
	for _, i := range in {
		if i.IP != "" {
			out = append(out, i.IP)
		}
		if i.Hostname != "" {
			out = append(out, i.Hostname)
		}
	}
	return sortedUnique(out)
}

func backendPort(p networkingv1.ServiceBackendPort) string {
	if p.Name != "" {
		return p.Name
	}
	return strconv.Itoa(int(p.Number))
}

func (n *Normalizer) ingress(em *emitter, obj *unstructured.Unstructured, e *entry) error {
	var in networkingv1.Ingress
	if err := convert(obj, &in); err != nil {
		return err
	}
	if in.Spec.IngressClassName != nil {
		em.put("ingressClassName", *in.Spec.IngressClassName)
	}
	e.backends = map[string][]string{}
	var hosts, backends, paths []string
	add := func(b *networkingv1.IngressBackend) string {
		if b == nil || b.Service == nil || b.Service.Name == "" {
			return ""
		}
		port := backendPort(b.Service.Port)
		backends = append(backends, b.Service.Name+":"+port)
		e.backends[b.Service.Name] = append(e.backends[b.Service.Name], port)
		return b.Service.Name + ":" + port
	}
	add(in.Spec.DefaultBackend)
	for _, r := range in.Spec.Rules {
		if r.Host != "" {
			hosts = append(hosts, r.Host)
		}
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			target := add(&p.Backend)
			pt := ""
			if p.PathType != nil {
				pt = string(*p.PathType)
			}
			paths = append(paths, strings.TrimSpace(r.Host+" "+p.Path+" "+pt)+" -> "+target)
		}
	}
	for svc, ports := range e.backends {
		e.backends[svc] = sortedUnique(ports)
	}
	em.put("hosts", sortedUnique(hosts))
	em.put("backends", sortedUnique(backends))
	em.put("tls", len(in.Spec.TLS) > 0)
	em.put("paths", sortedUnique(paths))
	var lb []string
	for _, i := range in.Status.LoadBalancer.Ingress {
		lb = append(lb, i.IP, i.Hostname)
	}
	em.put("loadBalancerIngress", sortedUnique(nonEmpty(lb)))
	return nil
}

func (n *Normalizer) networkPolicy(em *emitter, obj *unstructured.Unstructured, e *entry) error {
	var np networkingv1.NetworkPolicy
	if err := convert(obj, &np); err != nil {
		return err
	}
	if sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector); err == nil {
		e.sel = sel
		em.put("podSelector", selectorString(sel))
	}
	e.selAttrs = map[string]any{}
	var types []string
	for _, t := range np.Spec.PolicyTypes {
		types = append(types, string(t))
	}
	em.put("policyTypes", sortedUnique(types))
	em.put("ingressRules", len(np.Spec.Ingress))
	em.put("egressRules", len(np.Spec.Egress))
	return nil
}

func accessModes(in []corev1.PersistentVolumeAccessMode) []string {
	var out []string
	for _, m := range in {
		out = append(out, string(m))
	}
	return sortedUnique(out)
}

func (n *Normalizer) pvc(em *emitter, obj *unstructured.Unstructured, e *entry) error {
	var c corev1.PersistentVolumeClaim
	if err := convert(obj, &c); err != nil {
		return err
	}
	em.put("phase", string(c.Status.Phase))
	if c.Spec.StorageClassName != nil {
		em.put("storageClassName", *c.Spec.StorageClassName)
	}
	em.put("accessModes", accessModes(c.Spec.AccessModes))
	if q, ok := c.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
		em.put("requests.storage", quantityValue(corev1.ResourceStorage, q))
	}
	if q, ok := c.Status.Capacity[corev1.ResourceStorage]; ok {
		em.put("capacity.storage", quantityValue(corev1.ResourceStorage, q))
	}
	em.put("volumeName", c.Spec.VolumeName)
	if c.Spec.VolumeMode != nil {
		em.put("volumeMode", string(*c.Spec.VolumeMode))
	}
	em.conditions(obj, pvcConditionTypes)
	e.volumeName = c.Spec.VolumeName
	return nil
}

var pvSpecNonSource = map[string]bool{
	"capacity": true, "accessModes": true, "claimRef": true, "persistentVolumeReclaimPolicy": true,
	"storageClassName": true, "mountOptions": true, "volumeMode": true, "nodeAffinity": true, "volumeAttributesClassName": true,
}

func pvDriver(obj *unstructured.Unstructured) string {
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	keys := make([]string, 0, len(spec))
	for k := range spec {
		if !pvSpecNonSource[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "csi" {
			d, _, _ := unstructured.NestedString(spec, "csi", "driver")
			return d
		}
		if _, ok := spec[k].(map[string]any); ok {
			return k
		}
	}
	return ""
}

// NodeAffinitySummary renders required node affinity terms canonically; terms are ORed.
func NodeAffinitySummary(na *corev1.VolumeNodeAffinity) string {
	if na == nil || na.Required == nil {
		return ""
	}
	var terms []string
	for _, t := range na.Required.NodeSelectorTerms {
		var reqs []string
		for _, r := range t.MatchExpressions {
			reqs = append(reqs, requirementString(r.Key, r.Operator, r.Values))
		}
		for _, r := range t.MatchFields {
			reqs = append(reqs, requirementString("field:"+r.Key, r.Operator, r.Values))
		}
		if reqs = sortedUnique(reqs); len(reqs) > 0 {
			terms = append(terms, strings.Join(reqs, ","))
		}
	}
	return strings.Join(sortedUnique(terms), " || ")
}

func requirementString(key string, op corev1.NodeSelectorOperator, values []string) string {
	vals := sortedUnique(values)
	switch op {
	case corev1.NodeSelectorOpExists, corev1.NodeSelectorOpDoesNotExist:
		return key + " " + strings.ToLower(string(op))
	}
	return key + " " + strings.ToLower(string(op)) + " (" + strings.Join(vals, ",") + ")"
}

func (n *Normalizer) pv(em *emitter, obj *unstructured.Unstructured) error {
	var v corev1.PersistentVolume
	if err := convert(obj, &v); err != nil {
		return err
	}
	em.put("phase", string(v.Status.Phase))
	em.put("storageClassName", v.Spec.StorageClassName)
	if q, ok := v.Spec.Capacity[corev1.ResourceStorage]; ok {
		em.put("capacity.storage", quantityValue(corev1.ResourceStorage, q))
	}
	em.put("accessModes", accessModes(v.Spec.AccessModes))
	em.put("reclaimPolicy", string(v.Spec.PersistentVolumeReclaimPolicy))
	if v.Spec.VolumeMode != nil {
		em.put("volumeMode", string(*v.Spec.VolumeMode))
	}
	if c := v.Spec.ClaimRef; c != nil && c.Name != "" {
		em.put("claim", c.Namespace+"/"+c.Name)
	}
	em.put("driver", pvDriver(obj))
	em.put("nodeAffinity", NodeAffinitySummary(v.Spec.NodeAffinity))
	return nil
}

const (
	defaultClassAnnotation     = "storageclass.kubernetes.io/is-default-class"
	betaDefaultClassAnnotation = "storageclass.beta.kubernetes.io/is-default-class"
)

func (n *Normalizer) storageClass(em *emitter, obj *unstructured.Unstructured) error {
	var s storagev1.StorageClass
	if err := convert(obj, &s); err != nil {
		return err
	}
	em.put("provisioner", s.Provisioner)
	if s.ReclaimPolicy != nil {
		em.put("reclaimPolicy", string(*s.ReclaimPolicy))
	}
	if s.VolumeBindingMode != nil {
		em.put("volumeBindingMode", string(*s.VolumeBindingMode))
	}
	em.put("allowVolumeExpansion", s.AllowVolumeExpansion != nil && *s.AllowVolumeExpansion)
	em.put("isDefault", s.Annotations[defaultClassAnnotation] == "true" || s.Annotations[betaDefaultClassAnnotation] == "true")
	for k, v := range s.Parameters {
		em.set("parameters.<key>", "parameters."+k, n.red.KeyValue(k, v))
	}
	return nil
}

func (n *Normalizer) configMap(em *emitter, obj *unstructured.Unstructured) error {
	var keys []string
	for _, field := range []string{"data", "binaryData"} {
		m, _, _ := unstructured.NestedMap(obj.Object, field)
		for k := range m {
			keys = append(keys, k)
		}
	}
	em.put("keys", sortedUnique(keys))
	return nil
}

func (n *Normalizer) hpa(em *emitter, obj *unstructured.Unstructured, e *entry) error {
	var h autoscalingv2.HorizontalPodAutoscaler
	if err := convert(obj, &h); err != nil {
		return err
	}
	ref := h.Spec.ScaleTargetRef
	if gv, err := schema.ParseGroupVersion(ref.APIVersion); err == nil && ref.Kind != "" && ref.Name != "" {
		kind := ProtocolKind(gv.Group, ref.Kind)
		em.put("target.kind", kind)
		em.put("target.name", ref.Name)
		e.target = &objKey{kind: kind, ns: h.Namespace, name: ref.Name}
	}
	em.put("minReplicas", replicas(h.Spec.MinReplicas))
	em.put("maxReplicas", h.Spec.MaxReplicas)
	em.put("currentReplicas", h.Status.CurrentReplicas)
	em.put("desiredReplicas", h.Status.DesiredReplicas)
	var metrics []string
	for _, m := range h.Spec.Metrics {
		name := ""
		switch {
		case m.Resource != nil:
			name = string(m.Resource.Name)
		case m.ContainerResource != nil:
			name = string(m.ContainerResource.Name) + "/" + m.ContainerResource.Container
		case m.Pods != nil:
			name = m.Pods.Metric.Name
		case m.Object != nil:
			name = m.Object.Metric.Name
		case m.External != nil:
			name = m.External.Metric.Name
		}
		metrics = append(metrics, string(m.Type)+":"+name)
	}
	em.put("metrics", sortedUnique(metrics))
	em.conditions(obj, hpaConditionTypes)
	return nil
}

func (n *Normalizer) pdb(em *emitter, obj *unstructured.Unstructured, e *entry) error {
	var p policyv1.PodDisruptionBudget
	if err := convert(obj, &p); err != nil {
		return err
	}
	if p.Spec.Selector != nil {
		if sel, err := metav1.LabelSelectorAsSelector(p.Spec.Selector); err == nil {
			e.sel = sel
			em.put("selector", selectorString(sel))
		}
	}
	e.selAttrs = map[string]any{}
	if p.Spec.MinAvailable != nil {
		em.put("minAvailable", p.Spec.MinAvailable.String())
	}
	if p.Spec.MaxUnavailable != nil {
		em.put("maxUnavailable", p.Spec.MaxUnavailable.String())
	}
	em.put("currentHealthy", p.Status.CurrentHealthy)
	em.put("desiredHealthy", p.Status.DesiredHealthy)
	em.put("disruptionsAllowed", p.Status.DisruptionsAllowed)
	em.put("expectedPods", p.Status.ExpectedPods)
	em.conditions(obj, pdbConditionTypes)
	return nil
}
