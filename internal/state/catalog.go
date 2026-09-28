// Package state normalizes Kubernetes objects into protocol state, edges, scopes, and kube_* series.
package state

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CatalogSchema is the field catalog version; it changes whenever an exported path changes meaning.
const CatalogSchema = 1

// FieldType is the value type of an exported field.
type FieldType string

const (
	TypeString     FieldType = "string"
	TypeInt        FieldType = "int"
	TypeBool       FieldType = "bool"
	TypeQuantity   FieldType = "quantity"
	TypeTimestamp  FieldType = "timestamp"
	TypeStringList FieldType = "list<string>"
)

// Redaction is the redaction class of an exported field.
type Redaction string

const (
	// RedactStructural fields hold API enumerations, numbers, and addresses, exported as is.
	RedactStructural Redaction = "structural"
	// RedactReference fields hold object and key names, never the referenced values.
	RedactReference Redaction = "reference"
	// RedactText fields hold free text and pass through internal/redact.
	RedactText Redaction = "text"
	// RedactAllowlist fields are exported only for allowlisted keys, with values passed through internal/redact.
	RedactAllowlist Redaction = "allowlist"
)

// Field is one exported field path; placeholders are described in docs/field-catalog.md.
type Field struct {
	Path      string
	Source    string
	Type      FieldType
	Redaction Redaction
	Default   bool
}

// KindSpec describes one collected kind.
type KindSpec struct {
	Kind         string
	GVR          schema.GroupVersionResource
	APIKind      string
	Namespaced   bool
	MetadataOnly bool
	Aggregated   bool
	Fields       []Field
	byPath       map[string]*Field
}

// Protocol kind strings (SPEC 4.2).
const (
	KindNamespace   = "Namespace"
	KindNode        = "Node"
	KindPod         = "Pod"
	KindDeployment  = "apps/Deployment"
	KindReplicaSet  = "apps/ReplicaSet"
	KindStatefulSet = "apps/StatefulSet"
	KindDaemonSet   = "apps/DaemonSet"
	KindJob         = "batch/Job"
	KindCronJob     = "batch/CronJob"
	KindService     = "Service"
	KindIngress     = "networking.k8s.io/Ingress"
	KindNetPol      = "networking.k8s.io/NetworkPolicy"
	KindPVC         = "PersistentVolumeClaim"
	KindPV          = "PersistentVolume"
	KindStorageCls  = "storage.k8s.io/StorageClass"
	KindConfigMap   = "ConfigMap"
	KindHPA         = "autoscaling/HorizontalPodAutoscaler"
	KindPDB         = "policy/PodDisruptionBudget"
	KindEvent       = "Event"
)

// DefaultLabelAllowlist is used when no label allowlist is configured.
var DefaultLabelAllowlist = []string{
	"app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/component",
	"app.kubernetes.io/part-of", "app.kubernetes.io/version", "app", "k8s-app",
	"topology.kubernetes.io/zone", "topology.kubernetes.io/region", "node-role.kubernetes.io/*",
}

// DefaultAnnotationAllowlist is used when no annotation allowlist is configured: no annotations.
var DefaultAnnotationAllowlist = []string{}

var (
	podConditionTypes    = []string{"PodScheduled", "PodReadyToStartContainers", "Initialized", "ContainersReady", "Ready", "DisruptionTarget"}
	deployConditionTypes = []string{"Available", "Progressing", "ReplicaFailure"}
	rsConditionTypes     = []string{"ReplicaFailure"}
	jobConditionTypes    = []string{"Complete", "Failed", "Suspended", "FailureTarget", "SuccessCriteriaMet"}
	hpaConditionTypes    = []string{"AbleToScale", "ScalingActive", "ScalingLimited"}
	pdbConditionTypes    = []string{"DisruptionAllowed"}
	pvcConditionTypes    = []string{"Resizing", "FileSystemResizePending", "ModifyingVolume", "ModifyVolumeError"}
)

func f(path, source string, t FieldType, r Redaction, def bool) Field {
	return Field{Path: path, Source: source, Type: t, Redaction: r, Default: def}
}

func commonFields() []Field {
	return []Field{
		f("created", "metadata.creationTimestamp", TypeTimestamp, RedactStructural, true),
		f("terminating", "metadata.deletionTimestamp (present only while deletion is pending)", TypeBool, RedactStructural, true),
		f("labels.<key>", "metadata.labels (allowlisted keys)", TypeString, RedactAllowlist, true),
		f("annotations.<key>", "metadata.annotations (allowlisted keys)", TypeString, RedactAllowlist, true),
		f("owners.<kind>.<name>", "metadata.ownerReferences[] (value: controller flag)", TypeBool, RedactReference, true),
	}
}

func conditionFields(src string, types []string) []Field {
	list := "any type"
	if types != nil {
		list = strings.Join(types, ", ")
	}
	return []Field{
		f("conditions.<type>.status", src+"[type in "+list+"].status", TypeString, RedactStructural, true),
		f("conditions.<type>.reason", src+"[type in "+list+"].reason", TypeString, RedactText, true),
	}
}

func podSpecFields(p string, pod bool) []Field {
	var fs []Field
	for _, c := range []string{"containers", "initContainers"} {
		b := c + ".<container>."
		s := p + "." + c + "[]."
		fs = append(fs,
			f(b+"image", s+"image", TypeString, RedactStructural, true),
			f(b+"requests.<resource>", s+"resources.requests (cpu in cores, others in base units)", TypeQuantity, RedactStructural, true),
			f(b+"limits.<resource>", s+"resources.limits (cpu in cores, others in base units)", TypeQuantity, RedactStructural, true),
			f(b+"ports", s+"ports[] as name:port/protocol", TypeStringList, RedactStructural, true),
			f(b+"envRefs", s+"env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)", TypeStringList, RedactReference, true),
			f(b+"envFrom", s+"envFrom[] as configMap:name or secret:name", TypeStringList, RedactReference, true),
			f(b+"command", s+"command", TypeStringList, RedactText, false),
			f(b+"args", s+"args", TypeStringList, RedactText, false),
		)
		if pod {
			st := "status." + strings.TrimSuffix(c, "s") + "Statuses[]."
			fs = append(fs,
				f(b+"imageID", st+"imageID (digest reference)", TypeString, RedactStructural, true),
				f(b+"ready", st+"ready", TypeBool, RedactStructural, true),
				f(b+"restarts", st+"restartCount", TypeInt, RedactStructural, true),
				f(b+"state", st+"state (waiting, running, or terminated)", TypeString, RedactStructural, true),
				f(b+"waitingReason", st+"state.waiting.reason", TypeString, RedactText, true),
				f(b+"terminatedReason", st+"state.terminated.reason", TypeString, RedactText, true),
				f(b+"terminatedExitCode", st+"state.terminated.exitCode", TypeInt, RedactStructural, true),
				f(b+"lastTerminatedReason", st+"lastState.terminated.reason", TypeString, RedactText, true),
				f(b+"lastTerminatedExitCode", st+"lastState.terminated.exitCode", TypeInt, RedactStructural, true),
			)
		}
	}
	fs = append(fs,
		f("serviceAccountName", p+".serviceAccountName", TypeString, RedactReference, true),
		f("refs.configMaps", p+" volumes, projected sources, env and envFrom ConfigMap names", TypeStringList, RedactReference, true),
		f("refs.secrets", p+" volumes, projected sources, env, envFrom, and imagePullSecrets Secret names", TypeStringList, RedactReference, true),
		f("refs.claims", p+".volumes[].persistentVolumeClaim.claimName and ephemeral claim names", TypeStringList, RedactReference, true),
	)
	return fs
}

func workloadMeta() []Field {
	return []Field{
		f("generation", "metadata.generation", TypeInt, RedactStructural, true),
		f("observedGeneration", "status.observedGeneration", TypeInt, RedactStructural, true),
	}
}

func buildCatalog() []*KindSpec {
	core := func(res string) schema.GroupVersionResource {
		return schema.GroupVersionResource{Version: "v1", Resource: res}
	}
	gvr := func(g, v, r string) schema.GroupVersionResource {
		return schema.GroupVersionResource{Group: g, Version: v, Resource: r}
	}
	tmpl := "spec.template.spec"
	specs := []*KindSpec{
		{Kind: KindNamespace, GVR: core("namespaces"), APIKind: "Namespace", Fields: []Field{
			f("phase", "status.phase", TypeString, RedactStructural, true),
		}},
		{Kind: KindNode, GVR: core("nodes"), APIKind: "Node", Fields: append([]Field{
			f("capacity.<resource>", "status.capacity (cpu in cores, others in base units)", TypeQuantity, RedactStructural, true),
			f("allocatable.<resource>", "status.allocatable (cpu in cores, others in base units)", TypeQuantity, RedactStructural, true),
			f("taints", "spec.taints[] as key=value:Effect", TypeStringList, RedactStructural, true),
			f("unschedulable", "spec.unschedulable", TypeBool, RedactStructural, true),
			f("kubeletVersion", "status.nodeInfo.kubeletVersion", TypeString, RedactStructural, true),
			f("containerRuntimeVersion", "status.nodeInfo.containerRuntimeVersion", TypeString, RedactStructural, true),
			f("osImage", "status.nodeInfo.osImage", TypeString, RedactStructural, true),
			f("kernelVersion", "status.nodeInfo.kernelVersion", TypeString, RedactStructural, true),
			f("architecture", "status.nodeInfo.architecture", TypeString, RedactStructural, true),
			f("operatingSystem", "status.nodeInfo.operatingSystem", TypeString, RedactStructural, true),
			f("providerID", "spec.providerID", TypeString, RedactStructural, true),
			f("podCIDR", "spec.podCIDR", TypeString, RedactStructural, true),
			f("internalIP", "status.addresses[type=InternalIP].address", TypeString, RedactStructural, true),
			f("zone", "metadata.labels[topology.kubernetes.io/zone]", TypeString, RedactStructural, true),
			f("region", "metadata.labels[topology.kubernetes.io/region]", TypeString, RedactStructural, true),
		}, conditionFields("status.conditions", nil)...)},
		{Kind: KindPod, GVR: core("pods"), APIKind: "Pod", Namespaced: true, Fields: append(append([]Field{
			f("phase", "status.phase", TypeString, RedactStructural, true),
			f("reason", "status.reason", TypeString, RedactText, true),
			f("nodeName", "spec.nodeName", TypeString, RedactReference, true),
			f("hostIP", "status.hostIP", TypeString, RedactStructural, true),
			f("podIP", "status.podIP", TypeString, RedactStructural, true),
			f("qosClass", "status.qosClass", TypeString, RedactStructural, true),
			f("priorityClassName", "spec.priorityClassName", TypeString, RedactReference, true),
			f("hostNetwork", "spec.hostNetwork", TypeBool, RedactStructural, true),
			f("ready", "status.conditions[type=Ready].status", TypeBool, RedactStructural, true),
		}, conditionFields("status.conditions", podConditionTypes)...), podSpecFields("spec", true)...)},
		{Kind: KindDeployment, GVR: gvr("apps", "v1", "deployments"), APIKind: "Deployment", Namespaced: true, Fields: concat(
			[]Field{
				f("replicas", "spec.replicas (default 1)", TypeInt, RedactStructural, true),
				f("paused", "spec.paused", TypeBool, RedactStructural, true),
				f("strategy", "spec.strategy.type", TypeString, RedactStructural, true),
				f("statusReplicas", "status.replicas", TypeInt, RedactStructural, true),
				f("readyReplicas", "status.readyReplicas", TypeInt, RedactStructural, true),
				f("availableReplicas", "status.availableReplicas", TypeInt, RedactStructural, true),
				f("updatedReplicas", "status.updatedReplicas", TypeInt, RedactStructural, true),
				f("unavailableReplicas", "status.unavailableReplicas", TypeInt, RedactStructural, true),
			}, workloadMeta(), conditionFields("status.conditions", deployConditionTypes), podSpecFields(tmpl, false))},
		{Kind: KindReplicaSet, GVR: gvr("apps", "v1", "replicasets"), APIKind: "ReplicaSet", Namespaced: true, Fields: concat(
			[]Field{
				f("replicas", "spec.replicas (default 1)", TypeInt, RedactStructural, true),
				f("statusReplicas", "status.replicas", TypeInt, RedactStructural, true),
				f("readyReplicas", "status.readyReplicas", TypeInt, RedactStructural, true),
				f("availableReplicas", "status.availableReplicas", TypeInt, RedactStructural, true),
			}, workloadMeta(), conditionFields("status.conditions", rsConditionTypes), podSpecFields(tmpl, false))},
		{Kind: KindStatefulSet, GVR: gvr("apps", "v1", "statefulsets"), APIKind: "StatefulSet", Namespaced: true, Fields: concat(
			[]Field{
				f("replicas", "spec.replicas (default 1)", TypeInt, RedactStructural, true),
				f("serviceName", "spec.serviceName", TypeString, RedactReference, true),
				f("podManagementPolicy", "spec.podManagementPolicy", TypeString, RedactStructural, true),
				f("updateStrategy", "spec.updateStrategy.type", TypeString, RedactStructural, true),
				f("statusReplicas", "status.replicas", TypeInt, RedactStructural, true),
				f("readyReplicas", "status.readyReplicas", TypeInt, RedactStructural, true),
				f("availableReplicas", "status.availableReplicas", TypeInt, RedactStructural, true),
				f("currentReplicas", "status.currentReplicas", TypeInt, RedactStructural, true),
				f("updatedReplicas", "status.updatedReplicas", TypeInt, RedactStructural, true),
				f("currentRevision", "status.currentRevision", TypeString, RedactStructural, true),
				f("updateRevision", "status.updateRevision", TypeString, RedactStructural, true),
			}, workloadMeta(), podSpecFields(tmpl, false))},
		{Kind: KindDaemonSet, GVR: gvr("apps", "v1", "daemonsets"), APIKind: "DaemonSet", Namespaced: true, Fields: concat(
			[]Field{
				f("updateStrategy", "spec.updateStrategy.type", TypeString, RedactStructural, true),
				f("desiredNumberScheduled", "status.desiredNumberScheduled", TypeInt, RedactStructural, true),
				f("currentNumberScheduled", "status.currentNumberScheduled", TypeInt, RedactStructural, true),
				f("numberReady", "status.numberReady", TypeInt, RedactStructural, true),
				f("numberAvailable", "status.numberAvailable", TypeInt, RedactStructural, true),
				f("numberUnavailable", "status.numberUnavailable", TypeInt, RedactStructural, true),
				f("numberMisscheduled", "status.numberMisscheduled", TypeInt, RedactStructural, true),
				f("updatedNumberScheduled", "status.updatedNumberScheduled", TypeInt, RedactStructural, true),
			}, workloadMeta(), podSpecFields(tmpl, false))},
		{Kind: KindJob, GVR: gvr("batch", "v1", "jobs"), APIKind: "Job", Namespaced: true, Fields: concat(
			[]Field{
				f("completions", "spec.completions", TypeInt, RedactStructural, true),
				f("parallelism", "spec.parallelism", TypeInt, RedactStructural, true),
				f("backoffLimit", "spec.backoffLimit", TypeInt, RedactStructural, true),
				f("suspend", "spec.suspend", TypeBool, RedactStructural, true),
				f("completionMode", "spec.completionMode", TypeString, RedactStructural, true),
				f("active", "status.active", TypeInt, RedactStructural, true),
				f("succeeded", "status.succeeded", TypeInt, RedactStructural, true),
				f("failed", "status.failed", TypeInt, RedactStructural, true),
			}, conditionFields("status.conditions", jobConditionTypes), podSpecFields(tmpl, false))},
		{Kind: KindCronJob, GVR: gvr("batch", "v1", "cronjobs"), APIKind: "CronJob", Namespaced: true, Fields: concat(
			[]Field{
				f("schedule", "spec.schedule", TypeString, RedactStructural, true),
				f("timeZone", "spec.timeZone", TypeString, RedactStructural, true),
				f("suspend", "spec.suspend", TypeBool, RedactStructural, true),
				f("concurrencyPolicy", "spec.concurrencyPolicy", TypeString, RedactStructural, true),
				f("active", "len(status.active)", TypeInt, RedactStructural, true),
				f("lastScheduleTime", "status.lastScheduleTime", TypeTimestamp, RedactStructural, false),
				f("lastSuccessfulTime", "status.lastSuccessfulTime", TypeTimestamp, RedactStructural, false),
			}, podSpecFields("spec.jobTemplate.spec.template.spec", false))},
		{Kind: KindService, GVR: core("services"), APIKind: "Service", Namespaced: true, Fields: []Field{
			f("type", "spec.type", TypeString, RedactStructural, true),
			f("clusterIP", "spec.clusterIP", TypeString, RedactStructural, true),
			f("ports", "spec.ports[] as name:port/protocol->targetPort", TypeStringList, RedactStructural, true),
			f("hasSelector", "spec.selector is non-empty", TypeBool, RedactStructural, true),
			f("selector", "spec.selector as a canonical selector", TypeString, RedactText, false),
			f("sessionAffinity", "spec.sessionAffinity", TypeString, RedactStructural, true),
			f("externalTrafficPolicy", "spec.externalTrafficPolicy", TypeString, RedactStructural, true),
			f("internalTrafficPolicy", "spec.internalTrafficPolicy", TypeString, RedactStructural, true),
			f("externalName", "spec.externalName", TypeString, RedactText, false),
			f("loadBalancerIngress", "status.loadBalancer.ingress[] ip or hostname", TypeStringList, RedactStructural, false),
		}},
		{Kind: KindIngress, GVR: gvr("networking.k8s.io", "v1", "ingresses"), APIKind: "Ingress", Namespaced: true, Fields: []Field{
			f("ingressClassName", "spec.ingressClassName", TypeString, RedactReference, true),
			f("hosts", "spec.rules[].host", TypeStringList, RedactStructural, true),
			f("backends", "spec.defaultBackend and spec.rules[].http.paths[].backend as service:port", TypeStringList, RedactReference, true),
			f("tls", "spec.tls is non-empty", TypeBool, RedactStructural, true),
			f("paths", "spec.rules[].http.paths[] as host path pathType -> service:port", TypeStringList, RedactText, false),
			f("loadBalancerIngress", "status.loadBalancer.ingress[] ip or hostname", TypeStringList, RedactStructural, false),
		}},
		{Kind: KindNetPol, GVR: gvr("networking.k8s.io", "v1", "networkpolicies"), APIKind: "NetworkPolicy", Namespaced: true, Fields: []Field{
			f("podSelector", "spec.podSelector as a canonical selector (* selects every pod)", TypeString, RedactText, true),
			f("policyTypes", "spec.policyTypes", TypeStringList, RedactStructural, true),
			f("ingressRules", "len(spec.ingress)", TypeInt, RedactStructural, true),
			f("egressRules", "len(spec.egress)", TypeInt, RedactStructural, true),
		}},
		{Kind: KindPVC, GVR: core("persistentvolumeclaims"), APIKind: "PersistentVolumeClaim", Namespaced: true, Fields: append([]Field{
			f("phase", "status.phase", TypeString, RedactStructural, true),
			f("storageClassName", "spec.storageClassName", TypeString, RedactReference, true),
			f("accessModes", "spec.accessModes", TypeStringList, RedactStructural, true),
			f("requests.storage", "spec.resources.requests.storage (bytes)", TypeQuantity, RedactStructural, true),
			f("capacity.storage", "status.capacity.storage (bytes)", TypeQuantity, RedactStructural, true),
			f("volumeName", "spec.volumeName", TypeString, RedactReference, true),
			f("volumeMode", "spec.volumeMode", TypeString, RedactStructural, true),
		}, conditionFields("status.conditions", pvcConditionTypes)...)},
		{Kind: KindPV, GVR: core("persistentvolumes"), APIKind: "PersistentVolume", Fields: []Field{
			f("phase", "status.phase", TypeString, RedactStructural, true),
			f("storageClassName", "spec.storageClassName", TypeString, RedactReference, true),
			f("capacity.storage", "spec.capacity.storage (bytes)", TypeQuantity, RedactStructural, true),
			f("accessModes", "spec.accessModes", TypeStringList, RedactStructural, true),
			f("reclaimPolicy", "spec.persistentVolumeReclaimPolicy", TypeString, RedactStructural, true),
			f("volumeMode", "spec.volumeMode", TypeString, RedactStructural, true),
			f("claim", "spec.claimRef as namespace/name", TypeString, RedactReference, true),
			f("driver", "spec.csi.driver or the in-tree volume source name", TypeString, RedactStructural, true),
			f("nodeAffinity", "spec.nodeAffinity.required as canonical terms", TypeString, RedactText, true),
		}},
		{Kind: KindStorageCls, GVR: gvr("storage.k8s.io", "v1", "storageclasses"), APIKind: "StorageClass", Fields: []Field{
			f("provisioner", "provisioner", TypeString, RedactStructural, true),
			f("reclaimPolicy", "reclaimPolicy", TypeString, RedactStructural, true),
			f("volumeBindingMode", "volumeBindingMode", TypeString, RedactStructural, true),
			f("allowVolumeExpansion", "allowVolumeExpansion", TypeBool, RedactStructural, true),
			f("isDefault", "metadata.annotations[storageclass.kubernetes.io/is-default-class]", TypeBool, RedactStructural, true),
			f("parameters.<key>", "parameters", TypeString, RedactText, false),
		}},
		{Kind: KindConfigMap, GVR: core("configmaps"), APIKind: "ConfigMap", Namespaced: true, MetadataOnly: true, Fields: []Field{
			f("keys", "data and binaryData key names (never values; selecting it replaces the metadata-only informer)", TypeStringList, RedactReference, false),
		}},
		{Kind: KindHPA, GVR: gvr("autoscaling", "v2", "horizontalpodautoscalers"), APIKind: "HorizontalPodAutoscaler", Namespaced: true, Fields: append([]Field{
			f("target.kind", "spec.scaleTargetRef apiVersion and kind as a protocol kind", TypeString, RedactReference, true),
			f("target.name", "spec.scaleTargetRef.name", TypeString, RedactReference, true),
			f("minReplicas", "spec.minReplicas (default 1)", TypeInt, RedactStructural, true),
			f("maxReplicas", "spec.maxReplicas", TypeInt, RedactStructural, true),
			f("currentReplicas", "status.currentReplicas", TypeInt, RedactStructural, true),
			f("desiredReplicas", "status.desiredReplicas", TypeInt, RedactStructural, true),
			f("metrics", "spec.metrics[] as type:name", TypeStringList, RedactStructural, true),
		}, conditionFields("status.conditions", hpaConditionTypes)...)},
		{Kind: KindPDB, GVR: gvr("policy", "v1", "poddisruptionbudgets"), APIKind: "PodDisruptionBudget", Namespaced: true, Fields: append([]Field{
			f("selector", "spec.selector as a canonical selector (* selects every pod)", TypeString, RedactText, true),
			f("minAvailable", "spec.minAvailable", TypeString, RedactStructural, true),
			f("maxUnavailable", "spec.maxUnavailable", TypeString, RedactStructural, true),
			f("currentHealthy", "status.currentHealthy", TypeInt, RedactStructural, true),
			f("desiredHealthy", "status.desiredHealthy", TypeInt, RedactStructural, true),
			f("disruptionsAllowed", "status.disruptionsAllowed", TypeInt, RedactStructural, true),
			f("expectedPods", "status.expectedPods", TypeInt, RedactStructural, true),
		}, conditionFields("status.conditions", pdbConditionTypes)...)},
		{Kind: KindEvent, GVR: core("events"), APIKind: "Event", Namespaced: true, Aggregated: true, Fields: []Field{
			f("events.warning.<reason>", "Warning events per involvedObject.uid and reason: occurrences within the sliding window, set on the involved object", TypeInt, RedactStructural, true),
		}},
	}
	for _, s := range specs {
		if !s.Aggregated {
			s.Fields = append(commonFields(), s.Fields...)
		}
		s.byPath = map[string]*Field{}
		for i := range s.Fields {
			s.byPath[s.Fields[i].Path] = &s.Fields[i]
		}
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Kind < specs[j].Kind })
	return specs
}

func concat(parts ...[]Field) []Field {
	var out []Field
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	catalog       = buildCatalog()
	catalogByKind = func() map[string]*KindSpec {
		m := map[string]*KindSpec{}
		for _, s := range catalog {
			m[s.Kind] = s
		}
		return m
	}()
)

// Catalog returns a copy of the field catalog ordered by kind.
func Catalog() []KindSpec {
	out := make([]KindSpec, len(catalog))
	for i, s := range catalog {
		out[i] = *s
		out[i].Fields = append([]Field(nil), s.Fields...)
		out[i].byPath = nil
	}
	return out
}

// LookupKind returns the catalog entry for a protocol kind.
func LookupKind(kind string) (KindSpec, bool) {
	s, ok := catalogByKind[kind]
	if !ok {
		return KindSpec{}, false
	}
	c := *s
	c.Fields = append([]Field(nil), s.Fields...)
	c.byPath = nil
	return c, true
}

// ProtocolKind returns the protocol kind string for an API group and kind.
func ProtocolKind(group, kind string) string {
	if group == "" {
		return kind
	}
	return group + "/" + kind
}

// ResolveKinds maps configured resource names to catalog kinds and returns the unsupported names.
func ResolveKinds(names []string) (kinds []string, unsupported []string) {
	if len(names) == 0 {
		for _, s := range catalog {
			kinds = append(kinds, s.Kind)
		}
		return kinds, nil
	}
	want := map[string]bool{}
	for _, n := range names {
		found := false
		for _, s := range catalog {
			res := s.GVR.Resource
			full := res
			if s.GVR.Group != "" {
				full = res + "." + s.GVR.Group
			}
			if n == s.Kind || n == s.APIKind || strings.EqualFold(n, res) || strings.EqualFold(n, full) {
				want[s.Kind] = true
				found = true
			}
		}
		if !found {
			unsupported = append(unsupported, n)
		}
	}
	for _, s := range catalog {
		if want[s.Kind] {
			kinds = append(kinds, s.Kind)
		}
	}
	sort.Strings(unsupported)
	return kinds, unsupported
}

var placeholderRe = regexp.MustCompile(`<[a-z]+>`)

// PathPattern compiles a catalog path into a regular expression matching concrete field keys.
func PathPattern(path string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	last := 0
	for _, loc := range placeholderRe.FindAllStringIndex(path, -1) {
		b.WriteString(regexp.QuoteMeta(path[last:loc[0]]))
		switch path[loc[0]:loc[1]] {
		case "<resource>", "<key>", "<name>":
			b.WriteString(".+")
		default:
			b.WriteString("[^.]+")
		}
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(path[last:]))
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// RenderFieldCatalog renders docs/field-catalog.md from the catalog.
func RenderFieldCatalog() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Field catalog\n\nGenerated from `internal/state/catalog.go` by `go test ./internal/state -run TestGeneratedDocs -update`. Do not edit by hand.\n\n")
	fmt.Fprintf(&b, "Catalog schema: %d.\n\n", CatalogSchema)
	b.WriteString("Every exported field of a normalized resource is listed here. Fields not marked default are exported only when selected deliberately (normalizer option `Fields` as `<kind>:<path>`). ")
	b.WriteString("Field keys are flat; placeholders in angle brackets stand for one key segment (`<container>`, `<type>`, `<kind>`, `<reason>`) or the rest of the key (`<resource>`, `<key>`, `<name>`). ")
	b.WriteString("Absent keys mean unset or empty. Lists whose order is not meaningful are sorted. Quantities are floats in base units: CPU in cores, memory and storage in bytes. Timestamps are integer milliseconds since the Unix epoch. ")
	b.WriteString("Heartbeat timestamps, `resourceVersion`, `managedFields`, condition messages, ConfigMap values, Secret contents, and environment variable values are never exported.\n\n")
	b.WriteString("## Redaction classes\n\n|Class|Meaning|\n|---|---|\n")
	b.WriteString("|structural|API enumerations, numbers, and addresses, exported as is.|\n")
	b.WriteString("|reference|Object and key names; the referenced values are never read or exported.|\n")
	b.WriteString("|text|Free text; every value passes through `internal/redact` (credentials in URLs, tokens, key=value secrets).|\n")
	b.WriteString("|allowlist|Exported only for keys matching the configured allowlist; values pass through `internal/redact`.|\n\n")
	b.WriteString("## Allowlists\n\nLabels (`kubernetes.labelAllowlist`, a trailing `*` matches a prefix), default:\n\n")
	for _, l := range DefaultLabelAllowlist {
		fmt.Fprintf(&b, "- `%s`\n", l)
	}
	b.WriteString("\nAnnotations (`kubernetes.annotationAllowlist`): none by default.\n\n")
	b.WriteString("## Scopes\n\nScope keys are `<kind>|<namespace>`, with an empty namespace for cluster-wide collection. Permission loss and collection failure set the scope unavailable; they never delete resources. Scope removal deletes with reason scope removed.\n\n")
	b.WriteString("## Edges\n\n|Type|From|To|Attributes|\n|---|---|---|---|\n")
	for _, e := range edgeDocs {
		fmt.Fprintf(&b, "|`%s`|%s|%s|%s|\n", e[0], e[1], e[2], e[3])
	}
	b.WriteString("\nAn edge exists only while both endpoints are in state.\n")
	for _, s := range catalog {
		scope := "cluster"
		if s.Namespaced {
			scope = "namespaced"
		}
		fmt.Fprintf(&b, "\n## %s\n\nAPI: `%s` `%s`, %s", s.Kind, s.GVR.GroupVersion().String(), s.GVR.Resource, scope)
		if s.MetadataOnly {
			b.WriteString(", metadata-only informer by default")
		}
		if s.Aggregated {
			b.WriteString(", not exported as a resource: aggregated onto the involved object (Normal events are ignored)")
		}
		b.WriteString(".\n\n|Field|Source|Type|Redaction|Default|\n|---|---|---|---|---|\n")
		for _, fd := range s.Fields {
			def := "no"
			if fd.Default {
				def = "yes"
			}
			fmt.Fprintf(&b, "|`%s`|%s|%s|%s|%s|\n", fd.Path, strings.ReplaceAll(fd.Source, "|", `\|`), fd.Type, fd.Redaction, def)
		}
	}
	b.WriteString("\n## Published kube_* subset\n\nSee `kube-series.md` for labels and sources.\n\n")
	for _, s := range kubeSeriesSpecs {
		fmt.Fprintf(&b, "- `%s`\n", s.Name)
	}
	return b.String()
}
