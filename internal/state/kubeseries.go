package state

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Series is one synthesized kube_* sample at time T (milliseconds).
type Series struct {
	Labels labels.Labels
	Value  float64
	T      int64
}

// SeriesSpec documents one published kube_* series.
type SeriesSpec struct {
	Name   string
	Kind   string
	Labels []string
	Source string
}

var (
	podLabels       = []string{"namespace", "pod", "uid"}
	containerLabels = []string{"namespace", "pod", "uid", "container"}
	resourceLabels  = []string{"namespace", "pod", "uid", "container", "node", "resource", "unit"}
)

var kubeSeriesSpecs = []SeriesSpec{
	{"kube_pod_info", KindPod, append(podLabels[:3:3], "host_ip", "pod_ip", "node", "created_by_kind", "created_by_name", "priority_class", "host_network"), "hostIP, podIP, nodeName, controller owner, priorityClassName, hostNetwork; value 1"},
	{"kube_pod_status_phase", KindPod, append(podLabels[:3:3], "phase"), "phase; 1 for the current phase, 0 for Pending, Running, Succeeded, Failed, Unknown otherwise"},
	{"kube_pod_status_ready", KindPod, append(podLabels[:3:3], "condition"), "conditions.Ready.status; condition true, false, unknown with 1 for the current status"},
	{"kube_pod_container_info", KindPod, append(containerLabels[:4:4], "image_spec", "image", "image_id"), "containers.<container>.image and imageID; value 1"},
	{"kube_pod_container_status_restarts_total", KindPod, containerLabels, "containers.<container>.restarts"},
	{"kube_pod_container_status_waiting_reason", KindPod, append(containerLabels[:4:4], "reason"), "containers.<container>.waitingReason; value 1 while waiting"},
	{"kube_pod_container_status_last_terminated_reason", KindPod, append(containerLabels[:4:4], "reason"), "containers.<container>.lastTerminatedReason; value 1"},
	{"kube_pod_container_resource_requests", KindPod, resourceLabels, "containers.<container>.requests.<resource>"},
	{"kube_pod_container_resource_limits", KindPod, resourceLabels, "containers.<container>.limits.<resource>"},
	{"kube_pod_owner", KindPod, append(podLabels[:3:3], "owner_kind", "owner_name", "owner_is_controller"), "owners.<kind>.<name>; one series per owner, <none> without owners; value 1"},
	{"kube_node_info", KindNode, []string{"node", "kernel_version", "os_image", "container_runtime_version", "kubelet_version", "provider_id", "pod_cidr", "internal_ip"}, "nodeInfo, providerID, podCIDR, internalIP; value 1"},
	{"kube_node_status_condition", KindNode, []string{"node", "condition", "status"}, "conditions.<type>.status; status true, false, unknown with 1 for the current status"},
	{"kube_node_status_capacity", KindNode, []string{"node", "resource", "unit"}, "capacity.<resource>"},
	{"kube_node_status_allocatable", KindNode, []string{"node", "resource", "unit"}, "allocatable.<resource>"},
	{"kube_node_spec_unschedulable", KindNode, []string{"node"}, "unschedulable as 0 or 1"},
	{"kube_deployment_spec_replicas", KindDeployment, []string{"namespace", "deployment"}, "replicas"},
	{"kube_deployment_status_replicas_available", KindDeployment, []string{"namespace", "deployment"}, "availableReplicas"},
	{"kube_deployment_status_replicas_unavailable", KindDeployment, []string{"namespace", "deployment"}, "unavailableReplicas"},
	{"kube_statefulset_replicas", KindStatefulSet, []string{"namespace", "statefulset"}, "replicas"},
	{"kube_statefulset_status_replicas_ready", KindStatefulSet, []string{"namespace", "statefulset"}, "readyReplicas"},
	{"kube_daemonset_status_desired_number_scheduled", KindDaemonSet, []string{"namespace", "daemonset"}, "desiredNumberScheduled"},
	{"kube_daemonset_status_number_ready", KindDaemonSet, []string{"namespace", "daemonset"}, "numberReady"},
	{"kube_job_status_failed", KindJob, []string{"namespace", "job_name"}, "failed"},
	{"kube_persistentvolumeclaim_status_phase", KindPVC, []string{"namespace", "persistentvolumeclaim", "phase"}, "phase; 1 for the current phase, 0 for Pending, Bound, Lost otherwise"},
	{"kube_persistentvolumeclaim_resource_requests_storage_bytes", KindPVC, []string{"namespace", "persistentvolumeclaim"}, "requests.storage"},
	{"kube_persistentvolumeclaim_info", KindPVC, []string{"namespace", "persistentvolumeclaim", "storageclass", "volumename", "volumemode"}, "storageClassName, volumeName, volumeMode; value 1"},
}

// PublishedSubset returns the set of published kube_* series names for rule validation.
func PublishedSubset() map[string]bool {
	out := make(map[string]bool, len(kubeSeriesSpecs))
	for _, s := range kubeSeriesSpecs {
		out[s.Name] = true
	}
	return out
}

// KubeSeriesCatalog returns the published series specifications.
func KubeSeriesCatalog() []SeriesSpec {
	out := make([]SeriesSpec, len(kubeSeriesSpecs))
	for i, s := range kubeSeriesSpecs {
		out[i] = s
		out[i].Labels = append([]string(nil), s.Labels...)
	}
	return out
}

var (
	podPhases = []string{"Pending", "Running", "Succeeded", "Failed", "Unknown"}
	pvcPhases = []string{"Pending", "Bound", "Lost"}
)

// KubeSeries synthesizes the published kube_* subset from state with kube-state-metrics v2 semantics.
func KubeSeries(st *protocol.State, nowMs int64) []Series {
	var out []Series
	for _, r := range st.SortedResources() {
		out = append(out, resourceSeries(&r, nowMs)...)
	}
	sortSeries(out)
	return out
}

// PodSeriesFromPods derives pod-scoped series from a node agent's own pod watch.
func PodSeriesFromPods(n *Normalizer, pods []*unstructured.Unstructured, nowMs int64) ([]Series, error) {
	if n == nil {
		n = defaultNormalizer
	}
	var out []Series
	for _, p := range pods {
		if KindOf(p) != KindPod {
			return nil, fmt.Errorf("%w: %s is not a Pod", ErrUnsupportedKind, KindOf(p))
		}
		e, err := n.normalize(p)
		if err != nil {
			return nil, err
		}
		out = append(out, podSeries(&e.res, nowMs)...)
	}
	sortSeries(out)
	return out, nil
}

// NodeScoped returns the series pushed to one node: pod series for pods on it plus its kube_node_* series.
func NodeScoped(series []Series, nodeName string) []Series {
	uids := map[string]bool{}
	for _, s := range series {
		if s.Labels.Get(labels.MetricName) == "kube_pod_info" && s.Labels.Get("node") == nodeName {
			uids[s.Labels.Get("uid")] = true
		}
	}
	var out []Series
	for _, s := range series {
		name := s.Labels.Get(labels.MetricName)
		switch {
		case strings.HasPrefix(name, "kube_pod_") && uids[s.Labels.Get("uid")]:
			out = append(out, s)
		case strings.HasPrefix(name, "kube_node_") && s.Labels.Get("node") == nodeName:
			out = append(out, s)
		}
	}
	return out
}

func sortSeries(s []Series) {
	sort.SliceStable(s, func(i, j int) bool { return labels.Compare(s[i].Labels, s[j].Labels) < 0 })
}

func mk(t int64, v float64, name string, kv ...string) Series {
	m := map[string]string{labels.MetricName: name}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return Series{Labels: labels.FromMap(m), Value: v, T: t}
}

func fstr(f map[string]any, k string) string {
	s, _ := f[k].(string)
	return s
}

func fnum(f map[string]any, k string) (float64, bool) {
	switch x := f[k].(type) {
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

func fbool(f map[string]any, k string) bool {
	b, _ := f[k].(bool)
	return b
}

func b01(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func resourceSeries(r *protocol.Resource, t int64) []Series {
	f := r.Fields
	ns, name := r.Namespace, r.Name
	num := func(series, label, key string) []Series {
		if v, ok := fnum(f, key); ok {
			return []Series{mk(t, v, series, "namespace", ns, label, name)}
		}
		return nil
	}
	var out []Series
	switch r.Kind {
	case KindPod:
		return podSeries(r, t)
	case KindNode:
		return nodeSeries(r, t)
	case KindDeployment:
		out = append(out, num("kube_deployment_spec_replicas", "deployment", "replicas")...)
		out = append(out, num("kube_deployment_status_replicas_available", "deployment", "availableReplicas")...)
		out = append(out, num("kube_deployment_status_replicas_unavailable", "deployment", "unavailableReplicas")...)
	case KindStatefulSet:
		out = append(out, num("kube_statefulset_replicas", "statefulset", "replicas")...)
		out = append(out, num("kube_statefulset_status_replicas_ready", "statefulset", "readyReplicas")...)
	case KindDaemonSet:
		out = append(out, num("kube_daemonset_status_desired_number_scheduled", "daemonset", "desiredNumberScheduled")...)
		out = append(out, num("kube_daemonset_status_number_ready", "daemonset", "numberReady")...)
	case KindJob:
		out = append(out, num("kube_job_status_failed", "job_name", "failed")...)
	case KindPVC:
		phase := fstr(f, "phase")
		for _, p := range pvcPhases {
			out = append(out, mk(t, b01(p == phase), "kube_persistentvolumeclaim_status_phase", "namespace", ns, "persistentvolumeclaim", name, "phase", p))
		}
		out = append(out, num("kube_persistentvolumeclaim_resource_requests_storage_bytes", "persistentvolumeclaim", "requests.storage")...)
		out = append(out, mk(t, 1, "kube_persistentvolumeclaim_info", "namespace", ns, "persistentvolumeclaim", name,
			"storageclass", fstr(f, "storageClassName"), "volumename", fstr(f, "volumeName"), "volumemode", fstr(f, "volumeMode")))
	}
	return out
}

var invalidLabelChar = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// resourceUnit maps a resource name to its sanitized label and unit as kube-state-metrics v2 does.
func resourceUnit(res string) (string, string, bool) {
	unit := ""
	switch {
	case res == "cpu":
		unit = "core"
	case res == "memory" || res == "storage" || res == "ephemeral-storage" ||
		strings.HasPrefix(res, "hugepages-") || strings.HasPrefix(res, "attachable-volumes-"):
		unit = "byte"
	case res == "pods" || (strings.Contains(res, "/") && !strings.HasPrefix(res, "kubernetes.io/")):
		unit = "integer"
	default:
		return "", "", false
	}
	return invalidLabelChar.ReplaceAllString(res, "_"), unit, true
}

// segments returns, for keys "<prefix><a>.<rest>", the sorted distinct first segments a.
func segments(f map[string]any, prefix string) []string {
	set := map[string]bool{}
	for k := range f {
		if rest, ok := strings.CutPrefix(k, prefix); ok {
			if seg, _, ok := strings.Cut(rest, "."); ok {
				set[seg] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func conditionStatus(s string) string {
	switch s {
	case "True":
		return "true"
	case "False":
		return "false"
	}
	return "unknown"
}

func podSeries(r *protocol.Resource, t int64) []Series {
	f := r.Fields
	id := []string{"namespace", r.Namespace, "pod", r.Name, "uid", r.UID}
	with := func(kv ...string) []string { return append(append([]string(nil), id...), kv...) }
	node := fstr(f, "nodeName")
	var owners [][3]string
	ownerKinds := segments(f, "owners.")
	for _, kind := range ownerKinds {
		p := "owners." + kind + "."
		for k, v := range f {
			if name, ok := strings.CutPrefix(k, p); ok {
				ctrl, _ := v.(bool)
				owners = append(owners, [3]string{kind, name, strconv.FormatBool(ctrl)})
			}
		}
	}
	sort.Slice(owners, func(i, j int) bool {
		if owners[i][0] != owners[j][0] {
			return owners[i][0] < owners[j][0]
		}
		return owners[i][1] < owners[j][1]
	})
	createdKind, createdName := "", ""
	for _, o := range owners {
		if o[2] == "true" {
			createdKind, createdName = o[0], o[1]
			break
		}
	}
	out := []Series{mk(t, 1, "kube_pod_info", with("host_ip", fstr(f, "hostIP"), "pod_ip", fstr(f, "podIP"), "node", node,
		"created_by_kind", createdKind, "created_by_name", createdName, "priority_class", fstr(f, "priorityClassName"),
		"host_network", strconv.FormatBool(fbool(f, "hostNetwork")))...)}
	if phase := fstr(f, "phase"); phase != "" {
		for _, p := range podPhases {
			out = append(out, mk(t, b01(p == phase), "kube_pod_status_phase", with("phase", p)...))
		}
	}
	if st, ok := f["conditions.Ready.status"].(string); ok {
		cur := conditionStatus(st)
		for _, c := range []string{"true", "false", "unknown"} {
			out = append(out, mk(t, b01(c == cur), "kube_pod_status_ready", with("condition", c)...))
		}
	}
	if len(owners) == 0 {
		out = append(out, mk(t, 1, "kube_pod_owner", with("owner_kind", "<none>", "owner_name", "<none>", "owner_is_controller", "<none>")...))
	}
	for _, o := range owners {
		out = append(out, mk(t, 1, "kube_pod_owner", with("owner_kind", o[0], "owner_name", o[1], "owner_is_controller", o[2])...))
	}
	for _, c := range segments(f, "containers.") {
		p := "containers." + c + "."
		cl := with("container", c)
		if img := fstr(f, p+"image"); img != "" {
			out = append(out, mk(t, 1, "kube_pod_container_info", append(cl, "image_spec", img, "image", img, "image_id", fstr(f, p+"imageID"))...))
		}
		if v, ok := fnum(f, p+"restarts"); ok {
			out = append(out, mk(t, v, "kube_pod_container_status_restarts_total", cl...))
		}
		if w := fstr(f, p+"waitingReason"); w != "" {
			out = append(out, mk(t, 1, "kube_pod_container_status_waiting_reason", append(cl, "reason", w)...))
		}
		if lt := fstr(f, p+"lastTerminatedReason"); lt != "" {
			out = append(out, mk(t, 1, "kube_pod_container_status_last_terminated_reason", append(cl, "reason", lt)...))
		}
		for _, kind := range []string{"requests", "limits"} {
			rp := p + kind + "."
			for k := range f {
				res, ok := strings.CutPrefix(k, rp)
				if !ok {
					continue
				}
				label, unit, ok := resourceUnit(res)
				v, isNum := fnum(f, k)
				if !ok || !isNum {
					continue
				}
				out = append(out, mk(t, v, "kube_pod_container_resource_"+kind, append(cl, "node", node, "resource", label, "unit", unit)...))
			}
		}
	}
	return out
}

func nodeSeries(r *protocol.Resource, t int64) []Series {
	f := r.Fields
	n := r.Name
	out := []Series{
		mk(t, 1, "kube_node_info", "node", n, "kernel_version", fstr(f, "kernelVersion"), "os_image", fstr(f, "osImage"),
			"container_runtime_version", fstr(f, "containerRuntimeVersion"), "kubelet_version", fstr(f, "kubeletVersion"),
			"provider_id", fstr(f, "providerID"), "pod_cidr", fstr(f, "podCIDR"), "internal_ip", fstr(f, "internalIP")),
		mk(t, b01(fbool(f, "unschedulable")), "kube_node_spec_unschedulable", "node", n),
	}
	for _, c := range segments(f, "conditions.") {
		st, ok := f["conditions."+c+".status"].(string)
		if !ok {
			continue
		}
		cur := conditionStatus(st)
		for _, s := range []string{"true", "false", "unknown"} {
			out = append(out, mk(t, b01(s == cur), "kube_node_status_condition", "node", n, "condition", c, "status", s))
		}
	}
	for _, kind := range []string{"capacity", "allocatable"} {
		for k := range f {
			res, ok := strings.CutPrefix(k, kind+".")
			if !ok {
				continue
			}
			label, unit, ok := resourceUnit(res)
			v, isNum := fnum(f, k)
			if ok && isNum {
				out = append(out, mk(t, v, "kube_node_status_"+kind, "node", n, "resource", label, "unit", unit))
			}
		}
	}
	return out
}

// RenderKubeSeriesDoc renders docs/kube-series.md.
func RenderKubeSeriesDoc() string {
	var b strings.Builder
	b.WriteString("# Published kube_* series\n\nGenerated from `internal/state/kubeseries.go` by `go test ./internal/state -run TestGeneratedDocs -update`. Do not edit by hand.\n\n")
	b.WriteString("The coordinator synthesizes these series from its normalized informer state with kube-state-metrics v2 names, labels, and value semantics. ")
	b.WriteString("Customer kube-state-metrics is never a dependency. Rules referencing any other `kube_*` series are rejected at bundle validation. ")
	b.WriteString("Labels with empty values are omitted. Resource labels are sanitized (`nvidia.com/gpu` becomes `nvidia_com_gpu`) with unit `core` for CPU, `byte` for memory, storage, and huge pages, and `integer` for pods and extended resources.\n\n")
	b.WriteString("Node-scoped subset: every `kube_pod_*` series of pods whose `node` in `kube_pod_info` is the node, plus that node's `kube_node_*` series. ")
	b.WriteString("Node agents derive the pod-scoped series from their own pod watch with the same synthesis, so both sides produce identical series.\n\n")
	b.WriteString("|Series|Kind|Labels|Source|\n|---|---|---|---|\n")
	for _, s := range kubeSeriesSpecs {
		fmt.Fprintf(&b, "|`%s`|%s|%s|%s|\n", s.Name, s.Kind, "`"+strings.Join(s.Labels, "`, `")+"`", s.Source)
	}
	return b.String()
}
