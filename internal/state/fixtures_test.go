package state

import (
	"testing"
	"time"

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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	secretLiteral = "SECRET_VALUE_LITERAL"
	secretCMValue = "hunter2-configmap"
)

var fixtureTime = metav1.NewTime(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))

func ptr[T any](v T) *T { return &v }

func toU(t testing.TB, obj runtime.Object) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	return &unstructured.Unstructured{Object: m}
}

func meta(name, ns, uid string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: name, Namespace: ns, UID: types.UID(uid), ResourceVersion: "12345", Generation: 4,
		CreationTimestamp: fixtureTime,
		Labels:            map[string]string{"app": "web", "team": "payments-internal"},
		Annotations: map[string]string{
			"kubectl.kubernetes.io/last-applied-configuration": `{"password":"` + secretLiteral + `"}`,
			"example.com/owner": "alice",
		},
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply}},
	}
}

func owned(m metav1.ObjectMeta, kind, name, uid string) metav1.ObjectMeta {
	m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: kind, Name: name, UID: types.UID(uid), Controller: ptr(true)}}
	return m
}

func rl(kv ...string) corev1.ResourceList {
	out := corev1.ResourceList{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[corev1.ResourceName(kv[i])] = resource.MustParse(kv[i+1])
	}
	return out
}

func podSpec() corev1.PodSpec {
	return corev1.PodSpec{
		ServiceAccountName: "web",
		NodeName:           "node-a",
		PriorityClassName:  "high",
		ImagePullSecrets:   []corev1.LocalObjectReference{{Name: "regcred"}},
		InitContainers: []corev1.Container{{
			Name: "init", Image: "busybox:1.36", Command: []string{"sh", "-c"}, Args: []string{"echo ready"},
			Ports:     []corev1.ContainerPort{{Name: "probe", ContainerPort: 7070}},
			Env:       []corev1.EnvVar{{Name: "SEED", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "seed"}, Key: "value"}}}},
			EnvFrom:   []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "init-secret"}}}},
			Resources: corev1.ResourceRequirements{Requests: rl("cpu", "10m"), Limits: rl("memory", "16Mi")},
		}},
		Containers: []corev1.Container{{
			Name:    "app",
			Image:   "nginx:1.25",
			Command: []string{"/app/server"},
			Args:    []string{"--db=postgres://admin:hunter2@db:5432/app", "--verbose"},
			Ports:   []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}, {ContainerPort: 9090, Protocol: corev1.ProtocolUDP}},
			Env: []corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: secretLiteral},
				{Name: "MODE", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "web-config"}, Key: "mode"}}},
				{Name: "API_TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "web-secret"}, Key: "token"}}},
				{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
				{Name: "MEM", ValueFrom: &corev1.EnvVarSource{ResourceFieldRef: &corev1.ResourceFieldSelector{Resource: "limits.memory"}}},
			},
			EnvFrom: []corev1.EnvFromSource{
				{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "web-env"}}},
				{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "web-env-secret"}}},
			},
			Resources: corev1.ResourceRequirements{
				Requests: rl("cpu", "250m", "memory", "128Mi", "nvidia.com/gpu", "1"),
				Limits:   rl("cpu", "1", "memory", "256Mi", "nvidia.com/gpu", "1"),
			},
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz?token=abc"}}},
		}},
		Volumes: []corev1.Volume{
			{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}},
			{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "web-config"}}}},
			{Name: "creds", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "web-secret"}}},
			{Name: "scratch", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}},
			{Name: "bundle", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
				{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "ca-bundle"}}},
				{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "tls"}}},
			}}}},
		},
	}
}

func template() corev1.PodTemplateSpec {
	s := podSpec()
	s.NodeName = ""
	return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}, Spec: s}
}

func fixturePod(name, uid, node string) *corev1.Pod {
	spec := podSpec()
	spec.NodeName = node
	m := owned(meta(name, "shop", uid), "ReplicaSet", "web-abc", "rs-1")
	m.Labels["pod-template-hash"] = "abc"
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: m,
		Spec:       spec,
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, HostIP: "10.0.0.1", PodIP: "10.1.0." + uid[len(uid)-1:], QOSClass: corev1.PodQOSBurstable,
			Message: "free text status",
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastProbeTime: fixtureTime, Message: "ready"},
				{Type: corev1.PodScheduled, Status: corev1.ConditionTrue, Reason: "Scheduled"},
				{Type: "example.com/gate", Status: corev1.ConditionTrue},
			},
			InitContainerStatuses: []corev1.ContainerStatus{{
				Name: "init", ImageID: "docker.io/library/busybox@sha256:1111", Ready: true,
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed", ExitCode: 0, Message: "done"}},
			}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app", ImageID: "docker.io/library/nginx@sha256:2222", Ready: true, RestartCount: 2,
				State:                corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: fixtureTime}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, Message: "oom"}},
			}},
		},
	}
}

func waitingPod(name, uid, node string) *corev1.Pod {
	p := fixturePod(name, uid, node)
	p.Status.Phase = corev1.PodPending
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ContainersNotReady"}}
	p.Status.ContainerStatuses[0].Ready = false
	p.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "back-off"}}
	p.Status.ContainerStatuses[0].LastTerminationState = corev1.ContainerState{}
	p.Status.Reason = "Evicted"
	p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "sidecar", Image: "envoy:1.30"})
	p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: "sidecar", ImageID: "envoy@sha256:3333",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1}}})
	p.Status.InitContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}
	p.Status.InitContainerStatuses[0].LastTerminationState = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 2}}
	return p
}

func fixtureNode(name, uid, zone string) *corev1.Node {
	m := meta(name, "", uid)
	m.Labels = map[string]string{
		"topology.kubernetes.io/zone": zone, "topology.kubernetes.io/region": "eu-west-1",
		"node-role.kubernetes.io/worker": "", "kubernetes.io/hostname": name,
	}
	return &corev1.Node{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
		ObjectMeta: m,
		Spec: corev1.NodeSpec{PodCIDR: "10.1.0.0/24", ProviderID: "aws:///eu-west-1a/i-0abc",
			Taints: []corev1.Taint{{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule, TimeAdded: &fixtureTime}}},
		Status: corev1.NodeStatus{
			Capacity:    rl("cpu", "4", "memory", "16Gi", "pods", "110", "nvidia.com/gpu", "1", "ephemeral-storage", "100Gi"),
			Allocatable: rl("cpu", "3800m", "memory", "15Gi", "pods", "110", "nvidia.com/gpu", "1", "ephemeral-storage", "90Gi"),
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "KubeletReady", LastHeartbeatTime: fixtureTime, Message: "kubelet is posting ready status"},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse, Reason: "KubeletHasSufficientMemory"},
			},
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeHostName, Address: name}, {Type: corev1.NodeInternalIP, Address: "10.0.0.1"}},
			NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.34.1", ContainerRuntimeVersion: "containerd://2.0.0", OSImage: "Ubuntu 24.04",
				KernelVersion: "6.8.0", Architecture: "amd64", OperatingSystem: "linux"},
			Images: []corev1.ContainerImage{{Names: []string{"nginx:1.25"}, SizeBytes: 1000}},
		},
	}
}

func fixtureDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: meta("web", "shop", "dep-1"),
		Spec: appsv1.DeploymentSpec{Replicas: ptr(int32(3)), Template: template(),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 4, Replicas: 3, ReadyReplicas: 2, AvailableReplicas: 2, UpdatedReplicas: 3, UnavailableReplicas: 1,
			Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionFalse, Reason: "MinimumReplicasUnavailable", LastUpdateTime: fixtureTime, Message: "Deployment does not have minimum availability."}}},
	}
}

func fixtureObjects(t testing.TB) []*unstructured.Unstructured {
	t.Helper()
	ns := &corev1.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta("shop", "", "ns-1"),
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
	rs := &appsv1.ReplicaSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"},
		ObjectMeta: owned(meta("web-abc", "shop", "rs-1"), "Deployment", "web", "dep-1"),
		Spec:       appsv1.ReplicaSetSpec{Replicas: ptr(int32(3)), Template: template()},
		Status: appsv1.ReplicaSetStatus{Replicas: 3, ReadyReplicas: 2, AvailableReplicas: 2, ObservedGeneration: 4,
			Conditions: []appsv1.ReplicaSetCondition{{Type: appsv1.ReplicaSetReplicaFailure, Status: corev1.ConditionTrue, Reason: "FailedCreate"}}},
	}
	sts := &appsv1.StatefulSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "StatefulSet"},
		ObjectMeta: meta("db", "shop", "sts-1"),
		Spec: appsv1.StatefulSetSpec{Replicas: ptr(int32(1)), ServiceName: "db", Template: template(),
			PodManagementPolicy: appsv1.OrderedReadyPodManagement, UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType}},
		Status: appsv1.StatefulSetStatus{Replicas: 1, ReadyReplicas: 1, AvailableReplicas: 1, CurrentReplicas: 1, UpdatedReplicas: 1,
			CurrentRevision: "db-7d9", UpdateRevision: "db-7d9", ObservedGeneration: 4},
	}
	ds := &appsv1.DaemonSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "DaemonSet"},
		ObjectMeta: meta("agent", "shop", "ds-1"),
		Spec:       appsv1.DaemonSetSpec{Template: template(), UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType}},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, CurrentNumberScheduled: 2, NumberReady: 1, NumberAvailable: 1,
			NumberUnavailable: 1, NumberMisscheduled: 0, UpdatedNumberScheduled: 2, ObservedGeneration: 4},
	}
	job := &batchv1.Job{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: meta("migrate", "shop", "job-1"),
		Spec: batchv1.JobSpec{Completions: ptr(int32(1)), Parallelism: ptr(int32(1)), BackoffLimit: ptr(int32(6)), Suspend: ptr(false),
			CompletionMode: ptr(batchv1.NonIndexedCompletion), Template: template()},
		Status: batchv1.JobStatus{Active: 0, Succeeded: 0, Failed: 2,
			Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}}},
	}
	cj := &batchv1.CronJob{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "CronJob"},
		ObjectMeta: meta("nightly", "shop", "cj-1"),
		Spec: batchv1.CronJobSpec{Schedule: "0 2 * * *", TimeZone: ptr("Etc/UTC"), Suspend: ptr(false), ConcurrencyPolicy: batchv1.ForbidConcurrent,
			JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: template()}}},
		Status: batchv1.CronJobStatus{Active: []corev1.ObjectReference{{Name: "nightly-1"}}, LastScheduleTime: &fixtureTime, LastSuccessfulTime: &fixtureTime},
	}
	svc := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: meta("web", "shop", "svc-1"),
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.96.0.10", Selector: map[string]string{"app": "web"},
			Ports:           []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromString("http"), Protocol: corev1.ProtocolTCP}},
			SessionAffinity: corev1.ServiceAffinityNone, ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			InternalTrafficPolicy: ptr(corev1.ServiceInternalTrafficPolicyCluster)},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "203.0.113.5"}}}},
	}
	ext := &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: meta("payments", "shop", "svc-2"),
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "https://user:s3cr3t@payments.example.com"},
	}
	ing := &networkingv1.Ingress{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "Ingress"},
		ObjectMeta: meta("web", "shop", "ing-1"),
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr("nginx"),
			TLS:              []networkingv1.IngressTLS{{Hosts: []string{"shop.example.com"}, SecretName: "shop-tls"}},
			Rules: []networkingv1.IngressRule{{Host: "shop.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: ptr(networkingv1.PathTypePrefix),
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Name: "http"}}}}},
			}}}},
		},
		Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{Ingress: []networkingv1.IngressLoadBalancerIngress{{Hostname: "lb.example.com"}}}},
	}
	np := &networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: meta("web", "shop", "np-1"),
		Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, Ingress: []networkingv1.NetworkPolicyIngressRule{{}}},
	}
	pvc := &corev1.PersistentVolumeClaim{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: meta("data", "shop", "pvc-1"),
		Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: ptr("fast"), AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			Resources: corev1.VolumeResourceRequirements{Requests: rl("storage", "10Gi")}, VolumeName: "pv-data", VolumeMode: ptr(corev1.PersistentVolumeFilesystem)},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: rl("storage", "10Gi"),
			Conditions: []corev1.PersistentVolumeClaimCondition{{Type: corev1.PersistentVolumeClaimResizing, Status: corev1.ConditionFalse, Reason: "ResizeFinished"}}},
	}
	pv := fixturePV()
	sc := &storagev1.StorageClass{
		TypeMeta:             metav1.TypeMeta{APIVersion: "storage.k8s.io/v1", Kind: "StorageClass"},
		ObjectMeta:           meta("fast", "", "sc-1"),
		Provisioner:          "ebs.csi.aws.com",
		ReclaimPolicy:        ptr(corev1.PersistentVolumeReclaimDelete),
		VolumeBindingMode:    ptr(storagev1.VolumeBindingWaitForFirstConsumer),
		AllowVolumeExpansion: ptr(true),
		Parameters:           map[string]string{"type": "gp3", "kmsKeyId": "arn:aws:kms:key/abc"},
	}
	sc.Annotations[defaultClassAnnotation] = "true"
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		TypeMeta:   metav1.TypeMeta{APIVersion: "autoscaling/v2", Kind: "HorizontalPodAutoscaler"},
		ObjectMeta: meta("web", "shop", "hpa-1"),
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "web"},
			MinReplicas:    ptr(int32(2)), MaxReplicas: 10,
			Metrics: []autoscalingv2.MetricSpec{{Type: autoscalingv2.ResourceMetricSourceType, Resource: &autoscalingv2.ResourceMetricSource{Name: corev1.ResourceCPU}}},
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{CurrentReplicas: 3, DesiredReplicas: 3,
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionTrue, Reason: "ReadyForNewScale"}}},
	}
	pdb := &policyv1.PodDisruptionBudget{
		TypeMeta:   metav1.TypeMeta{APIVersion: "policy/v1", Kind: "PodDisruptionBudget"},
		ObjectMeta: meta("web", "shop", "pdb-1"),
		Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: ptr(intstr.FromInt32(1)), MaxUnavailable: ptr(intstr.FromString("50%")),
			Selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"web"}}}}},
		Status: policyv1.PodDisruptionBudgetStatus{CurrentHealthy: 1, DesiredHealthy: 1, DisruptionsAllowed: 0, ExpectedPods: 2,
			Conditions: []metav1.Condition{{Type: "DisruptionAllowed", Status: metav1.ConditionFalse, Reason: "InsufficientPods", Message: "free text"}}},
	}
	objs := []runtime.Object{
		ns, fixtureNode("node-a", "node-1", "eu-west-1a"), fixtureNode("node-b", "node-2", "eu-west-1b"),
		fixtureDeployment(), rs, fixturePod("web-abc-1", "pod-1", "node-a"), waitingPod("web-abc-2", "pod-2", "node-b"),
		sts, ds, job, cj, svc, ext, ing, np, pvc, pv, sc, fixtureConfigMap(), hpa, pdb,
	}
	out := make([]*unstructured.Unstructured, len(objs))
	for i, o := range objs {
		out[i] = toU(t, o)
	}
	return out
}

func fixturePV() *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolume"},
		ObjectMeta: meta("pv-data", "", "pv-1"),
		Spec: corev1.PersistentVolumeSpec{
			Capacity: rl("storage", "10Gi"), AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain, StorageClassName: "fast",
			VolumeMode:             ptr(corev1.PersistentVolumeFilesystem),
			ClaimRef:               &corev1.ObjectReference{Namespace: "shop", Name: "data", UID: "pvc-1"},
			PersistentVolumeSource: corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: "/mnt/disks/ssd1"}},
			NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{{Key: corev1.LabelHostname, Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a"}}},
			}}}},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}
}

func fixtureConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: meta("web-config", "shop", "cm-1"),
		Data:       map[string]string{"mode": "prod", "db.password": secretCMValue},
		BinaryData: map[string][]byte{"cert.der": []byte{1, 2, 3}},
	}
}

func fixtureByUID(t testing.TB, uid string) *unstructured.Unstructured {
	t.Helper()
	for _, o := range fixtureObjects(t) {
		if string(o.GetUID()) == uid {
			return o
		}
	}
	t.Fatalf("no fixture %s", uid)
	return nil
}

func warningEvent(uid, involved, reason string, count int32, last time.Time) *unstructured.Unstructured {
	ev := &corev1.Event{
		TypeMeta:       metav1.TypeMeta{APIVersion: "v1", Kind: "Event"},
		ObjectMeta:     metav1.ObjectMeta{Name: uid, Namespace: "shop", UID: types.UID(uid)},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "shop", Name: "web-abc-1", UID: types.UID(involved)},
		Reason:         reason, Message: "Back-off restarting failed container " + secretLiteral, Type: corev1.EventTypeWarning,
		Count: count, FirstTimestamp: metav1.NewTime(last), LastTimestamp: metav1.NewTime(last),
	}
	m, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(ev)
	return &unstructured.Unstructured{Object: m}
}
