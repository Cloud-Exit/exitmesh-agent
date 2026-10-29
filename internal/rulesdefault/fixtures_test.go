package rulesdefault

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const (
	k8s  = bundle.TargetKubernetes
	host = bundle.TargetHost
)

func res(uid, kind, ns, name string, fields map[string]any) *protocol.Resource {
	return &protocol.Resource{UID: uid, Kind: kind, Namespace: ns, Name: name, Fields: fields}
}

func st(rs ...*protocol.Resource) *protocol.State {
	s := protocol.NewState()
	for _, r := range rs {
		s.Resources[r.UID] = r
	}
	return s
}

func pod(uid string, fields map[string]any) *protocol.Resource {
	return res(uid, "Pod", "shop", "web-"+uid, fields)
}

func merge(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

var running = map[string]any{
	"phase": "Running", "ready": true, "conditions.PodScheduled.status": "True",
	"containers.web.state": "running", "containers.web.ready": true, "containers.web.restarts": int64(0),
}

func stateFixtures() []fixture {
	waiting := func(ctr, reason string) map[string]any {
		return merge(running, map[string]any{"ready": false, "containers." + ctr + ".state": "waiting", "containers." + ctr + ".waitingReason": reason, "containers." + ctr + ".ready": false})
	}
	return []fixture{
		{
			id: "manifest.pod_status_failure.crashloop", target: k8s,
			bad:    st(pod("1", merge(waiting("web", "CrashLoopBackOff"), map[string]any{"containers.worker.waitingReason": "CrashLoopBackOff"}))),
			good:   st(pod("1", merge(running, map[string]any{"containers.web.lastTerminatedReason": "Error"}))),
			labels: map[string]string{"kind": "Pod", "namespace": "shop", "name": "web-1", "container": "web"},
		},
		{
			id: "manifest.pod_status_failure.image_pull", target: k8s,
			bad:    st(pod("1", waiting("web", "ImagePullBackOff"))),
			good:   st(pod("1", waiting("web", "ContainerCreating"))),
			labels: map[string]string{"container": "web"},
		},
		{
			id: "manifest.pod_status_failure.create_container", target: k8s,
			bad:    st(pod("1", map[string]any{"phase": "Pending", "initContainers.init.state": "waiting", "initContainers.init.waitingReason": "CreateContainerConfigError"})),
			good:   st(pod("1", map[string]any{"phase": "Pending", "initContainers.init.state": "waiting", "initContainers.init.waitingReason": "PodInitializing"})),
			labels: map[string]string{"container": "init"},
		},
		{
			id: "manifest.pod_status_failure.oom_killed", target: k8s,
			bad: st(
				pod("1", merge(running, map[string]any{"containers.web.lastTerminatedReason": "OOMKilled", "containers.web.lastTerminatedExitCode": int64(137)})),
				pod("2", merge(running, map[string]any{"containers.web.state": "terminated", "containers.web.terminatedReason": "Error", "containers.web.terminatedExitCode": int64(137)})),
			),
			good: st(
				pod("1", merge(running, map[string]any{"containers.web.lastTerminatedReason": "Completed", "containers.web.lastTerminatedExitCode": int64(0)})),
				pod("2", merge(running, map[string]any{"containers.web.lastTerminatedReason": "Error", "containers.web.lastTerminatedExitCode": int64(1)})),
			),
			firing: 2,
			labels: map[string]string{"name": "web-1", "container": "web"},
		},
		{
			id: "event.warning_spike", target: k8s,
			bad:    st(pod("1", merge(running, map[string]any{"events.warning.BackOff": int64(8), "events.warning.Unhealthy": int64(7), "events.warning.Failed": int64(6)}))),
			good:   st(pod("1", merge(running, map[string]any{"events.warning.BackOff": int64(8), "events.warning.Unhealthy": int64(7), "events.warning.Failed": int64(4)}))),
			labels: map[string]string{"kind": "Pod", "name": "web-1"},
		},
		{
			id: "event.reason_spike", target: k8s,
			bad: st(
				res("n1", "Node", "", "node-a", map[string]any{"events.warning.Rebooted": int64(1)}),
				pod("1", merge(running, map[string]any{"events.warning.Unhealthy": int64(12), "events.warning.BackOff": int64(11), "events.warning.Failed": int64(2)})),
			),
			good: st(
				res("n1", "Node", "", "node-a", map[string]any{"events.warning.Rebooted": int64(1)}),
				pod("1", merge(running, map[string]any{"events.warning.Unhealthy": int64(9), "events.warning.BackOff": int64(9)})),
			),
			labels: map[string]string{"name": "web-1", "reason": "BackOff"},
		},
		{
			id: "event.new_reason", target: k8s,
			bad: st(
				res("c1", "PersistentVolumeClaim", "shop", "data", map[string]any{"phase": "Pending", "events.warning.ProvisioningFailed": int64(1)}),
				res("d1", "apps/Deployment", "shop", "web", map[string]any{"replicas": int64(2)}),
			),
			good: st(
				res("c1", "PersistentVolumeClaim", "shop", "data", map[string]any{"phase": "Bound"}),
				res("d1", "apps/Deployment", "shop", "web", map[string]any{"replicas": int64(2)}),
			),
			labels: map[string]string{"kind": "PersistentVolumeClaim", "name": "data", "reason_count": "1"},
		},
		{
			id: "event.backoff_loop", target: k8s,
			bad:    st(pod("1", merge(waiting("web", "CrashLoopBackOff"), map[string]any{"events.warning.BackOff": int64(4)}))),
			good:   st(pod("1", merge(running, map[string]any{"events.warning.BackOff": int64(4)}))),
			labels: map[string]string{"container": "web"},
		},
		{
			id: "event.scheduling_failure", target: k8s,
			bad:  st(pod("1", map[string]any{"phase": "Pending", "conditions.PodScheduled.status": "False", "conditions.PodScheduled.reason": "Unschedulable", "events.warning.FailedScheduling": int64(3)})),
			good: st(pod("1", merge(running, map[string]any{"events.warning.FailedScheduling": int64(3)}))),
		},
		{
			id: "event.image_pull_failure", target: k8s,
			bad: st(
				pod("1", merge(waiting("web", "ErrImagePull"), map[string]any{"events.warning.Failed": int64(2)})),
				pod("2", waiting("web", "ErrImagePull")),
			),
			good: st(
				pod("1", merge(running, map[string]any{"events.warning.Failed": int64(2)})),
				pod("2", waiting("web", "ErrImagePull")),
			),
			labels: map[string]string{"name": "web-1", "container": "web"},
		},
		{
			id: "event.volume_failure", target: k8s,
			bad: st(
				pod("1", map[string]any{"phase": "Pending", "events.warning.FailedMount": int64(3)}),
				res("c1", "PersistentVolumeClaim", "shop", "data", map[string]any{"phase": "Pending", "events.warning.ProvisioningFailed": int64(2)}),
			),
			good: st(
				pod("1", merge(running, map[string]any{"events.warning.FailedMount": int64(3)})),
				res("c1", "PersistentVolumeClaim", "shop", "data", map[string]any{"phase": "Bound", "events.warning.ProvisioningFailed": int64(2)}),
			),
			firing: 2,
			labels: map[string]string{"kind": "PersistentVolumeClaim", "name": "data"},
		},
		{
			id: "event.node_pressure", target: k8s,
			bad:    st(res("n1", "Node", "", "node-a", map[string]any{"conditions.Ready.status": "True", "conditions.MemoryPressure.status": "True", "conditions.DiskPressure.status": "False", "conditions.PIDPressure.status": "True"})),
			good:   st(res("n1", "Node", "", "node-a", map[string]any{"conditions.Ready.status": "True", "conditions.MemoryPressure.status": "False", "conditions.DiskPressure.status": "False", "conditions.PIDPressure.status": "False"})),
			labels: map[string]string{"name": "node-a", "pressure": "MemoryPressure,PIDPressure"},
		},
		{
			id: "manifest.node_not_ready", target: k8s,
			bad: st(
				res("n1", "Node", "", "node-a", map[string]any{"conditions.Ready.status": "False", "conditions.Ready.reason": "KubeletNotReady"}),
				res("n2", "Node", "", "node-b", map[string]any{"conditions.Ready.status": "True", "conditions.Ready.reason": "KubeletReady"}),
			),
			good: st(
				res("n1", "Node", "", "node-a", map[string]any{"conditions.Ready.status": "True", "conditions.Ready.reason": "KubeletReady"}),
				res("n2", "Node", "", "node-b", map[string]any{"conditions.Ready.status": "True", "conditions.Ready.reason": "KubeletReady"}),
			),
			labels: map[string]string{"kind": "Node", "name": "node-a", "status": "False", "reason": "KubeletNotReady"},
		},
		{
			id: "manifest.workload_unavailable.deployment", target: k8s,
			bad: st(
				res("d1", "apps/Deployment", "shop", "web", map[string]any{"replicas": int64(4), "availableReplicas": int64(2)}),
				res("d2", "apps/Deployment", "shop", "api", map[string]any{"replicas": int64(10), "availableReplicas": int64(9)}),
				res("d3", "apps/Deployment", "shop", "idle", map[string]any{"replicas": int64(0)}),
			),
			good: st(
				res("d1", "apps/Deployment", "shop", "web", map[string]any{"replicas": int64(4), "availableReplicas": int64(4)}),
				res("d2", "apps/Deployment", "shop", "api", map[string]any{"replicas": int64(10), "availableReplicas": int64(9)}),
				res("d3", "apps/Deployment", "shop", "idle", map[string]any{"replicas": int64(0)}),
			),
			labels: map[string]string{"kind": "apps/Deployment", "name": "web", "available": "2", "desired": "4"},
		},
		{
			id: "manifest.workload_unavailable.statefulset", target: k8s,
			bad:    st(res("s1", "apps/StatefulSet", "data", "nats", map[string]any{"replicas": int64(3), "readyReplicas": int64(1), "availableReplicas": int64(1)})),
			good:   st(res("s1", "apps/StatefulSet", "data", "nats", map[string]any{"replicas": int64(3), "readyReplicas": int64(3), "availableReplicas": int64(3)})),
			labels: map[string]string{"kind": "apps/StatefulSet", "name": "nats", "ready": "1", "desired": "3"},
		},
		{
			id: "manifest.cronjob_stale", target: k8s,
			bad: st(
				cronJob("c1", "backup", "@daily", false, t0.AddDate(0, 0, -3)),
				cronJob("c2", "paused", "@daily", true, t0.AddDate(0, 0, -30)),
				cronJob("c3", "monitor", "*/5 * * * *", false, t0.Add(time.Hour)),
			),
			good: st(
				cronJob("c1", "backup", "@daily", false, t0),
				cronJob("c2", "paused", "@daily", true, t0.AddDate(0, 0, -30)),
				cronJob("c3", "monitor", "*/5 * * * *", false, t0.Add(time.Hour)),
			),
			labels: map[string]string{"kind": "batch/CronJob", "name": "backup", "last_success": "2026-08-29T00:00:00Z"},
		},
		{
			id: "host.systemd_unit_failed", target: host,
			bad: st(
				res("host:unit:backup.service", "host/Unit", "", "backup.service", map[string]any{"load_state": "loaded", "active_state": "failed", "sub_state": "failed"}),
				res("host:unit:sshd.service", "host/Unit", "", "sshd.service", map[string]any{"load_state": "loaded", "active_state": "active", "sub_state": "running"}),
			),
			good: st(
				res("host:unit:backup.service", "host/Unit", "", "backup.service", map[string]any{"load_state": "loaded", "active_state": "inactive", "sub_state": "dead"}),
				res("host:unit:sshd.service", "host/Unit", "", "sshd.service", map[string]any{"load_state": "loaded", "active_state": "active", "sub_state": "running"}),
			),
			labels: map[string]string{"kind": "host/Unit", "name": "backup.service", "sub_state": "failed"},
		},
	}
}

// cronJob is a CronJob created long before t0 whose last successful run was at lastSuccess.
func cronJob(uid, name, schedule string, suspend bool, lastSuccess time.Time) *protocol.Resource {
	return res(uid, "batch/CronJob", "ops", name, map[string]any{
		"schedule": schedule, "suspend": suspend, "active": int64(0),
		"created":            t0.AddDate(0, -2, 0).UnixMilli(),
		"lastSuccessfulTime": lastSuccess.UnixMilli(),
	})
}

// nodeMemory reports a 64 GiB node with availGiB available while bad.
func nodeMemory(availGiB float64) func(timeline) []engine.Series {
	return func(tl timeline) []engine.Series {
		return []engine.Series{
			series(tl, gauge(64*fixtureGiB, 64*fixtureGiB), "__name__", "node_memory_MemTotal_bytes", "node", "node-a"),
			series(tl, gauge(30*fixtureGiB, availGiB*fixtureGiB), "__name__", "node_memory_MemAvailable_bytes", "node", "node-a"),
		}
	}
}

// ownedPod is limitedPod owned by the ReplicaSet of Deployment web.
func ownedPod() *corev1.Pod {
	p := limitedPod()
	controller := true
	p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-5d8f7c9b4", UID: "rs-1", Controller: &controller}}
	return p
}

func limitedPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "shop", UID: "pod-1"},
		Spec: corev1.PodSpec{
			NodeName: "node-a",
			Containers: []corev1.Container{
				{Name: "app", Image: "shop/web:1", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("512Mi"),
				}}},
				{Name: "sidecar", Image: "shop/proxy:1"},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, HostIP: "10.0.0.1", PodIP: "10.1.0.5"},
	}
}

func cadvisor(name, ctr string) []string {
	return []string{"__name__", name, "namespace", "shop", "pod", "web-1", "container", ctr, "id", "/kubepods/pod-1/" + ctr, "image", "shop/" + ctr + ":1",
		"job", "kubelet", "metrics_path", "/metrics/cadvisor", "node", "node-a", "instance", "10.0.0.1:10250"}
}

func volume(name string) []string {
	return []string{"__name__", name, "namespace", "shop", "persistentvolumeclaim", "data", "job", "kubelet", "metrics_path", "/metrics", "node", "node-a", "instance", "10.0.0.1:10250"}
}

func filesystem(name, device, fstype, mount string) []string {
	return []string{"__name__", name, "device", device, "fstype", fstype, "mountpoint", mount}
}

func promFixtures() []fixture {
	cpu := func(bad float64) func(timeline) []engine.Series {
		return func(tl timeline) []engine.Series {
			return []engine.Series{
				series(tl, counter(0.3, bad), cadvisor("container_cpu_usage_seconds_total", "app")...),
				series(tl, counter(1.5, 1.5), cadvisor("container_cpu_usage_seconds_total", "sidecar")...),
			}
		}
	}
	mem := func(bad float64) func(timeline) []engine.Series {
		return func(tl timeline) []engine.Series {
			return []engine.Series{
				series(tl, gauge(200*fixtureMiB, bad*512*fixtureMiB), cadvisor("container_memory_working_set_bytes", "app")...),
				series(tl, gauge(900*fixtureMiB, 900*fixtureMiB), cadvisor("container_memory_working_set_bytes", "sidecar")...),
			}
		}
	}
	fill := func(tl timeline, lset []string) engine.Series {
		return series(tl, func(t time.Duration, w window) float64 {
			switch {
			case w.after(t):
				return 80 * fixtureGiB
			case w.active(t):
				return 60*fixtureGiB - 0.5*fixtureGiB*(t-w.start).Minutes()
			}
			return 60 * fixtureGiB
		}, lset...)
	}
	cpuModes := func(idle, user, system, iowait float64) func(timeline) []engine.Series {
		return func(tl timeline) []engine.Series {
			var out []engine.Series
			good := map[string]float64{"idle": 0.7, "user": 0.2, "system": 0.05, "iowait": 0.05}
			bad := map[string]float64{"idle": idle, "user": user, "system": system, "iowait": iowait}
			for _, c := range []string{"0", "1"} {
				for _, m := range []string{"idle", "user", "system", "iowait"} {
					out = append(out, series(tl, counter(good[m], bad[m]), "__name__", "node_cpu_seconds_total", "cpu", c, "mode", m))
				}
			}
			return out
		}
	}
	memAvail := func(bad float64) func(timeline) []engine.Series {
		return func(tl timeline) []engine.Series {
			return []engine.Series{
				series(tl, gauge(16*fixtureGiB, 16*fixtureGiB), "__name__", "node_memory_MemTotal_bytes"),
				series(tl, gauge(8*fixtureGiB, bad*16*fixtureGiB), "__name__", "node_memory_MemAvailable_bytes"),
			}
		}
	}
	fsFull := func(badAvail float64) func(timeline) []engine.Series {
		return func(tl timeline) []engine.Series {
			return []engine.Series{
				series(tl, gauge(50*fixtureGiB, badAvail), filesystem("node_filesystem_avail_bytes", "/dev/sda1", "ext4", "/")...),
				series(tl, gauge(100*fixtureGiB, 100*fixtureGiB), filesystem("node_filesystem_size_bytes", "/dev/sda1", "ext4", "/")...),
				series(tl, gauge(0, 0), filesystem("node_filesystem_readonly", "/dev/sda1", "ext4", "/")...),
				series(tl, gauge(fixtureMiB, fixtureMiB), filesystem("node_filesystem_avail_bytes", "tmpfs", "tmpfs", "/run")...),
				series(tl, gauge(fixtureGiB, fixtureGiB), filesystem("node_filesystem_size_bytes", "tmpfs", "tmpfs", "/run")...),
				series(tl, gauge(0, 0), filesystem("node_filesystem_readonly", "tmpfs", "tmpfs", "/run")...),
				series(tl, gauge(fixtureMiB, fixtureMiB), filesystem("node_filesystem_avail_bytes", "/dev/loop0", "squashfs", "/snap/core")...),
				series(tl, gauge(fixtureGiB, fixtureGiB), filesystem("node_filesystem_size_bytes", "/dev/loop0", "squashfs", "/snap/core")...),
				series(tl, gauge(1, 1), filesystem("node_filesystem_readonly", "/dev/loop0", "squashfs", "/snap/core")...),
			}
		}
	}
	return []fixture{
		{id: "metric.saturation.cpu.high", target: k8s, warmup: 10 * time.Minute, badFor: 30 * time.Minute, series: cpu(0.93), kube: []*corev1.Pod{limitedPod()},
			labels: map[string]string{"namespace": "shop", "pod": "web-1", "container": "app", "severity": "high"}},
		{id: "metric.saturation.cpu.critical", target: k8s, warmup: 10 * time.Minute, badFor: 30 * time.Minute, series: cpu(0.99), kube: []*corev1.Pod{limitedPod()},
			labels: map[string]string{"container": "app", "severity": "critical"}},
		{id: "metric.saturation.memory.high", target: k8s, warmup: 10 * time.Minute, badFor: 20 * time.Minute, series: mem(0.93), kube: []*corev1.Pod{limitedPod()},
			labels: map[string]string{"namespace": "shop", "pod": "web-1", "container": "app", "severity": "high"}},
		{id: "metric.saturation.memory.critical", target: k8s, warmup: 10 * time.Minute, badFor: 20 * time.Minute, series: mem(0.99), kube: []*corev1.Pod{limitedPod()},
			labels: map[string]string{"container": "app", "severity": "critical"}},
		{id: "metric.slope_change.memory", target: k8s, warmup: 160 * time.Minute, badFor: 45 * time.Minute, recover: 90 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, func(t time.Duration, w window) float64 {
						return 100*fixtureMiB + 2*fixtureMiB*w.overlap(t).Minutes()
					}, cadvisor("container_memory_working_set_bytes", "app")...),
					series(tl, func(t time.Duration, _ window) float64 {
						return 100*fixtureMiB + 0.5*fixtureMiB*t.Minutes()
					}, cadvisor("container_memory_working_set_bytes", "sidecar")...),
				}
			},
			labels: map[string]string{"namespace": "shop", "pod": "web-1", "container": "app"}},
		{id: "metric.active_series_spike", target: k8s, warmup: 80 * time.Minute, badFor: 20 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, gauge(1000, 5000), "__name__", "scrape_samples_scraped", "job", "kubernetes-pods", "instance", "10.1.0.5:8080", "namespace", "shop", "pod", "web-1"),
					series(tl, gauge(20000, 20000), "__name__", "scrape_samples_scraped", "job", "kubelet", "instance", "10.0.0.1:10250", "metrics_path", "/metrics/cadvisor"),
				}
			},
			labels: map[string]string{"job": "kubernetes-pods", "instance": "10.1.0.5:8080"}},
		{id: "metric.volume_saturation", target: k8s, warmup: 10 * time.Minute, badFor: 20 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, gauge(5*fixtureGiB, 9.5*fixtureGiB), volume("kubelet_volume_stats_used_bytes")...),
					series(tl, gauge(10*fixtureGiB, 10*fixtureGiB), volume("kubelet_volume_stats_capacity_bytes")...),
				}
			},
			labels: map[string]string{"namespace": "shop", "persistentvolumeclaim": "data"}},
		{id: "metric.volume_fill_trend", target: k8s, warmup: 60 * time.Minute, badFor: 70 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					fill(tl, volume("kubelet_volume_stats_available_bytes")),
					series(tl, gauge(100*fixtureGiB, 100*fixtureGiB), volume("kubelet_volume_stats_capacity_bytes")...),
				}
			},
			labels: map[string]string{"namespace": "shop", "persistentvolumeclaim": "data"}},
		{id: "metric.volume_saturation.warning", target: k8s, warmup: 10 * time.Minute, badFor: 30 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, gauge(5*fixtureGiB, 8.5*fixtureGiB), volume("kubelet_volume_stats_used_bytes")...),
					series(tl, gauge(10*fixtureGiB, 10*fixtureGiB), volume("kubelet_volume_stats_capacity_bytes")...),
				}
			},
			labels: map[string]string{"namespace": "shop", "persistentvolumeclaim": "data"}},
		{id: "metric.scrape_down.kubelet", target: k8s, warmup: 10 * time.Minute, badFor: 15 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, gauge(1, 0), "__name__", "up", "job", "kubelet", "metrics_path", "/metrics/cadvisor", "node", "node-a", "instance", "10.0.0.1:10250"),
					series(tl, gauge(1, 1), "__name__", "up", "job", "kubelet", "metrics_path", "/metrics", "node", "node-a", "instance", "10.0.0.1:10250"),
					series(tl, gauge(1, 1), "__name__", "up", "job", "kubernetes-pods", "namespace", "shop", "pod", "web-1", "node", "node-a", "instance", "10.1.0.5:8080"),
				}
			},
			labels: map[string]string{"node": "node-a", "metrics_path": "/metrics/cadvisor"}},
		{id: "metric.node_memory_saturation.warning", target: k8s, warmup: 10 * time.Minute, badFor: 20 * time.Minute, series: nodeMemory(6),
			labels: map[string]string{"node": "node-a"}},
		{id: "metric.node_memory_saturation.critical", target: k8s, warmup: 10 * time.Minute, badFor: 15 * time.Minute, series: nodeMemory(1),
			labels: map[string]string{"node": "node-a"}},
		{id: "metric.node_cpu_saturation", target: k8s, warmup: 10 * time.Minute, badFor: 20 * time.Minute,
			series: func(tl timeline) []engine.Series {
				mode := func(m string, good, bad float64) engine.Series {
					return series(tl, counter(good, bad), "__name__", "node_cpu_seconds_total", "mode", m, "node", "node-a")
				}
				return []engine.Series{mode("user", 0.8, 3.7), mode("system", 0.2, 0.2), mode("idle", 3, 0.1), mode("iowait", 0, 0)}
			},
			labels: map[string]string{"node": "node-a"}},
		{id: "metric.node_filesystem_saturation", target: k8s, warmup: 10 * time.Minute, badFor: 25 * time.Minute,
			series: func(tl timeline) []engine.Series {
				fs := func(name, mount string) []string {
					return []string{"__name__", name, "mountpoint", mount, "node", "node-a"}
				}
				return []engine.Series{
					series(tl, gauge(100*fixtureGiB, 100*fixtureGiB), fs("node_filesystem_size_bytes", "/var/lib/exitmesh")...),
					series(tl, gauge(50*fixtureGiB, 10*fixtureGiB), fs("node_filesystem_avail_bytes", "/var/lib/exitmesh")...),
					series(tl, gauge(500*fixtureGiB, 500*fixtureGiB), fs("node_filesystem_size_bytes", "/var/lib/containerd")...),
					series(tl, gauge(300*fixtureGiB, 300*fixtureGiB), fs("node_filesystem_avail_bytes", "/var/lib/containerd")...),
				}
			},
			labels: map[string]string{"node": "node-a", "mountpoint": "/var/lib/exitmesh"}},
		{id: "metric.cpu_throttling", target: k8s, warmup: 15 * time.Minute, badFor: 25 * time.Minute, kube: []*corev1.Pod{ownedPod()},
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, counter(0.05, 4), cadvisor("container_cpu_cfs_throttled_periods_total", "app")...),
					series(tl, counter(10, 10), cadvisor("container_cpu_cfs_periods_total", "app")...),
					series(tl, counter(0.05, 0.05), cadvisor("container_cpu_cfs_throttled_periods_total", "sidecar")...),
					series(tl, counter(10, 10), cadvisor("container_cpu_cfs_periods_total", "sidecar")...),
				}
			},
			labels: map[string]string{"namespace": "shop", "workload_kind": "Deployment", "workload": "web", "container": "app"}},
		{id: "metric.node_requests_exhausted", target: k8s, warmup: 10 * time.Minute, badFor: 25 * time.Minute,
			series: func(tl timeline) []engine.Series {
				request := func(pod, resource string, good, bad float64) engine.Series {
					return series(tl, gauge(good, bad), "__name__", "kube_pod_container_resource_requests", "namespace", "shop", "pod", pod, "uid", pod,
						"container", "app", "node", "node-a", "resource", resource)
				}
				phase := func(pod, p string) engine.Series {
					return series(tl, gauge(1, 1), "__name__", "kube_pod_status_phase", "namespace", "shop", "pod", pod, "uid", pod, "phase", p)
				}
				return []engine.Series{
					series(tl, gauge(4, 4), "__name__", "kube_node_status_allocatable", "node", "node-a", "resource", "cpu"),
					series(tl, gauge(16*fixtureGiB, 16*fixtureGiB), "__name__", "kube_node_status_allocatable", "node", "node-a", "resource", "memory"),
					request("web-1", "cpu", 1, 2.9), request("web-2", "cpu", 1, 1), request("done-1", "cpu", 3, 3),
					request("web-1", "memory", 2*fixtureGiB, 2*fixtureGiB), request("web-2", "memory", 2*fixtureGiB, 2*fixtureGiB),
					phase("web-1", "Running"), phase("web-2", "Pending"), phase("done-1", "Succeeded"),
				}
			},
			labels: map[string]string{"node": "node-a", "resource": "cpu"}},
		{id: "metric.node_network_saturation", target: k8s, warmup: 10 * time.Minute, badFor: 20 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, counter(1.2e8, 9e8), "__name__", "node_network_receive_bytes_total", "device", "enp193s0f0np0", "node", "node-a"),
					series(tl, gauge(1.25e9, 1.25e9), "__name__", "node_network_speed_bytes", "device", "enp193s0f0np0", "node", "node-a"),
					series(tl, counter(1.2e8, 1.2e8), "__name__", "node_network_receive_bytes_total", "device", "enp193s0f1np1", "node", "node-a"),
					series(tl, gauge(1.25e9, 1.25e9), "__name__", "node_network_speed_bytes", "device", "enp193s0f1np1", "node", "node-a"),
				}
			},
			labels: map[string]string{"node": "node-a", "device": "enp193s0f0np0"}},
		requestCollapse("metric.request_rate_collapse.http", "http_requests_total"),
		requestCollapse("metric.request_rate_collapse.http_server", "http_server_request_duration_seconds_count"),
		requestCollapse("metric.request_rate_collapse.grpc", "grpc_server_handled_total"),
		replicaStacking("metric.replica_stacking.deployment", "ReplicaSet", "web-5d8f7c9b4", "deployment", "web"),
		replicaStacking("metric.replica_stacking.statefulset", "StatefulSet", "db", "statefulset", "db"),
		{id: "host.filesystem_almost_full.high", target: host, warmup: 10 * time.Minute, badFor: 30 * time.Minute, series: fsFull(7 * fixtureGiB),
			labels: map[string]string{"mountpoint": "/", "severity": "high"}},
		{id: "host.filesystem_almost_full.critical", target: host, warmup: 10 * time.Minute, badFor: 20 * time.Minute, series: fsFull(1 * fixtureGiB),
			labels: map[string]string{"mountpoint": "/", "severity": "critical"}},
		{id: "host.filesystem_predicted_full", target: host, warmup: 60 * time.Minute, badFor: 70 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					fill(tl, filesystem("node_filesystem_avail_bytes", "/dev/sda1", "ext4", "/")),
					series(tl, gauge(100*fixtureGiB, 100*fixtureGiB), filesystem("node_filesystem_size_bytes", "/dev/sda1", "ext4", "/")...),
					series(tl, gauge(0, 0), filesystem("node_filesystem_readonly", "/dev/sda1", "ext4", "/")...),
				}
			},
			labels: map[string]string{"mountpoint": "/"}},
		{id: "host.cpu_saturation.high", target: host, warmup: 10 * time.Minute, badFor: 30 * time.Minute, series: cpuModes(0.05, 0.85, 0.08, 0.02),
			labels: map[string]string{"severity": "high"}},
		{id: "host.cpu_saturation.critical", target: host, warmup: 10 * time.Minute, badFor: 30 * time.Minute, series: cpuModes(0.01, 0.9, 0.08, 0.01),
			labels: map[string]string{"severity": "critical"}},
		{id: "host.memory_saturation.high", target: host, warmup: 10 * time.Minute, badFor: 25 * time.Minute, series: memAvail(0.07),
			labels: map[string]string{"severity": "high"}},
		{id: "host.memory_saturation.critical", target: host, warmup: 10 * time.Minute, badFor: 15 * time.Minute, series: memAvail(0.01),
			labels: map[string]string{"severity": "critical"}},
		{id: "host.memory_pressure", target: host, warmup: 10 * time.Minute, badFor: 25 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{series(tl, counter(0.01, 0.3), "__name__", "node_pressure_memory_waiting_seconds_total")}
			}},
		{id: "host.high_load", target: host, warmup: 10 * time.Minute, badFor: 25 * time.Minute,
			series: func(tl timeline) []engine.Series {
				out := []engine.Series{series(tl, gauge(1, 10), "__name__", "node_load1")}
				for c := range 4 {
					out = append(out, series(tl, counter(0.5, 0.1), "__name__", "node_cpu_seconds_total", "cpu", fmt.Sprint(c), "mode", "idle"))
				}
				return out
			}},
		{id: "host.disk_io_saturation", target: host, warmup: 10 * time.Minute, badFor: 40 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{
					series(tl, counter(0.5, 20), "__name__", "node_disk_io_time_weighted_seconds_total", "device", "sda"),
					series(tl, counter(0.5, 0.5), "__name__", "node_disk_io_time_weighted_seconds_total", "device", "sdb"),
				}
			},
			labels: map[string]string{"device": "sda"}},
		{id: "host.clock_skew", target: host, warmup: 10 * time.Minute, badFor: 20 * time.Minute,
			series: func(tl timeline) []engine.Series {
				return []engine.Series{series(tl, gauge(0.001, 0.2), "__name__", "node_timex_offset_seconds")}
			}},
	}
}

// requestCollapse drops one pod's request rate from 50 to 1 per second while a second pod keeps serving.
func requestCollapse(id, metric string) fixture {
	pod := func(name, ip string) []string {
		return []string{"job", "kubernetes-pods", "namespace", "shop", "pod", name, "container", "app", "node", "node-a", "instance", ip + ":8080"}
	}
	return fixture{id: id, target: k8s, warmup: 70 * time.Minute, badFor: 15 * time.Minute,
		series: func(tl timeline) []engine.Series {
			return []engine.Series{
				series(tl, counter(50, 1), append([]string{"__name__", metric}, pod("web-1", "10.1.0.5")...)...),
				series(tl, counter(40, 40), append([]string{"__name__", metric}, pod("web-2", "10.1.0.6")...)...),
				series(tl, gauge(1, 1), append([]string{"__name__", "up"}, pod("web-1", "10.1.0.5")...)...),
				series(tl, gauge(1, 1), append([]string{"__name__", "up"}, pod("web-2", "10.1.0.6")...)...),
			}
		},
		labels: map[string]string{"namespace": "shop", "pod": "web-1"}}
}

// replicaStacking runs six pods of one workload on three schedulable nodes, four of them on node-a while bad.
func replicaStacking(id, ownerKind, ownerName, label, workload string) fixture {
	return fixture{id: id, target: k8s, warmup: 10 * time.Minute, badFor: 45 * time.Minute,
		series: func(tl timeline) []engine.Series {
			var out []engine.Series
			for i, node := range []string{"node-a", "node-b", "node-c"} {
				out = append(out, series(tl, gauge(0, 0), "__name__", "kube_node_spec_unschedulable", "node", node))
				for _, p := range []int{2 * i, 2*i + 1} {
					name := fmt.Sprintf("%s-%d", workload, p)
					badNode := node
					if p == 2 || p == 3 {
						badNode = "node-a"
					}
					info := func(n string) []string {
						return []string{"__name__", "kube_pod_info", "namespace", "shop", "pod", name, "uid", name, "node", n, "created_by_kind", ownerKind, "created_by_name", ownerName}
					}
					if badNode == node {
						out = append(out, series(tl, gauge(1, 1), info(node)...))
					} else {
						out = append(out,
							presence(tl, func(t time.Duration, w window) bool { return !w.active(t) }, info(node)...),
							presence(tl, func(t time.Duration, w window) bool { return w.active(t) }, info(badNode)...),
						)
					}
					out = append(out, series(tl, gauge(1, 1), "__name__", "kube_pod_status_phase", "namespace", "shop", "pod", name, "uid", name, "phase", "Running"))
				}
			}
			return out
		},
		labels: map[string]string{"namespace": "shop", label: workload}}
}

var workload = map[string]string{
	"namespace": "shop", "pod": "web-1", "pod_uid": "pod-1", "container": "app", "stream": "stdout",
	"node": "node-a", "workload": "web", "workload_kind": "Deployment",
}

func repeatLine(n int, labels map[string]string, text string) []line {
	out := make([]line, n)
	for i := range out {
		out[i] = line{labels: labels, text: text}
	}
	return out
}

// letters spells i with letters only, so every value yields a distinct message fingerprint.
func letters(i int) string {
	s := ""
	for {
		s = string(rune('a'+i%26)) + s
		i /= 26
		if i == 0 {
			break
		}
	}
	return "code" + s
}

func logFixtures() []fixture {
	info := repeatLine(5, workload, `level=info msg="request served" status=200 path=/cart`)
	var burst int
	patterns := []string{"cache refresh completed", "order queue drained", "session store synced"}
	kernel := map[string]string{"transport": "kernel", "syslog_identifier": "kernel", "priority": "3"}
	app := map[string]string{"unit": "app.service", "syslog_identifier": "app", "transport": "stdout", "priority": "3"}
	appInfo := map[string]string{"unit": "app.service", "syslog_identifier": "app", "transport": "stdout", "priority": "6"}
	return []fixture{
		{id: "log.process_failure", target: k8s, warmup: 5 * time.Minute, badFor: 3 * time.Minute,
			lines: func(_ time.Duration, bad bool) []line {
				if bad {
					return append(repeatLine(1, workload, "panic: runtime error: invalid memory address or nil pointer dereference"), info...)
				}
				return append(repeatLine(1, workload, `level=error msg="payment declined"`), info...)
			},
			labels: map[string]string{"namespace": "shop", "workload": "web", "workload_kind": "Deployment", "container": "app"}},
		{id: "log.error_rate_spike", target: k8s, warmup: 5 * time.Minute, badFor: 15 * time.Minute,
			lines: func(_ time.Duration, bad bool) []line {
				n := 1
				if bad {
					n = 15
				}
				return append(repeatLine(n, workload, `level=error msg="database timeout"`), info...)
			},
			labels: map[string]string{"namespace": "shop", "workload": "web"}},
		{id: "log.severity_mix_shift", target: k8s, warmup: 5 * time.Minute, badFor: 25 * time.Minute,
			lines: func(_ time.Duration, bad bool) []line {
				n := 1
				if bad {
					n = 10
				}
				return append(repeatLine(n, workload, `{"level":"warn","msg":"slow upstream response"}`), info...)
			},
			labels: map[string]string{"workload": "web"}},
		{id: "log.new_fingerprint_burst", target: k8s, warmup: 5 * time.Minute, badFor: 15 * time.Minute,
			lines: func(_ time.Duration, bad bool) []line {
				var out []line
				for _, p := range patterns {
					out = append(out, line{labels: workload, text: p + " in 12ms"})
				}
				if bad {
					burst++
					out = append(out, line{labels: workload, text: "unexpected " + letters(burst) + " state reached"})
				}
				return out
			},
			labels: map[string]string{"workload": "web"}},
		{id: "log.dominant_fingerprint", target: k8s, warmup: 5 * time.Minute, badFor: 35 * time.Minute,
			lines: func(_ time.Duration, bad bool) []line {
				var out []line
				for i := range 10 {
					out = append(out, repeatLine(2, workload, "worker "+letters(i)+" finished batch")...)
				}
				if bad {
					out = append(out, repeatLine(20, workload, "health check passed for upstream")...)
				}
				return out
			},
			labels: map[string]string{"workload": "web"}},
		{id: "host.log.oom_kill", target: host, warmup: 5 * time.Minute, badFor: 2 * time.Minute,
			lines: func(t time.Duration, bad bool) []line {
				if bad && t%time.Minute == 0 {
					return []line{{labels: kernel, text: "Out of memory: Killed process 4242 (java) total-vm:8123456kB, anon-rss:4000000kB"}}
				}
				return []line{{labels: kernel, text: "eth0: renamed from veth12ab"}}
			},
			labels: map[string]string{"syslog_identifier": "kernel"}},
		{id: "host.log.process_failure", target: host, warmup: 5 * time.Minute, badFor: 2 * time.Minute,
			lines: func(_ time.Duration, bad bool) []line {
				if bad {
					return []line{{labels: kernel, text: "app[1234]: segfault at 0 ip 00007f3a sp 00007ffd error 4 in libc.so.6"}}
				}
				return []line{{labels: appInfo, text: "Started app.service"}}
			},
			labels: map[string]string{"syslog_identifier": "kernel"}},
		{id: "host.log.error_rate_spike", target: host, warmup: 5 * time.Minute, badFor: 15 * time.Minute,
			lines: func(t time.Duration, bad bool) []line {
				out := repeatLine(10, appInfo, "request handled")
				switch {
				case bad:
					out = append(out, repeatLine(10, app, "cannot reach database")...)
				case t%time.Minute == 0:
					out = append(out, repeatLine(1, app, "cannot reach database")...)
				}
				return out
			},
			labels: map[string]string{"unit": "app.service", "syslog_identifier": "app"}},
	}
}

func fixtures() []fixture {
	var out []fixture
	out = append(out, stateFixtures()...)
	out = append(out, promFixtures()...)
	out = append(out, logFixtures()...)
	return out
}
