package e2e

// bundleFiles is the compact test bundle: one rule of every class the roles split between them.
var bundleFiles = map[string]string{
	"bundle.yaml": `version: "` + version + `"
engine_version: 1
schema_version: 1
target_type: kubernetes
created_at: 2026-09-01T00:00:00Z
rules:
  - id: deploy-bad-image
    version: 1
    class: state
    target: kubernetes
    scope: cluster
    category: change
    severity: high
    capabilities: [inventory]
    dedup_key: kind,namespace,name
    summary: "Deployment {{ $labels.namespace }}/{{ $labels.name }} runs a forbidden image"
  - id: mem-near-limit
    version: 1
    class: promql
    target: kubernetes
    scope: node
    file: prometheus/node.yaml
    group: node
    alert: MemNearLimit
    category: metric.saturation
    severity: high
    capabilities: [metrics]
    dedup_key: namespace,pod,container
    resource_labels: {kind: Pod, namespace: namespace, name: pod}
    summary: "Container {{ $labels.namespace }}/{{ $labels.pod }}/{{ $labels.container }} uses more than 90% of its memory limit"
  - id: cluster-cpu
    version: 1
    class: promql
    target: kubernetes
    scope: cluster
    file: prometheus/cluster.yaml
    group: cluster
    alert: NamespaceCPUHigh
    category: metric.saturation
    severity: medium
    capabilities: [metrics]
    dedup_key: namespace
    summary: "Namespace {{ $labels.namespace }} uses more than one core across the cluster"
  - id: app-errors
    version: 1
    class: logql
    target: kubernetes
    scope: node
    file: loki/app.yaml
    group: app
    alert: AppErrors
    category: log.errors
    severity: high
    capabilities: [logs]
    dedup_key: namespace,pod,container
    resource_labels: {kind: Pod, namespace: namespace, name: pod}
    budget: {max_series: 100}
    evidence: {max_samples: 5}
    summary: "{{ $labels.namespace }}/{{ $labels.pod }} container {{ $labels.container }} logs errors"
`,
	"state/deployments.yaml": `- id: deploy-bad-image
  version: 1
  target: kubernetes
  kinds: [apps/Deployment]
  interval: 10s
  expr: 'field(r, "containers.app.image", "") == "nginx:bad"'
`,
	"prometheus/node.yaml": `groups:
  - name: node
    interval: 10s
    rules:
      - alert: MemNearLimit
        expr: container_memory_working_set_bytes{container!=""} / on (namespace, pod, container) kube_pod_container_resource_limits{resource="memory"} > 0.9
`,
	"prometheus/cluster.yaml": `groups:
  - name: cluster
    interval: 10s
    rules:
      - alert: NamespaceCPUHigh
        expr: sum by (namespace) (rate(container_cpu_usage_seconds_total{container!=""}[5m])) > 1
`,
	"loki/app.yaml": `groups:
  - name: app
    interval: 10s
    rules:
      - alert: AppErrors
        expr: sum by (namespace, pod, container) (count_over_time({namespace="shop", container="app"} |= "ERROR" [1m])) > 1
`,
}
