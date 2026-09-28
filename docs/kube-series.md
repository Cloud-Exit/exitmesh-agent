# Published kube_* series

Generated from `internal/state/kubeseries.go` by `go test ./internal/state -run TestGeneratedDocs -update`. Do not edit by hand.

The coordinator synthesizes these series from its normalized informer state with kube-state-metrics v2 names, labels, and value semantics. Customer kube-state-metrics is never a dependency. Rules referencing any other `kube_*` series are rejected at bundle validation. Labels with empty values are omitted. Resource labels are sanitized (`nvidia.com/gpu` becomes `nvidia_com_gpu`) with unit `core` for CPU, `byte` for memory, storage, and huge pages, and `integer` for pods and extended resources.

Node-scoped subset: every `kube_pod_*` series of pods whose `node` in `kube_pod_info` is the node, plus that node's `kube_node_*` series. Node agents derive the pod-scoped series from their own pod watch with the same synthesis, so both sides produce identical series.

|Series|Kind|Labels|Source|
|---|---|---|---|
|`kube_pod_info`|Pod|`namespace`, `pod`, `uid`, `host_ip`, `pod_ip`, `node`, `created_by_kind`, `created_by_name`, `priority_class`, `host_network`|hostIP, podIP, nodeName, controller owner, priorityClassName, hostNetwork; value 1|
|`kube_pod_status_phase`|Pod|`namespace`, `pod`, `uid`, `phase`|phase; 1 for the current phase, 0 for Pending, Running, Succeeded, Failed, Unknown otherwise|
|`kube_pod_status_ready`|Pod|`namespace`, `pod`, `uid`, `condition`|conditions.Ready.status; condition true, false, unknown with 1 for the current status|
|`kube_pod_container_info`|Pod|`namespace`, `pod`, `uid`, `container`, `image_spec`, `image`, `image_id`|containers.<container>.image and imageID; value 1|
|`kube_pod_container_status_restarts_total`|Pod|`namespace`, `pod`, `uid`, `container`|containers.<container>.restarts|
|`kube_pod_container_status_waiting_reason`|Pod|`namespace`, `pod`, `uid`, `container`, `reason`|containers.<container>.waitingReason; value 1 while waiting|
|`kube_pod_container_status_last_terminated_reason`|Pod|`namespace`, `pod`, `uid`, `container`, `reason`|containers.<container>.lastTerminatedReason; value 1|
|`kube_pod_container_resource_requests`|Pod|`namespace`, `pod`, `uid`, `container`, `node`, `resource`, `unit`|containers.<container>.requests.<resource>|
|`kube_pod_container_resource_limits`|Pod|`namespace`, `pod`, `uid`, `container`, `node`, `resource`, `unit`|containers.<container>.limits.<resource>|
|`kube_pod_owner`|Pod|`namespace`, `pod`, `uid`, `owner_kind`, `owner_name`, `owner_is_controller`|owners.<kind>.<name>; one series per owner, <none> without owners; value 1|
|`kube_node_info`|Node|`node`, `kernel_version`, `os_image`, `container_runtime_version`, `kubelet_version`, `provider_id`, `pod_cidr`, `internal_ip`|nodeInfo, providerID, podCIDR, internalIP; value 1|
|`kube_node_status_condition`|Node|`node`, `condition`, `status`|conditions.<type>.status; status true, false, unknown with 1 for the current status|
|`kube_node_status_capacity`|Node|`node`, `resource`, `unit`|capacity.<resource>|
|`kube_node_status_allocatable`|Node|`node`, `resource`, `unit`|allocatable.<resource>|
|`kube_node_spec_unschedulable`|Node|`node`|unschedulable as 0 or 1|
|`kube_deployment_spec_replicas`|apps/Deployment|`namespace`, `deployment`|replicas|
|`kube_deployment_status_replicas_available`|apps/Deployment|`namespace`, `deployment`|availableReplicas|
|`kube_deployment_status_replicas_unavailable`|apps/Deployment|`namespace`, `deployment`|unavailableReplicas|
|`kube_statefulset_replicas`|apps/StatefulSet|`namespace`, `statefulset`|replicas|
|`kube_statefulset_status_replicas_ready`|apps/StatefulSet|`namespace`, `statefulset`|readyReplicas|
|`kube_daemonset_status_desired_number_scheduled`|apps/DaemonSet|`namespace`, `daemonset`|desiredNumberScheduled|
|`kube_daemonset_status_number_ready`|apps/DaemonSet|`namespace`, `daemonset`|numberReady|
|`kube_job_status_failed`|batch/Job|`namespace`, `job_name`|failed|
|`kube_persistentvolumeclaim_status_phase`|PersistentVolumeClaim|`namespace`, `persistentvolumeclaim`, `phase`|phase; 1 for the current phase, 0 for Pending, Bound, Lost otherwise|
|`kube_persistentvolumeclaim_resource_requests_storage_bytes`|PersistentVolumeClaim|`namespace`, `persistentvolumeclaim`|requests.storage|
|`kube_persistentvolumeclaim_info`|PersistentVolumeClaim|`namespace`, `persistentvolumeclaim`, `storageclass`, `volumename`, `volumemode`|storageClassName, volumeName, volumeMode; value 1|
