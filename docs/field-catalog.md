# Field catalog

Generated from `internal/state/catalog.go` by `go test ./internal/state -run TestGeneratedDocs -update`. Do not edit by hand.

Catalog schema: 1.

Every exported field of a normalized resource is listed here. Fields not marked default are exported only when selected deliberately (normalizer option `Fields` as `<kind>:<path>`). Field keys are flat; placeholders in angle brackets stand for one key segment (`<container>`, `<type>`, `<kind>`, `<reason>`) or the rest of the key (`<resource>`, `<key>`, `<name>`). Absent keys mean unset or empty. Lists whose order is not meaningful are sorted. Quantities are floats in base units: CPU in cores, memory and storage in bytes. Timestamps are integer milliseconds since the Unix epoch. Heartbeat timestamps, `resourceVersion`, `managedFields`, condition messages, ConfigMap values, Secret contents, and environment variable values are never exported.

## Redaction classes

|Class|Meaning|
|---|---|
|structural|API enumerations, numbers, and addresses, exported as is.|
|reference|Object and key names; the referenced values are never read or exported.|
|text|Free text; every value passes through `internal/redact` (credentials in URLs, tokens, key=value secrets).|
|allowlist|Exported only for keys matching the configured allowlist; values pass through `internal/redact`.|

## Allowlists

Labels (`kubernetes.labelAllowlist`, a trailing `*` matches a prefix), default:

- `app.kubernetes.io/name`
- `app.kubernetes.io/instance`
- `app.kubernetes.io/component`
- `app.kubernetes.io/managed-by`
- `helm.sh/chart`
- `app.kubernetes.io/part-of`
- `app.kubernetes.io/version`
- `app`
- `k8s-app`
- `topology.kubernetes.io/zone`
- `topology.kubernetes.io/region`
- `node-role.kubernetes.io/*`

Annotations (`kubernetes.annotationAllowlist`): Helm release name and namespace by default; Secret annotations are always omitted.

Custom resources discovered from CRDs use projection version 1: identity, allowlisted metadata, generation, observed generation, and bounded conditions (type, status, redacted reason, observed generation). Arbitrary spec/status fields are omitted. ExternalSecret additionally exports its target Secret and SecretStore references. Helm revisions are represented by Secret or ConfigMap storage objects with `helm.name`, `helm.revision`, and `helm.status`; the greatest revision for a namespace/name is the latest release. Secret data and stringData keys are retained with constant redacted values before caching or export; Helm release payloads are never decoded.

## Scopes

Scope keys are `<kind>|<namespace>`, with an empty namespace for cluster-wide collection. Permission loss and collection failure set the scope unavailable; they never delete resources. Scope removal deletes with reason scope removed.

## Edges

|Type|From|To|Attributes|
|---|---|---|---|
|`needs-secret-sync`|workload|ExternalSecret targeting a referenced Secret|none; exists even when the Secret is missing|
|`uses-secret`|workload|Secret referenced by its pod spec|none|
|`produces-secret`|ExternalSecret|Secret named by spec.target.name|none|
|`owns`|owner (ownerReferences[].uid)|owned object|`controller` (bool)|
|`runs-on`|Pod|Node (by spec.nodeName)|none|
|`selects`|Service|Pod (spec.selector within the namespace)|`ports`: sorted port names, or port/protocol when unnamed|
|`mounts`|Pod|PersistentVolumeClaim (volumes, ephemeral claims)|none|
|`binds`|PersistentVolumeClaim|PersistentVolume (spec.volumeName)|none|
|`routes`|networking.k8s.io/Ingress|Service (backends)|`ports`: sorted backend ports|
|`targets`|networking.k8s.io/NetworkPolicy|Pod (spec.podSelector within the namespace)|none|
|`scales`|autoscaling/HorizontalPodAutoscaler|scale target (spec.scaleTargetRef)|none|
|`guards`|policy/PodDisruptionBudget|Pod (spec.selector within the namespace)|none|

An edge exists only while both endpoints are in state.

## ConfigMap

API: `v1` `configmaps`, namespaced, metadata-only informer by default.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`keys`|data and binaryData key names (never values; selecting it replaces the metadata-only informer)|list<string>|reference|no|
|`helm.name`|metadata.labels.name when owner=helm|string|reference|yes|
|`helm.revision`|metadata.labels.version when owner=helm|int|structural|yes|
|`helm.status`|metadata.labels.status when owner=helm|string|structural|yes|

## Event

API: `v1` `events`, namespaced, not exported as a resource: aggregated onto the involved object (Normal events are ignored).

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`events.warning.<reason>`|Warning events per involvedObject.uid and reason: occurrences within the sliding window, set on the involved object|int|structural|yes|

## Namespace

API: `v1` `namespaces`, cluster.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`phase`|status.phase|string|structural|yes|

## Node

API: `v1` `nodes`, cluster.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`capacity.<resource>`|status.capacity (cpu in cores, others in base units)|quantity|structural|yes|
|`allocatable.<resource>`|status.allocatable (cpu in cores, others in base units)|quantity|structural|yes|
|`taints`|spec.taints[] as key=value:Effect|list<string>|structural|yes|
|`unschedulable`|spec.unschedulable|bool|structural|yes|
|`kubeletVersion`|status.nodeInfo.kubeletVersion|string|structural|yes|
|`containerRuntimeVersion`|status.nodeInfo.containerRuntimeVersion|string|structural|yes|
|`osImage`|status.nodeInfo.osImage|string|structural|yes|
|`kernelVersion`|status.nodeInfo.kernelVersion|string|structural|yes|
|`architecture`|status.nodeInfo.architecture|string|structural|yes|
|`operatingSystem`|status.nodeInfo.operatingSystem|string|structural|yes|
|`providerID`|spec.providerID|string|structural|yes|
|`podCIDR`|spec.podCIDR|string|structural|yes|
|`internalIP`|status.addresses[type=InternalIP].address|string|structural|yes|
|`zone`|metadata.labels[topology.kubernetes.io/zone]|string|structural|yes|
|`region`|metadata.labels[topology.kubernetes.io/region]|string|structural|yes|
|`conditions.<type>.status`|status.conditions[type in any type].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in any type].reason|string|text|yes|

## PersistentVolume

API: `v1` `persistentvolumes`, cluster.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`phase`|status.phase|string|structural|yes|
|`storageClassName`|spec.storageClassName|string|reference|yes|
|`capacity.storage`|spec.capacity.storage (bytes)|quantity|structural|yes|
|`accessModes`|spec.accessModes|list<string>|structural|yes|
|`reclaimPolicy`|spec.persistentVolumeReclaimPolicy|string|structural|yes|
|`volumeMode`|spec.volumeMode|string|structural|yes|
|`claim`|spec.claimRef as namespace/name|string|reference|yes|
|`driver`|spec.csi.driver or the in-tree volume source name|string|structural|yes|
|`nodeAffinity`|spec.nodeAffinity.required as canonical terms|string|text|yes|

## PersistentVolumeClaim

API: `v1` `persistentvolumeclaims`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`phase`|status.phase|string|structural|yes|
|`storageClassName`|spec.storageClassName|string|reference|yes|
|`accessModes`|spec.accessModes|list<string>|structural|yes|
|`requests.storage`|spec.resources.requests.storage (bytes)|quantity|structural|yes|
|`capacity.storage`|status.capacity.storage (bytes)|quantity|structural|yes|
|`volumeName`|spec.volumeName|string|reference|yes|
|`volumeMode`|spec.volumeMode|string|structural|yes|
|`conditions.<type>.status`|status.conditions[type in Resizing, FileSystemResizePending, ModifyingVolume, ModifyVolumeError].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in Resizing, FileSystemResizePending, ModifyingVolume, ModifyVolumeError].reason|string|text|yes|

## Pod

API: `v1` `pods`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`phase`|status.phase|string|structural|yes|
|`reason`|status.reason|string|text|yes|
|`nodeName`|spec.nodeName|string|reference|yes|
|`hostIP`|status.hostIP|string|structural|yes|
|`podIP`|status.podIP|string|structural|yes|
|`qosClass`|status.qosClass|string|structural|yes|
|`priorityClassName`|spec.priorityClassName|string|reference|yes|
|`hostNetwork`|spec.hostNetwork|bool|structural|yes|
|`ready`|status.conditions[type=Ready].status|bool|structural|yes|
|`conditions.<type>.status`|status.conditions[type in PodScheduled, PodReadyToStartContainers, Initialized, ContainersReady, Ready, DisruptionTarget].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in PodScheduled, PodReadyToStartContainers, Initialized, ContainersReady, Ready, DisruptionTarget].reason|string|text|yes|
|`containers.<container>.image`|spec.containers[].image|string|structural|yes|
|`containers.<container>.requests.<resource>`|spec.containers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.limits.<resource>`|spec.containers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.ports`|spec.containers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`containers.<container>.envRefs`|spec.containers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`containers.<container>.envFrom`|spec.containers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`containers.<container>.command`|spec.containers[].command|list<string>|text|no|
|`containers.<container>.args`|spec.containers[].args|list<string>|text|no|
|`containers.<container>.imageID`|status.containerStatuses[].imageID (digest reference)|string|structural|yes|
|`containers.<container>.ready`|status.containerStatuses[].ready|bool|structural|yes|
|`containers.<container>.restarts`|status.containerStatuses[].restartCount|int|structural|yes|
|`containers.<container>.state`|status.containerStatuses[].state (waiting, running, or terminated)|string|structural|yes|
|`containers.<container>.waitingReason`|status.containerStatuses[].state.waiting.reason|string|text|yes|
|`containers.<container>.terminatedReason`|status.containerStatuses[].state.terminated.reason|string|text|yes|
|`containers.<container>.terminatedExitCode`|status.containerStatuses[].state.terminated.exitCode|int|structural|yes|
|`containers.<container>.lastTerminatedReason`|status.containerStatuses[].lastState.terminated.reason|string|text|yes|
|`containers.<container>.lastTerminatedExitCode`|status.containerStatuses[].lastState.terminated.exitCode|int|structural|yes|
|`initContainers.<container>.image`|spec.initContainers[].image|string|structural|yes|
|`initContainers.<container>.requests.<resource>`|spec.initContainers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.limits.<resource>`|spec.initContainers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.ports`|spec.initContainers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`initContainers.<container>.envRefs`|spec.initContainers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`initContainers.<container>.envFrom`|spec.initContainers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`initContainers.<container>.command`|spec.initContainers[].command|list<string>|text|no|
|`initContainers.<container>.args`|spec.initContainers[].args|list<string>|text|no|
|`initContainers.<container>.imageID`|status.initContainerStatuses[].imageID (digest reference)|string|structural|yes|
|`initContainers.<container>.ready`|status.initContainerStatuses[].ready|bool|structural|yes|
|`initContainers.<container>.restarts`|status.initContainerStatuses[].restartCount|int|structural|yes|
|`initContainers.<container>.state`|status.initContainerStatuses[].state (waiting, running, or terminated)|string|structural|yes|
|`initContainers.<container>.waitingReason`|status.initContainerStatuses[].state.waiting.reason|string|text|yes|
|`initContainers.<container>.terminatedReason`|status.initContainerStatuses[].state.terminated.reason|string|text|yes|
|`initContainers.<container>.terminatedExitCode`|status.initContainerStatuses[].state.terminated.exitCode|int|structural|yes|
|`initContainers.<container>.lastTerminatedReason`|status.initContainerStatuses[].lastState.terminated.reason|string|text|yes|
|`initContainers.<container>.lastTerminatedExitCode`|status.initContainerStatuses[].lastState.terminated.exitCode|int|structural|yes|
|`serviceAccountName`|spec.serviceAccountName|string|reference|yes|
|`refs.configMaps`|spec volumes, projected sources, env and envFrom ConfigMap names|list<string>|reference|yes|
|`refs.secrets`|spec volumes, projected sources, env, envFrom, and imagePullSecrets Secret names|list<string>|reference|yes|
|`refs.claims`|spec.volumes[].persistentVolumeClaim.claimName and ephemeral claim names|list<string>|reference|yes|

## Secret

API: `v1` `secrets`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`apiVersion`|apiVersion|string|structural|yes|
|`type`|type|string|structural|yes|
|`immutable`|immutable|bool|structural|yes|
|`data.<key>`|data keys with values replaced by a constant redaction marker|string|structural|yes|
|`stringData.<key>`|stringData keys with values replaced by a constant redaction marker|string|structural|yes|
|`helm.name`|metadata.labels.name when owner=helm|string|reference|yes|
|`helm.revision`|metadata.labels.version when owner=helm|int|structural|yes|
|`helm.status`|metadata.labels.status when owner=helm|string|structural|yes|

## Service

API: `v1` `services`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`type`|spec.type|string|structural|yes|
|`clusterIP`|spec.clusterIP|string|structural|yes|
|`ports`|spec.ports[] as name:port/protocol->targetPort|list<string>|structural|yes|
|`hasSelector`|spec.selector is non-empty|bool|structural|yes|
|`selector`|spec.selector as a canonical selector|string|text|no|
|`sessionAffinity`|spec.sessionAffinity|string|structural|yes|
|`externalTrafficPolicy`|spec.externalTrafficPolicy|string|structural|yes|
|`internalTrafficPolicy`|spec.internalTrafficPolicy|string|structural|yes|
|`externalName`|spec.externalName|string|text|no|
|`loadBalancerIngress`|status.loadBalancer.ingress[] ip or hostname|list<string>|structural|no|

## apiextensions.k8s.io/CustomResourceDefinition

API: `apiextensions.k8s.io/v1` `customresourcedefinitions`, cluster.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`generation`|metadata.generation|int|structural|yes|
|`observedGeneration`|status.observedGeneration|int|structural|yes|
|`conditions.<type>.status`|status.conditions[type in any type].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in any type].reason|string|text|yes|
|`apiVersion`|apiVersion|string|structural|yes|
|`projectionVersion`|generic custom-resource projection version|int|structural|yes|
|`conditions.<type>.observedGeneration`|status.conditions[].observedGeneration|int|structural|yes|
|`crd.group`|CustomResourceDefinition spec.group|string|structural|yes|
|`crd.kind`|CustomResourceDefinition spec.names.kind|string|structural|yes|
|`crd.plural`|CustomResourceDefinition spec.names.plural|string|structural|yes|
|`crd.scope`|CustomResourceDefinition spec.scope|string|structural|yes|
|`crd.servedVersions`|CustomResourceDefinition spec.versions[].name where served|list<string>|structural|yes|

## apps/DaemonSet

API: `apps/v1` `daemonsets`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`updateStrategy`|spec.updateStrategy.type|string|structural|yes|
|`desiredNumberScheduled`|status.desiredNumberScheduled|int|structural|yes|
|`currentNumberScheduled`|status.currentNumberScheduled|int|structural|yes|
|`numberReady`|status.numberReady|int|structural|yes|
|`numberAvailable`|status.numberAvailable|int|structural|yes|
|`numberUnavailable`|status.numberUnavailable|int|structural|yes|
|`numberMisscheduled`|status.numberMisscheduled|int|structural|yes|
|`updatedNumberScheduled`|status.updatedNumberScheduled|int|structural|yes|
|`generation`|metadata.generation|int|structural|yes|
|`observedGeneration`|status.observedGeneration|int|structural|yes|
|`containers.<container>.image`|spec.template.spec.containers[].image|string|structural|yes|
|`containers.<container>.requests.<resource>`|spec.template.spec.containers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.limits.<resource>`|spec.template.spec.containers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.ports`|spec.template.spec.containers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`containers.<container>.envRefs`|spec.template.spec.containers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`containers.<container>.envFrom`|spec.template.spec.containers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`containers.<container>.command`|spec.template.spec.containers[].command|list<string>|text|no|
|`containers.<container>.args`|spec.template.spec.containers[].args|list<string>|text|no|
|`initContainers.<container>.image`|spec.template.spec.initContainers[].image|string|structural|yes|
|`initContainers.<container>.requests.<resource>`|spec.template.spec.initContainers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.limits.<resource>`|spec.template.spec.initContainers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.ports`|spec.template.spec.initContainers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`initContainers.<container>.envRefs`|spec.template.spec.initContainers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`initContainers.<container>.envFrom`|spec.template.spec.initContainers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`initContainers.<container>.command`|spec.template.spec.initContainers[].command|list<string>|text|no|
|`initContainers.<container>.args`|spec.template.spec.initContainers[].args|list<string>|text|no|
|`serviceAccountName`|spec.template.spec.serviceAccountName|string|reference|yes|
|`refs.configMaps`|spec.template.spec volumes, projected sources, env and envFrom ConfigMap names|list<string>|reference|yes|
|`refs.secrets`|spec.template.spec volumes, projected sources, env, envFrom, and imagePullSecrets Secret names|list<string>|reference|yes|
|`refs.claims`|spec.template.spec.volumes[].persistentVolumeClaim.claimName and ephemeral claim names|list<string>|reference|yes|

## apps/Deployment

API: `apps/v1` `deployments`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`replicas`|spec.replicas (default 1)|int|structural|yes|
|`paused`|spec.paused|bool|structural|yes|
|`strategy`|spec.strategy.type|string|structural|yes|
|`statusReplicas`|status.replicas|int|structural|yes|
|`readyReplicas`|status.readyReplicas|int|structural|yes|
|`availableReplicas`|status.availableReplicas|int|structural|yes|
|`updatedReplicas`|status.updatedReplicas|int|structural|yes|
|`unavailableReplicas`|status.unavailableReplicas|int|structural|yes|
|`generation`|metadata.generation|int|structural|yes|
|`observedGeneration`|status.observedGeneration|int|structural|yes|
|`conditions.<type>.status`|status.conditions[type in Available, Progressing, ReplicaFailure].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in Available, Progressing, ReplicaFailure].reason|string|text|yes|
|`containers.<container>.image`|spec.template.spec.containers[].image|string|structural|yes|
|`containers.<container>.requests.<resource>`|spec.template.spec.containers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.limits.<resource>`|spec.template.spec.containers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.ports`|spec.template.spec.containers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`containers.<container>.envRefs`|spec.template.spec.containers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`containers.<container>.envFrom`|spec.template.spec.containers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`containers.<container>.command`|spec.template.spec.containers[].command|list<string>|text|no|
|`containers.<container>.args`|spec.template.spec.containers[].args|list<string>|text|no|
|`initContainers.<container>.image`|spec.template.spec.initContainers[].image|string|structural|yes|
|`initContainers.<container>.requests.<resource>`|spec.template.spec.initContainers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.limits.<resource>`|spec.template.spec.initContainers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.ports`|spec.template.spec.initContainers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`initContainers.<container>.envRefs`|spec.template.spec.initContainers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`initContainers.<container>.envFrom`|spec.template.spec.initContainers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`initContainers.<container>.command`|spec.template.spec.initContainers[].command|list<string>|text|no|
|`initContainers.<container>.args`|spec.template.spec.initContainers[].args|list<string>|text|no|
|`serviceAccountName`|spec.template.spec.serviceAccountName|string|reference|yes|
|`refs.configMaps`|spec.template.spec volumes, projected sources, env and envFrom ConfigMap names|list<string>|reference|yes|
|`refs.secrets`|spec.template.spec volumes, projected sources, env, envFrom, and imagePullSecrets Secret names|list<string>|reference|yes|
|`refs.claims`|spec.template.spec.volumes[].persistentVolumeClaim.claimName and ephemeral claim names|list<string>|reference|yes|

## apps/ReplicaSet

API: `apps/v1` `replicasets`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`replicas`|spec.replicas (default 1)|int|structural|yes|
|`statusReplicas`|status.replicas|int|structural|yes|
|`readyReplicas`|status.readyReplicas|int|structural|yes|
|`availableReplicas`|status.availableReplicas|int|structural|yes|
|`generation`|metadata.generation|int|structural|yes|
|`observedGeneration`|status.observedGeneration|int|structural|yes|
|`conditions.<type>.status`|status.conditions[type in ReplicaFailure].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in ReplicaFailure].reason|string|text|yes|
|`containers.<container>.image`|spec.template.spec.containers[].image|string|structural|yes|
|`containers.<container>.requests.<resource>`|spec.template.spec.containers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.limits.<resource>`|spec.template.spec.containers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.ports`|spec.template.spec.containers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`containers.<container>.envRefs`|spec.template.spec.containers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`containers.<container>.envFrom`|spec.template.spec.containers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`containers.<container>.command`|spec.template.spec.containers[].command|list<string>|text|no|
|`containers.<container>.args`|spec.template.spec.containers[].args|list<string>|text|no|
|`initContainers.<container>.image`|spec.template.spec.initContainers[].image|string|structural|yes|
|`initContainers.<container>.requests.<resource>`|spec.template.spec.initContainers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.limits.<resource>`|spec.template.spec.initContainers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.ports`|spec.template.spec.initContainers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`initContainers.<container>.envRefs`|spec.template.spec.initContainers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`initContainers.<container>.envFrom`|spec.template.spec.initContainers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`initContainers.<container>.command`|spec.template.spec.initContainers[].command|list<string>|text|no|
|`initContainers.<container>.args`|spec.template.spec.initContainers[].args|list<string>|text|no|
|`serviceAccountName`|spec.template.spec.serviceAccountName|string|reference|yes|
|`refs.configMaps`|spec.template.spec volumes, projected sources, env and envFrom ConfigMap names|list<string>|reference|yes|
|`refs.secrets`|spec.template.spec volumes, projected sources, env, envFrom, and imagePullSecrets Secret names|list<string>|reference|yes|
|`refs.claims`|spec.template.spec.volumes[].persistentVolumeClaim.claimName and ephemeral claim names|list<string>|reference|yes|

## apps/StatefulSet

API: `apps/v1` `statefulsets`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`replicas`|spec.replicas (default 1)|int|structural|yes|
|`serviceName`|spec.serviceName|string|reference|yes|
|`podManagementPolicy`|spec.podManagementPolicy|string|structural|yes|
|`updateStrategy`|spec.updateStrategy.type|string|structural|yes|
|`statusReplicas`|status.replicas|int|structural|yes|
|`readyReplicas`|status.readyReplicas|int|structural|yes|
|`availableReplicas`|status.availableReplicas|int|structural|yes|
|`currentReplicas`|status.currentReplicas|int|structural|yes|
|`updatedReplicas`|status.updatedReplicas|int|structural|yes|
|`currentRevision`|status.currentRevision|string|structural|yes|
|`updateRevision`|status.updateRevision|string|structural|yes|
|`generation`|metadata.generation|int|structural|yes|
|`observedGeneration`|status.observedGeneration|int|structural|yes|
|`containers.<container>.image`|spec.template.spec.containers[].image|string|structural|yes|
|`containers.<container>.requests.<resource>`|spec.template.spec.containers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.limits.<resource>`|spec.template.spec.containers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.ports`|spec.template.spec.containers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`containers.<container>.envRefs`|spec.template.spec.containers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`containers.<container>.envFrom`|spec.template.spec.containers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`containers.<container>.command`|spec.template.spec.containers[].command|list<string>|text|no|
|`containers.<container>.args`|spec.template.spec.containers[].args|list<string>|text|no|
|`initContainers.<container>.image`|spec.template.spec.initContainers[].image|string|structural|yes|
|`initContainers.<container>.requests.<resource>`|spec.template.spec.initContainers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.limits.<resource>`|spec.template.spec.initContainers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.ports`|spec.template.spec.initContainers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`initContainers.<container>.envRefs`|spec.template.spec.initContainers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`initContainers.<container>.envFrom`|spec.template.spec.initContainers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`initContainers.<container>.command`|spec.template.spec.initContainers[].command|list<string>|text|no|
|`initContainers.<container>.args`|spec.template.spec.initContainers[].args|list<string>|text|no|
|`serviceAccountName`|spec.template.spec.serviceAccountName|string|reference|yes|
|`refs.configMaps`|spec.template.spec volumes, projected sources, env and envFrom ConfigMap names|list<string>|reference|yes|
|`refs.secrets`|spec.template.spec volumes, projected sources, env, envFrom, and imagePullSecrets Secret names|list<string>|reference|yes|
|`refs.claims`|spec.template.spec.volumes[].persistentVolumeClaim.claimName and ephemeral claim names|list<string>|reference|yes|

## autoscaling/HorizontalPodAutoscaler

API: `autoscaling/v2` `horizontalpodautoscalers`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`target.kind`|spec.scaleTargetRef apiVersion and kind as a protocol kind|string|reference|yes|
|`target.name`|spec.scaleTargetRef.name|string|reference|yes|
|`minReplicas`|spec.minReplicas (default 1)|int|structural|yes|
|`maxReplicas`|spec.maxReplicas|int|structural|yes|
|`currentReplicas`|status.currentReplicas|int|structural|yes|
|`desiredReplicas`|status.desiredReplicas|int|structural|yes|
|`metrics`|spec.metrics[] as type:name|list<string>|structural|yes|
|`conditions.<type>.status`|status.conditions[type in AbleToScale, ScalingActive, ScalingLimited].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in AbleToScale, ScalingActive, ScalingLimited].reason|string|text|yes|

## batch/CronJob

API: `batch/v1` `cronjobs`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`schedule`|spec.schedule|string|structural|yes|
|`timeZone`|spec.timeZone|string|structural|yes|
|`suspend`|spec.suspend|bool|structural|yes|
|`concurrencyPolicy`|spec.concurrencyPolicy|string|structural|yes|
|`active`|len(status.active)|int|structural|yes|
|`lastScheduleTime`|status.lastScheduleTime|timestamp|structural|no|
|`lastSuccessfulTime`|status.lastSuccessfulTime|timestamp|structural|no|
|`containers.<container>.image`|spec.jobTemplate.spec.template.spec.containers[].image|string|structural|yes|
|`containers.<container>.requests.<resource>`|spec.jobTemplate.spec.template.spec.containers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.limits.<resource>`|spec.jobTemplate.spec.template.spec.containers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.ports`|spec.jobTemplate.spec.template.spec.containers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`containers.<container>.envRefs`|spec.jobTemplate.spec.template.spec.containers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`containers.<container>.envFrom`|spec.jobTemplate.spec.template.spec.containers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`containers.<container>.command`|spec.jobTemplate.spec.template.spec.containers[].command|list<string>|text|no|
|`containers.<container>.args`|spec.jobTemplate.spec.template.spec.containers[].args|list<string>|text|no|
|`initContainers.<container>.image`|spec.jobTemplate.spec.template.spec.initContainers[].image|string|structural|yes|
|`initContainers.<container>.requests.<resource>`|spec.jobTemplate.spec.template.spec.initContainers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.limits.<resource>`|spec.jobTemplate.spec.template.spec.initContainers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.ports`|spec.jobTemplate.spec.template.spec.initContainers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`initContainers.<container>.envRefs`|spec.jobTemplate.spec.template.spec.initContainers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`initContainers.<container>.envFrom`|spec.jobTemplate.spec.template.spec.initContainers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`initContainers.<container>.command`|spec.jobTemplate.spec.template.spec.initContainers[].command|list<string>|text|no|
|`initContainers.<container>.args`|spec.jobTemplate.spec.template.spec.initContainers[].args|list<string>|text|no|
|`serviceAccountName`|spec.jobTemplate.spec.template.spec.serviceAccountName|string|reference|yes|
|`refs.configMaps`|spec.jobTemplate.spec.template.spec volumes, projected sources, env and envFrom ConfigMap names|list<string>|reference|yes|
|`refs.secrets`|spec.jobTemplate.spec.template.spec volumes, projected sources, env, envFrom, and imagePullSecrets Secret names|list<string>|reference|yes|
|`refs.claims`|spec.jobTemplate.spec.template.spec.volumes[].persistentVolumeClaim.claimName and ephemeral claim names|list<string>|reference|yes|

## batch/Job

API: `batch/v1` `jobs`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`completions`|spec.completions|int|structural|yes|
|`parallelism`|spec.parallelism|int|structural|yes|
|`backoffLimit`|spec.backoffLimit|int|structural|yes|
|`suspend`|spec.suspend|bool|structural|yes|
|`completionMode`|spec.completionMode|string|structural|yes|
|`active`|status.active|int|structural|yes|
|`succeeded`|status.succeeded|int|structural|yes|
|`failed`|status.failed|int|structural|yes|
|`conditions.<type>.status`|status.conditions[type in Complete, Failed, Suspended, FailureTarget, SuccessCriteriaMet].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in Complete, Failed, Suspended, FailureTarget, SuccessCriteriaMet].reason|string|text|yes|
|`containers.<container>.image`|spec.template.spec.containers[].image|string|structural|yes|
|`containers.<container>.requests.<resource>`|spec.template.spec.containers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.limits.<resource>`|spec.template.spec.containers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`containers.<container>.ports`|spec.template.spec.containers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`containers.<container>.envRefs`|spec.template.spec.containers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`containers.<container>.envFrom`|spec.template.spec.containers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`containers.<container>.command`|spec.template.spec.containers[].command|list<string>|text|no|
|`containers.<container>.args`|spec.template.spec.containers[].args|list<string>|text|no|
|`initContainers.<container>.image`|spec.template.spec.initContainers[].image|string|structural|yes|
|`initContainers.<container>.requests.<resource>`|spec.template.spec.initContainers[].resources.requests (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.limits.<resource>`|spec.template.spec.initContainers[].resources.limits (cpu in cores, others in base units)|quantity|structural|yes|
|`initContainers.<container>.ports`|spec.template.spec.initContainers[].ports[] as name:port/protocol|list<string>|structural|yes|
|`initContainers.<container>.envRefs`|spec.template.spec.initContainers[].env[].valueFrom as NAME=configMap:name/key, NAME=secret:name/key, NAME=field:path, NAME=resource:name (never values)|list<string>|reference|yes|
|`initContainers.<container>.envFrom`|spec.template.spec.initContainers[].envFrom[] as configMap:name or secret:name|list<string>|reference|yes|
|`initContainers.<container>.command`|spec.template.spec.initContainers[].command|list<string>|text|no|
|`initContainers.<container>.args`|spec.template.spec.initContainers[].args|list<string>|text|no|
|`serviceAccountName`|spec.template.spec.serviceAccountName|string|reference|yes|
|`refs.configMaps`|spec.template.spec volumes, projected sources, env and envFrom ConfigMap names|list<string>|reference|yes|
|`refs.secrets`|spec.template.spec volumes, projected sources, env, envFrom, and imagePullSecrets Secret names|list<string>|reference|yes|
|`refs.claims`|spec.template.spec.volumes[].persistentVolumeClaim.claimName and ephemeral claim names|list<string>|reference|yes|

## networking.k8s.io/Ingress

API: `networking.k8s.io/v1` `ingresses`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`ingressClassName`|spec.ingressClassName|string|reference|yes|
|`hosts`|spec.rules[].host|list<string>|structural|yes|
|`backends`|spec.defaultBackend and spec.rules[].http.paths[].backend as service:port|list<string>|reference|yes|
|`tls`|spec.tls is non-empty|bool|structural|yes|
|`paths`|spec.rules[].http.paths[] as host path pathType -> service:port|list<string>|text|no|
|`loadBalancerIngress`|status.loadBalancer.ingress[] ip or hostname|list<string>|structural|no|

## networking.k8s.io/NetworkPolicy

API: `networking.k8s.io/v1` `networkpolicies`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`podSelector`|spec.podSelector as a canonical selector (* selects every pod)|string|text|yes|
|`policyTypes`|spec.policyTypes|list<string>|structural|yes|
|`ingressRules`|len(spec.ingress)|int|structural|yes|
|`egressRules`|len(spec.egress)|int|structural|yes|

## policy/PodDisruptionBudget

API: `policy/v1` `poddisruptionbudgets`, namespaced.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`selector`|spec.selector as a canonical selector (* selects every pod)|string|text|yes|
|`minAvailable`|spec.minAvailable|string|structural|yes|
|`maxUnavailable`|spec.maxUnavailable|string|structural|yes|
|`currentHealthy`|status.currentHealthy|int|structural|yes|
|`desiredHealthy`|status.desiredHealthy|int|structural|yes|
|`disruptionsAllowed`|status.disruptionsAllowed|int|structural|yes|
|`expectedPods`|status.expectedPods|int|structural|yes|
|`conditions.<type>.status`|status.conditions[type in DisruptionAllowed].status|string|structural|yes|
|`conditions.<type>.reason`|status.conditions[type in DisruptionAllowed].reason|string|text|yes|

## storage.k8s.io/StorageClass

API: `storage.k8s.io/v1` `storageclasses`, cluster.

|Field|Source|Type|Redaction|Default|
|---|---|---|---|---|
|`created`|metadata.creationTimestamp|timestamp|structural|yes|
|`terminating`|metadata.deletionTimestamp (present only while deletion is pending)|bool|structural|yes|
|`labels.<key>`|metadata.labels (allowlisted keys)|string|allowlist|yes|
|`annotations.<key>`|metadata.annotations (allowlisted keys)|string|allowlist|yes|
|`owners.<kind>.<name>`|metadata.ownerReferences[] (value: controller flag)|bool|reference|yes|
|`provisioner`|provisioner|string|structural|yes|
|`reclaimPolicy`|reclaimPolicy|string|structural|yes|
|`volumeBindingMode`|volumeBindingMode|string|structural|yes|
|`allowVolumeExpansion`|allowVolumeExpansion|bool|structural|yes|
|`isDefault`|metadata.annotations[storageclass.kubernetes.io/is-default-class]|bool|structural|yes|
|`parameters.<key>`|parameters|string|text|no|

## Published kube_* subset

See `kube-series.md` for labels and sources.

- `kube_pod_info`
- `kube_pod_status_phase`
- `kube_pod_status_ready`
- `kube_pod_container_info`
- `kube_pod_container_status_restarts_total`
- `kube_pod_container_status_waiting_reason`
- `kube_pod_container_status_last_terminated_reason`
- `kube_pod_container_resource_requests`
- `kube_pod_container_resource_limits`
- `kube_pod_owner`
- `kube_node_info`
- `kube_node_status_condition`
- `kube_node_status_capacity`
- `kube_node_status_allocatable`
- `kube_node_spec_unschedulable`
- `kube_deployment_spec_replicas`
- `kube_deployment_status_replicas_available`
- `kube_deployment_status_replicas_unavailable`
- `kube_statefulset_replicas`
- `kube_statefulset_status_replicas_ready`
- `kube_daemonset_status_desired_number_scheduled`
- `kube_daemonset_status_number_ready`
- `kube_job_status_failed`
- `kube_persistentvolumeclaim_status_phase`
- `kube_persistentvolumeclaim_resource_requests_storage_bytes`
- `kube_persistentvolumeclaim_info`
