# Installing on Kubernetes

The chart `oci://ghcr.io/cloud-exit/charts/exitmesh-agent` installs a DaemonSet of node agents and a single-replica coordinator StatefulSet. It supports Kubernetes 1.27 and later; CI installs it on every Kubernetes version in the compatibility matrix.

## Before you start

- The endpoint, enrollment token, and trust root come from the ExitMesh connector page. The token is stored in a Secret in the coordinator namespace and read only by the coordinator. The trust root is the public half of your workspace's agent trust root, which a workspace administrator generates once in ExitMesh under Settings > General > Encryption > Agent trust root; its private key stays in the ExitMesh Vault, and agent connections cannot be created until it exists. Agents verify every rule bundle and key manifest against it and refuse to start without it.
- The installing identity needs rights to create the two namespaces (unless they are pre-created), ClusterRoles and ClusterRoleBindings (or Roles and RoleBindings for the namespace profile), and the workloads. The agent identities never hold any of these rights.
- The coordinator needs a PersistentVolume from the default or a selected StorageClass. `ReadWriteOncePod` is used by default; set `coordinator.persistence.accessMode=ReadWriteOnce` if your CSI driver does not support it (the spool file lock then prevents two writers on one node). `ReadWriteMany` is refused at render time.

## Install

```sh
helm install exitmesh-agent oci://ghcr.io/cloud-exit/charts/exitmesh-agent \
  --version <version> \
  --namespace default \
  --set endpoint=https://<endpoint> \
  --set enrollment.token=<token> \
  --set-json 'trust.roots=["<root id>:<root public key>"]'
```

Keep your settings in a values file for upgrades (`-f exitmesh-values.yaml`). The release record is stored in the namespace given with `--namespace`; it must be an existing namespace other than the two the chart creates.

Check the rollout:

```sh
kubectl -n exitmesh rollout status statefulset/exitmesh-agent-coordinator
kubectl -n exitmesh-node rollout status daemonset/exitmesh-agent-node
```

## Namespaces and Pod Security

|Namespace|Default|PSA level|Why|
|---|---|---|---|
|Node agents|`exitmesh-node`|`privileged`|hostPath volumes are not allowed at `baseline` or `restricted`. The pods are still not privileged.|
|Coordinator|`exitmesh`|`restricted`|Only the DaemonSet namespace is relaxed.|

By default the chart creates both namespaces with `pod-security.kubernetes.io/enforce`, `audit`, and `warn` labels and the `helm.sh/resource-policy: keep` annotation, so they survive `helm uninstall` long enough for the cleanup hook to run (see [uninstall.md](uninstall.md)).

### Pre-created namespaces

Set `createNamespaces=false` to install into namespaces you manage:

```sh
kubectl create namespace exitmesh-node
kubectl label namespace exitmesh-node pod-security.kubernetes.io/enforce=privileged
kubectl create namespace exitmesh
kubectl label namespace exitmesh pod-security.kubernetes.io/enforce=restricted
helm install exitmesh-agent oci://ghcr.io/cloud-exit/charts/exitmesh-agent --version <version> \
  --namespace default --set createNamespaces=false -f exitmesh-values.yaml
```

With cluster access (`helm install`, `helm upgrade`, `helm install --dry-run=server`, Flux, Sveltos) the chart looks both namespaces up and fails with a clear message if either is missing or its `enforce` label is not `privileged` and `restricted` respectively. Offline renders (`helm template`, Argo CD) cannot run the lookup, so the chart refuses to render until you acknowledge the pre-created namespaces with `namespaces.skipLookupValidation=true`. Namespace names are set with `namespaces.node` and `namespaces.coordinator` and must differ.

## Collection profiles

|Profile|Values|RBAC|
|---|---|---|
|Cluster (default)|`kubernetes.scope=cluster`|ClusterRoles per capability.|
|Namespaces|`kubernetes.scope=namespaces`, `kubernetes.namespaces={team-a,team-b}`|A Role and RoleBinding per listed namespace for inventory and for node agent pod watches. Cluster-scoped gets (coordinator `get nodes` and `get persistentvolumes`, node agent `get nodes/metrics`) stay in narrow ClusterRoles unless `rbac.clusterReads=false`, which removes every ClusterRole; the affected facts are then reported as unavailable.|

Capabilities are independent and each carries only its own RBAC and mounts:

|Capability|Value|Grants|
|---|---|---|
|Inventory|`capabilities.inventory`|Coordinator wildcard `list`, `watch` within the selected scope for automatic inventory, including redacted Secret structure, Helm revisions, CRDs, and custom resources; built-in `get` rules remain in `rbac.inventory`. Namespace-scoped installations also read CRD definitions for discovery. Secret data and stringData values are redacted before caching or export.|
|Metrics|`capabilities.metrics`|Node agent `get` on `nodes/metrics`, used to scrape the local kubelet `/metrics` and `/metrics/cadvisor` at the node address. Annotated pod `/metrics` endpoints are reached over the pod network without RBAC; targets blocked by your NetworkPolicies are reported as coverage gaps.|
|Logs|`capabilities.logs`|Read-only hostPath `/var/log/pods`. `nodes/log` is never requested.|

## Permission and host-mount summary

This is the summary shown at onboarding and printed by the chart after install.

**Kubernetes permissions.** Verbs are `get`, `list`, and `watch` only. No identity can create, update, patch, or delete anything, including its own DaemonSet or StatefulSet. Never requested: Secret get access, `tokenreviews`, `subjectaccessreviews`, `pods/exec`, `pods/attach`, `pods/portforward`, `nodes/proxy`, `nodes/log`.

|Identity|Permission|Scope|
|---|---|---|
|Coordinator|inventory `get`, `list`, `watch`|Cluster, or the listed namespaces|
|Coordinator|`get` nodes, persistentvolumes|Cluster (detects node-pinned volumes and resolves node identities)|
|Coordinator|`get` pods|Node agent namespace only (resolves node agent token pod claims)|
|Node agents|`list`, `watch` pods|**Cluster-wide** in the cluster profile|
|Node agents|`get` nodes/metrics|Cluster (metrics capability)|

**Cluster-wide pod list disclosure.** Kubernetes RBAC cannot restrict `list` and `watch` on pods to the pods of one node, so each node agent holds cluster-wide pod read in RBAC terms. The agent always lists with a `spec.nodeName` field selector for its own node and never stores other nodes' pods. In the namespace profile the permission is limited to the listed namespaces.

**ConfigMaps.** ConfigMaps are in the default inventory list so the agent can record references and structural facts through a metadata-only watch. RBAC cannot express metadata-only access, so the role technically permits reading ConfigMap contents. Removing a resource from `rbac.inventory` does not narrow the automatic wildcard list/watch grant. For externally managed narrow permissions, set `rbac.create=false` and provide your own Roles and bindings; denied collection scopes remain visible as unavailable.

**Host mounts (node agents only).**

|Path|Access|Purpose|
|---|---|---|
|`/var/lib/exitmesh`|read-write, `DirectoryOrCreate`, mode 0700, owned by UID 65532|Node queue, local TSDB, log offsets, alert state. The only host write. Capped at `node.diskCap` (1 GiB) by the agent because kubelet eviction does not see hostPath usage. Removed on uninstall.|
|`/var/log/pods`|read-only|Log rules and investigation (logs capability).|

**Container security.** Node agents run as UID 65532 holding only `CAP_DAC_READ_SEARCH` (to read root-owned log files), with a read-only root filesystem, `allowPrivilegeEscalation: false`, seccomp `RuntimeDefault`, never `privileged`, and no host network, PID, or IPC. Container runtimes never grant an added capability to a non-root container process, so the container starts as UID 0 with `CAP_DAC_READ_SEARCH`, `CAP_SETGID`, and `CAP_SETUID`, and the agent's first action is `--run-as 65532:65532`: it switches to that UID and GID, keeps `CAP_DAC_READ_SEARCH` as its only (ambient) capability, and re-executes itself before reading configuration. Each node agent reports its UID and effective capabilities on registration, and the connector shows them. A short init container runs as root with only `CAP_CHOWN` to set the ownership and mode of `/var/lib/exitmesh`. The coordinator meets the `restricted` profile. `node.runAsRootFallback=true` skips the switch and runs the node agent as UID 0 with `CAP_DAC_READ_SEARCH` alone, for environments that forbid `CAP_SETUID`; it is flagged on the connector.

**Export preview.** Sent to ExitMesh: normalized state facts and deltas, the change graph, per-resource metric facts summarized per interval, findings, and capped redacted evidence. Never sent: raw logs, raw metric samples, full manifests, Secret values, ConfigMap values, environment values.

## Node to coordinator traffic

Node agents call the coordinator Service (`exitmesh-agent-coordinator.exitmesh.svc`, port 8443) over TLS. The serving certificate is generated by the chart and reused across upgrades (`tls.mode=generate`), issued by cert-manager (`tls.mode=certManager`), or supplied (`tls.mode=existingSecret`); the CA is mounted in the node agents. Node agents authenticate with a projected ServiceAccount token (audience `exitmesh-coordinator`, `expirationSeconds: 600`) that the coordinator validates offline against the cluster's issuer JWKS, so no `TokenReview` permission is needed. If your cluster removed the default `system:service-account-issuer-discovery` binding, set `rbac.issuerDiscovery=true`.

## NetworkPolicies

`networkPolicy.enabled=true` (default) ships policies that let default-deny namespaces work:

- Node agents: no ingress; egress to the coordinator pods on 8443, DNS, the API server, the kubelet port, and pods for annotated scraping (metrics capability).
- Coordinator: ingress only from node agent pods on 8443; egress to DNS, the API server, the ExitMesh endpoint, and each configured lookback source.

Destinations default to "any address on the listed ports". Restrict them with `networkPolicy.endpoint.cidrs`, `networkPolicy.apiServer.cidrs`, `networkPolicy.kubelet.cidrs`, and per lookback source with `lookback[].egress`.

## GitOps

All three tools below render the same chart; keep the values in Git and never commit the enrollment token in clear text (use `enrollment.existingSecret` with a sealed or externally managed Secret).

### Flux

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: exitmesh-agent
  namespace: flux-system
spec:
  interval: 1h
  url: oci://ghcr.io/cloud-exit/charts/exitmesh-agent
  ref:
    semver: "<version>"
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: exitmesh-agent
  namespace: flux-system
spec:
  interval: 1h
  chartRef:
    kind: OCIRepository
    name: exitmesh-agent
  targetNamespace: default
  uninstall:
    deletionPropagation: foreground
  values:
    endpoint: https://<endpoint>
    enrollment:
      existingSecret: exitmesh-enrollment
```

Flux uses the Helm SDK with cluster access, so namespace lookups, certificate reuse, and the post-delete cleanup hook work as with `helm`.

### Sveltos

```yaml
apiVersion: config.projectsveltos.io/v1beta1
kind: ClusterProfile
metadata:
  name: exitmesh-agent
spec:
  clusterSelector:
    matchLabels:
      exitmesh: enabled
  helmCharts:
    - repositoryURL: oci://ghcr.io/cloud-exit/charts
      repositoryName: exitmesh
      chartName: oci://ghcr.io/cloud-exit/charts/exitmesh-agent
      chartVersion: "<version>"
      releaseName: exitmesh-agent
      releaseNamespace: default
      helmChartAction: Install
      values: |
        endpoint: https://<endpoint>
        enrollment:
          existingSecret: exitmesh-enrollment
```

Sveltos installs through the Helm SDK against each managed cluster, so lookups and hooks behave as with `helm`.

### Argo CD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: exitmesh-agent
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ghcr.io/cloud-exit/charts
    chart: exitmesh-agent
    targetRevision: "<version>"
    helm:
      valuesObject:
        endpoint: https://<endpoint>
        enrollment:
          existingSecret: exitmesh-enrollment
        tls:
          mode: certManager
          caBundle: |
            <PEM of the issuing CA>
          certManager:
            issuerRef: {name: <issuer>, kind: ClusterIssuer}
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    syncOptions: [ServerSideApply=true]
```

Register `ghcr.io/cloud-exit/charts` as a Helm repository with `enableOCI: true`. Argo CD renders with `helm template` and has no cluster lookups, which has two consequences: a chart-generated TLS certificate would change on every render, so use `tls.mode=certManager` or `tls.mode=existingSecret`; and with `createNamespaces=false` you must set `namespaces.skipLookupValidation=true` after creating the labelled namespaces (for example with `managedNamespaceMetadata`). The cleanup DaemonSet carries `argocd.argoproj.io/hook: PostDelete`, so Argo CD runs it after deleting the application and removes it once every cleanup pod is ready. Delete the Application with foreground propagation. Tools without post-delete hooks follow the manual sequence in [uninstall.md](uninstall.md#manual-cleanup-for-gitops-tools-without-hooks).
