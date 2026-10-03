# Configuration reference

The agent reads one YAML file, passed with `exitmesh-agent run --config <file>`. Unknown keys are rejected. Sizes accept the suffixes `Ki`, `Mi`, `Gi`, `Ti` (powers of 1024) and `K`, `M`, `G`, `T` (powers of 1000). Durations use Go syntax (`30s`, `15m`, `6h`, `720h`); days are not accepted.

On Kubernetes the chart renders this file into ConfigMaps (`exitmesh-agent-coordinator-config` and `exitmesh-agent-node-config`) from its values; on hosts it is `/etc/exitmesh/agent.yaml`. The chart values are listed at the end.

## Top level

|Key|Default|Meaning|
|---|---|---|
|`role`|required|`node`, `coordinator`, or `host`.|
|`endpoint`|required for `coordinator` and `host` unless `airgap.enabled`|HTTPS URL of the ExitMesh control plane. Enrollment and the tunnel dial `/agent/v1/enroll` and `/agent/v1/tunnel` under it.|
|`endpointCAFile`|empty (system roots)|PEM CA bundle for the endpoint, for TLS-intercepting egress proxies.|
|`enrollmentTokenFile`|required for `coordinator` and `host` unless `airgap.enabled`|File holding the enrollment token (`emx1_c_...`, `emx1_h_...`, or `emx1_g_...`).|
|`stateDir`|`/data` for `coordinator`, otherwise `/var/lib/exitmesh`|Durable state: spool, TSDB, offsets, cursors, alert state, credential.|
|`capabilities`|`[inventory, metrics, logs]`|Enabled capabilities. Each can be removed independently.|

## kubernetes

|Key|Default|Meaning|
|---|---|---|
|`kubernetes.scope`|`cluster`|`cluster` or `namespaces` (namespace-scoped profile). In the namespaces profile a node agent runs one `spec.nodeName` pod watch per listed namespace, which the chart's per-namespace Roles grant; the cluster profile uses one cluster-wide watch.|
|`kubernetes.namespaces`|empty|Namespaces to collect; required when scope is `namespaces`. Node agents never tail, read on demand, or keep evidence from pods outside them.|
|`kubernetes.excludeNamespaces`|empty|Namespaces to skip in either profile: not collected, and node agents never watch their pods, tail or read their logs on demand, or keep evidence from them.|
|`kubernetes.labelAllowlist`|empty|Label keys recorded in state facts. Labels are never recorded without an allowlist.|
|`kubernetes.annotationAllowlist`|empty|Annotation keys recorded in state facts.|
|`kubernetes.resources`|empty (agent default set)|Built-in resource kinds to collect; does not disable custom-resource discovery.|
|`kubernetes.customResources.enabled`|`true`|Discover custom kinds from the CRD informer and collect instances after initial built-in sync.|
|`kubernetes.customResources.maxKinds`, `maxScopes`|`100`, `256`|Maximum custom kinds and kind/namespace collection scopes; exceeding either reports partial discovery coverage.|
|`kubernetes.customResources.include`, `exclude`|empty|Glob lists matching `group/Kind` or `plural.group`; exclusions win. These filters do not narrow RBAC.|
|`kubernetes.clusterName`|empty|Display name reported to ExitMesh.|

## coordinator

Used by the coordinator (listener side) and by node agents (client side).

|Key|Default|Meaning|
|---|---|---|
|`coordinator.listen`|`:8443`|Node API listen address (coordinator).|
|`coordinator.tlsCertFile`|empty|Serving certificate for the node API (coordinator).|
|`coordinator.tlsKeyFile`|empty|Serving key for the node API (coordinator).|
|`coordinator.serviceURL`|required for `node`|Node API URL, for example `https://exitmesh-agent-coordinator.exitmesh.svc:8443`.|
|`coordinator.caFile`|empty|CA that signed the coordinator certificate (node).|
|`coordinator.audience`|`exitmesh-coordinator`|Required audience of node agent ServiceAccount tokens.|
|`coordinator.tokenFile`|`/var/run/secrets/exitmesh/token`|Projected token presented by node agents.|
|`coordinator.namespace`|empty (from `POD_NAMESPACE`)|Coordinator namespace.|
|`coordinator.podName`|empty (from `POD_NAME`)|Coordinator pod name.|

## spool

Coordinator spool on the PVC (hosts use `host.spoolReserve`).

|Key|Default|Meaning|
|---|---|---|
|`spool.capacity`|`10Gi`|Hard budget for record bodies; about 7 days at the reference workload.|
|`spool.window`|`8Mi`|Transmitted-unconfirmed window.|
|`spool.coalesceAt`|`0.90`|Fill ratio in (0, 1] at which the oldest never-transmitted range is coalesced, after evidence eviction and sample compaction.|

## node

|Key|Default|Meaning|
|---|---|---|
|`node.name`|empty (from `NODE_NAME`)|Node this agent runs on.|
|`node.diskCap`|`1Gi`|Cap on `/var/lib/exitmesh` across queue, TSDB, and offsets, enforced by the agent.|
|`node.evidenceRing`|`16Mi`|In-memory evidence ring ceiling, shared per rule.|
|`node.logsPath`|`/var/log/pods`|Pod log root (logs capability).|
|`node.scrapeInterval`|`30s`|Scrape interval for the kubelet and annotated pods.|
|`node.maxTargets`|`200`|Scrape target budget per node.|
|`node.maxSeries`|`100000`|Series budget per node.|
|`node.maxSamplesPerSecond`|`20000`|Ingest budget per node.|
|`node.kubeletTLS`|`verify`|`verify` or `skip` verification of the kubelet serving certificate.|
|`node.kubeletPort`|`10250`|Kubelet port on the node address (`NODE_IP`).|

## host

|Key|Default|Meaning|
|---|---|---|
|`host.diskCap`|`2Gi`|Total cap on `/var/lib/exitmesh`.|
|`host.spoolReserve`|`1Gi`|Spool reserve no other use may consume. `spoolReserve + tsdbMax` must not exceed `diskCap`.|
|`host.tsdbMax`|`768Mi`|TSDB ceiling; retention shrinks first under disk pressure.|
|`host.evidenceRing`|`16Mi`|Evidence ring ceiling.|
|`host.scrapeInterval`|`30s`|Interval for host collectors and local endpoints.|
|`host.logFiles`|`[/var/log]`|Allowlisted log files or directories.|
|`host.journal`|`false` (`true` in the packaged file)|Read the systemd journal.|
|`host.journalDir`|empty (`/var/log/journal` and `/run/log/journal`)|Journal directory override.|
|`host.metricsEndpoints`|empty|Local `/metrics` URLs to scrape.|
|`host.allowNonLoopback`|`false`|Allow non-loopback `metricsEndpoints`.|

## Lookback sources

`lookback` is a list of optional, read-only external stores used only by investigations. The agent never writes to them and never stores their results. Lookback lets investigations reach the monitoring stack you already run.

|Key|Default|Meaning|
|---|---|---|
|`lookback[].name`|required, unique|Source name shown in investigations.|
|`lookback[].type`|required|`prometheus`, `mimir`, `victoriametrics`, `loki`, or `victorialogs`.|
|`lookback[].url`|required|`http` or `https` base URL.|
|`lookback[].tenant`|empty|Tenant (`X-Scope-OrgID`) for Mimir and Loki.|
|`lookback[].accountID`|empty|VictoriaMetrics and VictoriaLogs account ID.|
|`lookback[].projectID`|empty|VictoriaMetrics and VictoriaLogs project ID.|
|`lookback[].bearerTokenFile`|empty|File with a bearer token.|
|`lookback[].basicUsernameFile`|empty|File with a basic auth user name.|
|`lookback[].basicPasswordFile`|empty|File with a basic auth password.|
|`lookback[].caFile`|empty|CA bundle for the source.|
|`lookback[].timeout`|`30s`|Per-query timeout.|
|`lookback[].retention`|empty|Retention of the source, used to bound query windows and shown to users.|

## airgap

|Key|Default|Meaning|
|---|---|---|
|`airgap.enabled`|`false`|Air-gap profile: no connection to ExitMesh; bundles out of band; file export.|
|`airgap.bundleDir`|empty|Directory holding the signed bundle, signature, and key manifest delivered out of band ([bundle-format.md](bundle-format.md)).|
|`airgap.exportDir`|empty|Directory for export files ([airgap.md](airgap.md)).|

## trust

The rule bundle trust root of your ExitMesh workspace: the public half of the agent trust root a workspace administrator generates in ExitMesh under Settings > General > Encryption > Agent trust root, whose private key stays in the ExitMesh Vault. The connector page shows it next to the enrollment token. Required.

|Key|Default|Meaning|
|---|---|---|
|`trust.roots`|empty|Root public keys as `<id>:<base64 ed25519 public key>`; key manifests must be signed by them or by successor roots they introduced.|
|`trust.rootsFile`|empty|Alternative to `trust.roots`: a roots document (`keys` with `id` and `public_key`, optional `threshold`), for example from `exitmesh-bundle roots`.|
|`trust.threshold`|`1`|Distinct root signatures a key manifest needs.|

## policy

Local administrator upper bounds; rules cannot exceed them.

|Key|Default|Meaning|
|---|---|---|
|`policy.maxRuleEvalTime`|`2s`|Maximum evaluation time per rule.|
|`policy.maxRuleSamples`|`5000000`|Maximum samples loaded per PromQL evaluation.|
|`policy.maxRuleSeries`|`10000`|Maximum series per rule.|
|`policy.maxCounterBytes`|`8Mi`|Maximum LogQL counter state per rule.|
|`policy.maxEvidenceBytes`|`1Mi`|Maximum evidence per rule.|
|`policy.disabledRules`|empty|Rule IDs never evaluated; reported as disabled.|
|`policy.lateThreshold`|`15m`|Delay after which a finding is marked late-delivered.|
|`policy.redactionPatterns`|empty|Extra regular expressions redacted before every sink.|

## investigation

|Key|Default|Meaning|
|---|---|---|
|`investigation.maxConcurrency`|`4`|Concurrent investigation queries.|
|`investigation.timeout`|`30s`|Per-query timeout.|
|`investigation.maxBytes`|`4Mi`|Result size limit.|
|`investigation.maxLines`|`5000`|Log line limit.|
|`investigation.maxSeries`|`1000`|Series limit.|
|`investigation.maxSamples`|`500000`|Sample limit.|
|`investigation.maxWindow`|`6h`|Maximum time window of a live query.|

## logging

|Key|Default|Meaning|
|---|---|---|
|`logging.level`|`info`|`debug`, `info`, `warn`, or `error`.|
|`logging.format`|`json`|`json` or `text`. Every record passes the redaction handler.|

## Environment

|Variable|Set by|Meaning|
|---|---|---|
|`NODE_NAME`, `POD_NAME`, `POD_NAMESPACE`, `NODE_IP`|chart, downward API|Identity and node address of each pod.|
|`EXITMESH_MEMORY_LIMIT_MIB`|chart, `resourceFieldRef` on `limits.memory`|Container memory limit in MiB.|
|`GOMEMLIMIT`|chart and systemd unit|Go soft memory limit with headroom. The chart renders `$(EXITMESH_MEMORY_LIMIT_MIB)000KiB`, about 97.7 percent of the container limit, so it follows the effective limit; the unit sets `172MiB` under `MemoryMax=192M`.|

## Helm chart values

|Value|Default|Meaning|
|---|---|---|
|`endpoint`, `endpointCA`|empty|Rendered to `endpoint` and `endpointCAFile`. `endpoint` is required unless `airgap.enabled`.|
|`enrollment.token`|empty|Enrollment token; stored in a Secret in the coordinator namespace.|
|`enrollment.existingSecret`, `enrollment.existingSecretKey`|empty, `token`|Use an existing Secret instead.|
|`image.repository`, `image.tag`, `image.digest`, `image.pullPolicy`|`ghcr.io/cloud-exit/exitmesh-agent`, chart `appVersion`, empty, `IfNotPresent`|Image; a digest pins it and takes precedence over the tag.|
|`imagePullSecrets`|empty|Pull secrets for both workloads.|
|`createNamespaces`|`true`|Create both namespaces with PSA labels (kept on uninstall).|
|`namespaces.node`, `namespaces.coordinator`|`exitmesh-node`, `exitmesh`|Namespace names; must differ.|
|`namespaces.skipLookupValidation`|`false`|Acknowledge pre-created namespaces when rendering without cluster access.|
|`namespaces.extraLabels`|empty|Extra labels on created namespaces.|
|`capabilities.inventory`, `.metrics`, `.logs`|`true`|Capabilities; at least one must be enabled.|
|`kubernetes.*`|see above|Rendered to the `kubernetes` section of both roles. `kubernetes.clusterDomain` (`cluster.local`) is used for certificate names only.|
|`rbac.create`|`true`|Render RBAC.|
|`rbac.clusterReads`|`true`|Cluster-scoped gets (`nodes`, `persistentvolumes`, `nodes/metrics`).|
|`rbac.issuerDiscovery`|`false`|Grant the coordinator `get` on the issuer discovery URLs.|
|`rbac.inventory.namespaced`, `rbac.inventory.cluster`|workload, network, storage, policy resources|Additional built-in inventory rules (`get`, `list`, `watch`); Secrets, subresources, and wildcards are refused in these get-capable lists. The chart separately grants wildcard `list`, `watch` for automatic custom-resource and Secret metadata inventory.|
|`tls.mode`|`generate`|`generate`, `certManager`, or `existingSecret` for the node API certificate.|
|`tls.caBundle`|empty|CA for node agents; required unless `generate`.|
|`tls.existingSecret`|empty|`kubernetes.io/tls` Secret in the coordinator namespace.|
|`tls.certManager.issuerRef`, `.duration`, `.renewBefore`|empty, `2160h`, `360h`|cert-manager issuance.|
|`tls.validityDays`|`3650`|Validity of generated certificates.|
|`coordinator.resources`|requests `200m`/`512Mi`, limits `1`/`1Gi`|Coordinator resources.|
|`coordinator.persistence.storageClassName`|empty (default class)|StorageClass; `-` for none.|
|`coordinator.persistence.accessMode`|`ReadWriteOncePod`|Or `ReadWriteOnce`; `ReadWriteMany` is refused.|
|`coordinator.persistence.size`|`12Gi`|PVC size.|
|`coordinator.spool.capacity`, `.window`, `.coalesceAt`|`10Gi`, `8Mi`, `0.90`|Rendered to `spool`.|
|`coordinator.nodeSelector`, `.tolerations`, `.affinity`, `.priorityClassName`, `.podAnnotations`, `.podLabels`, `.terminationGracePeriodSeconds`|empty, `60`|Scheduling and metadata.|
|`node.resources`|requests and limits `100m`/`192Mi`|Node agent resources (Guaranteed QoS).|
|`node.uid`, `node.gid`|`65532`|Non-root identity the node agent switches to at start (`--run-as`) and owner of `/var/lib/exitmesh`.|
|`node.runAsRootFallback`|`false`|Run node agents as UID 0 with `CAP_DAC_READ_SEARCH` alone instead of switching to `node.uid` (for policies that forbid `CAP_SETUID`). Flagged.|
|`node.diskCap` ... `node.kubeletPort`|see `node` above|Rendered to `node`.|
|`node.tolerations`|`[{operator: Exists}]`|Run on every node.|
|`node.nodeSelector`, `.affinity`, `.priorityClassName`, `.podAnnotations`, `.podLabels`, `.terminationGracePeriodSeconds`|empty, `30`|Scheduling and metadata.|
|`nodeAPI.port`, `.audience`, `.tokenExpirationSeconds`|`8443`, `exitmesh-coordinator`, `600`|Node API Service port and projected token.|
|`lookback[]`|empty|Lookback sources. Besides the keys above, each entry takes `bearerToken: {secretName, key}`, `basicAuth: {secretName, usernameKey, passwordKey}`, `ca: {secretName or configMapName, key}` (mounted under `/etc/exitmesh/lookback/<name>/`), and `egress: {ports, cidrs, namespaceSelector, podSelector}` for its NetworkPolicy rule (default: the URL port to any destination).|
|`airgap.enabled`|`false`|Air-gap profile.|
|`airgap.bundles.configMap`|empty|ConfigMap with the bundle files, mounted under `/etc/exitmesh/bundles`.|
|`airgap.bundles.files`|`[keymanifest.json, bundle.tar.gz, bundle.sig]`|Keys of that ConfigMap, each mounted with `subPath` as a regular file.|
|`airgap.bundles.imagePath`|empty|Bundle directory inside a derived image.|
|`airgap.exportDir`|`/data/export`|Export directory on the PVC.|
|`airgap.persistenceSize`, `airgap.spoolCapacity`|`60Gi`, `50Gi`|Enlarged PVC and spool when `airgap.enabled`.|
|`policy`, `investigation`|empty|Rendered to the matching sections.|
|`logging.level`, `logging.format`|`info`, `json`|Rendered to `logging`.|
|`networkPolicy.enabled`|`true`|Ship NetworkPolicies.|
|`networkPolicy.dns.ports`|`[53]`|DNS egress (UDP and TCP).|
|`networkPolicy.apiServer`, `.endpoint`, `.kubelet`|`cidrs: []`; ports `[443, 6443]`, `[443]`, `[10250]`|Egress rules; empty `cidrs` means any destination on those ports.|
|`cleanup.enabled`, `cleanup.resources`|`true`|Post-delete cleanup DaemonSet ([uninstall.md](uninstall.md)).|

### Example lookback values

```yaml
lookback:
  - name: mimir
    type: mimir
    url: http://mimir-query-frontend.monitoring.svc:8080/prometheus
    tenant: team-a
    retention: 720h
    bearerToken: {secretName: mimir-reader, key: token}
    egress:
      namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: monitoring}}
  - name: logs
    type: victorialogs
    url: https://victorialogs.example.com
    basicAuth: {secretName: victorialogs-reader}
    ca: {configMapName: internal-ca, key: ca.crt}
    egress: {cidrs: [203.0.113.0/24]}
```
