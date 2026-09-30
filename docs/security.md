# Security model

The agent is built to be installed by teams that do not want to trust it with more than reading. This document lists every privilege it holds, why, and how each claim is enforced and tested. Vulnerability reporting is in [SECURITY.md](../SECURITY.md).

## Boundary

- The agent never writes to the Kubernetes API, never executes commands, never reads Secrets, and never self-updates.
- It opens no inbound listener beyond the node-to-coordinator ClusterIP Service (port 8443). All traffic to ExitMesh is outbound over one WebSocket tunnel from the coordinator (or the host agent).
- It writes only under `/var/lib/exitmesh` on nodes and hosts, and on the coordinator PVC mounted at `/data`.
- A tunnel session confers no write authority over history: writer ownership is validated against the committed chain by ExitMesh on every session.

These properties are asserted by `internal/deploytest` on every chart render (no `privileged: true`, only `get`, `list`, `watch`, no forbidden resources, exact capabilities, exact host paths, restricted coordinator) and by the kind integration job with `kubectl auth can-i` against the installed identities.

## Kubernetes RBAC

Capabilities are separate and independently removable; removing one removes its RBAC and mounts.

|Capability|Identity|Rules|
|---|---|---|
|inventory|coordinator|`get`, `list`, `watch` on the configured resource list (`rbac.inventory`). The chart refuses to render `secrets`, any subresource, wildcards, or review APIs in that list.|
|metrics|node agents|`get` on `nodes/metrics`, for the local kubelet `/metrics` and `/metrics/cadvisor` only.|
|logs|node agents|No RBAC; read-only hostPath `/var/log/pods`.|
|always|node agents|`list`, `watch` on pods (cluster-wide in the cluster profile; the agent filters by `spec.nodeName`).|
|always|coordinator|`get` on nodes and persistentvolumes (cluster-scoped reads, `rbac.clusterReads`), `get` on pods in the node agent namespace (token identity resolution).|

Never requested by any capability: `nodes/proxy` (reaches the full kubelet API), `nodes/log`, `pods/exec`, `pods/attach`, `pods/portforward`, `tokenreviews`, `subjectaccessreviews`, and any write verb. Neither identity can modify its own DaemonSet or StatefulSet. The namespace profile replaces ClusterRoles with a Role and RoleBinding per namespace.

## Host access

|Where|Access|Enforcement|
|---|---|---|
|Node agent|`/var/log/pods` read-only; `/var/lib/exitmesh` read-write, mode 0700, owned by UID 65532|Pod spec; the chart renders no other hostPath. `DirectoryOrCreate`; an init container running as root with only `CAP_CHOWN` sets ownership and mode once.|
|Node agent container|runs as UID 65532 holding only `CAP_DAC_READ_SEARCH`, read-only root filesystem, `allowPrivilegeEscalation: false`, seccomp `RuntimeDefault`, no host network, PID, or IPC, never `privileged`|Pod security context plus `--run-as` (below); the node namespace is labelled `privileged` only because hostPath volumes require it. The UID and effective capabilities are reported on the connector.|
|Coordinator|Pod Security `restricted`: non-root, no capabilities, read-only root filesystem, seccomp `RuntimeDefault`, only PVC, ConfigMap, Secret, and projected volumes|Namespace label `pod-security.kubernetes.io/enforce=restricted`.|
|Host agent|User `exitmesh`, groups `systemd-journal` and (where present) `adm`; unit with `NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/exitmesh`, `ProtectHome`, `PrivateTmp`, empty capability sets, kernel protections, address family and system call filters|systemd unit shipped in the package.|

`CAP_DAC_READ_SEARCH` lets the node agent read root-owned pod log files without being root. Kubernetes adds `securityContext.capabilities.add` only to the bounding set of a non-root container, so a process started as non-root never holds it (containerd and CRI-O alike). The container therefore starts as UID 0 with `CAP_DAC_READ_SEARCH`, `CAP_SETGID`, and `CAP_SETUID`, and `exitmesh-agent run --run-as 65532:65532` does nothing before it drops privileges: it clears supplementary groups, sets the real, effective, and saved GID and UID to 65532 with `PR_SET_KEEPCAPS`, reduces its permitted, effective, and inheritable sets to `CAP_DAC_READ_SEARCH`, raises that capability as ambient, and re-executes itself. The running agent is UID 65532 with exactly that one capability; `CAP_SETGID` and `CAP_SETUID` do not survive the exec, and `no_new_privs` prevents regaining them. `node.runAsRootFallback=true` runs the node agent as UID 0 with `CAP_DAC_READ_SEARCH` alone, for clusters whose policy forbids `CAP_SETUID`. This is flagged in the install notes, as a pod annotation, in the agent log, and on the connector.

## Node agent authentication

Node agents present a projected ServiceAccount token with audience `exitmesh-coordinator` and `expirationSeconds: 600` (the minimum Kubernetes allows), refreshed by the kubelet. The coordinator validates it offline against the cluster issuer's JWKS (`/openid/v1/jwks`, readable through the default issuer discovery binding), so no `TokenReview` is needed. Offline validation does not check binding liveness, so a token stays valid until it expires even if its pod is deleted; this is accepted because tokens expire within 10 minutes and a token can only submit records for its own node. The node identity comes from the token's node claim where the Kubernetes version provides it, otherwise from its pod claim resolved through a `get` on the pod. Submissions for any other node are rejected and audited. The node API is served over TLS with a certificate whose CA is mounted in node agents. The enrollment token is mounted only in the coordinator and never leaves it.

## Redaction

Redaction runs before every sink: the evidence ring, the spool, transmission, and the agent's own logs. The agent logs through a redacting handler; debug logs never contain raw payloads. Administrators add patterns with `policy.redactionPatterns`. Logs, annotations, and other workload-supplied text are treated as untrusted evidence; they never become instructions or authorization.

## What is exported

Normalized state facts and deltas, the change graph, per-resource metric facts summarized per interval, findings, and capped redacted evidence. Never exported: raw logs, raw metric samples, full manifests, Secret contents, ConfigMap values, environment values, and command lines except allowlisted, redacted fields. Labels and annotations require allowlists (`kubernetes.labelAllowlist`, `kubernetes.annotationAllowlist`). The local export policy is enforced even when a rule or investigation asks for more.

## Investigation

Investigations run over the reverse tunnel against in-cluster or on-host data and optional read-only lookback sources. Every query language (PromQL, LogQL, MetricsQL, LogsQL) is parsed and scope-injected at the AST before execution; requests cannot select arbitrary endpoints. Results are bounded by `investigation` limits and are never retained by the agent. Lookback credentials are mounted from Secrets you reference explicitly in `lookback[]` and are never obtained by listing Secrets.

## Rule bundles: signing and inspectability

The agent evaluates only signed rule bundles and never executes remote code. Each ExitMesh deployment has its own root key set, configured on its agents as `trust.roots`; bundle signing keys are published in key manifests signed by the root set, with overlapping validity windows for rotation and explicit revocation. Every manifest carries a monotonically increasing sequence number; the agent persists the highest verified sequence and rejects a lower or equal sequence with different content, whether delivered over the tunnel or out of band. Signature, engine compatibility, and budgets are validated before activation; an invalid bundle is rejected and the last known good bundle stays active. Root key compromise requires replacing `trust.roots` on the deployment's agents, as described in [SECURITY.md](../SECURITY.md#rule-bundle-signing-keys-and-root-key-compromise).

Signing protects integrity, not secrecy. Bundles are proprietary in licensing terms only and are not confidential: every rule that runs on your infrastructure is stored on the coordinator PVC and under `/var/lib/exitmesh` and can be read there. The format is documented in [bundle-format.md](bundle-format.md).

## Verifying releases

Container images, the Helm chart, release archives, checksums, and SBOMs are signed with cosign keyless signing by this repository's release workflow:

```sh
cosign verify ghcr.io/cloud-exit/exitmesh-agent@<digest> \
  --certificate-identity-regexp '^https://github.com/cloud-exit/exitmesh-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify ghcr.io/cloud-exit/charts/exitmesh-agent@<chart digest> \
  --certificate-identity-regexp '^https://github.com/cloud-exit/exitmesh-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob checksums.txt --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/cloud-exit/exitmesh-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing checksums.txt
```

deb and rpm packages and the package repositories are signed with a package key that is separate from the rule bundle signing keys. Binaries are static and reproducible from their tag; CI rebuilds from two checkouts and compares checksums on every change.
