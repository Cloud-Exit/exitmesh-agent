# ExitMesh Telemetry Agent
<img width="1434" height="626" alt="ExitMesh Telemetry Agent architecture: node agents and the coordinator in a Kubernetes cluster, a host agent on a Linux host, both dialing out to the ExitMesh control plane" src="https://github.com/user-attachments/assets/a710a297-d67f-42a5-bbd6-3dfedaead542" />

The open source ExitMesh Telemetry Agent. One Go binary, `exitmesh-agent`, runs in the three roles shown above.

**In a Kubernetes cluster**

- **Node agent** (DaemonSet, one per node): scrapes the kubelet and cAdvisor into a local TSDB, tails pod logs, evaluates PromQL and LogQL rules against bounded local windows, and tracks findings. Findings and per-resource metric facts wait in a durable local queue until the coordinator acknowledges them.
- **Node agent to coordinator**: node agents submit over HTTPS on the coordinator ClusterIP Service (port 8443), authenticated with their projected ServiceAccount token, and long-poll the coordinator for the current rule bundle and investigation tasks. Nothing outside the cluster network is involved.
- **Coordinator** (StatefulSet, one replica): watches cluster state through informers, keeps a compact normalized model of it, records every meaningful change as a restorable delta, evaluates CEL state rules and cluster PromQL rules, and merges node records into one hash-chained spool on its volume.

**On a Linux host**

- **Host agent** (systemd service, single process): runs the node and coordinator roles together, with no Kubernetes components and no node API hop. It collects host state, `node_*` metrics, the journal, and log files.

**To ExitMesh**

- **Coordinator or host agent to ExitMesh**: the only connection that leaves your network is an outbound WebSocket tunnel to your ExitMesh endpoint. Checkpoint, delta, range, and finding records flow out over the open [History Protocol](protocol/SPEC.md) (EMHP v1).
- **ExitMesh back to the agent**: over that same tunnel, ExitMesh commits records by sequence and chain hash (the spool keeps everything until then), delivers signed rule bundles, and calls investigation tools. ExitMesh owns the rule bundle trust roots; the agent only verifies bundles against the public half.

The agent is licensed under the [Apache License 2.0](LICENSE).

## Read-only and outbound-only

- **Secret inventory and privacy.** Secret objects are captured as metadata, including identity, ownership, and workload dependencies. Secret values are redacted by omission before storage or transit: the agent requests metadata-only responses and never collects or sends `data` or `stringData` to ExitMesh. Helm release names, revisions, and statuses come from storage-object labels, without decoding release payloads. Custom resources are discovered from the CRD watch by default and exported as bounded identity and condition projections. Independent discovery controls, include/exclude filters, and kind/scope limits keep collection bounded without delaying initial synchronization. ExternalSecret conditions, target Secret names, and workload references expose failed synchronization and affected workloads.
- **Inventory permissions.** Automatic coverage grants the coordinator read-only `list` and `watch` across API groups and resources within the selected scope. Kubernetes cannot restrict these permissions to metadata-only responses; the agent enforces that boundary for Secrets. No write verbs are granted.
- **Read-only.** Kubernetes access is `get`, `list`, and `watch` only. No writes of any kind, no Secret values, no `tokenreviews` or `subjectaccessreviews`, no `pods/exec`, `pods/attach`, `pods/portforward`, `nodes/proxy`, or `nodes/log`. The agent never executes commands and never self-updates.
- **One disclosed host directory.** Node agents mount `/var/log/pods` read-only and write only to `/var/lib/exitmesh` (mode 0700, capped at 1 GiB by the agent). Hosts run as the unprivileged `exitmesh` user under a hardened systemd unit whose only writable path is `/var/lib/exitmesh`.
- **Outbound-only.** The coordinator (or host agent) dials out to your ExitMesh endpoint over a WebSocket tunnel. Nothing listens outside the cluster network; node agents reach the coordinator over a ClusterIP Service. Shipped NetworkPolicies make default-deny namespaces work unchanged.
- **Durable store and forward.** Every checkpoint, delta, metric fact, and finding is spooled before it counts as emitted and is resent byte-identical until committed, so outages leave no gaps.
- **Inspectable rules.** Rule bundles are signed for integrity, not secrecy. Every rule that runs on your infrastructure can be read on the coordinator volume or under `/var/lib/exitmesh`.

## Quickstart: Kubernetes

Your ExitMesh workspace needs an agent trust root first: a workspace administrator generates it once in ExitMesh under Settings > General > Encryption > Agent trust root (Generate trust root). Its private key stays in the ExitMesh Vault, and agent connections cannot be created until it exists. Then copy the endpoint, enrollment token, and trust root (the public half of that key, which signs the workspace's rule bundles) from the ExitMesh connector page:

```sh
helm install exitmesh-agent oci://ghcr.io/cloud-exit/charts/exitmesh-agent \
  --version 0.1.0 \
  --namespace default \
  --set endpoint=https://<endpoint from the connector page> \
  --set enrollment.token=<enrollment token> \
  --set-json 'trust.roots=["<root id>:<root public key>"]'
```

The chart creates two namespaces: `exitmesh-node` (Pod Security `privileged`, required for the hostPath volumes) and `exitmesh` (Pod Security `restricted`). The release record lives in the namespace passed with `--namespace`. Profiles, GitOps installs, and pre-created namespaces are covered in [docs/install-kubernetes.md](docs/install-kubernetes.md).

## Quickstart: Linux hosts

```sh
# Debian and Ubuntu
sudo apt install ./exitmesh-agent_0.1.0_amd64.deb
# RHEL, Fedora, Rocky, Alma
sudo dnf install ./exitmesh-agent-0.1.0-1.x86_64.rpm

sudo sed -i 's#^endpoint: ""#endpoint: "https://<endpoint from the connector page>"#' /etc/exitmesh/agent.yaml
sudo sed -i 's#^  roots: \[\]#  roots: ["<root id>:<root public key>"]#' /etc/exitmesh/agent.yaml
printf '%s\n' '<enrollment token>' | sudo install -m 0640 -o root -g exitmesh /dev/stdin /etc/exitmesh/enrollment-token
sudo systemctl start exitmesh-agent
```

Groups, golden images, and the tarball install are covered in [docs/install-host.md](docs/install-host.md).

## Documentation

|Topic|Document|
|---|---|
|Kubernetes install, profiles, GitOps|[docs/install-kubernetes.md](docs/install-kubernetes.md)|
|Host install|[docs/install-host.md](docs/install-host.md)|
|Configuration reference|[docs/configuration.md](docs/configuration.md)|
|Security model|[docs/security.md](docs/security.md)|
|Operations runbook|[docs/operations.md](docs/operations.md)|
|Upgrades|[docs/upgrades.md](docs/upgrades.md)|
|Air-gap profile|[docs/airgap.md](docs/airgap.md)|
|Uninstall and removal|[docs/uninstall.md](docs/uninstall.md)|
|Architecture and internal contracts|[docs/architecture.md](docs/architecture.md)|
|History Protocol specification|[protocol/SPEC.md](protocol/SPEC.md)|
|Command line|[docs/cli.md](docs/cli.md)|
|Rule bundle format and signing|[docs/bundle-format.md](docs/bundle-format.md)|
|State rules (CEL)|[docs/state-rules.md](docs/state-rules.md)|
|PromQL rules|[docs/promql-rules.md](docs/promql-rules.md)|
|LogQL subset|[docs/logql-subset.md](docs/logql-subset.md)|
|Default rules and insight coverage|[docs/insight-coverage.md](docs/insight-coverage.md)|
|Investigation tools and lookback|[docs/investigation.md](docs/investigation.md)|
|Kubernetes field catalog|[docs/field-catalog.md](docs/field-catalog.md)|
|Published kube_* series|[docs/kube-series.md](docs/kube-series.md)|
|Host facts and availability|[docs/host-facts.md](docs/host-facts.md)|
|Log tailing contract|[docs/log-contract.md](docs/log-contract.md)|

## Building

```sh
make build        # static binary in bin/, CGO_ENABLED=0, -trimpath
make test         # unit tests
make chart-test   # helm lint and chart assertions
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for every quality gate, the DCO sign-off, and dependency rules. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

Coordinator enrollment-token rotation is detected at startup. Update the mounted Secret and restart the coordinator using a version supporting automatic refresh; it re-enrolls the same writer and preserves queued history. See [token rotation](docs/operations.md#coordinator-token-rotation) for upgrade behavior and recovery limits.
