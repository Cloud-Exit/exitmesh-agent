# exitmesh-agent

The open source ExitMesh agent. One Go binary, `exitmesh-agent`, runs in three roles:

- **node** (Kubernetes DaemonSet): scrapes the local kubelet and annotated pods, tails pod logs, evaluates PromQL and LogQL rules locally against bounded windows, and queues findings and per-resource metric facts for the coordinator.
- **coordinator** (Kubernetes StatefulSet, one replica): keeps a compact, normalized model of cluster state, records every meaningful change as a restorable delta, builds the change graph, evaluates state rules, and holds the single outbound connection to ExitMesh.
- **host** (Linux systemd service): both roles in one process for a Linux host without Kubernetes, collecting host state, `node_*` metrics, the journal, and log files.

The agent speaks the open [History Protocol](protocol/SPEC.md) and evaluates signed rule bundles. It is licensed under the [Apache License 2.0](LICENSE).

## Read-only and outbound-only

- **Read-only.** Kubernetes access is `get`, `list`, and `watch` only. No writes of any kind, no Secrets, no `tokenreviews` or `subjectaccessreviews`, no `pods/exec`, `pods/attach`, `pods/portforward`, `nodes/proxy`, or `nodes/log`. The agent never executes commands and never self-updates.
- **One disclosed host directory.** Node agents mount `/var/log/pods` read-only and write only to `/var/lib/exitmesh` (mode 0700, capped at 1 GiB by the agent). Hosts run as the unprivileged `exitmesh` user under a hardened systemd unit whose only writable path is `/var/lib/exitmesh`.
- **Outbound-only.** The coordinator (or host agent) dials out to your ExitMesh endpoint over a WebSocket tunnel. Nothing listens outside the cluster network; node agents reach the coordinator over a ClusterIP Service. Shipped NetworkPolicies make default-deny namespaces work unchanged.
- **Durable store and forward.** Every checkpoint, delta, metric fact, and finding is spooled before it counts as emitted and is resent byte-identical until committed, so outages leave no gaps.
- **Inspectable rules.** Rule bundles are signed for integrity, not secrecy. Every rule that runs on your infrastructure can be read on the coordinator volume or under `/var/lib/exitmesh`.

## Historical search is not an ExitMesh feature

ExitMesh keeps no archive of raw logs, raw metrics, or manifests, and historical telemetry search is not an ExitMesh feature and will not become one. To search past logs or metrics beyond what is currently available in the cluster, run your own monitoring stack (for example Grafana with Loki and Mimir, or VictoriaMetrics and VictoriaLogs) fed by your own shipper (for example Alloy, vmagent, or an OpenTelemetry Collector), and connect it to the agent as a read-only **lookback source**. Investigations then query it through the agent, scope-injected at the query AST. Prometheus, Mimir, VictoriaMetrics, Loki, and VictoriaLogs adapters ship in the agent; see [docs/configuration.md](docs/configuration.md#lookback-sources).

## Quickstart: Kubernetes

Copy the endpoint, enrollment token, and trust roots (the root public keys of your ExitMesh deployment, which sign its rule bundles) from the ExitMesh connector page, then:

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
