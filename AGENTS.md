# exitmesh-agent: contributor and agent guide

Read this before changing code.

## What this repository is

The open source ExitMesh Telemetry Agent: a Go codebase producing one binary, `exitmesh-agent`, with roles `node` (Kubernetes DaemonSet), `coordinator` (Kubernetes StatefulSet), and `host` (Linux systemd service). The only interface to the ExitMesh control plane is the History Protocol (`protocol/SPEC.md`), the rule bundle format (`docs/bundle-format.md`), and the tunnel binding. Nothing in this repository may reference proprietary backend code, repositories, or internal URLs.

## Layout

|Path|Contents|
|---|---|
|`cmd/exitmesh-agent`|Entry point, role selection, subcommands.|
|`pkg/protocol`|Public History Protocol implementation: encoding, records, hashing, fold, reconstruction, ownership decisions, session types.|
|`pkg/protocol/client`|Transport-agnostic writer session client: hello, resume, drain, ack, divergence handling.|
|`pkg/protocol/refcp`|Reference control plane used by contract and end-to-end tests.|
|`protocol/`|Specification, CDDL, Python reference oracle, vectors, scenarios.|
|`internal/spool`|Coordinator and host spool, node agent queue, directory locks.|
|`internal/tunnel`|WebSocket tunnel transport and enrollment client.|
|`internal/state`|Kubernetes normalization, field catalog, edges, tracker, relist and diff, `kube_*` synthesis.|
|`internal/rules`|Bundles and trust, CEL state rules, PromQL and LogQL evaluation, alert state, budgets.|
|`internal/findings`|Finding episodes, deduplication, lifecycle summary.|
|`internal/telemetry`|Scrape loop, TSDB, log tailing, evidence ring, metric facts.|
|`internal/investigate`|Live and lookback queries, AST scope injection, adapters, LogQL to LogsQL translation.|
|`internal/hostfacts`|Host state collectors, availability catalog, host metrics, journal reader.|
|`internal/coordinator`, `internal/node`, `internal/host`|Role wiring.|
|`internal/nodeapi`|Node agent to coordinator HTTPS API, wire types, offline ServiceAccount token validation.|
|`internal/admin`|Local unix-socket administration API used by the CLI.|
|`internal/rules/validators`|Bundle validators backed by the real engines.|
|`internal/rulesdefault`, `rules/`|Default rule bundle sources and their fixture tests.|
|`internal/e2e`|In-process full-system tests: coordinator, node agents, reference control plane.|
|`internal/redact`, `internal/kv`, `internal/config`|Shared redaction, durable key-value metadata, configuration.|
|`deploy/helm`, `deploy/packaging`|Helm chart; deb, rpm, tarball, systemd unit.|

## Rules

- Go only, `CGO_ENABLED=0` for everything. Pure-Go dependencies under Apache 2.0, MIT, BSD, or ISC. Never import Loki, Grafana, or any AGPL or GPL code.
- Never write stubs, placeholder handlers, `TODO` bodies, or fake logic. Every behavior ships with tests that exercise it. If something cannot be finished, say so explicitly; do not mark it done.
- Comments: at most one short line, only for a non-obvious why. No narrative blocks, no requirement-ID tags in code. Rationale belongs in `docs/`.
- Never use em dashes or en dashes anywhere (code, comments, docs, commit messages). Use commas, colons, parentheses, or separate sentences.
- Redaction precedes every sink: evidence rings, spools, transmission, logs. Use `internal/redact`; log through `redact.NewHandler`.
- The agent never writes to Kubernetes, never executes commands, collects Secret metadata only (never Secret data or stringData), never opens inbound listeners beyond the node-to-coordinator Service, and writes only under `/var/lib/exitmesh` (or the coordinator PVC).
- New modules need review: pure Go, licensed Apache 2.0, MIT, BSD, or ISC; anything else (including MPL-2.0 transitive dependencies) is listed and approved explicitly.
- Verify with `go build ./... && go vet ./... && go test ./...` (race detector for concurrency-heavy packages). `golangci-lint` may not run in every sandbox; CI runs it.
