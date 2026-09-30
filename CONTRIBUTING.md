# Contributing

Thank you for helping improve the ExitMesh agent. This project is licensed under the Apache License 2.0 and accepts contributions under the same license.

Read `AGENTS.md` before changing code: it states the repository layout and the rules every change must follow (Go only, `CGO_ENABLED=0`, permissive dependencies only, no stubs, redaction before every sink, and the agent's read-only, outbound-only boundary).

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Signing off certifies that you wrote the change or otherwise have the right to submit it under the project license. Add the trailer with `git commit --signoff`, which appends:

```
Signed-off-by: Your Name <you@example.com>
```

The name and email must match the commit author. The `dco` CI job rejects pull requests with unsigned commits; fix them with `git rebase --signoff origin/main` and force-push the branch.

## Quality gates

Pull requests merge only when every CI job passes. Run the same checks locally:

|Gate|Command|
|---|---|
|Build and vet|`make vet` (`go build ./... && go vet ./...`)|
|Lint|`make lint` (golangci-lint v2, `.golangci.yml`)|
|Tests with the race detector|`make test-race`|
|Vulnerabilities|`make vuln` (govulncheck)|
|Dependency licenses|`make licenses` (go-licenses; only Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC)|
|No Loki, Grafana, or AGPL code|`make check-deps`|
|Protocol contract suite|`make vectors` (Go vectors and the Python reference oracle in `protocol/reference`)|
|Fuzzing smoke|`make fuzz` (every native fuzz target, `FUZZTIME` per target)|
|Helm chart|`make chart-test` (`helm lint --strict` and `internal/deploytest`)|
|Reproducible build|`make reproducible`|

CI additionally installs the chart into kind clusters across the supported Kubernetes versions, runs the uninstall sequence, and runs the LogQL differential tests against a Loki container used only as an unlinked test oracle.

## Dependencies

Dependencies are pinned in `go.mod`. A new module must be pure Go and licensed under Apache 2.0, MIT, BSD, or ISC; open an issue before adding one. Never import Loki, Grafana, or any AGPL or GPL code.

Approved license exceptions (MPL-2.0, approved by Cloud Exit B.V. on 2026-09-30):

|Module|Reached through|
|---|---|
|`github.com/cyphar/filepath-securejoin`|node_exporter collectors, via `github.com/opencontainers/selinux`|
|`github.com/hashicorp/go-envparse`|node_exporter collectors|

Both are used unmodified. MPL-2.0 is copyleft per file: these modules stay under MPL-2.0, the rest of the agent stays under Apache 2.0, and `NOTICE` names them with their source locations. Modifying their files, or adding any other exception, needs a new explicit approval. `internal/deploytest` fails when the go-licenses ignore lists in CI and the `Makefile` differ from this table.

## Style

- Comments are at most one short line and explain a non-obvious why. Rationale belongs in `docs/`.
- Never use em dashes or en dashes in code, comments, docs, or commit messages.
- Every behavior ships with tests that exercise it.
- Keep commit subjects short and imperative.

## Reporting security issues

Do not open public issues for vulnerabilities. Follow `SECURITY.md`.

## Code of conduct

Participation in this project is governed by `CODE_OF_CONDUCT.md`.
