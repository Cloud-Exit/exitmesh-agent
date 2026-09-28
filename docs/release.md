# Release and CI/CD

Every push to `main` that passes every gate publishes a new version. There are no manual release steps.

## Workflows

|Workflow|Trigger|Purpose|
|---|---|---|
|`ci.yml`|pull requests, merge queue, pushes to other branches|Runs `quality.yml` and `artifacts.yml` in snapshot mode, plus the DCO check.|
|`quality.yml`|called|`go build`, `go vet`, gofmt, golangci-lint, `go test -race`, govulncheck, go-licenses (Apache-2.0, MIT, BSD, ISC only), forbidden-module check, protocol contract suite (Go vectors and the Python oracle), fuzz smoke, chart lint (`helm lint`, `ct lint`), kubeconform schema validation across Kubernetes 1.27 to 1.37, chart render assertions (`internal/deploytest`), reproducible build.|
|`artifacts.yml`|called|Builds once and gates on those exact artifacts (list below).|
|`release.yml`|push to `main`, or manual with a bump level|Version, quality, artifacts, publish, verify.|
|`loki-oracle.yml`|LogQL changes, nightly|Differential tests of the LogQL subset against a real Loki.|

`artifacts.yml` builds:

- static `exitmesh-agent` binaries for linux/amd64 and linux/arm64 (`CGO_ENABLED=0`, `-trimpath`, fixed build ID and timestamps), deb and rpm packages, tarballs, checksums, and SBOMs with GoReleaser;
- the Helm chart package;
- in release mode, a candidate multi-arch image pushed by digest as `ghcr.io/<owner>/exitmesh-agent:candidate-<sha>`.

It then runs these gates against the artifacts it built:

|Gate|What it proves|
|---|---|
|static check|No program interpreter and no shared library dependency in either binary; both run (`version`) on amd64 and, through QEMU, arm64.|
|package smoke|Install, upgrade from the previous GitHub release, configuration and state preservation, the missing `trust.roots` message, remove keeps `/var/lib/exitmesh`, reinstall resumes, purge deletes it; on Debian 12, Ubuntu 22.04 and 24.04, Rocky 9, Fedora 41, Amazon Linux 2023, openSUSE Leap 15.6.|
|tarball smoke|`install.sh`, `uninstall.sh`, and `uninstall.sh --purge` under systemd.|
|host smoke|The real `.deb` under systemd on the runner against `exitmesh-refcp`: enrollment, committed records, health reports, runs as `exitmesh` with `ProtectSystem=strict`, `NoNewPrivileges`, and an empty capability set, writes nothing outside `/var/lib/exitmesh`, admin socket, restart resumes the same epoch, clean stop, purge.|
|kind|The exact chart package and image on Kubernetes 1.34 to 1.37 against `exitmesh-refcp`: namespace validation, enrollment, first checkpoint committed, every node agent registered on the published bundle, PSA labels, read-only RBAC, host state directory ownership, certificate reuse on upgrade, uninstall with the cleanup DaemonSet and PVC deletion.|

## Versioning

The next version is `max(Chart.yaml version, latest vX.Y.Z tag)` incremented at the patch level (or minor or major when started manually with `workflow_dispatch`). Because the latest tag counts, a release that fails after tagging never lets a later run reuse its version.

The publish job, in order:

1. commits the `Chart.yaml` `version` and `appVersion` bump as `release: vX.Y.Z [skip ci]`, tags the built commit `vX.Y.Z`, and pushes both with `git push --atomic`, rebasing and retrying when `main` moved;
2. signs every release file with cosign keyless signing;
3. tags the gated candidate image `X.Y.Z` and `latest` (same digest) and signs it;
4. pushes the chart package to `oci://ghcr.io/<owner>/charts/exitmesh-agent` and signs it;
5. updates the signed APT and YUM repository on GitHub Pages (newest 10 versions per architecture; every version stays attached to its GitHub release);
6. creates the GitHub release with the contract versions (History Protocol, state schema, rule engine), the image and chart digests, pinned `helm`, `apt`, and `dnf` commands, and verification commands.

The `verify` job then checks every signature, pulls the published chart and renders it with the published digest, and installs the published package from the APT and YUM repositories in clean Debian and Rocky containers.

The bump commit contains `[skip ci]`, so it starts no workflow.

## One-time setup

|Setting|Why|
|---|---|
|Secret `PACKAGE_SIGNING_KEY`|ASCII-armored GPG private key that signs deb and rpm packages and the repository metadata. Separate from rule bundle signing keys, which belong to each ExitMesh deployment. Without it, packages are unsigned and the repository is not published (the run warns).|
|Secret `PACKAGE_SIGNING_PASSPHRASE`|Passphrase of that key, if it has one.|
|GitHub Pages|Serve from the `gh-pages` branch, root folder. The first release creates the branch.|
|Branch protection on `main`|Allow `github-actions[bot]` to push the bump commit and the tag (bypass list), or the publish job fails at the push.|
|ghcr package visibility|`exitmesh-agent` and `charts/exitmesh-agent` are private after their first push; make them public, or install with `imagePullSecrets`.|
|Actions permissions|Workflows need read and write permissions (`contents`, `packages`) and OIDC tokens (`id-token: write`) for keyless signing.|
|Token scope for maintainers|Pushing changes to `.github/workflows` requires a token with the `workflow` scope.|

Generating the package signing key offline:

```sh
gpg --quick-generate-key "ExitMesh packages <contact@cloud-exit.com>" ed25519 sign 3y
gpg --armor --export-secret-keys "ExitMesh packages" > package-signing.asc   # store as PACKAGE_SIGNING_KEY, then delete
gpg --armor --export "ExitMesh packages" > exitmesh-archive-keyring.asc      # public; the repository publishes it too
```

Rotating the key: publish the new public key, set the new secret, and announce it; clients re-import `exitmesh-archive-keyring.gpg` from the repository.

## Local equivalents

```sh
make release-check      # goreleaser check
make release-snapshot   # snapshot binaries, packages, tarballs in dist/
make package-smoke IMAGE=rockylinux:9 OLD=previous   # needs docker
make chart-validate     # kubeconform (needs kubeconform on PATH)
make kind-e2e           # needs kind, ko, helm, docker, and a cluster named exitmesh
make next-version BUMP=minor
```
