# Release and CI/CD

Every push to `main` that passes every gate publishes a new version. There are no manual release steps.

## Workflows

|Workflow|Trigger|Purpose|
|---|---|---|
|`ci.yml`|pull requests, merge queue, pushes to other branches|Runs `quality.yml` and `artifacts.yml` in snapshot mode, plus the DCO check.|
|`quality.yml`|called|`go build`, `go vet`, gofmt, golangci-lint, `go test -race`, govulncheck, go-licenses (Apache-2.0, MIT, BSD, ISC only), forbidden-module check, protocol contract suite (Go vectors and the Python oracle), fuzz smoke, chart lint (`helm lint`, `ct lint`), kubeconform schema validation across Kubernetes 1.27 to 1.37, chart render assertions (`internal/deploytest`), reproducible build.|
|`artifacts.yml`|called|Builds once and gates on those exact artifacts (list below).|
|`release.yml`|push to `main` (minor bump), or manual (minor or major)|Version, quality, artifacts, publish, verify.|
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

Every push or merge to `main` releases a new minor version (`0.2.0`, `0.3.0`, ...). A major version is only ever released by running `release` manually (Actions, release, Run workflow, bump `major`). The image, the binaries and packages, and the chart all carry the same version.

The `version` job computes `max(Chart.yaml version, latest vX.Y.Z tag)` plus one minor (or major) and reserves it by pushing the annotated tag `vX.Y.Z` on the built commit. Tags cannot be overwritten, so a run that loses the race takes the next version; every run gets its own version even when several pushes land together, which is why the workflow has no concurrency group (a group would cancel pending runs). A run that published nothing (its gates failed, or publishing stopped before the first image tag) deletes its reserved tag again (`unreserve-version.sh`); once the image tag, chart, packages, or release exist, the tag stays, so a version is never reused for different artifacts.

The publish job, in order:

1. signs every release file with cosign keyless signing, writing a `<file>.sigstore.json` Sigstore bundle next to it;
2. tags the gated candidate image `X.Y.Z` and signs it, and moves `latest` to it when it is the newest release;
3. pushes the chart package to `oci://ghcr.io/<owner>/charts/exitmesh-agent` as version `X.Y.Z` and signs it;
4. updates the signed APT and YUM repository on GitHub Pages (newest 10 versions per architecture; every version stays attached to its GitHub release), rebuilding on the new tip when a concurrent release pushed first;
5. creates the GitHub release with the contract versions (History Protocol, state schema, rule engine), the image and chart digests, pinned `helm`, `apt`, and `dnf` commands, and verification commands;
6. commits the `Chart.yaml` `version` and `appVersion` bump to `main` as `release: vX.Y.Z [skip ci]`, unless `main` already records a newer version.

The `verify` job then checks every signature, pulls the published chart and renders it with the published digest, and installs the published package from the APT and YUM repositories in clean Debian and Rocky containers.

The bump commit contains `[skip ci]`, so it starts no workflow.

Installing a published version:

```sh
helm install exitmesh-agent oci://ghcr.io/cloud-exit/charts/exitmesh-agent --version X.Y.Z --namespace default ...
docker pull ghcr.io/cloud-exit/exitmesh-agent:X.Y.Z
```

## One-time setup

|Setting|Why|
|---|---|
|Secret `PACKAGE_SIGNING_KEY`|ASCII-armored GPG private key that signs deb and rpm packages and the repository metadata. Separate from rule bundle signing keys, which belong to each ExitMesh deployment. Without it, packages are unsigned and the repository is not published (the run warns).|
|Secret `PACKAGE_SIGNING_PASSPHRASE`|Passphrase of that key, if it has one.|
|GitHub Pages|Serve from the `gh-pages` branch, root folder. The first release creates the branch.|
|Branch protection on `main`, tag rules|Allow `github-actions[bot]` to push the bump commit to `main` and to create and delete `v*` tags (bypass list), or the version or publish job fails at the push.|
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
