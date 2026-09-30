# Upgrades

Neither the node agent nor the coordinator self-updates, and neither identity has RBAC to modify its own DaemonSet or StatefulSet. Upgrades are always an action you take: a Helm command, a merged pull request, or a package manager command. ExitMesh flags an agent as outdated when it is below the minimum version for its assigned rule bundle or affected by a known-fixed defect; a newer optional version is shown separately. Rules that need a newer engine are reported as "unsupported: agent upgrade required" until you upgrade.

## Helm

The connector page shows the exact command with the pinned chart version and image digest. Its form is:

```sh
helm upgrade exitmesh-agent oci://ghcr.io/cloud-exit/charts/exitmesh-agent \
  --version 0.2.0 \
  --namespace default \
  --reuse-values \
  --set image.digest=sha256:<image digest for 0.2.0> \
  --wait --timeout 10m
```

If you keep values in a file, use `-f exitmesh-values.yaml` instead of `--reuse-values` and record `image.digest` in that file. Every release's notes list the image digest and the chart digest. Verify both before upgrading:

```sh
cosign verify ghcr.io/cloud-exit/exitmesh-agent@sha256:<image digest> \
  --certificate-identity-regexp '^https://github.com/cloud-exit/exitmesh-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
helm pull oci://ghcr.io/cloud-exit/charts/exitmesh-agent --version 0.2.0
```

During the upgrade the coordinator pod is replaced (the old pod terminates before the new one starts) and node agents roll one node at a time without surge, so there is never more than one writer per spool or per node directory. Node agents spool while the coordinator restarts. The generated node API certificate is reused across upgrades.

## GitOps pull request

Where a configuration repository is recorded at enrollment, ExitMesh opens a pull request against it that bumps the chart version (and the image digest, where your manifests pin one). This needs a GitHub App installation scoped to that one repository and the manifest path recorded at enrollment. ExitMesh never merges; merging is your action, after which Flux, Argo CD, or Sveltos apply the new version. The pull request path works whenever the repository host is reachable from ExitMesh, even if the cluster itself is not.

Example of the change in a Flux `OCIRepository` or `HelmRelease`, an Argo CD `Application`, or a Sveltos `ClusterProfile`:

```diff
-    semver: "0.1.0"
+    semver: "0.2.0"
```

## Epochs and state migration

Every upgrade prompt and every release's notes state:

- **Epoch:** whether the new version resumes the current epoch or requires a new baseline (a new epoch opened at the committed head of the current one, followed by a full checkpoint).
- **State formats:** whether the coordinator spool and `/var/lib/exitmesh` migrate in place. Migrations run at startup under the state lock before anything is transmitted; downgrading across a migration is not supported and the release notes say so when it applies.
- **Writer ID:** an upgrade never changes the writer ID. The coordinator keeps its PVC and each node keeps `/var/lib/exitmesh`; a new writer ID only ever results from losing or purging that state.

Release notes also state the supported History Protocol, state schema, and rule engine versions; the control plane's compatibility matrix decides which agent versions it accepts.

## Air-gap mirroring

Air-gapped clusters mirror the image and chart before upgrading. The connector page and the release notes give the image reference with digest; mirror by digest, not by tag:

```sh
crane copy ghcr.io/cloud-exit/exitmesh-agent@sha256:<digest> registry.internal.example/exitmesh/exitmesh-agent@sha256:<digest>
helm pull oci://ghcr.io/cloud-exit/charts/exitmesh-agent --version 0.2.0
helm push exitmesh-agent-0.2.0.tgz oci://registry.internal.example/charts
cosign copy ghcr.io/cloud-exit/exitmesh-agent@sha256:<digest> registry.internal.example/exitmesh/exitmesh-agent
helm upgrade exitmesh-agent oci://registry.internal.example/charts/exitmesh-agent --version 0.2.0 \
  --namespace default --reuse-values \
  --set image.repository=registry.internal.example/exitmesh/exitmesh-agent \
  --set image.digest=sha256:<digest>
```

`cosign copy` carries the signatures so they can be verified inside the air gap. The GitOps pull request path also works for air-gapped clusters whose configuration repository is reachable from ExitMesh. See [airgap.md](airgap.md) for bundles.

## Hosts

The connector shows the exact package manager command with a pinned version:

```sh
sudo apt-get update && sudo apt-get install exitmesh-agent=0.2.0   # Debian, Ubuntu
sudo dnf install exitmesh-agent-0.2.0                              # RHEL family
sudo zypper install exitmesh-agent-0.2.0                           # SUSE
```

These use the signed package repository described in [install-host.md](install-host.md#package-repository). Every merge to `main` publishes a new minor release ([release.md](release.md)); pin versions in configuration management and upgrade deliberately.

For tarball installs, run `install.sh` from the newer tarball. Package upgrades restart the service on the new binary and keep `/etc/exitmesh/agent.yaml` and `/var/lib/exitmesh`; the writer ID does not change. Where a configuration repository is recorded at enrollment, ExitMesh opens a pull request bumping the version pin in it. Air-gapped hosts install packages mirrored from the signed repository.
