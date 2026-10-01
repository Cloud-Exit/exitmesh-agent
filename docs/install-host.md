# Installing on Linux hosts

Host mode runs one `exitmesh-agent` process per Linux host that combines the node agent and coordinator roles: host state, `node_*` metrics, the journal and allowlisted log files, local rule evaluation, a durable spool, and one outbound tunnel to ExitMesh. It needs no Kubernetes. On a Kubernetes node (a host running kubelet) the agent refuses to start in host mode and points to the Helm chart, so collection is never duplicated.

## Packages

Each release publishes, for x86_64 and arm64:

|Form|File|Notes|
|---|---|---|
|deb|`exitmesh-agent_<version>_amd64.deb`, `_arm64.deb`|Debian, Ubuntu|
|rpm|`exitmesh-agent-<version>-1.x86_64.rpm`, `.aarch64.rpm`|RHEL, Rocky, Alma, Fedora, SUSE|
|tarball|`exitmesh-agent_<version>_linux_<arch>.tar.gz`|Any systemd distribution; `install.sh` and `uninstall.sh` inside|

The binary is static (`CGO_ENABLED=0`) and needs no system libraries. Packages are signed with the package repository key; release files, checksums, and SBOMs are signed with cosign (see [security.md](security.md#verifying-releases)). The supported distributions and kernels are listed in the compatibility matrix.

## Package repository

Every release is also published to a signed APT and YUM repository at `https://cloud-exit.github.io/exitmesh-agent` (repository metadata and packages are signed with the ExitMesh package key, which is separate from rule bundle signing keys):

```sh
# Debian and Ubuntu
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://cloud-exit.github.io/exitmesh-agent/exitmesh-archive-keyring.gpg | sudo tee /etc/apt/keyrings/exitmesh-archive-keyring.gpg >/dev/null
curl -fsSL https://cloud-exit.github.io/exitmesh-agent/exitmesh-agent.sources | sudo tee /etc/apt/sources.list.d/exitmesh-agent.sources >/dev/null
sudo apt-get update && sudo apt-get install exitmesh-agent=<version>

# RHEL, Rocky, Alma, Fedora, Amazon Linux
curl -fsSL https://cloud-exit.github.io/exitmesh-agent/exitmesh-agent.repo | sudo tee /etc/yum.repos.d/exitmesh-agent.repo >/dev/null
sudo dnf install exitmesh-agent-<version>

# openSUSE and SLES
sudo zypper addrepo https://cloud-exit.github.io/exitmesh-agent/exitmesh-agent.repo
sudo zypper install exitmesh-agent-<version>
```

The repository keeps the newest ten versions per architecture; every version stays attached to its GitHub release. For air-gapped hosts, mirror the repository or copy the packages from the release.

## Install from files

```sh
# Debian and Ubuntu
sudo apt install ./exitmesh-agent_<version>_amd64.deb
# RHEL family
sudo dnf install ./exitmesh-agent-<version>-1.x86_64.rpm
# tarball
tar -xzf exitmesh-agent_<version>_linux_amd64.tar.gz && sudo ./install.sh
```

The tarball installs the binary to `/usr/local/bin` (override with `PREFIX=`), the unit to `/etc/systemd/system`, and the sysusers entry to `/etc/sysusers.d`.

Then configure and start. The endpoint, enrollment token, and trust root come from the ExitMesh connector page; the trust root is the public half of your workspace's agent trust root, which a workspace administrator generates once in ExitMesh under Settings > General > Encryption > Agent trust root (agent connections cannot be created before it exists):

```sh
sudo sed -i 's#^endpoint: ""#endpoint: "https://<endpoint from the connector page>"#' /etc/exitmesh/agent.yaml
sudo sed -i 's#^  roots: \[\]#  roots: ["<root id>:<root public key>"]#' /etc/exitmesh/agent.yaml
printf '%s\n' '<enrollment token>' | sudo install -m 0640 -o root -g exitmesh /dev/stdin /etc/exitmesh/enrollment-token
sudo systemctl start exitmesh-agent
systemctl status exitmesh-agent
```

The package enables the unit at install. It starts only once `/etc/exitmesh/enrollment-token` exists or `/var/lib/exitmesh` already holds state, so an unconfigured host never crash-loops. On first connect the token (`emx1_h_...` for a host, `emx1_g_...` for a host group) is exchanged for a per-host credential, stored in `/var/lib/exitmesh` with mode 0600 and bound to this host's writer ID and machine ID. The token file can be removed afterwards.

## What the package installs

|Path|Purpose|
|---|---|
|`/usr/bin/exitmesh-agent`|The agent binary.|
|`/usr/lib/systemd/system/exitmesh-agent.service`|Hardened unit.|
|`/usr/lib/sysusers.d/exitmesh-agent.conf`|The `exitmesh` system user.|
|`/etc/exitmesh/agent.yaml`|Configuration, kept on upgrade without prompting. The deb installs it from `/usr/share/exitmesh-agent/agent.yaml` only when it is missing and removes it on purge; the rpm marks it `%config(noreplace)`, so a changed default arrives as `agent.yaml.rpmnew`. Keys are in [configuration.md](configuration.md).|
|`/var/lib/exitmesh`|State: spool, TSDB, cursors, offsets, alert state, credential. Mode 0700, owned by `exitmesh`. The only path the agent writes.|
|`/etc/systemd/system/exitmesh-agent.service.d/10-adm.conf`|Written at install only where an `adm` group exists.|

## User, groups, and privileges

The agent runs as the dedicated non-root system user `exitmesh` (no shell, no sudo, no login). It never runs as root, never executes commands, and never uses container runtime sockets.

|Group|Why|
|---|---|
|`systemd-journal`|Read the system journal from the journal files.|
|`adm`|Read `/var/log` files on distributions that grant log access to `adm` (Debian and Ubuntu). Added by a drop-in only where the group exists, because systemd refuses to start a unit that names a missing group.|

**Disclosure: membership in `systemd-journal` and `adm` grants read access to all system logs on the host.** The agent reads only the journal and the log files in `host.logFiles` (default `/var/log`), redacts matched lines before they reach the evidence ring, the spool, or diagnostics, and never transmits raw logs; but the permission itself is host-wide. Remove `/var/log` from `host.logFiles` or set `host.journal: false` to narrow what is read.

The unit enforces the boundary: `NoNewPrivileges=yes`, `ProtectSystem=strict` with `ReadWritePaths=/var/lib/exitmesh` as the only writable path, `ProtectHome=yes`, `PrivateTmp=yes`, an empty `CapabilityBoundingSet=` and `AmbientCapabilities=`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `LockPersonality`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, a `@system-service` system call filter, `MemoryMax=192M`, `CPUQuota=10%`, and `GOMEMLIMIT=172MiB`. Facts that cannot be collected without extra privilege (for example the process owning another user's listening socket) are reported as unavailable with their reason, never silently omitted.

## Resource budget

One process uses at most 100 millicores and 192 MiB of memory, including a 16 MiB evidence ring. Disk under `/var/lib/exitmesh` is capped at 2 GiB by the agent: a 1 GiB spool reserve nothing else may consume, TSDB up to 768 MiB, and the remainder for cursors, offsets, alert state, and credentials. Under disk pressure TSDB retention shrinks first.

## Local metrics endpoints

List loopback `/metrics` endpoints to scrape in `host.metricsEndpoints` (for example `http://127.0.0.1:9100/metrics`). Non-loopback addresses are refused unless `host.allowNonLoopback: true`.

## Golden images and cloning

**Golden images must exclude `/var/lib/exitmesh`.** The directory holds the writer ID, credential, and epoch; a clone that boots with a copy presents the same identity as its source, which the control plane detects as an identity conflict and resolves by rejecting records until an administrator decides. Before capturing an image of a host that already ran the agent:

```sh
sudo systemctl stop exitmesh-agent
sudo exitmesh-agent prepare-image --dir /var/lib/exitmesh
sudo rm -f /etc/exitmesh/enrollment-token
```

`prepare-image` takes the state lock, removes the identity and all state, and leaves an empty directory, so every instance started from the image enrolls as a new target. Provide the enrollment token per instance at boot (cloud-init or your configuration management); a host-group token (`emx1_g_...`) lets many instances share one token while each receives its own credential and `target_id`.

## Reinstall and identity

Removing the package keeps `/var/lib/exitmesh`, so a reinstall resumes the same `target_id`, writer ID, and epoch. Purging deletes it; a reinstall after purge is a new enrollment unless an administrator explicitly binds it to the previous target. See [uninstall.md](uninstall.md#hosts).

## Upgrades

Install the newer package with your package manager (`apt install exitmesh-agent=<version>`, `dnf install exitmesh-agent-<version>`, or `install.sh` from the newer tarball). The service restarts on the new binary; state migrates in place and the writer ID never changes. See [upgrades.md](upgrades.md#hosts).
