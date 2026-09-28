# exitmesh-agent command line

`exitmesh-agent` is one static binary for every role (`node`, `coordinator`, `host`) and for the administration tasks around them. The role comes from the configuration file ([configuration.md](configuration.md)), not from a flag.

```
exitmesh-agent <command> [flags]
```

Flags use Go syntax: `--flag value`, `--flag=value`, or a single dash. `exitmesh-agent help` lists the commands and `exitmesh-agent <command> -h` prints the flags of one command.

|Exit status|Meaning|
|---|---|
|`0`|Success, or help was printed.|
|`1`|The command failed; the reason is printed on standard error.|
|`2`|Invalid invocation: unknown command, unknown or missing flag, unexpected argument, malformed `--args`.|

## Commands

|Command|Used by|Needs a running agent|
|---|---|---|
|[`run`](#run)|systemd unit, DaemonSet, StatefulSet|no|
|[`version`](#version)|operators, release checks|no|
|[`status`](#status)|operators|yes|
|[`investigate`](#investigate)|operators, air-gap profile|yes|
|[`export`](#export)|air-gap profile|no (host); yes (coordinator)|
|[`commit`](#commit)|air-gap profile|yes|
|[`deenroll`](#deenroll)|package purge flow, operators|no (host); yes (coordinator)|
|[`prepare-state`](#prepare-state)|node DaemonSet init container|no|
|[`cleanup`](#cleanup)|uninstall cleanup DaemonSet|must not be running|
|[`purge-state`](#purge-state)|deb and rpm purge, tarball `uninstall.sh --purge`|must not be running|
|[`prepare-image`](#prepare-image)|golden image preparation|must not be running|

Commands marked "needs a running agent" talk to the local administration socket `<stateDir>/admin.sock` (HTTP over a unix socket with mode 0600, never a network listener), so they run as the agent's user (`sudo -u exitmesh` on hosts, `kubectl exec` in Kubernetes). They fail with `is the agent running?` when the socket is absent.

### run

```
exitmesh-agent run --config <file>
```

|Flag|Required|Meaning|
|---|---|---|
|`--config`|yes|Agent configuration file. The packages use `/etc/exitmesh/agent.yaml`; the chart mounts `/etc/exitmesh/config/agent.yaml`.|

Loads and validates the configuration, then runs the role it names until `SIGTERM` or `SIGINT`, which shut the agent down gracefully (offsets, cursors, and export files are flushed; the spool and state lock are released). Diagnostics go to standard error as JSON (`logging.format: json`, the default) or logfmt text (`logging.format: text`) at `logging.level`; every record passes the redaction handler first.

Runtime limits (PRD 6.5): when `GOMEMLIMIT` is not set in the environment, the agent reads its cgroup memory limit (cgroup v2 `memory.max`, else v1 `memory.limit_in_bytes`, taking the tightest of its cgroup and its ancestors) and sets the Go memory limit to 90 percent of it. The packaged systemd unit sets `GOMEMLIMIT=172MiB` explicitly under `MemoryMax=192M`. `GOMAXPROCS` follows the CPU quota through the Go runtime's own cgroup support.

In the host role the agent refuses to start on a Kubernetes node (a running `kubelet` or `kubelite`, or kubelet state on disk) and points to the Helm chart; see [host-facts.md](host-facts.md#kubernetes-node-detection). A host that was de-enrolled exits with status 0 and a message instead of restarting in a loop.

### version

```
exitmesh-agent version
```

Prints the agent version, commit, and build date (set at build time with `-ldflags "-X main.version=... -X main.commit=... -X main.date=..."`), the History Protocol version, the record schema version, the rule engine version, the bundle schema version, and the Go version and platform. No flags.

### status

```
exitmesh-agent status --config <file>
```

|Flag|Required|Meaning|
|---|---|---|
|`--config`|yes|Agent configuration file; `stateDir` locates the admin socket.|

Prints the running agent's status document as indented JSON: identity (target, writer ID, incarnation, epoch, machine ID and any identity conflict), session (connected, committed head, backlog, last error, halt), spool use and projected outage window, disk cap use, TSDB and metrics collection, active bundle and rule states, unavailable fact scopes, scrape targets, log inputs, and evidence-limited rules.

### investigate

```
exitmesh-agent investigate --config <file> --tool <name> [--args <json>|@<file>]
```

|Flag|Required|Meaning|
|---|---|---|
|`--config`|yes|Agent configuration file.|
|`--tool`|yes|Tool name: `state.query`, `graph.query`, `promql.query`, `logql.query`, `logsql.query`, `lookback.query`, `evidence.query`, or `finding.save`.|
|`--args`|no|Tool arguments as a JSON object, or `@path` to read them from a file. Default `{}`.|

Runs one investigation locally through the running agent (PRD A9), with the same parsing, scope injection, limits, and audit as an investigation over the tunnel, and prints the result as indented JSON. Nothing is retained. The call times out after `investigation.timeout` plus 30 seconds.

```sh
sudo -u exitmesh exitmesh-agent investigate --config /etc/exitmesh/agent.yaml --tool promql.query \
  --args '{"requester":"local:admin","purpose":"disk check","scope":{"cluster":true},"query":"node_filesystem_avail_bytes","window":{"start":1790000000000,"end":1790000600000}}'
```

### export

```
exitmesh-agent export --config <file> --out <path>|- [--from <seq>]
```

|Flag|Required|Meaning|
|---|---|---|
|`--config`|yes|Agent configuration file.|
|`--out`|yes|Output file, or `-` for standard output. A file is written to `<path>.tmp` with mode 0600 and renamed when complete.|
|`--from`|no|First sequence to export. Default 0: every spooled record.|

Writes an export file (History Protocol section 10: `EMHPX1`, a header with target, writer ID, incarnation, epoch, committed head, export time, and agent version, then the exact bytes of every spooled record in chain order). For the host role, a stopped agent's spool is read directly after taking the state lock; while the agent runs, the export goes through its admin socket. Other roles export through the admin socket only. In the air-gap profile the exported records are marked transmitted first, so they are never coalesced before ExitMesh confirms them.

In the air-gap profile the running agent also writes rolling export files on its own into `airgap.exportDir`: `exitmesh-<target>-<epoch>-<first>-<last>.emhpx`, finished every 64 MiB, every hour, at an epoch change, and at shutdown. A file that is still being written ends in `.emhpx.part`; one left behind by a crash is discarded at the next start and its records, still spooled, are exported again.

### decode

```sh
exitmesh-agent decode --in <export file|->
```

Prints an export file (from `export`) as JSON lines for support: first the export header, then one object per record with named fields (record id, type, chain position, writer, incarnation, record hash, the chain hash when the file starts at the beginning of an epoch, and the decoded checkpoint, delta, range, or finding body; range records show their unavailable interior). Every record is strictly decoded and chain-checked; a malformed file fails with the reason. Nothing is modified.

### commit

```
exitmesh-agent commit --config <file> --receipt <file>
```

|Flag|Required|Meaning|
|---|---|---|
|`--config`|yes|Agent configuration file.|
|`--receipt`|yes|Commit receipt downloaded from ExitMesh after importing an export.|

Applies an air-gap commit receipt through the running agent: records at or below the receipt's sequence are deleted from the spool after the recovery snapshot covers them, and finished export files whose records are all committed are removed. The receipt is JSON:

```json
{"epoch": "<32 hex digits>", "seq": 1234, "chain_hash": "<64 hex digits>"}
```

A receipt whose chain hash does not match the spool is refused. Receipts apply only in the air-gap profile.

### deenroll

```
exitmesh-agent deenroll --config <file> [--reason <text>]
```

|Flag|Required|Meaning|
|---|---|---|
|`--config`|yes|Agent configuration file.|
|`--reason`|no|Reason recorded in ExitMesh. Default `de-enrolled with exitmesh-agent deenroll`.|

Explicit de-enrollment (PRD A6): ExitMesh revokes the credential, the agent deletes it locally, halts its writer, and stops. This is the only way the agent revokes its own credential; stopping, removing, or purging never does. For a running agent the request goes through the admin socket and needs an active session. For a stopped host agent the command takes the state lock, connects with the stored credential, delivers spooled records (waiting up to 30 seconds), and then de-enrolls. It is not available in the air-gap profile, where an administrator de-enrolls the host in ExitMesh.

### prepare-state

```
exitmesh-agent prepare-state --dir <dir> --uid <n> --gid <n>
```

|Flag|Required|Meaning|
|---|---|---|
|`--dir`|yes|State directory (`/var/lib/exitmesh`), an absolute path other than `/`.|
|`--uid`|yes|Owner user ID of the agent.|
|`--gid`|yes|Owner group ID of the agent.|

Runs as root with only `CAP_CHOWN` in the node DaemonSet's init container. If the directory already has owner `uid:gid` and mode 0700 it changes nothing. Otherwise it changes the owner to root (so the chmod needs no other capability), sets mode 0700, and changes the owner to `uid:gid`. Only the top directory is touched; a missing directory is created with mode 0700; a symbolic link is refused.

### cleanup

```
exitmesh-agent cleanup --dir <dir> [--wait]
```

|Flag|Required|Meaning|
|---|---|---|
|`--dir`|yes|State directory, an absolute path other than `/`.|
|`--wait`|no|After deleting, release the lock and block until `SIGTERM` or `SIGINT`.|

Used by the uninstall cleanup DaemonSet ([uninstall.md](uninstall.md)). Takes the directory lock (`<dir>/LOCK`); if an agent holds it, deletes nothing and exits 1 with a message, so the kubelet retries. Otherwise deletes the contents (the lock file last) and the directory itself unless it is a mount point, which is the case for the chart's hostPath volume (`EBUSY` is tolerated). A missing directory counts as clean. With `--wait` the pod stays Running as the per-node completion signal.

### purge-state

```
exitmesh-agent purge-state --dir <dir>
```

|Flag|Required|Meaning|
|---|---|---|
|`--dir`|yes|State directory, an absolute path other than `/`.|

Used by `apt purge`, `EXITMESH_PURGE=1 dnf remove`, and `uninstall.sh --purge` (PRD H12). Takes the lock and deletes the directory like `cleanup`; exits 1 and deletes nothing if the lock is held. Purging does not de-enroll.

### prepare-image

```
exitmesh-agent prepare-image --dir <dir>
```

|Flag|Required|Meaning|
|---|---|---|
|`--dir`|yes|State directory, an absolute path other than `/`.|

For golden images (PRD H14). Refuses while the service holds the lock. Otherwise deletes the identity, credential, spool, and all other state, leaving an empty directory, so every instance started from the image enrolls as a new target. It prints the reminder that the image tooling must also reset `/etc/machine-id`; the agent does not write outside its state directory.
