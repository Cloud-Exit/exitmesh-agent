# Host facts

Generated from `internal/hostfacts/catalog.go` and `internal/hostfacts/docs.go` by `go test ./internal/hostfacts -run TestCatalogDocCurrent -update`. Do not edit by hand.

Host mode collects the facts below as resources of kind `host/<Kind>` and relationships as edges (PRD H4). Every fact and edge has a scope key; each collection sets the scope to complete, partial, or unavailable with a reason code (PRD H4a). A fact that is not obtainable as the non-root `exitmesh` user is reported unavailable with its reason, never omitted and never rendered empty. When a fact becomes unavailable, its last collected resources and edges are kept and only the scope status changes, so a collection failure is never expressed as a deletion.

Excluded by design: file contents, home directories, environment values, container inventory, and process command lines except for comm names on the administrator allowlist, which are redacted before they leave the collector.

### Identity and churn

UIDs are derived from target-local identity and are stable across collections: `host:unit:<name>`, `host:timer:<name>`, `host:package:<manager>|<name>|<arch>` (plus the version when several versions of one name and architecture are installed), `host:mount:<mount point>|<source>`, `host:filesystem:<fstype>|<source>` (plus the first mount point for sources that are not device paths), `host:blockdevice:<name>`, `host:interface:<name>`, `host:socket:<protocol>|<address>|<port>`, and `host:process:<pid>|<start time>` so a reused PID is a new process. High-churn values are bucketed or excluded: used space is reported in 10 percent buckets with a two point hysteresis, free bytes are excluded, a timer's next elapse is reported only as `scheduled`, its last trigger only as a UTC day, temporary IPv6 addresses are dropped, and CPU frequency, uptime, and restart counters are not collected. Repeated collection of an unchanged host produces zero ops.

Sockets listening on the same protocol, address, and port (for example `SO_REUSEPORT` workers) are one resource with all inodes listed. The owning process is the lowest PID of the agent's UID holding one of the inodes; sockets of other users carry `unavailable_edges: [process, unit]` and `unavailable_reason: other_user_fd`, keeping their address and owning UID.

Unit types collected by default: service, socket, target, timer, mount, automount, swap, path, slice. Device units mirror block devices and terminals, and scope units are transient sessions and containers, so both are excluded. Mount points under `/dev`, `/proc`, `/sys`, `/run/credentials`, `/run/user`, `/run/netns`, `/run/docker`, `/run/containerd`, `/run/snapd/ns`, `/var/lib/docker`, `/var/lib/containers/storage`, and `/var/lib/kubelet/pods`, pseudo filesystem types, and `veth` interfaces are excluded by default for the same reason.

Package databases are re-read only when their size or modification time changes. rpm sqlite databases are read by the in-house read-only SQLite reader (`internal/hostfacts/sqlitedb`), which applies committed write-ahead log frames validated by salt and checksum and is registered as the `database/sql` driver go-rpmdb opens unless another driver already owns that name. The reader takes no SQLite locks, so a read racing an rpm transaction can fail; the last good package list is then kept and the scope reports `read_failed` until the next collection succeeds.

## Facts

|Scope key|Kind|Fields|Source|Permission|As non-root|
|---|---|---|---|---|---|
|`host/fact/os`|`host/OS`|`id`, `id_like`, `name`, `pretty_name`, `version_id`, `version_codename`, `variant_id`|`/etc/os-release`, falling back to `/usr/lib/os-release`|world-readable file|available|
|`host/fact/hostname`|`host/OS`|`hostname`|`uname(2)` nodename|none|available|
|`host/fact/machine_id`|`host/OS`|`machine_id`|`/etc/machine-id`|world-readable file|available|
|`host/fact/kernel`|`host/Kernel`|`sysname`, `release`, `version`, `machine`|`uname(2)`|none|available|
|`host/fact/cpu`|`host/CPU`|`model_name`, `vendor_id`, `logical_cpus`, `cores`, `packages`|`/proc/cpuinfo`|world-readable procfs file|available|
|`host/fact/memory`|`host/Memory`|`mem_total_bytes`, `swap_total_bytes`|`/proc/meminfo`|world-readable procfs file|available|
|`host/fact/block_devices`|`host/BlockDevice`|`device`, `size_bytes`, `rotational`, `removable`, `read_only`, `model`, `partition`, `dm_name`|`/sys/block/<dev>`: `dev`, `size`, `queue/rotational`, `removable`, `ro`, `device/model`, `dm/name`, partition subdirectories|world-readable sysfs|available|
|`host/fact/filesystems`|`host/Filesystem`|`fstype`, `source`, `device`, `size_bytes`, `used_pct_bucket`, `inodes_total`, `capacity_unavailable`|`/proc/self/mountinfo` grouped by superblock, capacity from `statfs(2)` on the first mount point; used space is bucketed to 10 percent|search permission on the mount point path|available; a mount point below a directory the agent cannot search reports `capacity_unavailable`|
|`host/fact/mounts`|`host/Mount`|`mount_point`, `source`, `fstype`, `root`, `device`, `read_only`, `options`|`/proc/self/mountinfo`, excluding pseudo filesystems and per-session or container mount points|world-readable procfs file|available|
|`host/fact/interfaces`|`host/Interface`|`index`, `mtu`, `hardware_addr`, `flags`, `addresses`, `operstate`|netlink link and address dumps (`net.Interfaces`), `/proc/net/if_inet6` to drop temporary IPv6 addresses, `/sys/class/net/<if>/operstate`|none|available|
|`host/fact/sockets`|`host/Socket`|`protocol`, `address`, `port`, `uid`, `uids`, `inodes`, `unavailable_edges`, `unavailable_reason`|`/proc/net/tcp`, `tcp6` (state LISTEN), `udp`, `udp6` (unconnected bound sockets) of the agent's network namespace|world-readable procfs files|available|
|`host/fact/units`|`host/Unit`|`description`, `load_state`, `active_state`, `sub_state`, `unit_file_state`, `fragment_path`|D-Bus `org.freedesktop.systemd1.Manager.ListUnits`; `Unit` properties `FragmentPath`, `UnitFileState`; `Service` property `MainPID`|system bus connection; read-only property queries are allowed to unprivileged clients by the systemd bus policy|available where systemd runs|
|`host/fact/timers`|`host/Timer`|`description`, `load_state`, `active_state`, `sub_state`, `unit_file_state`, `fragment_path`, `scheduled`, `last_trigger_day`|D-Bus `Timer` properties `Unit`, `NextElapseUSecRealtime` (reported only as `scheduled`), `LastTriggerUSec` (bucketed to the UTC day)|system bus connection|available where systemd runs|
|`host/fact/packages`|`host/Package`|`manager`, `name`, `version`, `arch`, `state`|dpkg `/var/lib/dpkg/status`; rpm database (`rpmdb.sqlite`, `Packages.db`, or Berkeley DB `Packages`) via go-rpmdb; apk `/lib/apk/db/installed`|world-readable package databases|available|
|`host/fact/processes`|`host/Process`|`pid`, `comm`, `uid`, `cmdline`|`/proc/<pid>/stat`, `/proc/<pid>/status`; `cmdline` only for allowlisted comm names, redacted. Only unit main processes and socket owners are collected|world-readable procfs files (hidden when procfs is mounted with `hidepid`)|available unless `hidepid` is set|

## Edges

|Scope key|From|Type|To|Source|Permission|As non-root|
|---|---|---|---|---|---|---|
|`host/edge/unit_process`|`host/Unit`|`main_process`|`host/Process`|`Service.MainPID` resolved to `/proc/<pid>/stat`|as host/Process|available|
|`host/edge/mount_device`|`host/Mount`|`device`|`host/BlockDevice`|mountinfo `major:minor`, else the mount source path, matched to `/sys/block` devices and device-mapper names|none|available|
|`host/edge/mount_filesystem`|`host/Mount`|`filesystem`|`host/Filesystem`|mountinfo superblock `major:minor`|none|available|
|`host/edge/partition_disk`|`host/BlockDevice`|`partition_of`|`host/BlockDevice`|partition subdirectories of `/sys/block/<disk>`|none|available|
|`host/edge/package_unit`|`host/Package`|`provides_unit`|`host/Unit`, `host/Timer`|unit `FragmentPath` matched to dpkg `/var/lib/dpkg/info/*.list` or rpm file lists (usr-merge aliases included)|world-readable package databases|available|
|`host/edge/socket_process`|`host/Socket`|`process`|`host/Process`|`socket:[inode]` links in `/proc/<pid>/fd`, read only for processes of the agent's own UID|ptrace read access to the owning process, which a non-root user has only for its own processes|partial: sockets owned by other users report `unavailable_edges` with reason `other_user_fd`|
|`host/edge/socket_unit`|`host/Socket`|`unit`|`host/Unit`|`/proc/<pid>/cgroup` of the owning process matched to a loaded unit|requires the socket to process edge|partial, as the socket to process edge|
|`host/edge/timer_unit`|`host/Timer`|`triggers`|`host/Unit`|`Timer.Unit` property|system bus connection|available where systemd runs|

## Reason codes

|Reason|Meaning|
|---|---|
|`source_absent`|The documented source does not exist on this host (for example no systemd, or no package database).|
|`permission_denied`|The agent user cannot read the source (restrictive modes, or procfs mounted with `hidepid`).|
|`dbus_unavailable`|The system bus or `org.freedesktop.systemd1` is not reachable.|
|`read_failed`|The source exists but reading or parsing it failed.|
|`other_user_fd`|Mapping the socket to its process needs `/proc/<pid>/fd` of another user, which a non-root user cannot read.|
|`owner_not_found`|The socket belongs to the agent's UID but no process of that UID holds it.|
|`dependency_unavailable`|The edge depends on a fact that is unavailable in this collection.|
|`process_vanished`|The process exited between listing and reading.|
|`capacity_permission_denied`|`statfs(2)` on the mount point was denied; the filesystem is reported without capacity.|

## Kubernetes node detection

Host mode refuses to start when `IsKubernetesNode` finds a process whose comm is `kubelet` or `kubelite`, or kubelet state at `/var/lib/kubelet/config.yaml`, `/etc/kubernetes/kubelet.conf`, `/var/lib/rancher/k3s/agent/kubelet.kubeconfig`, or `/var/lib/rancher/rke2/agent/kubelet.kubeconfig` (a state directory that exists but cannot be searched also counts). Such hosts are covered by the Helm chart (PRD H11).

## Host metrics

`internal/hostfacts/nodemetrics` runs upstream node_exporter collectors in process and appends their samples, so `node_*` series and upstream node-exporter rules work unchanged (PRD H5). Default collectors for the H15 budget: `cpu`, `meminfo`, `loadavg`, `filesystem`, `diskstats`, `netdev`, `uname`, `time`, `stat` (which provides `node_boot_time_seconds` on Linux), `filefd`, `vmstat`, `pressure`. The `systemd` collector is disabled by default. A series guard (5,000 series by default) drops whole metric families past the limit and reports them. Collectors run as node_exporter runs them, except that a collector that panics fails alone: it reports `node_scrape_collector_success 0` like any failing collector instead of stopping the process. node_exporter keeps its flags and constructed collectors in process-global state, so one process runs one configuration of procfs, sysfs, and rootfs paths.

## Journal reader

`internal/hostfacts/journal` reads systemd journal files directly, read-only and without cgo (PRD H6, open decision 17). It implements the documented file format: every header revision from 208 to 272 bytes, regular and compact mode, keyed and Jenkins hash modes, and XZ, LZ4, and ZSTD compressed data objects. Entries are read sequentially through the global entry array and their data objects; hash table, field, and tag objects are not needed for that and are not consulted. Files with unknown incompatible flags are refused.

The tests generate journal files with an in-test writer that follows the specification (hash tables with SipHash-2-4 or Jenkins lookup3, per-data entry arrays, the compact tail fields, and compressed data objects in each algorithm); where `journalctl` is installed, the tests also check every generated variant with `journalctl --verify` and read it back through `journalctl`.

It reads every `*.journal` and `*.journal~` file in the configured directories and their machine ID subdirectories, merges entries in realtime order (ties by sequence number), and follows by polling: online and offline files are re-read for appended entries, new files are opened, and rotated files are recognized by file ID so a rename does not re-read them. The cursor (sequence number ID, sequence number, realtime, in journald's `s=;i=;t=` syntax) is persisted in the key-value store after each delivered batch and before returning when the consumer fails, in which case it points before the failed entry; delivery is at least once across a restart. An online file whose tail is not yet fully written is retried on the next poll rather than reported corrupt, and a file that fails to open is retried once its size or modification time changes. Entries at or below the cursor are skipped in files of the cursor's sequence number ID, and entries at or before the cursor's realtime in other files.

Stream labels for LogQL: `unit` from `_SYSTEMD_UNIT`, `syslog_identifier` from `SYSLOG_IDENTIFIER`, `priority` from `PRIORITY`, `transport` from `_TRANSPORT`; the line is `MESSAGE`.

Limits: Forward Secure Sealing tags are skipped and seals are not verified; data object hashes are not verified; a file that is corrupt is skipped from the first invalid object on and reported; a data object larger than the configured maximum (16 MiB by default) is skipped as a field; entries are ordered by realtime across files, so a wall clock step backwards can deliver entries out of sequence order across files.
