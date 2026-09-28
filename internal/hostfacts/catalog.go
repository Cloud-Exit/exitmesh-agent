package hostfacts

import (
	"fmt"
	"strings"
)

// Catalog IDs of facts and edges.
const (
	FactOS           = "fact/os"
	FactHostname     = "fact/hostname"
	FactMachineID    = "fact/machine_id"
	FactKernel       = "fact/kernel"
	FactCPU          = "fact/cpu"
	FactMemory       = "fact/memory"
	FactBlockDevices = "fact/block_devices"
	FactFilesystems  = "fact/filesystems"
	FactMounts       = "fact/mounts"
	FactInterfaces   = "fact/interfaces"
	FactSockets      = "fact/sockets"
	FactUnits        = "fact/units"
	FactTimers       = "fact/timers"
	FactPackages     = "fact/packages"
	FactProcesses    = "fact/processes"

	EdgeIDUnitProcess     = "edge/unit_process"
	EdgeIDMountDevice     = "edge/mount_device"
	EdgeIDMountFilesystem = "edge/mount_filesystem"
	EdgeIDPartitionDisk   = "edge/partition_disk"
	EdgeIDPackageUnit     = "edge/package_unit"
	EdgeIDSocketProcess   = "edge/socket_process"
	EdgeIDSocketUnit      = "edge/socket_unit"
	EdgeIDTimerUnit       = "edge/timer_unit"
)

// Entry catalogues one fact or edge with its source and the permission it needs (H4a).
type Entry struct {
	ID         string
	Kind       string
	EdgeType   string
	ToKinds    []string
	Fields     []string
	Whole      bool
	Source     string
	Permission string
	NonRoot    string
	DependsOn  []string
}

// Catalog lists every host fact and edge the collectors produce.
var Catalog = []Entry{
	{ID: FactOS, Kind: KindOS, Fields: []string{"id", "id_like", "name", "pretty_name", "version_id", "version_codename", "variant_id"},
		Source: "`/etc/os-release`, falling back to `/usr/lib/os-release`", Permission: "world-readable file", NonRoot: "available"},
	{ID: FactHostname, Kind: KindOS, Fields: []string{"hostname"},
		Source: "`uname(2)` nodename", Permission: "none", NonRoot: "available"},
	{ID: FactMachineID, Kind: KindOS, Fields: []string{"machine_id"},
		Source: "`/etc/machine-id`", Permission: "world-readable file", NonRoot: "available"},
	{ID: FactKernel, Kind: KindKernel, Whole: true, Fields: []string{"sysname", "release", "version", "machine"},
		Source: "`uname(2)`", Permission: "none", NonRoot: "available"},
	{ID: FactCPU, Kind: KindCPU, Whole: true, Fields: []string{"model_name", "vendor_id", "logical_cpus", "cores", "packages"},
		Source: "`/proc/cpuinfo`", Permission: "world-readable procfs file", NonRoot: "available"},
	{ID: FactMemory, Kind: KindMemory, Whole: true, Fields: []string{"mem_total_bytes", "swap_total_bytes"},
		Source: "`/proc/meminfo`", Permission: "world-readable procfs file", NonRoot: "available"},
	{ID: FactBlockDevices, Kind: KindBlockDevice, Whole: true, Fields: []string{"device", "size_bytes", "rotational", "removable", "read_only", "model", "partition", "dm_name"},
		Source: "`/sys/block/<dev>`: `dev`, `size`, `queue/rotational`, `removable`, `ro`, `device/model`, `dm/name`, partition subdirectories", Permission: "world-readable sysfs", NonRoot: "available"},
	{ID: FactFilesystems, Kind: KindFilesystem, Whole: true, Fields: []string{"fstype", "source", "device", "size_bytes", "used_pct_bucket", "inodes_total", "capacity_unavailable"},
		Source: "`/proc/self/mountinfo` grouped by superblock, capacity from `statfs(2)` on the first mount point; used space is bucketed to 10 percent", Permission: "search permission on the mount point path", NonRoot: "available; a mount point below a directory the agent cannot search reports `capacity_unavailable`"},
	{ID: FactMounts, Kind: KindMount, Whole: true, Fields: []string{"mount_point", "source", "fstype", "root", "device", "read_only", "options"},
		Source: "`/proc/self/mountinfo`, excluding pseudo filesystems and per-session or container mount points", Permission: "world-readable procfs file", NonRoot: "available"},
	{ID: FactInterfaces, Kind: KindInterface, Whole: true, Fields: []string{"index", "mtu", "hardware_addr", "flags", "addresses", "operstate"},
		Source: "netlink link and address dumps (`net.Interfaces`), `/proc/net/if_inet6` to drop temporary IPv6 addresses, `/sys/class/net/<if>/operstate`", Permission: "none", NonRoot: "available"},
	{ID: FactSockets, Kind: KindSocket, Whole: true, Fields: []string{"protocol", "address", "port", "uid", "uids", "inodes", "unavailable_edges", "unavailable_reason"},
		Source: "`/proc/net/tcp`, `tcp6` (state LISTEN), `udp`, `udp6` (unconnected bound sockets) of the agent's network namespace", Permission: "world-readable procfs files", NonRoot: "available"},
	{ID: FactUnits, Kind: KindUnit, Whole: true, Fields: []string{"description", "load_state", "active_state", "sub_state", "unit_file_state", "fragment_path"},
		Source: "D-Bus `org.freedesktop.systemd1.Manager.ListUnits`; `Unit` properties `FragmentPath`, `UnitFileState`; `Service` property `MainPID`", Permission: "system bus connection; read-only property queries are allowed to unprivileged clients by the systemd bus policy", NonRoot: "available where systemd runs"},
	{ID: FactTimers, Kind: KindTimer, Whole: true, Fields: []string{"description", "load_state", "active_state", "sub_state", "unit_file_state", "fragment_path", "scheduled", "last_trigger_day"},
		Source: "D-Bus `Timer` properties `Unit`, `NextElapseUSecRealtime` (reported only as `scheduled`), `LastTriggerUSec` (bucketed to the UTC day)", Permission: "system bus connection", NonRoot: "available where systemd runs"},
	{ID: FactPackages, Kind: KindPackage, Whole: true, Fields: []string{"manager", "name", "version", "arch", "state"},
		Source: "dpkg `/var/lib/dpkg/status`; rpm database (`rpmdb.sqlite`, `Packages.db`, or Berkeley DB `Packages`) via go-rpmdb; apk `/lib/apk/db/installed`", Permission: "world-readable package databases", NonRoot: "available"},
	{ID: FactProcesses, Kind: KindProcess, Whole: true, Fields: []string{"pid", "comm", "uid", "cmdline"},
		Source: "`/proc/<pid>/stat`, `/proc/<pid>/status`; `cmdline` only for allowlisted comm names, redacted. Only unit main processes and socket owners are collected", Permission: "world-readable procfs files (hidden when procfs is mounted with `hidepid`)", NonRoot: "available unless `hidepid` is set"},

	{ID: EdgeIDUnitProcess, Kind: KindUnit, EdgeType: EdgeMainProcess, ToKinds: []string{KindProcess}, DependsOn: []string{FactUnits},
		Source: "`Service.MainPID` resolved to `/proc/<pid>/stat`", Permission: "as host/Process", NonRoot: "available"},
	{ID: EdgeIDMountDevice, Kind: KindMount, EdgeType: EdgeDevice, ToKinds: []string{KindBlockDevice}, DependsOn: []string{FactMounts, FactBlockDevices},
		Source: "mountinfo `major:minor`, else the mount source path, matched to `/sys/block` devices and device-mapper names", Permission: "none", NonRoot: "available"},
	{ID: EdgeIDMountFilesystem, Kind: KindMount, EdgeType: EdgeFilesystem, ToKinds: []string{KindFilesystem}, DependsOn: []string{FactMounts, FactFilesystems},
		Source: "mountinfo superblock `major:minor`", Permission: "none", NonRoot: "available"},
	{ID: EdgeIDPartitionDisk, Kind: KindBlockDevice, EdgeType: EdgePartitionOf, ToKinds: []string{KindBlockDevice}, DependsOn: []string{FactBlockDevices},
		Source: "partition subdirectories of `/sys/block/<disk>`", Permission: "none", NonRoot: "available"},
	{ID: EdgeIDPackageUnit, Kind: KindPackage, EdgeType: EdgeProvidesUnit, ToKinds: []string{KindUnit, KindTimer}, DependsOn: []string{FactPackages, FactUnits, FactTimers},
		Source: "unit `FragmentPath` matched to dpkg `/var/lib/dpkg/info/*.list` or rpm file lists (usr-merge aliases included)", Permission: "world-readable package databases", NonRoot: "available"},
	{ID: EdgeIDSocketProcess, Kind: KindSocket, EdgeType: EdgeProcess, ToKinds: []string{KindProcess}, DependsOn: []string{FactSockets},
		Source: "`socket:[inode]` links in `/proc/<pid>/fd`, read only for processes of the agent's own UID", Permission: "ptrace read access to the owning process, which a non-root user has only for its own processes", NonRoot: "partial: sockets owned by other users report `unavailable_edges` with reason `other_user_fd`"},
	{ID: EdgeIDSocketUnit, Kind: KindSocket, EdgeType: EdgeUnit, ToKinds: []string{KindUnit}, DependsOn: []string{FactSockets, FactUnits},
		Source: "`/proc/<pid>/cgroup` of the owning process matched to a loaded unit", Permission: "requires the socket to process edge", NonRoot: "partial, as the socket to process edge"},
	{ID: EdgeIDTimerUnit, Kind: KindTimer, EdgeType: EdgeTriggers, ToKinds: []string{KindUnit}, DependsOn: []string{FactTimers, FactUnits},
		Source: "`Timer.Unit` property", Permission: "system bus connection", NonRoot: "available where systemd runs"},
}

// Reasons documents every reason code.
var Reasons = [][2]string{
	{ReasonSourceAbsent, "The documented source does not exist on this host (for example no systemd, or no package database)."},
	{ReasonPermission, "The agent user cannot read the source (restrictive modes, or procfs mounted with `hidepid`)."},
	{ReasonDBus, "The system bus or `org.freedesktop.systemd1` is not reachable."},
	{ReasonReadFailed, "The source exists but reading or parsing it failed."},
	{ReasonOtherUserFD, "Mapping the socket to its process needs `/proc/<pid>/fd` of another user, which a non-root user cannot read."},
	{ReasonOwnerNotFound, "The socket belongs to the agent's UID but no process of that UID holds it."},
	{ReasonDependency, "The edge depends on a fact that is unavailable in this collection."},
	{ReasonProcessVanished, "The process exited between listing and reading."},
	{ReasonCapacityDenied, "`statfs(2)` on the mount point was denied; the filesystem is reported without capacity."},
}

func entry(id string) Entry {
	for _, e := range Catalog {
		if e.ID == id {
			return e
		}
	}
	panic("hostfacts: unknown catalog id " + id)
}

// RenderCatalog renders docs/host-facts.md.
func RenderCatalog() string {
	var b strings.Builder
	b.WriteString("# Host facts\n\nGenerated from `internal/hostfacts/catalog.go` and `internal/hostfacts/docs.go` by `go test ./internal/hostfacts -run TestCatalogDocCurrent -update`. Do not edit by hand.\n\n")
	b.WriteString(docIntro)
	b.WriteString("\n## Facts\n\n|Scope key|Kind|Fields|Source|Permission|As non-root|\n|---|---|---|---|---|---|\n")
	for _, e := range Catalog {
		if e.EdgeType != "" {
			continue
		}
		fmt.Fprintf(&b, "|`%s`|`%s`|%s|%s|%s|%s|\n", ScopeKey(e.ID), e.Kind, codeList(e.Fields), e.Source, e.Permission, e.NonRoot)
	}
	b.WriteString("\n## Edges\n\n|Scope key|From|Type|To|Source|Permission|As non-root|\n|---|---|---|---|---|---|---|\n")
	for _, e := range Catalog {
		if e.EdgeType == "" {
			continue
		}
		fmt.Fprintf(&b, "|`%s`|`%s`|`%s`|%s|%s|%s|%s|\n", ScopeKey(e.ID), e.Kind, e.EdgeType, codeList(e.ToKinds), e.Source, e.Permission, e.NonRoot)
	}
	b.WriteString("\n## Reason codes\n\n|Reason|Meaning|\n|---|---|\n")
	for _, r := range Reasons {
		fmt.Fprintf(&b, "|`%s`|%s|\n", r[0], r[1])
	}
	b.WriteString(docTail)
	return b.String()
}

func codeList(s []string) string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = "`" + v + "`"
	}
	return strings.Join(out, ", ")
}
