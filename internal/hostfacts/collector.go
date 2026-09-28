package hostfacts

import (
	"context"
	"net"
	"os"
	"regexp"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

// Uname is the subset of utsname the collectors use.
type Uname struct {
	Sysname, Nodename, Release, Version, Machine string
}

// NetInterface is one network interface with its addresses in CIDR form.
type NetInterface struct {
	Name         string
	Index        int
	MTU          int
	HardwareAddr string
	Flags        []string
	Addrs        []string
}

// Options configures the collectors. Zero values are replaced by DefaultOptions values.
type Options struct {
	ProcRoot     string
	SysRoot      string
	EtcRoot      string
	UsrLibRoot   string
	DpkgDir      string
	RPMPaths     []string
	APKInstalled string

	// Systemd is used when set; otherwise DialSystemd is called on each collection until it succeeds.
	Systemd     Systemd
	DialSystemd func(ctx context.Context) (Systemd, error)

	Uname      func() (Uname, error)
	Interfaces func() ([]NetInterface, error)
	Statfs     func(path string, st *unix.Statfs_t) error
	UID        int

	CmdlineAllowlist   []string
	Redactor           *redact.Redactor
	MountPointsExclude *regexp.Regexp
	FSTypesExclude     *regexp.Regexp
	InterfacesExclude  *regexp.Regexp
	UnitTypes          []string
}

// Default exclusions follow node_exporter's filesystem collector plus per-session and container paths.
var (
	DefaultMountPointsExclude = regexp.MustCompile(`^/(dev|proc|sys|run/credentials/.+|run/user/.+|run/netns/.+|run/docker/.+|run/containerd/.+|run/snapd/ns(/.*)?|var/lib/docker/.+|var/lib/containers/storage/.+|var/lib/kubelet/pods/.+)($|/)`)
	DefaultFSTypesExclude     = regexp.MustCompile(`^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|sysfs|tracefs|efivarfs)$`)
	DefaultInterfacesExclude  = regexp.MustCompile(`^veth`)
	DefaultUnitTypes          = []string{"service", "socket", "target", "timer", "mount", "automount", "swap", "path", "slice"}
)

// DefaultOptions returns production paths and system sources.
func DefaultOptions() Options {
	return Options{
		ProcRoot:     "/proc",
		SysRoot:      "/sys",
		EtcRoot:      "/etc",
		UsrLibRoot:   "/usr/lib",
		DpkgDir:      "/var/lib/dpkg",
		RPMPaths:     DefaultRPMPaths,
		APKInstalled: "/lib/apk/db/installed",
		DialSystemd:  DialSystemBus,
		Uname:        SystemUname,
		Interfaces:   SystemInterfaces,
		Statfs:       unix.Statfs,
		UID:          os.Geteuid(),
		Redactor:     redact.Default(),
	}
}

func (o Options) withDefaults() Options {
	d := DefaultOptions()
	if o.ProcRoot == "" {
		o.ProcRoot = d.ProcRoot
	}
	if o.SysRoot == "" {
		o.SysRoot = d.SysRoot
	}
	if o.EtcRoot == "" {
		o.EtcRoot = d.EtcRoot
	}
	if o.UsrLibRoot == "" {
		o.UsrLibRoot = d.UsrLibRoot
	}
	if o.DpkgDir == "" {
		o.DpkgDir = d.DpkgDir
	}
	if o.RPMPaths == nil {
		o.RPMPaths = d.RPMPaths
	}
	if o.APKInstalled == "" {
		o.APKInstalled = d.APKInstalled
	}
	if o.Uname == nil {
		o.Uname = d.Uname
	}
	if o.Interfaces == nil {
		o.Interfaces = d.Interfaces
	}
	if o.Statfs == nil {
		o.Statfs = d.Statfs
	}
	if o.Redactor == nil {
		o.Redactor = d.Redactor
	}
	if o.MountPointsExclude == nil {
		o.MountPointsExclude = DefaultMountPointsExclude
	}
	if o.FSTypesExclude == nil {
		o.FSTypesExclude = DefaultFSTypesExclude
	}
	if o.InterfacesExclude == nil {
		o.InterfacesExclude = DefaultInterfacesExclude
	}
	if o.UnitTypes == nil {
		o.UnitTypes = DefaultUnitTypes
	}
	return o
}

// SystemUname reads uname(2).
func SystemUname() (Uname, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Uname{}, err
	}
	return Uname{
		Sysname:  unix.ByteSliceToString(u.Sysname[:]),
		Nodename: unix.ByteSliceToString(u.Nodename[:]),
		Release:  unix.ByteSliceToString(u.Release[:]),
		Version:  unix.ByteSliceToString(u.Version[:]),
		Machine:  unix.ByteSliceToString(u.Machine[:]),
	}, nil
}

// SystemInterfaces lists interfaces and addresses through the standard library (netlink on Linux).
func SystemInterfaces() ([]NetInterface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]NetInterface, 0, len(ifs))
	for _, i := range ifs {
		ni := NetInterface{Name: i.Name, Index: i.Index, MTU: i.MTU, HardwareAddr: i.HardwareAddr.String()}
		for _, f := range []struct {
			flag net.Flags
			name string
		}{{net.FlagUp, "up"}, {net.FlagBroadcast, "broadcast"}, {net.FlagLoopback, "loopback"}, {net.FlagPointToPoint, "pointtopoint"}, {net.FlagMulticast, "multicast"}, {net.FlagRunning, "running"}} {
			if i.Flags&f.flag != 0 {
				ni.Flags = append(ni.Flags, f.name)
			}
		}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ni.Addrs = append(ni.Addrs, a.String())
		}
		out = append(out, ni)
	}
	return out, nil
}

// Collector gathers host facts from the configured sources.
type Collector struct {
	o       Options
	mu      sync.Mutex
	systemd Systemd
	pkgs    *packageCache
	allow   map[string]bool
	buckets map[string]int64

	readRPMFile func(string) ([]Package, error)
}

// NewCollector returns a collector over o.
func NewCollector(o Options) *Collector {
	o = o.withDefaults()
	c := &Collector{o: o, systemd: o.Systemd, pkgs: newPackageCache(), allow: map[string]bool{}, readRPMFile: ReadRPM}
	for _, n := range o.CmdlineAllowlist {
		c.allow[n] = true
	}
	return c
}

// Close releases the D-Bus connection if one was dialed.
func (c *Collector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.systemd != nil && c.o.Systemd == nil {
		err := c.systemd.Close()
		c.systemd = nil
		return err
	}
	return nil
}

// Collect gathers one snapshot. It never fails as a whole: every source error becomes a fact status.
func (c *Collector) Collect(ctx context.Context) *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := newSnapshot()
	c.collectOS(s)
	c.collectCPU(s)
	c.collectMemory(s)
	devs := c.collectBlockDevices(s)
	c.collectMounts(s, devs)
	c.collectInterfaces(s)
	units := c.collectSystemd(ctx, s)
	procs := newProcessSet(c, s)
	c.linkUnitProcesses(s, units, procs)
	c.collectSockets(s, units, procs)
	c.collectPackages(s, units)
	procs.finish()
	return s
}
