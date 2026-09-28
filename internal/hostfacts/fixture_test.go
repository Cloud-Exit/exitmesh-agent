package hostfacts

import (
	"context"
	"errors"
	"fmt"

	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(content, "->") {
			if err := os.Symlink(strings.TrimPrefix(content, "->"), full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func procStat(pid int, comm string, start uint64) string {
	return fmt.Sprintf("%d (%s) S 1 %d %d 0 -1 4194560 1234 0 0 0 10 5 0 0 20 0 3 0 %d 123456789 2000 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid, comm, pid, pid, start)
}

func procStatus(comm string, uid int) string {
	return fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t1\nPid:\t1\nUid:\t%d\t%d\t%d\t%d\nGid:\t0\t0\t0\t0\n", comm, uid, uid, uid, uid)
}

func tcpLine(sl int, local, remote, st string, uid int, inode int) string {
	return fmt.Sprintf("  %d: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n", sl, local, remote, st, uid, inode)
}

func udpLine(sl int, local, remote, st string, uid int, inode int) string {
	return fmt.Sprintf("  %d: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 2 0000000000000000 0\n", sl, local, remote, st, uid, inode)
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
const udpHeader = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"

const cpuinfoX86 = `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU @ 2.20GHz
cpu MHz		: 2200.000
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 2

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU @ 2.20GHz
cpu MHz		: 2199.998
physical id	: 0
siblings	: 4
core id		: 0
cpu cores	: 2

processor	: 2
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU @ 2.20GHz
cpu MHz		: 2200.000
physical id	: 0
siblings	: 4
core id		: 1
cpu cores	: 2

processor	: 3
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU @ 2.20GHz
cpu MHz		: 2200.000
physical id	: 0
siblings	: 4
core id		: 1
cpu cores	: 2
`

const mountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
23 22 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
24 22 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
25 22 253:0 / /var rw,relatime shared:3 - xfs /dev/mapper/vg-var rw,attr2
26 22 0:30 /@home /home rw,relatime shared:4 - btrfs /dev/sda2 rw,space_cache
27 22 0:30 /@srv /srv ro,relatime shared:5 - btrfs /dev/sda2 rw,space_cache
28 22 0:40 / /run rw,nosuid,nodev shared:6 - tmpfs tmpfs rw,size=800000k,mode=755
29 28 0:41 / /run/user/1000 rw,nosuid,nodev,relatime shared:7 - tmpfs tmpfs rw,size=400000k,mode=700,uid=1000
30 22 0:42 / /var/lib/docker/overlay2/abc/merged rw,relatime - overlay overlay rw,lowerdir=/x
31 22 0:43 / /tmp rw,nosuid,nodev shared:8 - tmpfs tmpfs rw
`

type fixture struct {
	root string
	uid  int
	sd   *fakeSystemd
	stat map[string]unix.Statfs_t
	ifs  []NetInterface
}

func (f *fixture) path(p string) string { return filepath.Join(f.root, p) }

// newDebianFixture builds a Debian-style host tree with processes owned by the test user.
func newDebianFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{root: t.TempDir(), uid: os.Getuid()}
	own := f.uid
	files := map[string]string{
		"etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n",
		"etc/machine-id": "0123456789abcdef0123456789abcdef\n",
		"proc/cpuinfo":   cpuinfoX86,
		"proc/meminfo":   "MemTotal:        8000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4000000 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n",

		"proc/self/mountinfo": mountinfo,
		"proc/net/if_inet6":   "20010db8000000000000000000001234 02 40 00 01     eth0\nfe80000000000000505400fffe123456 02 40 20 80     eth0\n20010db800000000505400fffe123456 02 40 00 00     eth0\n00000000000000000000000000000001 01 80 10 80       lo\n",
		"proc/net/tcp": tcpHeader +
			tcpLine(0, "00000000:0016", "00000000:0000", "0A", 0, 1001) +
			tcpLine(1, "0100007F:1F90", "00000000:0000", "0A", own, 1002) +
			tcpLine(2, "0500000A:0016", "0600000A:D431", "01", 0, 1003) +
			tcpLine(3, "0100007F:2382", "00000000:0000", "0A", own, 1004),
		"proc/net/tcp6": tcpHeader +
			tcpLine(0, "00000000000000000000000000000000:0050", "00000000000000000000000000000000:0000", "0A", 33, 2001) +
			tcpLine(1, "00000000000000000000000000000000:0050", "00000000000000000000000000000000:0000", "0A", 33, 2002),
		"proc/net/udp": udpHeader +
			udpLine(0, "00000000:0044", "00000000:0000", "07", 0, 3001) +
			udpLine(1, "0500000A:A000", "08080808:0035", "01", own, 3002),

		"proc/1234/stat":    procStat(1234, "nginx", 900),
		"proc/1234/status":  procStatus("nginx", 0),
		"proc/1234/comm":    "nginx\n",
		"proc/1234/cmdline": "nginx: master process /usr/sbin/nginx\x00",
		"proc/1234/cgroup":  "0::/system.slice/nginx.service\n",
		"proc/4242/stat":    procStat(4242, "myapp", 5000),
		"proc/4242/status":  procStatus("myapp", own),
		"proc/4242/comm":    "myapp\n",
		"proc/4242/cmdline": "/opt/myapp/bin/myapp\x00--password=hunter2\x00--port\x008080\x00",
		"proc/4242/cgroup":  "0::/system.slice/myapp.service\n",
		"proc/4242/fd/0":    "->/dev/null",
		"proc/4242/fd/3":    "->socket:[1002]",
		"proc/4243/stat":    procStat(4243, "myapp", 5100),
		"proc/4243/status":  procStatus("myapp", own),
		"proc/4243/comm":    "myapp\n",
		"proc/4243/cgroup":  "0::/system.slice/myapp.service\n",
		"proc/4243/fd/3":    "->socket:[1002]",
		"proc/4243/fd/4":    "->pipe:[77]",

		"sys/block/sda/size":              "2000000\n",
		"sys/block/sda/dev":               "8:0\n",
		"sys/block/sda/queue/rotational":  "1\n",
		"sys/block/sda/removable":         "0\n",
		"sys/block/sda/ro":                "0\n",
		"sys/block/sda/device/model":      "QEMU HARDDISK   \n",
		"sys/block/sda/sda1/partition":    "1\n",
		"sys/block/sda/sda1/size":         "1000000\n",
		"sys/block/sda/sda1/dev":          "8:1\n",
		"sys/block/sda/sda1/ro":           "0\n",
		"sys/block/sda/sda2/partition":    "2\n",
		"sys/block/sda/sda2/size":         "999000\n",
		"sys/block/sda/sda2/dev":          "8:2\n",
		"sys/block/dm-0/size":             "500000\n",
		"sys/block/dm-0/dev":              "253:0\n",
		"sys/block/dm-0/queue/rotational": "0\n",
		"sys/block/dm-0/dm/name":          "vg-var\n",
		"sys/block/loop0/size":            "0\n",
		"sys/block/loop0/dev":             "7:0\n",
		"sys/class/net/eth0/operstate":    "up\n",
		"sys/class/net/lo/operstate":      "unknown\n",

		"var/lib/dpkg/status": `Package: nginx
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 1.22.1-9
Description: small, powerful, scalable web/proxy server
 Nginx ("engine X") is a high-performance web and reverse proxy server.

Package: libc6
Status: install ok installed
Multi-Arch: same
Architecture: amd64
Version: 2.36-9+deb12u4

Package: oldthing
Status: deinstall ok config-files
Architecture: all
Version: 1.0

Package: myapp
Status: hold ok installed
Architecture: all
Version: 3.1
`,
		"var/lib/dpkg/info/nginx.list":       "/.\n/lib\n/lib/systemd\n/lib/systemd/system\n/lib/systemd/system/nginx.service\n/usr/sbin/nginx\n",
		"var/lib/dpkg/info/libc6:amd64.list": "/.\n/lib/x86_64-linux-gnu/libc.so.6\n",
		"var/lib/dpkg/info/myapp.list":       "/etc/systemd/system/myapp.service\n/etc/systemd/system/myapp-cleanup.timer\n/opt/myapp/bin/myapp\n",
		"var/lib/dpkg/info/oldthing.list":    "/lib/systemd/system/oldthing.service\n",
		"var/lib/kubelet-not-here/.keep":     "",
		"usr/lib/os-release":                 "ID=wrong\n",
	}
	writeTree(t, f.root, files)
	f.sd = &fakeSystemd{
		units: []SystemdUnit{
			{Name: "nginx.service", Description: "A high performance web server", LoadState: "loaded", ActiveState: "active", SubState: "running", Path: "/org/freedesktop/systemd1/unit/nginx_2eservice"},
			{Name: "myapp.service", Description: "My App", LoadState: "loaded", ActiveState: "active", SubState: "running", Path: "/org/freedesktop/systemd1/unit/myapp_2eservice"},
			{Name: "myapp-cleanup.timer", Description: "Clean up", LoadState: "loaded", ActiveState: "active", SubState: "waiting", Path: "/org/freedesktop/systemd1/unit/myapp_2dcleanup_2etimer"},
			{Name: "myapp-cleanup.service", Description: "Clean up job", LoadState: "loaded", ActiveState: "inactive", SubState: "dead", Path: "/org/freedesktop/systemd1/unit/myapp_2dcleanup_2eservice"},
			{Name: "multi-user.target", Description: "Multi-User System", LoadState: "loaded", ActiveState: "active", SubState: "active", Path: "/org/freedesktop/systemd1/unit/multi_2duser_2etarget"},
			{Name: "session-1.scope", Description: "Session 1", LoadState: "loaded", ActiveState: "active", SubState: "running", Path: "/org/freedesktop/systemd1/unit/session_2d1_2escope"},
			{Name: "dev-sda.device", Description: "QEMU HARDDISK", LoadState: "loaded", ActiveState: "active", SubState: "plugged", Path: "/org/freedesktop/systemd1/unit/dev_2dsda_2edevice"},
			{Name: "gone.service", Description: "Unloaded meanwhile", LoadState: "loaded", ActiveState: "inactive", SubState: "dead", Path: "/org/freedesktop/systemd1/unit/gone_2eservice"},
		},
		props: map[string]map[string]any{
			"/org/freedesktop/systemd1/unit/nginx_2eservice|" + ifaceUnit:              {"FragmentPath": "/usr/lib/systemd/system/nginx.service", "UnitFileState": "enabled"},
			"/org/freedesktop/systemd1/unit/nginx_2eservice|" + ifaceService:           {"MainPID": uint32(1234)},
			"/org/freedesktop/systemd1/unit/myapp_2eservice|" + ifaceUnit:              {"FragmentPath": "/etc/systemd/system/myapp.service", "UnitFileState": "enabled"},
			"/org/freedesktop/systemd1/unit/myapp_2eservice|" + ifaceService:           {"MainPID": uint32(4242)},
			"/org/freedesktop/systemd1/unit/myapp_2dcleanup_2etimer|" + ifaceUnit:      {"FragmentPath": "/etc/systemd/system/myapp-cleanup.timer", "UnitFileState": "enabled"},
			"/org/freedesktop/systemd1/unit/myapp_2dcleanup_2etimer|" + ifaceTimer:     {"Unit": "myapp-cleanup.service", "NextElapseUSecRealtime": uint64(1790000000000000), "LastTriggerUSec": uint64(1789900000123456)},
			"/org/freedesktop/systemd1/unit/myapp_2dcleanup_2eservice|" + ifaceUnit:    {"FragmentPath": "/etc/systemd/system/myapp-cleanup.service", "UnitFileState": "static"},
			"/org/freedesktop/systemd1/unit/myapp_2dcleanup_2eservice|" + ifaceService: {"MainPID": uint32(0)},
			"/org/freedesktop/systemd1/unit/multi_2duser_2etarget|" + ifaceUnit:        {"FragmentPath": "/usr/lib/systemd/system/multi-user.target", "UnitFileState": "static"},
		},
	}
	f.stat = map[string]unix.Statfs_t{
		"/":     {Bsize: 4096, Blocks: 1000000, Bfree: 450000, Files: 65536},
		"/var":  {Bsize: 4096, Blocks: 200000, Bfree: 190000, Files: 1000},
		"/home": {Bsize: 4096, Blocks: 400000, Bfree: 100000, Files: 0},
		"/run":  {Bsize: 4096, Blocks: 200000, Bfree: 199000, Files: 100000},
	}
	f.ifs = []NetInterface{
		{Name: "lo", Index: 1, MTU: 65536, Flags: []string{"up", "loopback", "running"}, Addrs: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "eth0", Index: 2, MTU: 1500, HardwareAddr: "52:54:00:12:34:56", Flags: []string{"up", "broadcast", "multicast", "running"}, Addrs: []string{"10.0.0.5/24", "2001:db8::1234/64", "2001:db8::5054:ff:fe12:3456/64", "fe80::5054:ff:fe12:3456/64"}},
		{Name: "veth1a2b3c", Index: 7, MTU: 1500, Flags: []string{"up"}, Addrs: nil},
	}
	return f
}

func (f *fixture) options() Options {
	return Options{
		ProcRoot:     f.path("proc"),
		SysRoot:      f.path("sys"),
		EtcRoot:      f.path("etc"),
		UsrLibRoot:   f.path("usr/lib"),
		DpkgDir:      f.path("var/lib/dpkg"),
		RPMPaths:     []string{f.path("var/lib/rpm/rpmdb.sqlite"), f.path("var/lib/rpm/Packages")},
		APKInstalled: f.path("lib/apk/db/installed"),
		Systemd:      f.sd,
		Uname: func() (Uname, error) {
			return Uname{Sysname: "Linux", Nodename: "web-1", Release: "6.1.0-18-amd64", Version: "#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1", Machine: "x86_64"}, nil
		},
		Interfaces: func() ([]NetInterface, error) { return f.ifs, nil },
		Statfs: func(p string, st *unix.Statfs_t) error {
			if p == "/tmp" {
				return syscall.EACCES
			}
			v, ok := f.stat[p]
			if !ok {
				return syscall.ENOENT
			}
			*st = v
			return nil
		},
		UID:              f.uid,
		CmdlineAllowlist: []string{"myapp"},
	}
}

type fakeSystemd struct {
	units   []SystemdUnit
	props   map[string]map[string]any
	listErr error
	closed  bool
}

func (f *fakeSystemd) ListUnits(context.Context) ([]SystemdUnit, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]SystemdUnit(nil), f.units...), nil
}

func (f *fakeSystemd) Properties(_ context.Context, path, iface string, names ...string) (map[string]any, error) {
	p, ok := f.props[path+"|"+iface]
	if !ok {
		return nil, ErrNoSuchUnit
	}
	out := map[string]any{}
	for _, n := range names {
		if v, ok := p[n]; ok {
			out[n] = v
		}
	}
	return out, nil
}

func (f *fakeSystemd) Close() error { f.closed = true; return nil }

var errBusDown = errors.New("connection closed")
