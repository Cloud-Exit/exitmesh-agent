// Package privdrop re-executes the process as an unprivileged user that keeps selected capabilities as ambient capabilities.
package privdrop

import (
	"bufio"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Target is the identity to switch to.
type Target struct {
	UID, GID int
	// Keep lists capability numbers (unix.CAP_*) the new process holds as ambient capabilities.
	Keep []int
}

// ParseTarget parses UID:GID; both must be non-zero.
func ParseTarget(s string) (Target, error) {
	u, g, ok := strings.Cut(s, ":")
	uid, uerr := strconv.Atoi(u)
	gid, gerr := strconv.Atoi(g)
	if !ok || uerr != nil || gerr != nil || uid <= 0 || gid <= 0 {
		return Target{}, fmt.Errorf("privdrop: %q is not a non-root UID:GID", s)
	}
	return Target{UID: uid, GID: gid}, nil
}

// Exec switches the calling thread to t and executes path with argv and env in its place. It returns only on failure,
// after which the process must exit because the thread may hold a partial identity.
func Exec(t Target, path string, argv, env []string) error {
	if t.UID <= 0 || t.GID <= 0 {
		return errors.New("privdrop: target must be a non-root UID and GID")
	}
	var set [2]uint32
	for _, c := range t.Keep {
		if c < 0 || c >= 64 {
			return fmt.Errorf("privdrop: capability %d out of range", c)
		}
		set[c/32] |= 1 << (c % 32)
	}
	// Credentials and capabilities are per thread; the same thread must change them and call execve.
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("privdrop: keep capabilities: %w", err)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETGROUPS, 0, 0, 0); e != 0 {
		return fmt.Errorf("privdrop: setgroups: %w", e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(t.GID), uintptr(t.GID), uintptr(t.GID)); e != 0 {
		return fmt.Errorf("privdrop: setresgid %d: %w", t.GID, e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(t.UID), uintptr(t.UID), uintptr(t.UID)); e != 0 {
		return fmt.Errorf("privdrop: setresuid %d: %w", t.UID, e)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: set[0], Permitted: set[0], Inheritable: set[0]},
		{Effective: set[1], Permitted: set[1], Inheritable: set[1]},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("privdrop: capset: %w", err)
	}
	for _, c := range t.Keep {
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c), 0, 0); err != nil {
			return fmt.Errorf("privdrop: raise ambient capability %d: %w", c, err)
		}
	}
	return unix.Exec(path, argv, env)
}

// Identity is the running process's user and effective capabilities.
type Identity struct {
	UID          int      `json:"uid"`
	GID          int      `json:"gid"`
	Capabilities []string `json:"capabilities"`
}

// Root reports whether the process runs as UID 0.
func (i Identity) Root() bool { return i.UID == 0 }

// Current reads the identity of the running process from /proc/self/status.
func Current() (Identity, error) { return readIdentity("/proc/self/status") }

func readIdentity(path string) (Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return Identity{}, err
	}
	defer f.Close()
	id := Identity{UID: -1, GID: -1, Capabilities: []string{}}
	var eff uint64
	seen := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			continue
		}
		switch k {
		case "Uid", "Gid":
			// The effective ID is the second field.
			if len(fs) < 2 {
				return Identity{}, fmt.Errorf("privdrop: %s: malformed %s line", path, k)
			}
			n, err := strconv.Atoi(fs[1])
			if err != nil {
				return Identity{}, fmt.Errorf("privdrop: %s: %s: %w", path, k, err)
			}
			if k == "Uid" {
				id.UID = n
			} else {
				id.GID = n
			}
			seen++
		case "CapEff":
			if eff, err = strconv.ParseUint(fs[0], 16, 64); err != nil {
				return Identity{}, fmt.Errorf("privdrop: %s: CapEff: %w", path, err)
			}
			seen++
		}
	}
	if err := sc.Err(); err != nil {
		return Identity{}, err
	}
	if seen != 3 {
		return Identity{}, fmt.Errorf("privdrop: %s lacks Uid, Gid, or CapEff", path)
	}
	for eff != 0 {
		c := bits.TrailingZeros64(eff)
		eff &^= 1 << c
		id.Capabilities = append(id.Capabilities, capName(c))
	}
	return id, nil
}

var capNames = map[int]string{
	unix.CAP_CHOWN: "CAP_CHOWN", unix.CAP_DAC_OVERRIDE: "CAP_DAC_OVERRIDE", unix.CAP_DAC_READ_SEARCH: "CAP_DAC_READ_SEARCH",
	unix.CAP_FOWNER: "CAP_FOWNER", unix.CAP_FSETID: "CAP_FSETID", unix.CAP_KILL: "CAP_KILL", unix.CAP_SETGID: "CAP_SETGID",
	unix.CAP_SETUID: "CAP_SETUID", unix.CAP_SETPCAP: "CAP_SETPCAP", unix.CAP_NET_BIND_SERVICE: "CAP_NET_BIND_SERVICE",
	unix.CAP_NET_RAW: "CAP_NET_RAW", unix.CAP_SYS_CHROOT: "CAP_SYS_CHROOT", unix.CAP_MKNOD: "CAP_MKNOD",
	unix.CAP_AUDIT_WRITE: "CAP_AUDIT_WRITE", unix.CAP_SETFCAP: "CAP_SETFCAP", unix.CAP_SYS_ADMIN: "CAP_SYS_ADMIN",
	unix.CAP_SYS_PTRACE: "CAP_SYS_PTRACE", unix.CAP_NET_ADMIN: "CAP_NET_ADMIN",
}

func capName(c int) string {
	if n, ok := capNames[c]; ok {
		return n
	}
	return "CAP_" + strconv.Itoa(c)
}
