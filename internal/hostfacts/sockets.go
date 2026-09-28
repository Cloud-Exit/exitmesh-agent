package hostfacts

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"
)

const (
	tcpListen = 0x0a
	udpClose  = 0x07
)

type socketGroup struct {
	proto  string
	addr   string
	port   uint64
	uids   map[uint64]bool
	inodes []uint64
}

type sockLine struct {
	local, remote net.IP
	lport, rport  uint64
	state, uid    uint64
	inode         uint64
}

func toLines(v procfs.NetIPSocket) []sockLine {
	out := make([]sockLine, len(v))
	for i, l := range v {
		out[i] = sockLine{l.LocalAddr, l.RemAddr, l.LocalPort, l.RemPort, l.St, l.UID, l.Inode}
	}
	return out
}

func (c *Collector) readSockets() ([]*socketGroup, error) {
	pfs, err := c.procFS()
	if err != nil {
		return nil, err
	}
	groups := map[string]*socketGroup{}
	for _, r := range []struct {
		proto    string
		optional bool
		fn       func() ([]sockLine, error)
	}{
		{"tcp", false, func() ([]sockLine, error) { v, err := pfs.NetTCP(); return toLines(procfs.NetIPSocket(v)), err }},
		{"tcp6", true, func() ([]sockLine, error) { v, err := pfs.NetTCP6(); return toLines(procfs.NetIPSocket(v)), err }},
		{"udp", false, func() ([]sockLine, error) { v, err := pfs.NetUDP(); return toLines(procfs.NetIPSocket(v)), err }},
		{"udp6", true, func() ([]sockLine, error) { v, err := pfs.NetUDP6(); return toLines(procfs.NetIPSocket(v)), err }},
	} {
		lines, err := r.fn()
		if err != nil {
			if r.optional && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		tcp := strings.HasPrefix(r.proto, "tcp")
		for _, l := range lines {
			if tcp && l.state != tcpListen || !tcp && (l.state != udpClose || l.rport != 0 || l.remote != nil && !l.remote.IsUnspecified()) {
				continue
			}
			addr := l.local.String()
			key := r.proto + "|" + addr + "|" + strconv.FormatUint(l.lport, 10)
			g, ok := groups[key]
			if !ok {
				g = &socketGroup{proto: r.proto, addr: addr, port: l.lport, uids: map[uint64]bool{}}
				groups[key] = g
			}
			g.uids[l.uid] = true
			g.inodes = append(g.inodes, l.inode)
		}
	}
	out := make([]*socketGroup, 0, len(groups))
	for _, g := range groups {
		sort.Slice(g.inodes, func(i, j int) bool { return g.inodes[i] < g.inodes[j] })
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].proto != out[j].proto {
			return out[i].proto < out[j].proto
		}
		if out[i].addr != out[j].addr {
			return out[i].addr < out[j].addr
		}
		return out[i].port < out[j].port
	})
	return out, nil
}

// ownSocketHolders maps socket inodes to the lowest PID of the agent's own UID holding them.
func (c *Collector) ownSocketHolders() map[uint64]int {
	out := map[uint64]int{}
	ents, err := os.ReadDir(c.o.ProcRoot)
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(c.o.ProcRoot, e.Name())
		fi, err := os.Stat(dir)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != c.o.UID {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			ino, ok := strings.CutPrefix(target, "socket:[")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimSuffix(ino, "]"), 10, 64)
			if err != nil {
				continue
			}
			if cur, ok := out[n]; !ok || pid < cur {
				out[n] = pid
			}
		}
	}
	return out
}

func (c *Collector) collectSockets(s *Snapshot, units *unitSet, procs *processSet) {
	groups, err := c.readSockets()
	if err != nil {
		s.unavailable(FactSockets, reasonFor(err))
		s.unavailable(EdgeIDSocketProcess, ReasonDependency)
		s.unavailable(EdgeIDSocketUnit, ReasonDependency)
		return
	}
	needFDs := false
	for _, g := range groups {
		if g.uids[uint64(c.o.UID)] {
			needFDs = true
		}
	}
	var holders map[uint64]int
	if needFDs {
		holders = c.ownSocketHolders()
	}
	var pt, ut tally
	for _, g := range groups {
		uids := make([]uint64, 0, len(g.uids))
		for u := range g.uids {
			uids = append(uids, u)
		}
		sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
		inodes := make([]any, len(g.inodes))
		for i, n := range g.inodes {
			inodes[i] = int64(n)
		}
		fields := map[string]any{"protocol": g.proto, "address": g.addr, "port": int64(g.port), "uid": int64(uids[0]), "inodes": inodes}
		if len(uids) > 1 {
			l := make([]any, len(uids))
			for i, u := range uids {
				l[i] = int64(u)
			}
			fields["uids"] = l
		}
		host := g.addr
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		name := g.proto + " " + net.JoinHostPort(g.addr, strconv.FormatUint(g.port, 10))
		suid := uid(KindSocket, g.proto, host, strconv.FormatUint(g.port, 10))
		pid := 0
		for _, n := range g.inodes {
			if p, ok := holders[n]; ok && (pid == 0 || p < pid) {
				pid = p
			}
		}
		var unavailable []string
		reason := ""
		switch {
		case pid == 0 && !g.uids[uint64(c.o.UID)]:
			reason = ReasonOtherUserFD
		case pid == 0:
			reason = ReasonOwnerNotFound
		}
		puid := ""
		if reason == "" {
			var r string
			puid, r = procs.get(pid)
			if r != "" {
				reason = r
			}
		}
		if reason != "" {
			unavailable = []string{EdgeProcess, EdgeUnit}
			pt.bad(reason)
			ut.bad(reason)
		} else {
			s.edge(suid, EdgeProcess, puid)
			pt.good()
			if units.ok {
				comps, err := cgroupUnits(c.o.ProcRoot, pid)
				switch {
				case err != nil:
					unavailable = []string{EdgeUnit}
					reason = procReason(err)
					ut.bad(reason)
				case len(comps) > 0 && units.byName[comps[0]] != nil:
					s.edge(suid, EdgeUnit, units.byName[comps[0]].uid)
					ut.good()
				default:
					ut.good()
				}
			}
		}
		if len(unavailable) > 0 {
			fields["unavailable_edges"] = strList(unavailable)
			fields["unavailable_reason"] = reason
		}
		s.add(suid, KindSocket, name, fields)
	}
	s.ok(FactSockets)
	st := pt.status()
	s.set(EdgeIDSocketProcess, st.State, st.Reason)
	if !units.ok {
		s.unavailable(EdgeIDSocketUnit, ReasonDependency)
		return
	}
	st = ut.status()
	s.set(EdgeIDSocketUnit, st.State, st.Reason)
}
