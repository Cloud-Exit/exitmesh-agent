package hostfacts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type processSet struct {
	c     *Collector
	s     *Snapshot
	byPID map[int]procResult
	t     tally
}

type procResult struct {
	uid    string
	reason string
}

func newProcessSet(c *Collector, s *Snapshot) *processSet {
	return &processSet{c: c, s: s, byPID: map[int]procResult{}}
}

// get returns the process resource UID for pid, creating the resource on first use.
func (p *processSet) get(pid int) (string, string) {
	if r, ok := p.byPID[pid]; ok {
		return r.uid, r.reason
	}
	r := p.read(pid)
	p.byPID[pid] = r
	switch r.reason {
	case "":
		p.t.good()
	case ReasonProcessVanished:
	default:
		p.t.bad(r.reason)
	}
	return r.uid, r.reason
}

func procReason(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ReasonProcessVanished
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermission
	}
	return ReasonReadFailed
}

func (p *processSet) read(pid int) procResult {
	pfs, err := p.c.procFS()
	if err != nil {
		return procResult{reason: reasonFor(err)}
	}
	proc, err := pfs.Proc(pid)
	if err != nil {
		return procResult{reason: procReason(err)}
	}
	st, err := proc.Stat()
	if err != nil {
		return procResult{reason: procReason(err)}
	}
	status, err := proc.NewStatus()
	if err != nil {
		return procResult{reason: procReason(err)}
	}
	fields := map[string]any{"pid": int64(pid), "comm": clean(st.Comm), "uid": int64(status.UIDs[0])}
	if p.c.allow[st.Comm] {
		if args, err := proc.CmdLine(); err == nil && len(args) > 0 {
			fields["cmdline"] = clean(p.c.o.Redactor.String(strings.Join(args, " ")))
		}
	}
	u := uid(KindProcess, strconv.Itoa(pid), strconv.FormatUint(st.Starttime, 10))
	p.s.add(u, KindProcess, st.Comm, fields)
	return procResult{uid: u}
}

func (p *processSet) finish() {
	st := p.t.status()
	p.s.set(FactProcesses, st.State, st.Reason)
}

// cgroupUnits returns the unit-like components of the systemd cgroup path of pid, deepest first.
func cgroupUnits(procRoot string, pid int) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || (parts[0] != "0" && !strings.Contains(parts[1], "name=systemd")) {
			continue
		}
		comps := strings.Split(strings.Trim(parts[2], "/"), "/")
		for i := len(comps) - 1; i >= 0; i-- {
			if strings.Contains(comps[i], ".") {
				out = append(out, comps[i])
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return out, nil
}
