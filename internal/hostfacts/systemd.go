package hostfacts

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// SystemdUnit is one entry of org.freedesktop.systemd1.Manager.ListUnits.
type SystemdUnit struct {
	Name, Description, LoadState, ActiveState, SubState string
	Path                                                string
}

// Systemd is the read-only systemd manager surface the collectors use.
type Systemd interface {
	ListUnits(ctx context.Context) ([]SystemdUnit, error)
	// Properties returns the named properties of iface on the object at path.
	Properties(ctx context.Context, path, iface string, names ...string) (map[string]any, error)
	Close() error
}

// ErrNoSuchUnit reports a unit that disappeared between listing and querying.
var ErrNoSuchUnit = errors.New("hostfacts: no such unit")

const (
	systemdDest     = "org.freedesktop.systemd1"
	systemdPath     = "/org/freedesktop/systemd1"
	ifaceUnit       = "org.freedesktop.systemd1.Unit"
	ifaceService    = "org.freedesktop.systemd1.Service"
	ifaceTimer      = "org.freedesktop.systemd1.Timer"
	methodListUnits = "org.freedesktop.systemd1.Manager.ListUnits"
	methodGet       = "org.freedesktop.DBus.Properties.Get"
)

type dbusSystemd struct{ conn *dbus.Conn }

// DialSystemBus connects to the system bus.
func DialSystemBus(context.Context) (Systemd, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return NewDBusSystemd(conn), nil
}

// NewDBusSystemd wraps an authenticated bus connection.
func NewDBusSystemd(conn *dbus.Conn) Systemd { return &dbusSystemd{conn: conn} }

func (d *dbusSystemd) ListUnits(ctx context.Context) ([]SystemdUnit, error) {
	var raw []struct {
		Name, Description, LoadState, ActiveState, SubState, Followed string
		Path                                                          dbus.ObjectPath
		JobID                                                         uint32
		JobType                                                       string
		JobPath                                                       dbus.ObjectPath
	}
	if err := d.conn.Object(systemdDest, systemdPath).CallWithContext(ctx, methodListUnits, 0).Store(&raw); err != nil {
		return nil, err
	}
	out := make([]SystemdUnit, len(raw))
	for i, r := range raw {
		out[i] = SystemdUnit{Name: r.Name, Description: r.Description, LoadState: r.LoadState, ActiveState: r.ActiveState, SubState: r.SubState, Path: string(r.Path)}
	}
	return out, nil
}

func (d *dbusSystemd) Properties(ctx context.Context, path, iface string, names ...string) (map[string]any, error) {
	obj := d.conn.Object(systemdDest, dbus.ObjectPath(path))
	out := make(map[string]any, len(names))
	for _, n := range names {
		var v dbus.Variant
		if err := obj.CallWithContext(ctx, methodGet, 0, iface, n).Store(&v); err != nil {
			var de dbus.Error
			if errors.As(err, &de) && (de.Name == "org.freedesktop.DBus.Error.UnknownObject" || de.Name == "org.freedesktop.systemd1.NoSuchUnit") {
				return nil, ErrNoSuchUnit
			}
			return nil, err
		}
		out[n] = v.Value()
	}
	return out, nil
}

func (d *dbusSystemd) Close() error { return d.conn.Close() }

type unitInfo struct {
	uid      string
	name     string
	fragment string
	mainPID  int
	trigger  string
}

type unitSet struct {
	ok     bool
	byName map[string]*unitInfo
}

func (c *Collector) systemdConn(ctx context.Context) (Systemd, error) {
	if c.systemd != nil {
		return c.systemd, nil
	}
	if c.o.DialSystemd == nil {
		return nil, errors.New("no systemd connection configured")
	}
	sd, err := c.o.DialSystemd(ctx)
	if err != nil {
		return nil, err
	}
	c.systemd = sd
	return sd, nil
}

func (c *Collector) dropSystemd() {
	if c.systemd != nil && c.o.Systemd == nil {
		_ = c.systemd.Close()
		c.systemd = nil
	}
}

func (c *Collector) collectSystemd(ctx context.Context, s *Snapshot) *unitSet {
	us := &unitSet{byName: map[string]*unitInfo{}}
	fail := func(reason string) *unitSet {
		s.unavailable(FactUnits, reason)
		s.unavailable(FactTimers, reason)
		s.unavailable(EdgeIDTimerUnit, ReasonDependency)
		return us
	}
	sd, err := c.systemdConn(ctx)
	if err != nil {
		return fail(ReasonDBus)
	}
	list, err := sd.ListUnits(ctx)
	if err != nil {
		c.dropSystemd()
		return fail(ReasonDBus)
	}
	types := map[string]bool{}
	for _, t := range c.o.UnitTypes {
		types[t] = true
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	var ut, tt tally
	var timers []*unitInfo
	for _, u := range list {
		dot := strings.LastIndexByte(u.Name, '.')
		if dot < 0 || !types[u.Name[dot+1:]] {
			continue
		}
		typ := u.Name[dot+1:]
		kind, t := KindUnit, &ut
		if typ == "timer" {
			kind, t = KindTimer, &tt
		}
		fields := map[string]any{"description": clean(u.Description), "load_state": u.LoadState, "active_state": u.ActiveState, "sub_state": u.SubState}
		info := &unitInfo{uid: uid(kind, u.Name), name: u.Name}
		props, err := sd.Properties(ctx, u.Path, ifaceUnit, "FragmentPath", "UnitFileState")
		if errors.Is(err, ErrNoSuchUnit) {
			continue
		}
		readErr := err != nil
		if err == nil {
			if v, _ := props["FragmentPath"].(string); v != "" {
				fields["fragment_path"] = clean(v)
				info.fragment = v
			}
			if v, _ := props["UnitFileState"].(string); v != "" {
				fields["unit_file_state"] = v
			}
		}
		switch typ {
		case "service":
			p, err := sd.Properties(ctx, u.Path, ifaceService, "MainPID")
			if errors.Is(err, ErrNoSuchUnit) {
				continue
			}
			if err != nil {
				readErr = true
			} else if pid, ok := p["MainPID"].(uint32); ok {
				info.mainPID = int(pid)
			}
		case "timer":
			p, err := sd.Properties(ctx, u.Path, ifaceTimer, "Unit", "NextElapseUSecRealtime", "LastTriggerUSec")
			if errors.Is(err, ErrNoSuchUnit) {
				continue
			}
			if err != nil {
				readErr = true
			} else {
				info.trigger, _ = p["Unit"].(string)
				next, _ := p["NextElapseUSecRealtime"].(uint64)
				fields["scheduled"] = next != 0
				if last, _ := p["LastTriggerUSec"].(uint64); last != 0 && last <= math.MaxInt64 {
					fields["last_trigger_day"] = time.UnixMicro(int64(last)).UTC().Format(time.DateOnly)
				}
				timers = append(timers, info)
			}
		}
		if readErr {
			t.bad(ReasonReadFailed)
		} else {
			t.good()
		}
		s.add(info.uid, kind, u.Name, fields)
		us.byName[u.Name] = info
	}
	us.ok = true
	st := ut.status()
	s.set(FactUnits, st.State, st.Reason)
	st = tt.status()
	s.set(FactTimers, st.State, st.Reason)
	for _, t := range timers {
		if target, ok := us.byName[t.trigger]; ok {
			s.edge(t.uid, EdgeTriggers, target.uid)
		}
	}
	s.ok(EdgeIDTimerUnit)
	return us
}

func (c *Collector) linkUnitProcesses(s *Snapshot, us *unitSet, procs *processSet) {
	if !us.ok {
		s.unavailable(EdgeIDUnitProcess, ReasonDependency)
		return
	}
	var t tally
	names := make([]string, 0, len(us.byName))
	for n := range us.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := us.byName[n]
		if u.mainPID <= 0 {
			continue
		}
		puid, reason := procs.get(u.mainPID)
		switch reason {
		case "":
			s.edge(u.uid, EdgeMainProcess, puid)
			t.good()
		case ReasonProcessVanished:
		default:
			t.bad(reason)
		}
	}
	st := t.status()
	s.set(EdgeIDUnitProcess, st.State, st.Reason)
}
