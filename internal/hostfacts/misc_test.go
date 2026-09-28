package hostfacts

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

var update = flag.Bool("update", false, "rewrite docs/host-facts.md")

func TestCatalogDocCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "host-facts.md")
	want := RenderCatalog()
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatal("docs/host-facts.md is stale; run go test ./internal/hostfacts -run TestCatalogDocCurrent -update")
	}
	for _, r := range want {
		if r == 0x2013 || r == 0x2014 {
			t.Fatal("rendered catalog contains an en or em dash")
		}
	}
}

func TestCatalogConsistent(t *testing.T) {
	seen := map[string]bool{}
	kinds := map[string]bool{KindOS: true, KindKernel: true, KindCPU: true, KindMemory: true, KindBlockDevice: true, KindFilesystem: true, KindMount: true,
		KindInterface: true, KindSocket: true, KindUnit: true, KindTimer: true, KindPackage: true, KindProcess: true}
	covered := map[string]bool{}
	reasons := map[string]bool{}
	for _, r := range Reasons {
		reasons[r[0]] = true
	}
	for _, e := range Catalog {
		if seen[e.ID] || e.Source == "" || e.Permission == "" || e.NonRoot == "" || !kinds[e.Kind] {
			t.Fatalf("bad catalog entry %+v", e)
		}
		seen[e.ID] = true
		covered[e.Kind] = true
		for _, k := range e.ToKinds {
			if !kinds[k] {
				t.Fatalf("%s: unknown target kind %s", e.ID, k)
			}
		}
		for _, d := range e.DependsOn {
			if entry(d).ID != d {
				t.Fatalf("%s: dependency %s", e.ID, d)
			}
		}
	}
	for k := range kinds {
		if !covered[k] {
			t.Fatalf("kind %s not cataloged", k)
		}
	}
	for _, r := range []string{ReasonSourceAbsent, ReasonPermission, ReasonDBus, ReasonReadFailed, ReasonOtherUserFD, ReasonOwnerNotFound, ReasonDependency, ReasonProcessVanished, ReasonCapacityDenied} {
		if !reasons[r] {
			t.Fatalf("reason %s undocumented", r)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unknown id accepted")
		}
	}()
	entry("fact/none")
}

func TestKubernetesNodeDetection(t *testing.T) {
	root := t.TempDir()
	proc, fsRoot := filepath.Join(root, "proc"), filepath.Join(root, "fs")
	writeTree(t, root, map[string]string{"proc/1/comm": "systemd\n", "proc/77/comm": "sshd\n", "proc/self/comm": "kubelet\n", "fs/etc/hostname": "h\n"})
	if ok, ev, err := IsKubernetesNode(proc, fsRoot); err != nil || ok {
		t.Fatalf("plain host detected as node: %v %q %v", ok, ev, err)
	}
	writeTree(t, root, map[string]string{"proc/901/comm": "kubelet\n"})
	if ok, ev, err := IsKubernetesNode(proc, fsRoot); err != nil || !ok || !strings.Contains(ev, "901") {
		t.Fatalf("running kubelet: %v %q %v", ok, ev, err)
	}
	os.RemoveAll(filepath.Join(proc, "901"))
	writeTree(t, root, map[string]string{"fs/etc/kubernetes/kubelet.conf": "apiVersion: v1\n"})
	if ok, ev, err := IsKubernetesNode(proc, fsRoot); err != nil || !ok || !strings.Contains(ev, "kubelet.conf") {
		t.Fatalf("kubelet state: %v %q %v", ok, ev, err)
	}
	os.RemoveAll(filepath.Join(fsRoot, "etc", "kubernetes"))
	writeTree(t, root, map[string]string{"fs/var/lib/kubelet/pods/.keep": ""})
	locked := filepath.Join(fsRoot, "var", "lib", "kubelet")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o755)
	if _, err := os.Stat(filepath.Join(locked, "config.yaml")); err == nil || os.IsNotExist(err) {
		t.Skip("running with privileges that bypass directory modes")
	}
	if ok, ev, err := IsKubernetesNode(proc, fsRoot); err != nil || !ok || !strings.Contains(ev, "not searchable") {
		t.Fatalf("unsearchable kubelet directory: %v %q %v", ok, ev, err)
	}
	if _, _, err := IsKubernetesNode(filepath.Join(root, "missing"), fsRoot); err == nil {
		t.Fatal("missing procfs accepted")
	}
}

func TestSystemSources(t *testing.T) {
	u, err := SystemUname()
	if err != nil || u.Sysname != "Linux" || u.Release == "" || u.Machine == "" {
		t.Fatalf("uname %+v %v", u, err)
	}
	ifs, err := SystemInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	lo := false
	for _, i := range ifs {
		for _, f := range i.Flags {
			if f == "loopback" {
				lo = true
			}
		}
	}
	if !lo {
		t.Fatalf("no loopback interface in %+v", ifs)
	}
	d := DefaultOptions()
	if d.ProcRoot != "/proc" || d.DialSystemd == nil || d.UID != os.Geteuid() || len(d.RPMPaths) == 0 {
		t.Fatalf("defaults %+v", d)
	}
}

// fakeBus serves the systemd manager over a raw D-Bus connection after a SASL EXTERNAL handshake.
func fakeBus(t *testing.T, units any, props map[string]any) *dbus.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	go func() {
		br := bufio.NewReader(server)
		if b, err := br.ReadByte(); err != nil || b != 0 {
			return
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case line == "AUTH":
				server.Write([]byte("REJECTED EXTERNAL\r\n"))
			case strings.HasPrefix(line, "AUTH EXTERNAL"), strings.HasPrefix(line, "DATA"):
				server.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
			case line == "BEGIN":
				serveMessages(br, server, units, props)
				return
			default:
				server.Write([]byte("ERROR\r\n"))
			}
		}
	}()
	conn, err := dbus.NewConn(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal("1000")}); err != nil {
		t.Fatal(err)
	}
	return conn
}

func serveMessages(br *bufio.Reader, w net.Conn, units any, props map[string]any) {
	for {
		msg, err := dbus.DecodeMessage(br)
		if err != nil {
			return
		}
		member, _ := msg.Headers[dbus.FieldMember].Value().(string)
		path, _ := msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
		var body []any
		errName := ""
		switch member {
		case "ListUnits":
			body = []any{units}
		case "Get":
			key := string(path) + "|" + msg.Body[0].(string) + "|" + msg.Body[1].(string)
			if v, ok := props[key]; ok {
				body = []any{dbus.MakeVariant(v)}
			} else {
				errName = "org.freedesktop.DBus.Error.UnknownObject"
				body = []any{"no such object"}
			}
		default:
			errName = "org.freedesktop.DBus.Error.UnknownMethod"
			body = []any{"unknown"}
		}
		reply := &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldReplySerial: dbus.MakeVariant(msg.Serial()),
			dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf(body...)),
		}, Body: body}
		if errName != "" {
			reply.Type = dbus.TypeError
			reply.Headers[dbus.FieldErrorName] = dbus.MakeVariant(errName)
		}
		if err := reply.EncodeTo(w, binary.LittleEndian); err != nil {
			return
		}
	}
}

func TestDBusSystemdAdapter(t *testing.T) {
	type unitRow struct {
		Name, Description, LoadState, ActiveState, SubState, Followed string
		Path                                                          dbus.ObjectPath
		JobID                                                         uint32
		JobType                                                       string
		JobPath                                                       dbus.ObjectPath
	}
	rows := []unitRow{
		{"sshd.service", "OpenSSH server daemon", "loaded", "active", "running", "", "/org/freedesktop/systemd1/unit/sshd_2eservice", 0, "", "/"},
		{"fstrim.timer", "Discard unused blocks once a week", "loaded", "active", "waiting", "", "/org/freedesktop/systemd1/unit/fstrim_2etimer", 0, "", "/"},
	}
	props := map[string]any{
		"/org/freedesktop/systemd1/unit/sshd_2eservice|" + ifaceUnit + "|FragmentPath":            "/usr/lib/systemd/system/sshd.service",
		"/org/freedesktop/systemd1/unit/sshd_2eservice|" + ifaceUnit + "|UnitFileState":           "enabled",
		"/org/freedesktop/systemd1/unit/sshd_2eservice|" + ifaceService + "|MainPID":              uint32(812),
		"/org/freedesktop/systemd1/unit/fstrim_2etimer|" + ifaceUnit + "|FragmentPath":            "/usr/lib/systemd/system/fstrim.timer",
		"/org/freedesktop/systemd1/unit/fstrim_2etimer|" + ifaceUnit + "|UnitFileState":           "enabled",
		"/org/freedesktop/systemd1/unit/fstrim_2etimer|" + ifaceTimer + "|Unit":                   "fstrim.service",
		"/org/freedesktop/systemd1/unit/fstrim_2etimer|" + ifaceTimer + "|NextElapseUSecRealtime": uint64(1790000000000000),
		"/org/freedesktop/systemd1/unit/fstrim_2etimer|" + ifaceTimer + "|LastTriggerUSec":        uint64(0),
	}
	sd := NewDBusSystemd(fakeBus(t, rows, props))
	defer sd.Close()
	ctx := context.Background()
	list, err := sd.ListUnits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "sshd.service" || list[0].SubState != "running" || list[1].Path != "/org/freedesktop/systemd1/unit/fstrim_2etimer" {
		t.Fatalf("units %+v", list)
	}
	p, err := sd.Properties(ctx, list[0].Path, ifaceService, "MainPID")
	if err != nil || p["MainPID"] != uint32(812) {
		t.Fatalf("MainPID %v %v", p, err)
	}
	p, err = sd.Properties(ctx, list[1].Path, ifaceTimer, "Unit", "NextElapseUSecRealtime")
	if err != nil || p["Unit"] != "fstrim.service" || p["NextElapseUSecRealtime"] != uint64(1790000000000000) {
		t.Fatalf("timer %v %v", p, err)
	}
	if _, err := sd.Properties(ctx, "/org/freedesktop/systemd1/unit/gone_2eservice", ifaceUnit, "FragmentPath"); !errors.Is(err, ErrNoSuchUnit) {
		t.Fatalf("vanished unit err = %v", err)
	}
	empty := t.TempDir()
	c := NewCollector(Options{ProcRoot: empty, EtcRoot: empty, SysRoot: empty, UsrLibRoot: empty, DpkgDir: empty, APKInstalled: filepath.Join(empty, "apk"),
		RPMPaths: []string{}, Systemd: sd, Uname: func() (Uname, error) { return Uname{}, os.ErrNotExist },
		Interfaces: func() ([]NetInterface, error) { return nil, nil }})
	s := c.Collect(ctx)
	if s.Resources[uid(KindUnit, "sshd.service")].Fields["fragment_path"] != "/usr/lib/systemd/system/sshd.service" || s.Resources[uid(KindTimer, "fstrim.timer")].Fields["scheduled"] != true {
		t.Fatalf("collected over D-Bus: %v", keys(s))
	}
	if st := s.Status[EdgeIDUnitProcess]; st.State != 0 || len(s.Edges) != 0 {
		t.Fatalf("a main PID that exited is a race, not unavailability: %+v %v", st, s.Edges)
	}
}
