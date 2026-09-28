package hostfacts

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var osReleaseFields = map[string]string{
	"ID": "id", "ID_LIKE": "id_like", "NAME": "name", "PRETTY_NAME": "pretty_name",
	"VERSION_ID": "version_id", "VERSION_CODENAME": "version_codename", "VARIANT_ID": "variant_id",
}

// ParseOSRelease parses os-release(5) content.
func ParseOSRelease(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = unquoteShell(strings.TrimSpace(v))
	}
	return out
}

func unquoteShell(v string) string {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
		var b strings.Builder
		for i := 0; i < len(v); i++ {
			if v[i] == '\\' && i+1 < len(v) && strings.IndexByte("\"\\$`", v[i+1]) >= 0 {
				i++
			}
			b.WriteByte(v[i])
		}
		return b.String()
	}
	return v
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ReasonSourceAbsent
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermission
	}
	return ReasonReadFailed
}

func (c *Collector) collectOS(s *Snapshot) {
	fields := map[string]any{}
	b, err := os.ReadFile(filepath.Join(c.o.EtcRoot, "os-release"))
	if errors.Is(err, fs.ErrNotExist) {
		b, err = os.ReadFile(filepath.Join(c.o.UsrLibRoot, "os-release"))
	}
	if err != nil {
		s.unavailable(FactOS, reasonFor(err))
	} else {
		for k, v := range ParseOSRelease(b) {
			if f, ok := osReleaseFields[k]; ok && v != "" {
				fields[f] = clean(v)
			}
		}
		s.ok(FactOS)
	}
	u, uerr := c.o.Uname()
	if uerr != nil {
		s.unavailable(FactHostname, ReasonReadFailed)
		s.unavailable(FactKernel, ReasonReadFailed)
	} else {
		fields["hostname"] = clean(u.Nodename)
		s.ok(FactHostname)
		s.add(uid(KindKernel), KindKernel, u.Release, map[string]any{
			"sysname": clean(u.Sysname), "release": clean(u.Release), "version": clean(u.Version), "machine": clean(u.Machine),
		})
		s.ok(FactKernel)
	}
	mid, err := os.ReadFile(filepath.Join(c.o.EtcRoot, "machine-id"))
	id := strings.TrimSpace(string(mid))
	switch {
	case err != nil:
		s.unavailable(FactMachineID, reasonFor(err))
	case !validMachineID(id):
		s.unavailable(FactMachineID, ReasonReadFailed)
	default:
		fields["machine_id"] = id
		s.ok(FactMachineID)
	}
	if len(fields) > 0 {
		name, _ := fields["pretty_name"].(string)
		if name == "" {
			name, _ = fields["hostname"].(string)
		}
		s.add(uid(KindOS), KindOS, name, fields)
	}
}

func validMachineID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
