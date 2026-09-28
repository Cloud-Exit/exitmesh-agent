package hostfacts

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const ifaFTemporary = 0x01

// temporaryIPv6 returns the IPv6 privacy (temporary) addresses from if_inet6, which rotate and are excluded.
func temporaryIPv6(procRoot string) map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(filepath.Join(procRoot, "net", "if_inet6"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 6 {
			continue
		}
		flags, err := strconv.ParseUint(p[4], 16, 32)
		if err != nil || flags&ifaFTemporary == 0 {
			continue
		}
		b, err := hex.DecodeString(p[0])
		if err != nil || len(b) != net.IPv6len {
			continue
		}
		out[net.IP(b).String()] = true
	}
	return out
}

func (c *Collector) collectInterfaces(s *Snapshot) {
	ifs, err := c.o.Interfaces()
	if err != nil {
		s.unavailable(FactInterfaces, reasonFor(err))
		return
	}
	temp := temporaryIPv6(c.o.ProcRoot)
	for _, i := range ifs {
		if c.o.InterfacesExclude.MatchString(i.Name) {
			continue
		}
		var addrs []string
		for _, a := range i.Addrs {
			ip, _, err := net.ParseCIDR(a)
			if err == nil && temp[ip.String()] {
				continue
			}
			addrs = append(addrs, a)
		}
		fields := map[string]any{"index": int64(i.Index), "mtu": int64(i.MTU), "flags": strList(i.Flags), "addresses": strList(addrs)}
		if i.HardwareAddr != "" {
			fields["hardware_addr"] = i.HardwareAddr
		}
		if st, err := readTrim(filepath.Join(c.o.SysRoot, "class", "net", i.Name, "operstate")); err == nil && st != "" {
			fields["operstate"] = st
		}
		s.add(uid(KindInterface, i.Name), KindInterface, i.Name, fields)
	}
	s.ok(FactInterfaces)
}
