package hostfacts

import (
	"errors"
	"io/fs"
	"math"
	"sort"
	"strings"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const usedBucketPct = 10

func (c *Collector) collectMounts(s *Snapshot, devs *deviceIndex) {
	pfs, err := c.procFS()
	var mounts []*procfs.MountInfo
	if err == nil {
		mounts, err = pfs.GetMounts()
	}
	if err != nil {
		r := reasonFor(err)
		s.unavailable(FactMounts, r)
		s.unavailable(FactFilesystems, r)
		s.unavailable(EdgeIDMountDevice, ReasonDependency)
		s.unavailable(EdgeIDMountFilesystem, ReasonDependency)
		return
	}
	type mnt struct {
		uid string
		m   *procfs.MountInfo
	}
	byUID := map[string]mnt{}
	for _, m := range mounts {
		if c.o.FSTypesExclude.MatchString(m.FSType) || c.o.MountPointsExclude.MatchString(m.MountPoint) {
			continue
		}
		u := uid(KindMount, m.MountPoint, m.Source)
		byUID[u] = mnt{u, m}
	}
	list := make([]mnt, 0, len(byUID))
	for _, v := range byUID {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].m.MountPoint < list[j].m.MountPoint || list[i].m.MountPoint == list[j].m.MountPoint && list[i].uid < list[j].uid
	})
	groups := map[string][]*procfs.MountInfo{}
	var order []string
	for _, v := range list {
		m := v.m
		opts := make([]string, 0, len(m.Options))
		for k, val := range m.Options {
			if val != "" {
				k += "=" + val
			}
			opts = append(opts, k)
		}
		_, ro := m.Options["ro"]
		s.add(v.uid, KindMount, m.MountPoint, map[string]any{
			"mount_point": clean(m.MountPoint), "source": clean(m.Source), "fstype": m.FSType, "root": clean(m.Root),
			"device": m.MajorMinorVer, "read_only": ro, "options": strList(opts),
		})
		if d, ok := devs.byDev[m.MajorMinorVer]; ok {
			s.edge(v.uid, EdgeDevice, d)
		} else if name, ok := strings.CutPrefix(m.Source, "/dev/"); ok {
			if d, ok := devs.byName[name]; ok {
				s.edge(v.uid, EdgeDevice, d)
			}
		}
		if _, ok := groups[m.MajorMinorVer]; !ok {
			order = append(order, m.MajorMinorVer)
		}
		groups[m.MajorMinorVer] = append(groups[m.MajorMinorVer], m)
	}
	s.ok(FactMounts)
	s.ok(EdgeIDMountFilesystem)
	if devs.ok {
		s.ok(EdgeIDMountDevice)
	} else {
		s.unavailable(EdgeIDMountDevice, ReasonDependency)
	}
	var t tally
	for _, dev := range order {
		first := groups[dev][0]
		fsUID := uid(KindFilesystem, first.FSType, first.Source)
		if !strings.HasPrefix(first.Source, "/") {
			fsUID = uid(KindFilesystem, first.FSType, first.Source, first.MountPoint)
		}
		if _, dup := s.Resources[fsUID]; dup {
			fsUID = uid(KindFilesystem, first.FSType, first.Source, first.MountPoint)
		}
		fields := map[string]any{"fstype": first.FSType, "source": clean(first.Source), "device": dev}
		var st unix.Statfs_t
		switch err := c.o.Statfs(first.MountPoint, &st); {
		case err == nil:
			size, inodes, ok := capacity(&st)
			if !ok {
				fields["capacity_unavailable"] = ReasonReadFailed
				t.bad(ReasonReadFailed)
				break
			}
			fields["size_bytes"] = size
			fields["inodes_total"] = inodes
			if size > 0 {
				pct := float64(st.Blocks-st.Bfree) * 100 / float64(st.Blocks)
				fields["used_pct_bucket"] = c.bucket(fsUID, pct)
			}
			t.good()
		case errors.Is(err, fs.ErrPermission):
			fields["capacity_unavailable"] = ReasonCapacityDenied
			t.bad(ReasonCapacityDenied)
		default:
			fields["capacity_unavailable"] = ReasonReadFailed
			t.bad(ReasonReadFailed)
		}
		s.add(fsUID, KindFilesystem, first.MountPoint, fields)
		for _, m := range groups[dev] {
			s.edge(uid(KindMount, m.MountPoint, m.Source), EdgeFilesystem, fsUID)
		}
	}
	st := t.status()
	if st.State == protocol.ScopeUnavailable {
		st.State = protocol.ScopePartial
	}
	s.set(FactFilesystems, st.State, st.Reason)
}

// capacity returns the size in bytes and the inode count of a statfs result, false when either exceeds int64.
func capacity(st *unix.Statfs_t) (size, inodes int64, ok bool) {
	blocks, bsize, files := st.Blocks, int64(st.Bsize), st.Files //nolint:unconvert // Statfs_t.Bsize is int32 on 32-bit GOARCHes
	if bsize < 0 || blocks > math.MaxInt64 || files > math.MaxInt64 {
		return 0, 0, false
	}
	n := int64(blocks)
	if bsize > 0 && n > math.MaxInt64/bsize {
		return 0, 0, false
	}
	return n * bsize, int64(files), true
}

// bucket returns the used-space bucket with a two point hysteresis so a filesystem near a boundary does not flap.
func (c *Collector) bucket(fsUID string, pct float64) int64 {
	if c.buckets == nil {
		c.buckets = map[string]int64{}
	}
	b := int64(pct/usedBucketPct) * usedBucketPct
	if prev, ok := c.buckets[fsUID]; ok && pct >= float64(prev)-2 && pct < float64(prev+usedBucketPct)+2 {
		b = prev
	}
	c.buckets[fsUID] = b
	return b
}
