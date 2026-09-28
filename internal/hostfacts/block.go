package hostfacts

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type deviceIndex struct {
	byDev  map[string]string
	byName map[string]string
	ok     bool
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readInt(path string) (int64, bool) {
	s, err := readTrim(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

func (c *Collector) collectBlockDevices(s *Snapshot) *deviceIndex {
	idx := &deviceIndex{byDev: map[string]string{}, byName: map[string]string{}}
	root := filepath.Join(c.o.SysRoot, "block")
	ents, err := os.ReadDir(root)
	if err != nil {
		s.unavailable(FactBlockDevices, reasonFor(err))
		s.unavailable(EdgeIDPartitionDisk, ReasonDependency)
		return idx
	}
	idx.ok = true
	var t tally
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		dir := filepath.Join(root, name)
		size, ok := readInt(filepath.Join(dir, "size"))
		if !ok {
			t.bad(ReasonReadFailed)
			continue
		}
		if size == 0 {
			continue
		}
		dev, err := readTrim(filepath.Join(dir, "dev"))
		if err != nil {
			t.bad(reasonFor(err))
			continue
		}
		fields := map[string]any{"device": dev, "size_bytes": size * 512}
		for file, key := range map[string]string{"queue/rotational": "rotational", "removable": "removable", "ro": "read_only"} {
			if v, ok := readInt(filepath.Join(dir, file)); ok {
				fields[key] = v == 1
			}
		}
		if m, err := readTrim(filepath.Join(dir, "device", "model")); err == nil && m != "" {
			fields["model"] = clean(m)
		}
		if dm, err := readTrim(filepath.Join(dir, "dm", "name")); err == nil && dm != "" {
			fields["dm_name"] = clean(dm)
			idx.byName["mapper/"+dm] = uid(KindBlockDevice, name)
		}
		diskUID := uid(KindBlockDevice, name)
		s.add(diskUID, KindBlockDevice, name, fields)
		idx.byDev[dev] = diskUID
		idx.byName[name] = diskUID
		t.good()
		subs, _ := os.ReadDir(dir)
		for _, sub := range subs {
			pdir := filepath.Join(dir, sub.Name())
			pn, ok := readInt(filepath.Join(pdir, "partition"))
			if !ok {
				continue
			}
			psize, ok1 := readInt(filepath.Join(pdir, "size"))
			pdev, err := readTrim(filepath.Join(pdir, "dev"))
			if !ok1 || err != nil {
				t.bad(ReasonReadFailed)
				continue
			}
			pf := map[string]any{"device": pdev, "size_bytes": psize * 512, "partition": pn}
			if v, ok := readInt(filepath.Join(pdir, "ro")); ok {
				pf["read_only"] = v == 1
			}
			puid := uid(KindBlockDevice, sub.Name())
			s.add(puid, KindBlockDevice, sub.Name(), pf)
			s.edge(puid, EdgePartitionOf, diskUID)
			idx.byDev[pdev] = puid
			idx.byName[sub.Name()] = puid
			t.good()
		}
	}
	st := t.status()
	s.set(FactBlockDevices, st.State, st.Reason)
	s.ok(EdgeIDPartitionDisk)
	return idx
}
