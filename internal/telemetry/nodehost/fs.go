package nodehost

import (
	"syscall"

	"github.com/prometheus/prometheus/model/labels"
)

// gatherFilesystems emits size and available bytes once per filesystem; unreadable paths are skipped.
func (c *Collector) gatherFilesystems(emit func(l labels.Labels, v float64)) int {
	seen := map[uint64]bool{}
	n := 0
	for _, path := range c.o.Filesystems {
		var st syscall.Stat_t
		if path == "" || syscall.Stat(path, &st) != nil || seen[st.Dev] {
			continue
		}
		var fs syscall.Statfs_t
		if syscall.Statfs(path, &fs) != nil || fs.Blocks == 0 {
			continue
		}
		seen[st.Dev] = true
		bsize := float64(fs.Bsize)
		emit(c.labels("node_filesystem_size_bytes", "mountpoint", path), float64(fs.Blocks)*bsize)
		emit(c.labels("node_filesystem_avail_bytes", "mountpoint", path), float64(fs.Bavail)*bsize)
		n += 2
	}
	return n
}
