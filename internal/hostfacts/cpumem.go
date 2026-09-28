package hostfacts

import (
	"github.com/prometheus/procfs"
)

func (c *Collector) procFS() (procfs.FS, error) { return procfs.NewFS(c.o.ProcRoot) }

func (c *Collector) collectCPU(s *Snapshot) {
	fs, err := c.procFS()
	if err != nil {
		s.unavailable(FactCPU, reasonFor(err))
		return
	}
	infos, err := fs.CPUInfo()
	if err != nil || len(infos) == 0 {
		s.unavailable(FactCPU, reasonFor(err))
		return
	}
	pkgs := map[string]bool{}
	cores := map[[2]string]bool{}
	for _, i := range infos {
		if i.PhysicalID != "" {
			pkgs[i.PhysicalID] = true
		}
		if i.CoreID != "" {
			cores[[2]string{i.PhysicalID, i.CoreID}] = true
		}
	}
	fields := map[string]any{"logical_cpus": int64(len(infos))}
	if infos[0].ModelName != "" {
		fields["model_name"] = clean(infos[0].ModelName)
	}
	if infos[0].VendorID != "" {
		fields["vendor_id"] = clean(infos[0].VendorID)
	}
	if len(pkgs) > 0 {
		fields["packages"] = int64(len(pkgs))
	}
	if len(cores) > 0 {
		fields["cores"] = int64(len(cores))
	}
	name, _ := fields["model_name"].(string)
	s.add(uid(KindCPU), KindCPU, name, fields)
	s.ok(FactCPU)
}

func (c *Collector) collectMemory(s *Snapshot) {
	fs, err := c.procFS()
	if err != nil {
		s.unavailable(FactMemory, reasonFor(err))
		return
	}
	mi, err := fs.Meminfo()
	if err != nil || mi.MemTotal == nil {
		s.unavailable(FactMemory, reasonFor(err))
		return
	}
	fields := map[string]any{"mem_total_bytes": int64(*mi.MemTotal) * 1024}
	if mi.SwapTotal != nil {
		fields["swap_total_bytes"] = int64(*mi.SwapTotal) * 1024
	}
	s.add(uid(KindMemory), KindMemory, "memory", fields)
	s.ok(FactMemory)
}
