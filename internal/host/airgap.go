package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Export file rolling limits for the air-gap profile.
const (
	ExportRollBytes = 64 << 20
	ExportRollAge   = time.Hour
	exportSuffix    = ".emhpx"
	partSuffix      = ".part"
	keyOpenExport   = "open"
)

type exportFile struct {
	f      *os.File
	w      *protocol.ExportWriter
	path   string
	epoch  protocol.EpochID
	first  uint64
	last   uint64
	bytes  int64
	opened time.Time
}

type openExport struct {
	Path  string `json:"path"`
	Epoch string `json:"epoch"`
	First uint64 `json:"first"`
}

type countingWriter struct {
	f *os.File
	n *int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.f.Write(p)
	*c.n += int64(n)
	return n, err
}

func (h *Host) exportStore() (kv.Store, error) { return h.bucket("airgap") }

func cursorKey(epoch protocol.EpochID) string { return "exported/" + epoch.String() }

func (h *Host) exportDir() string {
	if h.cfg.AirGap.ExportDir != "" {
		return h.cfg.AirGap.ExportDir
	}
	return filepath.Join(h.cfg.StateDir, "export")
}

// recoverExport discards a file left open by a crash; its records are still spooled and are exported again.
func (h *Host) recoverExport(st kv.Store) error {
	b, ok, err := st.Get(keyOpenExport)
	if err != nil || !ok {
		return err
	}
	var o openExport
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	if err := os.Remove(o.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ops := map[string][]byte{keyOpenExport: nil}
	if o.First > 0 {
		ops["exported/"+o.Epoch] = []byte(strconv.FormatUint(o.First-1, 10))
	}
	h.log.Warn("discarded an unfinished export file; its records are exported again", "path", o.Path)
	return st.Batch(ops)
}

func exportedThrough(st kv.Store, epoch protocol.EpochID) (uint64, error) {
	b, ok, err := st.Get(cursorKey(epoch))
	if err != nil || !ok {
		return 0, err
	}
	return strconv.ParseUint(string(b), 10, 64)
}

// exportPending appends newly spooled records to the rolling export file, marking them transmitted first (A9).
func (h *Host) exportPending(now time.Time) error {
	st, err := h.exportStore()
	if err != nil {
		return err
	}
	if !h.exportRecovered {
		if err := h.recoverExport(st); err != nil {
			return err
		}
		h.exportRecovered = true
	}
	ep, ok := h.sp.Epoch()
	if !ok {
		return nil
	}
	x := h.exp
	if x != nil && (x.epoch != ep.ID || x.bytes >= ExportRollBytes || now.Sub(x.opened) >= ExportRollAge) {
		if err := h.finishExport(st); err != nil {
			return err
		}
	}
	through, err := exportedThrough(st, ep.ID)
	if err != nil {
		return err
	}
	if es := h.sp.Entries(through + 1); len(es) == 0 {
		return nil
	}
	if h.exp == nil {
		if err := h.startExport(st, ep.ID, through+1, now); err != nil {
			return err
		}
	}
	x = h.exp
	last, err := eachPage(h.sp, through+1, true, x.w.Write)
	if err != nil {
		h.setErr(&h.st.exportError, err)
		return err
	}
	if last == 0 {
		return nil
	}
	if err := x.f.Sync(); err != nil {
		return err
	}
	x.last = last
	if err := st.Put(cursorKey(ep.ID), []byte(strconv.FormatUint(last, 10))); err != nil {
		return err
	}
	h.mu.Lock()
	h.st.exported, h.st.exportError = last, ""
	h.mu.Unlock()
	return nil
}

func (h *Host) startExport(st kv.Store, epoch protocol.EpochID, first uint64, now time.Time) error {
	dir := h.exportDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	id := h.sp.Identity()
	name := fmt.Sprintf("exitmesh-%s-%s-%d", id.TargetID, epoch, first)
	path := filepath.Join(dir, name+exportSuffix+partSuffix)
	b, _ := json.Marshal(openExport{Path: path, Epoch: epoch.String(), First: first})
	if err := st.Put(keyOpenExport, b); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	x := &exportFile{f: f, path: path, epoch: epoch, first: first, opened: now}
	wid := h.sp.WriterID()
	lc, _ := h.sp.LastCommitted()
	x.w, err = protocol.NewExportWriter(countingWriter{f: f, n: &x.bytes}, protocol.ExportHeader{
		TargetID: id.TargetID, WriterID: wid[:], Incarnation: h.sp.Incarnation(), Epoch: epoch[:],
		LastCommitted: lc.Seq, ExportedAt: uint64(now.UnixMilli()), AgentVersion: Version,
	})
	if err != nil {
		return errors.Join(err, f.Close())
	}
	h.exp = x
	return nil
}

// finishExport renames the open file to its final name carrying the first and last sequence.
func (h *Host) finishExport(st kv.Store) error {
	x := h.exp
	if x == nil {
		return nil
	}
	h.exp = nil
	if err := x.f.Sync(); err != nil {
		return errors.Join(err, x.f.Close())
	}
	if err := x.f.Close(); err != nil {
		return err
	}
	if x.last == 0 {
		if err := os.Remove(x.path); err != nil {
			return err
		}
		return st.Delete(keyOpenExport)
	}
	final := strings.TrimSuffix(x.path, exportSuffix+partSuffix) + "-" + strconv.FormatUint(x.last, 10) + exportSuffix
	if err := os.Rename(x.path, final); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(final)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	h.mu.Lock()
	h.st.exportFiles++
	h.mu.Unlock()
	return st.Delete(keyOpenExport)
}

func (h *Host) closeExport() {
	if h.exp == nil || h.meta == nil {
		return
	}
	st, err := h.exportStore()
	if err == nil {
		err = h.finishExport(st)
	}
	if err != nil {
		h.log.Warn("finish export file", "err", err)
	}
}

// pruneExports deletes finished export files of epoch whose records are all committed.
func (h *Host) pruneExports(epoch protocol.EpochID, seq uint64) {
	ents, err := os.ReadDir(h.exportDir())
	if err != nil {
		return
	}
	id := h.sp.Identity()
	prefix := fmt.Sprintf("exitmesh-%s-%s-", id.TargetID, epoch)
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, exportSuffix) {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(n, prefix), exportSuffix), "-")
		if len(parts) != 2 {
			continue
		}
		last, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || last > seq {
			continue
		}
		if err := os.Remove(filepath.Join(h.exportDir(), n)); err != nil {
			h.log.Warn("remove committed export file", "file", n, "err", err)
		}
	}
}
