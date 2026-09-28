package investigate

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
)

const (
	hostLogMaxDepth   = 3
	hostLogMaxLine    = 64 << 10
	hostFilenameLabel = "filename"
)

// readStats collects on-demand read truncation across sources.
type readStats struct {
	omitted     int
	scanLimited bool
	longLines   int
	untimed     int
}

// hostFileSource reads the tails of allowlisted host log files within a scan budget.
type hostFileSource struct {
	paths      []string
	scanBudget int64
	stats      *readStats
}

var compressedExt = []string{".gz", ".xz", ".zst", ".bz2", ".lz4", ".zip"}

func (h *hostFileSource) files() []string {
	var out []string
	for _, root := range h.paths {
		fi, err := os.Stat(root)
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() {
			out = append(out, filepath.Clean(root))
			continue
		}
		if !fi.IsDir() {
			continue
		}
		base := strings.Count(filepath.Clean(root), string(filepath.Separator))
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(p, string(filepath.Separator))-base >= hostLogMaxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && !hasCompressedExt(p) {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}

func hasCompressedExt(p string) bool {
	for _, ext := range compressedExt {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func (h *hostFileSource) Scan(ctx context.Context, req logql.SourceRequest, yield func(logql.Line) bool) error {
	budget := h.scanBudget
	for _, p := range h.files() {
		if err := ctx.Err(); err != nil {
			return err
		}
		lbls := map[string]string{hostFilenameLabel: p}
		if !req.Match(lbls) {
			continue
		}
		if budget <= 0 {
			h.stats.scanLimited = true
			return nil
		}
		n, cont, err := h.scanFile(p, lbls, req, budget, yield)
		budget -= n
		if err != nil || !cont {
			return err
		}
	}
	return nil
}

func (h *hostFileSource) scanFile(p string, lbls map[string]string, req logql.SourceRequest, budget int64, yield func(logql.Line) bool) (int64, bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, true, nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.ModTime().Before(req.Start) {
		return 0, true, nil
	}
	off := max(fi.Size()-budget, 0)
	if off > 0 {
		h.stats.scanLimited = true
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return 0, true, nil
		}
	}
	r := bufio.NewReaderSize(io.LimitReader(f, fi.Size()-off), 64<<10)
	for skip := off > 0; skip; {
		_, err := r.ReadSlice('\n')
		if err == nil {
			break
		}
		if err != bufio.ErrBufferFull {
			return fi.Size() - off, true, nil
		}
	}
	mtime := fi.ModTime()
	var last time.Time
	for {
		line, err := readLine(r, h.stats)
		if len(line) > 0 {
			ts, ok := lineTime(line, mtime)
			switch {
			case ok:
				last = ts
			case !last.IsZero():
				ts = last
			default:
				ts = mtime
				h.stats.untimed++
			}
			if !ts.Before(req.Start) && !ts.After(req.End) {
				if !yield(logql.Line{Labels: lbls, Time: ts, Text: line}) {
					return fi.Size() - off, false, nil
				}
			}
		}
		if err != nil {
			return fi.Size() - off, true, nil
		}
	}
}

func readLine(r *bufio.Reader, st *readStats) (string, error) {
	var buf []byte
	long := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > hostLogMaxLine {
			chunk = chunk[:max(hostLogMaxLine-len(buf), 0)]
			long = true
		}
		buf = append(buf, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if long {
			st.longLines++
		}
		return string(bytes.TrimRight(buf, "\r\n")), err
	}
}

// lineTime parses an RFC 3339 or classic syslog timestamp prefix.
func lineTime(line string, mtime time.Time) (time.Time, bool) {
	if i := strings.IndexByte(line, ' '); i > 0 {
		if t, err := time.Parse(time.RFC3339Nano, line[:i]); err == nil {
			return t, true
		}
	}
	if len(line) >= 15 {
		t, err := time.ParseInLocation(time.Stamp, line[:15], mtime.Location())
		if err == nil {
			t = t.AddDate(mtime.Year(), 0, 0)
			if t.After(mtime.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}
