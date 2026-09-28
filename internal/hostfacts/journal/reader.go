package journal

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

// Entry is one journal entry.
type Entry struct {
	Realtime time.Time
	Fields   map[string]string
	Cursor   Cursor
}

var streamLabels = [][2]string{
	{"unit", "_SYSTEMD_UNIT"},
	{"syslog_identifier", "SYSLOG_IDENTIFIER"},
	{"priority", "PRIORITY"},
	{"transport", "_TRANSPORT"},
}

// Labels returns the LogQL stream labels of the entry; absent fields yield no label.
func (e Entry) Labels() map[string]string {
	out := make(map[string]string, len(streamLabels))
	for _, l := range streamLabels {
		if v := e.Fields[l[1]]; v != "" {
			out[l[0]] = v
		}
	}
	return out
}

// Message returns the log line.
func (e Entry) Message() string { return e.Fields["MESSAGE"] }

// Cursor identifies a position: the sequence number domain, the sequence number, and realtime in microseconds.
type Cursor struct {
	SeqnumID ID128
	Seqnum   uint64
	Realtime uint64
}

func (c Cursor) String() string {
	return fmt.Sprintf("s=%s;i=%x;t=%x", c.SeqnumID, c.Seqnum, c.Realtime)
}

// ParseCursor parses the form written by Cursor.String; unknown keys are ignored.
func ParseCursor(s string) (Cursor, error) {
	var c Cursor
	have := 0
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return c, fmt.Errorf("journal: malformed cursor %q", s)
		}
		switch k {
		case "s":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 16 {
				return c, fmt.Errorf("journal: malformed cursor %q", s)
			}
			copy(c.SeqnumID[:], b)
			have |= 1
		case "i", "t":
			n, err := strconv.ParseUint(v, 16, 64)
			if err != nil {
				return c, fmt.Errorf("journal: malformed cursor %q", s)
			}
			if k == "i" {
				c.Seqnum, have = n, have|2
			} else {
				c.Realtime, have = n, have|4
			}
		}
	}
	if have != 7 {
		return c, fmt.Errorf("journal: incomplete cursor %q", s)
	}
	return c, nil
}

// Options configures a Reader.
type Options struct {
	// Dirs are scanned with their immediate subdirectories (the machine ID directories).
	Dirs []string
	// Store persists the cursor under CursorKey; nil keeps it in memory only.
	Store     kv.Store
	CursorKey string
	// Since skips older entries when no cursor is stored; zero reads from the head.
	Since          time.Time
	PollInterval   time.Duration
	MaxObjectBytes int64
}

// DefaultCursorKey is the kv key of the persisted cursor.
const DefaultCursorKey = "journal/cursor"

// Reader merges the entries of every journal file in realtime order. It is not safe for concurrent use.
type Reader struct {
	o         Options
	files     []*jfile
	byID      map[ID128]*jfile
	paths     map[string]pathInfo
	done      map[ID128]bool
	cursor    Cursor
	hasCursor bool
	resume    Cursor
	hasResume bool
	zstd      *zstd.Decoder
	errs      map[string]error
}

type pathInfo struct {
	ino    uint64
	id     ID128
	failed bool
	size   int64
	mtime  int64
}

// Open loads the persisted cursor and opens every journal file.
func Open(o Options) (*Reader, error) {
	if o.CursorKey == "" {
		o.CursorKey = DefaultCursorKey
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.MaxObjectBytes <= 0 {
		o.MaxObjectBytes = 16 << 20
	}
	r := &Reader{o: o, byID: map[ID128]*jfile{}, paths: map[string]pathInfo{}, done: map[ID128]bool{}, errs: map[string]error{}}
	if o.Store != nil {
		b, ok, err := o.Store.Get(o.CursorKey)
		if err != nil {
			return nil, err
		}
		if ok {
			c, err := ParseCursor(string(b))
			if err != nil {
				return nil, err
			}
			r.cursor, r.hasCursor = c, true
			r.resume, r.hasResume = c, true
		}
	}
	if err := r.scan(); err != nil {
		return nil, err
	}
	return r, nil
}

// Close closes every open file.
func (r *Reader) Close() error {
	for _, f := range r.files {
		f.obj.f.Close()
	}
	r.files = nil
	if r.zstd != nil {
		r.zstd.Close()
	}
	return nil
}

// Cursor returns the position of the last delivered entry, or the loaded cursor.
func (r *Reader) Cursor() (Cursor, bool) { return r.cursor, r.hasCursor }

// SaveCursor persists the cursor.
func (r *Reader) SaveCursor() error {
	if r.o.Store == nil || !r.hasCursor {
		return nil
	}
	return r.o.Store.Put(r.o.CursorKey, []byte(r.cursor.String()))
}

// FileErrors returns files skipped because they are corrupt or unsupported, by path.
func (r *Reader) FileErrors() map[string]error {
	out := make(map[string]error, len(r.errs))
	for k, v := range r.errs {
		out[k] = v
	}
	return out
}

func (r *Reader) scan() error {
	var dirs []string
	for _, d := range r.o.Dirs {
		dirs = append(dirs, d)
		ents, err := os.ReadDir(d)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range ents {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join(d, e.Name()))
			}
		}
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".journal") || strings.HasSuffix(e.Name(), ".journal~")) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			p := filepath.Join(d, n)
			seen[p] = true
			r.consider(p)
		}
	}
	for p := range r.paths {
		if !seen[p] {
			delete(r.paths, p)
			delete(r.errs, p)
		}
	}
	return nil
}

func (r *Reader) consider(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	var ino uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = st.Ino
	}
	if pi, ok := r.paths[path]; ok && pi.ino == ino && (!pi.failed || pi.size == fi.Size() && pi.mtime == fi.ModTime().UnixNano()) {
		return
	}
	f, err := r.openFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			err = fmt.Errorf("journal: %s: %w", path, err)
		}
		r.errs[path] = err
		r.paths[path] = pathInfo{ino: ino, failed: true, size: fi.Size(), mtime: fi.ModTime().UnixNano()}
		return
	}
	id := f.obj.h.fileID
	r.paths[path] = pathInfo{ino: ino, id: id}
	if existing, ok := r.byID[id]; ok || r.done[id] {
		f.obj.f.Close()
		if ok {
			existing.path = path
		}
		return
	}
	delete(r.errs, path)
	r.initialSeek(f)
	if f.err != nil {
		r.errs[path] = f.err
		f.obj.f.Close()
		return
	}
	if f.finished() && f.obj.h.state == stateArchived {
		r.done[id] = true
		f.obj.f.Close()
		return
	}
	r.files = append(r.files, f)
	r.byID[id] = f
}

func (r *Reader) openFile(path string) (*jfile, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	o := &objects{f: fh, maxBytes: r.o.MaxObjectBytes}
	if err := o.refresh(); err != nil {
		fh.Close()
		return nil, fmt.Errorf("journal: %s: %w", path, err)
	}
	if r.zstd == nil {
		d, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(r.o.MaxObjectBytes)))
		if err != nil {
			fh.Close()
			return nil, err
		}
		r.zstd = d
	}
	o.zstd = r.zstd
	return &jfile{path: path, obj: o, cache: map[uint64][2]string{}}, nil
}

func (o *objects) refresh() error {
	fi, err := o.f.Stat()
	if err != nil {
		return err
	}
	o.size = fi.Size()
	b := make([]byte, 272)
	n, err := o.f.ReadAt(b, 0)
	if n < minHeaderSize {
		if err == nil {
			err = fmt.Errorf("%w: short header", ErrCorrupt)
		}
		return fmt.Errorf("%w: header: %v", ErrCorrupt, err)
	}
	h, err := parseHeader(b[:n])
	if err != nil {
		return err
	}
	if o.h.headerSize != 0 && h.fileID != o.h.fileID {
		return fmt.Errorf("%w: file ID changed in place", ErrCorrupt)
	}
	o.h = h
	return nil
}

// initialSeek skips whole files already covered by the resume cursor or older than Since.
func (r *Reader) initialSeek(f *jfile) {
	h := f.obj.h
	skip := false
	switch {
	case r.hasResume && h.seqnumID == r.resume.SeqnumID:
		skip = h.tailSeqnum <= r.resume.Seqnum
	case r.hasResume:
		skip = h.tailRealtime <= r.resume.Realtime
	case !r.o.Since.IsZero():
		skip = h.tailRealtime < uint64(r.o.Since.UnixMicro())
	}
	if skip {
		f.seekEnd()
	}
}

// after compares with the cursor loaded at Open, not the moving one, so a clock step cannot hide entries in a session.
func (r *Reader) after(f *jfile, e *entryHead) bool {
	switch {
	case r.hasResume && f.obj.h.seqnumID == r.resume.SeqnumID:
		return e.seqnum > r.resume.Seqnum
	case r.hasResume:
		return e.realtime > r.resume.Realtime
	case !r.o.Since.IsZero():
		return e.realtime >= uint64(r.o.Since.UnixMicro())
	}
	return true
}

func less(a *jfile, x *entryHead, b *jfile, y *entryHead) bool {
	if x.realtime != y.realtime {
		return x.realtime < y.realtime
	}
	if a.obj.h.seqnumID == b.obj.h.seqnumID && x.seqnum != y.seqnum {
		return x.seqnum < y.seqnum
	}
	if c := bytes.Compare(a.obj.h.fileID[:], b.obj.h.fileID[:]); c != 0 {
		return c < 0
	}
	return x.offset < y.offset
}

// Next returns the next entry available now across all files.
func (r *Reader) Next() (Entry, bool) {
	for {
		var best *jfile
		for _, f := range r.files {
			if f.err != nil || f.stalled {
				continue
			}
			h := f.peekAfter(r)
			if h == nil {
				continue
			}
			if best == nil || less(f, h, best, best.peek) {
				best = f
			}
		}
		if best == nil {
			r.reap()
			return Entry{}, false
		}
		e, err := best.read()
		switch {
		case err == nil:
		case errors.Is(err, errBeyondEOF):
			best.stalled = true
			continue
		default:
			best.err = err
			r.errs[best.path] = fmt.Errorf("journal: %s: %w", best.path, err)
			continue
		}
		r.cursor = Cursor{SeqnumID: best.obj.h.seqnumID, Seqnum: e.Cursor.Seqnum, Realtime: e.Cursor.Realtime}
		r.hasCursor = true
		e.Cursor = r.cursor
		return e, true
	}
}

// reap closes archived files that are fully read and files with permanent errors.
func (r *Reader) reap() {
	kept := r.files[:0]
	for _, f := range r.files {
		if f.err != nil {
			if _, ok := r.errs[f.path]; !ok {
				r.errs[f.path] = fmt.Errorf("journal: %s: %w", f.path, f.err)
			}
		}
		if f.err != nil || (f.obj.h.state == stateArchived && f.finished()) {
			f.obj.f.Close()
			delete(r.byID, f.obj.h.fileID)
			r.done[f.obj.h.fileID] = true
			continue
		}
		kept = append(kept, f)
	}
	r.files = kept
}

// Refresh re-reads the headers of growing files and picks up new and rotated files.
func (r *Reader) Refresh() error {
	for _, f := range r.files {
		if f.err != nil {
			continue
		}
		f.stalled = false
		if f.obj.h.state == stateArchived {
			continue
		}
		if err := f.obj.refresh(); err != nil {
			f.err = err
			r.errs[f.path] = fmt.Errorf("journal: %s: %w", f.path, err)
		}
	}
	return r.scan()
}

// Follow delivers entries until ctx ends or fn fails, saving the cursor per batch and, on failure, before the failed entry.
func (r *Reader) Follow(ctx context.Context, fn func(Entry) error) error {
	t := time.NewTicker(r.o.PollInterval)
	defer t.Stop()
	for {
		n := 0
		for {
			prev, hadPrev := r.cursor, r.hasCursor
			e, ok := r.Next()
			if !ok {
				break
			}
			if err := fn(e); err != nil {
				r.cursor, r.hasCursor = prev, hadPrev
				if serr := r.SaveCursor(); serr != nil {
					return errors.Join(err, serr)
				}
				return err
			}
			n++
			if n%1000 == 0 {
				if err := r.SaveCursor(); err != nil {
					return err
				}
			}
		}
		if n > 0 {
			if err := r.SaveCursor(); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		if err := r.Refresh(); err != nil {
			return err
		}
	}
}
