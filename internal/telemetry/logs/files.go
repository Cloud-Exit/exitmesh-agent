package logs

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

// FileOptions configures a FileTailer over allowlisted host paths (files or directories).
type FileOptions struct {
	Paths              []string
	Labels             map[string]string
	Store              kv.Store
	Sink               func(Line)
	OnEvent            func(Event)
	Filter             StreamFilter
	MaxLineBytes       int
	PollInterval       time.Duration
	CheckpointInterval time.Duration
	RescanInterval     time.Duration
	// RotatedIdle is how long a file renamed away keeps being read after it stops growing.
	RotatedIdle time.Duration
	ReadBudget  int64
	MaxDepth    int
	Clock       func() time.Time
}

const fileStatePrefix = "file/"

var rotatedName = regexp.MustCompile(`(\.\d+|\.old|[-_.]\d{8}(\d{2,6})?)(\.(gz|xz|bz2|zst))?$|\.(gz|xz|bz2|zst)$`)

type fileStream struct {
	path, key string
	labels    map[string]string
	filterGen uint64
	accept    bool
	tailing   bool
	backlog   bool
	fresh     bool
	candidate bool
	cur       *tracked
	old       []*tracked
	restore   *streamState
}

// FileTailer tails host log files; each file is a stream labeled filename.
type FileTailer struct {
	o         FileOptions
	filter    atomic.Pointer[StreamFilter]
	filterGen atomic.Uint64
	c         counters

	mu          sync.Mutex
	streams     map[string]*fileStream
	restore     map[string]*streamState
	cp          *checkpointer
	deleted     []string
	lastScan    time.Time
	scanGen     uint64
	initialized bool
	scratch     []byte
}

// NewFileTailer loads persisted offsets. Nothing is read until a filter is set.
func NewFileTailer(o FileOptions) (*FileTailer, error) {
	po := Options{MaxLineBytes: o.MaxLineBytes, PollInterval: o.PollInterval, CheckpointInterval: o.CheckpointInterval, ReadBudget: o.ReadBudget, Clock: o.Clock, Sink: o.Sink}
	po.defaults()
	o.MaxLineBytes, o.PollInterval, o.CheckpointInterval, o.ReadBudget, o.Clock, o.Sink = po.MaxLineBytes, po.PollInterval, po.CheckpointInterval, po.ReadBudget, po.Clock, po.Sink
	if o.RescanInterval <= 0 {
		o.RescanInterval = 10 * time.Second
	}
	if o.RotatedIdle <= 0 {
		o.RotatedIdle = 30 * time.Second
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 3
	}
	cp, loaded, err := newCheckpointer(o.Store, fileStatePrefix)
	if err != nil {
		return nil, err
	}
	ft := &FileTailer{o: o, streams: map[string]*fileStream{}, restore: loaded, cp: cp, scratch: make([]byte, readChunk)}
	if o.Filter != nil {
		ft.SetFilter(o.Filter)
	}
	return ft, nil
}

// SetFilter replaces the stream filter.
func (ft *FileTailer) SetFilter(f StreamFilter) {
	if f == nil {
		ft.filter.Store(nil)
	} else {
		ft.filter.Store(&f)
	}
	ft.filterGen.Add(1)
}

// Stats returns counters.
func (ft *FileTailer) Stats() Stats {
	ft.mu.Lock()
	s := Stats{}
	for _, st := range ft.streams {
		if st.tailing {
			s.Streams++
			s.Files += len(st.old)
			if st.cur != nil {
				s.Files++
			}
		}
	}
	ft.mu.Unlock()
	s.Lines, s.Bytes, s.TruncatedLines = ft.c.lines.Load(), ft.c.bytes.Load(), ft.c.truncated.Load()
	s.Unparsed, s.Gaps = ft.c.unparsed.Load(), ft.c.gaps.Load()
	return s
}

// Run polls and checkpoints until ctx ends.
func (ft *FileTailer) Run(ctx context.Context) error {
	poll := time.NewTicker(ft.o.PollInterval)
	defer poll.Stop()
	cpt := time.NewTicker(ft.o.CheckpointInterval)
	defer cpt.Stop()
	for {
		_ = ft.Poll(ctx)
		select {
		case <-ctx.Done():
			return ft.Close()
		case <-cpt.C:
			if err := ft.Checkpoint(); err != nil {
				ft.emit(Event{Kind: GapReadError, Time: ft.o.Clock(), LostBytes: -1, Detail: "checkpoint: " + err.Error()})
			}
		case <-poll.C:
		}
	}
}

func (ft *FileTailer) emit(e Event) {
	ft.c.gaps.Add(1)
	if ft.o.OnEvent != nil {
		ft.o.OnEvent(e)
	}
}

func (ft *FileTailer) gap(s *fileStream, path string, kind GapKind, lost int64, detail string) {
	ft.emit(Event{Kind: kind, Path: path, Labels: s.labels, Time: ft.o.Clock(), LostBytes: lost, Detail: detail})
}

func (ft *FileTailer) scan() []string {
	var out []string
	for _, p := range ft.o.Paths {
		p = filepath.Clean(p)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() {
			out = append(out, p)
			continue
		}
		if !fi.IsDir() {
			continue
		}
		depth0 := strings.Count(p, string(filepath.Separator))
		_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(path, string(filepath.Separator))-depth0 >= ft.o.MaxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && !rotatedName.MatchString(d.Name()) {
				out = append(out, path)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// Poll performs one discovery and read pass.
func (ft *FileTailer) Poll(ctx context.Context) error {
	fp := ft.filter.Load()
	if fp == nil {
		return nil
	}
	filter := *fp
	gen := ft.filterGen.Load()
	ft.mu.Lock()
	defer ft.mu.Unlock()
	now := ft.o.Clock()
	if !ft.initialized || gen != ft.scanGen || now.Sub(ft.lastScan) >= ft.o.RescanInterval {
		ft.lastScan, ft.scanGen = now, gen
		cands := map[string]bool{}
		for _, p := range ft.scan() {
			cands[p] = true
			if ft.streams[p] == nil {
				ft.streams[p] = &fileStream{path: p, key: fileStatePrefix + p, backlog: !ft.initialized}
			}
		}
		for p, s := range ft.streams {
			s.candidate = cands[p]
		}
		for key := range ft.restore {
			if !cands[strings.TrimPrefix(key, fileStatePrefix)] {
				delete(ft.restore, key)
				ft.deleted = append(ft.deleted, key)
			}
		}
	}
	ft.initialized = true
	for p, s := range ft.streams {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.candidate {
			if s.labels == nil {
				s.labels = map[string]string{}
				for k, v := range ft.o.Labels {
					s.labels[k] = v
				}
				s.labels["filename"] = p
			}
			if s.filterGen != gen {
				s.accept, s.filterGen = filter(s.labels), gen
			}
			if !s.accept {
				if s.tailing {
					ft.stop(s)
				}
				s.backlog = true
				if _, ok := ft.restore[s.key]; ok {
					delete(ft.restore, s.key)
					ft.deleted = append(ft.deleted, s.key)
				}
				continue
			}
			if !s.tailing {
				s.tailing, s.fresh = true, s.backlog
				if st := ft.restore[s.key]; st != nil {
					s.restore, s.fresh = st, false
					delete(ft.restore, s.key)
				}
			}
		}
		if !s.tailing {
			if !s.candidate {
				delete(ft.streams, p)
			}
			continue
		}
		ft.pollFile(s, now)
		if !s.candidate && s.cur == nil && len(s.old) == 0 {
			s.tailing = false
			delete(ft.streams, p)
			ft.deleted = append(ft.deleted, s.key)
		}
	}
	return nil
}

func (ft *FileTailer) stop(s *fileStream) {
	for _, tf := range append(s.old, s.cur) {
		if tf != nil {
			tf.close()
		}
	}
	s.cur, s.old, s.tailing, s.restore = nil, nil, false, nil
	ft.deleted = append(ft.deleted, s.key)
}

func (ft *FileTailer) handle(s *fileStream, pl physLine) {
	text, trunc := pl.head, pl.cut
	if n := len(text); n > 0 && text[n-1] == '\r' {
		text = text[:n-1]
	}
	ft.c.lines.Add(1)
	if trunc {
		ft.c.truncated.Add(1)
	}
	ft.o.Sink(Line{Labels: s.labels, Time: ft.o.Clock(), Text: string(text), Truncated: trunc})
}

func (ft *FileTailer) siblings(path string) (plain, gz []string) {
	dir, base := filepath.Split(path)
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	for _, de := range des {
		n := de.Name()
		if n == base || !strings.HasPrefix(n, base) || !strings.ContainsRune(".-_", rune(n[len(base)])) || !de.Type().IsRegular() {
			continue
		}
		if strings.HasSuffix(n, ".gz") {
			gz = append(gz, filepath.Join(dir, n))
		} else {
			plain = append(plain, filepath.Join(dir, n))
		}
	}
	return plain, gz
}

func (ft *FileTailer) restoreFile(s *fileStream, now time.Time) {
	plain, gz := ft.siblings(s.path)
	for _, fsd := range s.restore.Files {
		found := false
		for _, c := range append([]string{s.path}, plain...) {
			fi, err := os.Stat(c)
			if err != nil || statID(fi) != fsd.id() {
				continue
			}
			tf, err := openTracked(c, s.path, fsd.Offset, false)
			if err != nil {
				continue
			}
			if !fpMatches(tf.f, fsd.fp()) {
				tf.close()
				continue
			}
			if tf.size < fsd.Offset {
				ft.gap(s, c, GapOffsetBeyondSize, -1, "persisted offset beyond file size")
				tf.restart()
			}
			if c == s.path {
				s.cur = tf
			} else {
				tf.rotatedAt, tf.lastGrow = now, now
				s.old = append(s.old, tf)
			}
			found = true
			break
		}
		for i := 0; !found && fsd.FPLen > 0 && i < len(gz); i++ {
			matched, err := readGzipRemainder(gz[i], fsd.fp(), fsd.Offset, ft.o.MaxLineBytes, func(pl physLine) { ft.handle(s, pl) })
			if matched {
				found = true
				if err != nil {
					ft.gap(s, gz[i], GapReadError, -1, err.Error())
				}
			}
		}
		if !found {
			lost := int64(-1)
			if fsd.Size > fsd.Offset {
				lost = fsd.Size - fsd.Offset
			}
			ft.gap(s, s.path, GapMissedRotation, lost, "rotated file not found")
		}
	}
}

func (ft *FileTailer) pollFile(s *fileStream, now time.Time) {
	if s.restore != nil {
		ft.restoreFile(s, now)
		s.restore = nil
	}
	fi, err := os.Stat(s.path)
	switch {
	case err == nil && fi.Mode().IsRegular() && (s.cur == nil || s.cur.id != statID(fi)):
		if s.cur != nil {
			s.cur.rotatedAt, s.cur.lastGrow = now, now
			s.old = append(s.old, s.cur)
			s.cur = nil
		}
		var start int64
		if s.fresh {
			start = fi.Size()
		}
		tf, oerr := openTracked(s.path, s.path, start, true)
		if oerr != nil {
			ft.gap(s, s.path, GapReadError, -1, oerr.Error())
		} else {
			s.cur = tf
		}
	case err != nil && s.cur != nil:
		s.cur.rotatedAt, s.cur.lastGrow = now, now
		s.old = append(s.old, s.cur)
		s.cur = nil
	}
	s.fresh = false
	budget := ft.o.ReadBudget
	keep := s.old[:0]
	for i, tf := range s.old {
		n, eof, rerr := tf.read(ft.scratch, budget, ft.o.MaxLineBytes, func(pl physLine) { ft.handle(s, pl) })
		budget -= n
		ft.c.addBytes(n)
		if n > 0 {
			tf.lastGrow = now
		}
		if rerr != nil || !eof {
			if rerr != nil {
				ft.gap(s, tf.path, GapReadError, -1, rerr.Error())
			}
			s.old = append(keep, s.old[i:]...)
			return
		}
		tfi, serr := tf.f.Stat()
		if serr == nil && !unlinked(tfi) && now.Sub(tf.lastGrow) < ft.o.RotatedIdle {
			keep = append(keep, tf)
			continue
		}
		tf.finish(func(pl physLine) { ft.handle(s, pl) })
		tf.close()
	}
	s.old = keep
	if s.cur == nil {
		return
	}
	cfi, err := s.cur.f.Stat()
	if err != nil {
		ft.gap(s, s.path, GapReadError, -1, err.Error())
		return
	}
	s.cur.size = cfi.Size()
	if s.cur.rewritten() {
		ft.gap(s, s.path, GapTruncated, -1, "file shrank below the read offset")
		s.cur.restart()
	}
	n, _, err := s.cur.read(ft.scratch, budget, ft.o.MaxLineBytes, func(pl physLine) { ft.handle(s, pl) })
	ft.c.addBytes(n)
	if err != nil {
		ft.gap(s, s.path, GapReadError, -1, err.Error())
	}
}

// Checkpoint persists offsets of every tailed file in one batch.
func (ft *FileTailer) Checkpoint() error {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	states := map[string]*streamState{}
	for _, s := range ft.streams {
		if !s.tailing || s.restore != nil {
			continue
		}
		st := &streamState{}
		for _, tf := range append(append([]*tracked(nil), s.old...), s.cur) {
			if tf == nil {
				continue
			}
			tf.refreshFP()
			st.Files = append(st.Files, stateOf(tf, nil))
		}
		states[s.key] = st
	}
	if err := ft.cp.commit(states, ft.deleted); err != nil {
		return err
	}
	ft.deleted = nil
	return nil
}

// Close checkpoints and releases every open file.
func (ft *FileTailer) Close() error {
	err := ft.Checkpoint()
	ft.mu.Lock()
	defer ft.mu.Unlock()
	for _, s := range ft.streams {
		for _, tf := range append(s.old, s.cur) {
			if tf != nil {
				tf.close()
			}
		}
	}
	return err
}
