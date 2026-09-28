// Package logs tails container and host log files per the contract in docs/log-contract.md.
package logs

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

// Line is one delivered log line. Labels is shared by every line of its stream and must not be modified.
type Line struct {
	Labels    map[string]string
	Time      time.Time
	Text      string
	Truncated bool
}

// GapKind names a disclosed input gap.
type GapKind string

const (
	GapTruncated        GapKind = "truncated"
	GapOffsetBeyondSize GapKind = "offset_beyond_size"
	GapMissedRotation   GapKind = "missed_rotation"
	GapReadError        GapKind = "read_error"
)

// Event discloses a gap. LostBytes is -1 when the amount is unknown.
type Event struct {
	Kind      GapKind
	Path      string
	Labels    map[string]string
	Time      time.Time
	LostBytes int64
	Detail    string
}

// StreamFilter decides from stream labels whether a stream is read at all.
type StreamFilter func(labels map[string]string) bool

// EnrichFunc returns workload labels for a container, or nil while the pod is not yet known.
type EnrichFunc func(namespace, pod, uid, container string) map[string]string

// Defaults.
const (
	DefaultMaxLineBytes       = 64 << 10
	DefaultPollInterval       = time.Second
	DefaultCheckpointInterval = 10 * time.Second
	DefaultReadBudget         = 4 << 20
	DefaultEnrichWait         = time.Minute
)

// Options configures a pod log Tailer.
type Options struct {
	Root               string
	Node               string
	Store              kv.Store
	Sink               func(Line)
	OnEvent            func(Event)
	Filter             StreamFilter
	Enrich             EnrichFunc
	EnrichWait         time.Duration
	MaxLineBytes       int
	PollInterval       time.Duration
	CheckpointInterval time.Duration
	ReadBudget         int64
	Clock              func() time.Time
}

// Stats counts tailer activity.
type Stats struct {
	Streams        int
	Files          int
	Lines          uint64
	Bytes          uint64
	TruncatedLines uint64
	Unparsed       uint64
	Gaps           uint64
}

type counters struct {
	lines, bytes, truncated, unparsed, gaps atomic.Uint64
}

var criStreams = [2]string{"stdout", "stderr"}

const podStatePrefix = "pod/"

var logName = regexp.MustCompile(`^(\d+)\.log(?:\.(\d{8}-\d{6}))?(\.gz)?$`)

type dirEntry struct {
	name, path string
	n          int
	rot        string
	gz         bool
	id         fileID
	size       int64
}

func parseLogName(name string) (n int, rot string, gz bool, ok bool) {
	m := logName.FindStringSubmatch(name)
	if m == nil {
		return 0, "", false, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, "", false, false
	}
	return n, m[2], m[3] != "", true
}

func orderKey(n int, rot string) string {
	if rot == "" {
		rot = "~"
	}
	return strconv.Itoa(1_000_000_000+n) + rot
}

func listContainerDir(dir string) ([]*dirEntry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*dirEntry
	for _, de := range des {
		n, rot, gz, ok := parseLogName(de.Name())
		if !ok || !de.Type().IsRegular() {
			continue
		}
		e := &dirEntry{name: de.Name(), path: filepath.Join(dir, de.Name()), n: n, rot: rot, gz: gz}
		if !gz {
			fi, err := os.Stat(e.path)
			if err != nil {
				continue
			}
			e.id, e.size = statID(fi), fi.Size()
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		ki, kj := orderKey(out[i].n, out[i].rot), orderKey(out[j].n, out[j].rot)
		if ki != kj {
			return ki < kj
		}
		return !out[i].gz && out[j].gz
	})
	return out, nil
}

func parsePodDir(name string) (ns, pod, uid string, ok bool) {
	p := strings.Split(name, "_")
	if len(p) != 3 || p[0] == "" || p[1] == "" || p[2] == "" {
		return "", "", "", false
	}
	return p[0], p[1], p[2], true
}

type groupPos struct {
	f   *tracked
	off int64
}

type podStream struct {
	key, dir                string
	ns, pod, uid, container string
	firstSeen               time.Time
	backlog                 bool

	base      map[string]string
	labels    map[string]map[string]string
	sig       string
	filterGen uint64
	accept    map[string]bool

	tailing bool
	fresh   bool
	files   map[fileID]*tracked
	ignored map[fileID]bool
	rotated map[int]string
	asm     map[string]*assembler
	group   map[string]groupPos
	restore *streamState
}

// Tailer tails /var/log/pods/<namespace>_<pod>_<uid>/<container>/<N>.log for accepted streams.
type Tailer struct {
	o         Options
	filter    atomic.Pointer[StreamFilter]
	filterGen atomic.Uint64
	c         counters

	mu          sync.Mutex
	streams     map[string]*podStream
	restore     map[string]*streamState
	cp          *checkpointer
	deleted     []string
	initialized bool
	scratch     []byte
}

func (o *Options) defaults() {
	if o.MaxLineBytes <= 0 {
		o.MaxLineBytes = DefaultMaxLineBytes
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.CheckpointInterval <= 0 {
		o.CheckpointInterval = DefaultCheckpointInterval
	}
	if o.ReadBudget <= 0 {
		o.ReadBudget = DefaultReadBudget
	}
	if o.EnrichWait <= 0 {
		o.EnrichWait = DefaultEnrichWait
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Sink == nil {
		o.Sink = func(Line) {}
	}
}

// NewTailer loads persisted offsets. Nothing is read until a filter is set.
func NewTailer(o Options) (*Tailer, error) {
	o.defaults()
	cp, loaded, err := newCheckpointer(o.Store, podStatePrefix)
	if err != nil {
		return nil, err
	}
	t := &Tailer{o: o, streams: map[string]*podStream{}, restore: loaded, cp: cp, scratch: make([]byte, readChunk)}
	if o.Filter != nil {
		t.SetFilter(o.Filter)
	}
	return t, nil
}

// SetFilter replaces the stream filter; it is re-evaluated for every stream on the next poll.
func (t *Tailer) SetFilter(f StreamFilter) {
	if f == nil {
		t.filter.Store(nil)
	} else {
		t.filter.Store(&f)
	}
	t.filterGen.Add(1)
}

// Stats returns counters.
func (t *Tailer) Stats() Stats {
	t.mu.Lock()
	s := Stats{}
	for _, st := range t.streams {
		if st.tailing {
			s.Streams++
			s.Files += len(st.files)
		}
	}
	t.mu.Unlock()
	s.Lines, s.Bytes, s.TruncatedLines = t.c.lines.Load(), t.c.bytes.Load(), t.c.truncated.Load()
	s.Unparsed, s.Gaps = t.c.unparsed.Load(), t.c.gaps.Load()
	return s
}

// Run polls and checkpoints until ctx ends, then checkpoints and closes files.
func (t *Tailer) Run(ctx context.Context) error {
	poll := time.NewTicker(t.o.PollInterval)
	defer poll.Stop()
	cpt := time.NewTicker(t.o.CheckpointInterval)
	defer cpt.Stop()
	for {
		if err := t.Poll(ctx); err != nil && ctx.Err() == nil {
			t.emit(Event{Kind: GapReadError, Path: t.o.Root, Time: t.o.Clock(), LostBytes: -1, Detail: err.Error()})
		}
		select {
		case <-ctx.Done():
			return t.Close()
		case <-cpt.C:
			if err := t.Checkpoint(); err != nil {
				t.emit(Event{Kind: GapReadError, Path: t.o.Root, Time: t.o.Clock(), LostBytes: -1, Detail: "checkpoint: " + err.Error()})
			}
		case <-poll.C:
		}
	}
}

func (t *Tailer) emit(e Event) {
	t.c.gaps.Add(1)
	if t.o.OnEvent != nil {
		t.o.OnEvent(e)
	}
}

func (t *Tailer) physCap() int { return 2*t.o.MaxLineBytes + 1024 }

// Poll performs one discovery and read pass.
func (t *Tailer) Poll(ctx context.Context) error {
	fp := t.filter.Load()
	if fp == nil {
		return nil
	}
	filter := *fp
	gen := t.filterGen.Load()
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.o.Clock()
	pods, err := os.ReadDir(t.o.Root)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	seen := map[string]bool{}
	for _, pd := range pods {
		ns, pod, uid, ok := parsePodDir(pd.Name())
		if !ok || !pd.IsDir() {
			continue
		}
		pdir := filepath.Join(t.o.Root, pd.Name())
		cdirs, err := os.ReadDir(pdir)
		if err != nil {
			continue
		}
		for _, cd := range cdirs {
			if !cd.IsDir() {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			key := podStatePrefix + pd.Name() + "/" + cd.Name()
			seen[key] = true
			s := t.streams[key]
			if s == nil {
				s = &podStream{key: key, dir: filepath.Join(pdir, cd.Name()), ns: ns, pod: pod, uid: uid, container: cd.Name(), firstSeen: now, backlog: !t.initialized}
				t.streams[key] = s
			}
			if t.evaluate(s, filter, gen, now) {
				t.pollStream(s)
			}
		}
	}
	t.initialized = true
	for key, s := range t.streams {
		if seen[key] {
			continue
		}
		if s.tailing {
			t.drain(s)
		}
		delete(t.streams, key)
		t.deleted = append(t.deleted, key)
	}
	for key := range t.restore {
		if !seen[key] {
			delete(t.restore, key)
			t.deleted = append(t.deleted, key)
		}
	}
	return nil
}

func enrichSig(m map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(m) {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(0)
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func streamLabels(ns, pod, uid, container, node string, extra map[string]string) (map[string]string, map[string]map[string]string) {
	base := map[string]string{"namespace": ns, "pod": pod, "pod_uid": uid, "container": container}
	if node != "" {
		base["node"] = node
	}
	for k, v := range extra {
		if _, ok := base[k]; !ok && k != "stream" {
			base[k] = v
		}
	}
	per := map[string]map[string]string{}
	for _, cs := range criStreams {
		l := make(map[string]string, len(base)+1)
		for k, v := range base {
			l[k] = v
		}
		l["stream"] = cs
		per[cs] = l
	}
	return base, per
}

// evaluate applies enrichment and the filter; it reports whether the stream is tailed.
func (t *Tailer) evaluate(s *podStream, filter StreamFilter, gen uint64, now time.Time) bool {
	var extra map[string]string
	if t.o.Enrich != nil {
		extra = t.o.Enrich(s.ns, s.pod, s.uid, s.container)
		if extra == nil && s.labels == nil && now.Sub(s.firstSeen) < t.o.EnrichWait {
			return false
		}
	}
	// Enrichment that disappears (pod gone from the watch) keeps the last known labels.
	if sig := enrichSig(extra); s.labels == nil || (extra != nil && sig != s.sig) {
		s.base, s.labels = streamLabels(s.ns, s.pod, s.uid, s.container, t.o.Node, extra)
		s.sig, s.filterGen = sig, 0
	}
	if s.filterGen != gen || s.accept == nil {
		s.accept = map[string]bool{}
		for _, cs := range criStreams {
			s.accept[cs] = filter(s.labels[cs])
		}
		s.filterGen = gen
	}
	if !s.accept["stdout"] && !s.accept["stderr"] {
		if s.tailing {
			t.stopStream(s)
		}
		s.backlog = true
		if _, ok := t.restore[s.key]; ok {
			delete(t.restore, s.key)
			t.deleted = append(t.deleted, s.key)
		}
		return false
	}
	if !s.tailing {
		t.startStream(s)
	}
	return true
}

func (t *Tailer) startStream(s *podStream) {
	s.tailing = true
	s.files, s.ignored, s.rotated = map[fileID]*tracked{}, map[fileID]bool{}, map[int]string{}
	s.asm, s.group = map[string]*assembler{}, map[string]groupPos{}
	s.fresh = s.backlog
	if st := t.restore[s.key]; st != nil {
		s.restore = st
		delete(t.restore, s.key)
		s.fresh = false
	}
}

func (t *Tailer) stopStream(s *podStream) {
	for _, tf := range s.files {
		tf.close()
	}
	s.tailing, s.files, s.asm, s.group, s.restore = false, nil, nil, nil, nil
	t.deleted = append(t.deleted, s.key)
}

func (t *Tailer) ordered(s *podStream) []*tracked {
	out := make([]*tracked, 0, len(s.files))
	for _, tf := range s.files {
		out = append(out, tf)
	}
	sort.Slice(out, func(i, j int) bool {
		ni, ri, _, _ := parseLogName(out[i].name)
		nj, rj, _, _ := parseLogName(out[j].name)
		return orderKey(ni, ri) < orderKey(nj, rj)
	})
	return out
}

func (t *Tailer) gap(s *podStream, path string, kind GapKind, lost int64, detail string) {
	t.emit(Event{Kind: kind, Path: path, Labels: s.base, Time: t.o.Clock(), LostBytes: lost, Detail: detail})
}

func (t *Tailer) pollStream(s *podStream) {
	entries, err := listContainerDir(s.dir)
	if err != nil {
		return
	}
	byID := map[fileID]*dirEntry{}
	for _, e := range entries {
		if !e.gz {
			byID[e.id] = e
		}
	}
	for id := range s.ignored {
		if byID[id] == nil {
			delete(s.ignored, id)
		}
	}
	for id, tf := range s.files {
		if e := byID[id]; e != nil {
			tf.gone, tf.name, tf.path = false, e.name, e.path
		} else {
			tf.gone = true
		}
	}
	if s.restore != nil {
		t.restoreStream(s, entries, byID)
		s.restore = nil
	}
	for _, e := range entries {
		if e.gz || s.files[e.id] != nil || s.ignored[e.id] {
			continue
		}
		var start int64
		switch {
		case s.fresh && e.rot == "":
			start = e.size
		case s.fresh, e.rot != "" && e.rot <= s.rotated[e.n]:
			s.ignored[e.id] = true
			continue
		}
		tf, err := openTracked(e.path, e.name, start, true)
		if err != nil {
			t.gap(s, e.path, GapReadError, -1, err.Error())
			continue
		}
		s.files[tf.id] = tf
	}
	s.fresh = false
	for _, e := range entries {
		if e.rot > s.rotated[e.n] {
			s.rotated[e.n] = e.rot
		}
	}
	budget := t.o.ReadBudget
	for _, tf := range t.ordered(s) {
		fi, err := tf.f.Stat()
		if err != nil {
			t.gap(s, tf.path, GapReadError, -1, err.Error())
			return
		}
		tf.size = fi.Size()
		if tf.rewritten() {
			t.gap(s, tf.path, GapTruncated, -1, "file shrank below the read offset")
			tf.restart()
		}
		n, eof, err := tf.read(t.scratch, budget, t.physCap(), func(pl physLine) { t.handle(s, tf, pl) })
		budget -= n
		t.c.bytes.Add(uint64(n))
		if err != nil {
			t.gap(s, tf.path, GapReadError, -1, err.Error())
			return
		}
		if !eof {
			return
		}
		if tf.gone || unlinked(fi) {
			tf.finish(func(pl physLine) { t.handle(s, tf, pl) })
			tf.close()
			delete(s.files, tf.id)
		}
	}
}

// drain reads what remains in open files of a stream whose directory disappeared.
func (t *Tailer) drain(s *podStream) {
	for _, tf := range t.ordered(s) {
		for {
			n, eof, err := tf.read(t.scratch, t.o.ReadBudget, t.physCap(), func(pl physLine) { t.handle(s, tf, pl) })
			t.c.bytes.Add(uint64(n))
			if err != nil || eof {
				break
			}
		}
		tf.finish(func(pl physLine) { t.handle(s, tf, pl) })
		tf.close()
	}
	s.files = nil
	s.tailing = false
}

func (t *Tailer) handle(s *podStream, tf *tracked, pl physLine) {
	rec, ok := parseContainerLine(pl.head, pl.tail, pl.cut)
	if !ok {
		t.c.unparsed.Add(1)
		return
	}
	if pl.start < tf.replayUntil {
		if p, ok := tf.replay[rec.stream]; !ok || pl.start < p {
			return
		}
	}
	if !s.accept[rec.stream] {
		return
	}
	a := s.asm[rec.stream]
	if a == nil {
		a = &assembler{}
		s.asm[rec.stream] = a
	}
	if !a.active {
		s.group[rec.stream] = groupPos{tf, pl.start}
	}
	text, ts, trunc, done := a.add(rec, t.o.MaxLineBytes)
	if !done {
		return
	}
	delete(s.group, rec.stream)
	t.c.lines.Add(1)
	if trunc {
		t.c.truncated.Add(1)
	}
	t.o.Sink(Line{Labels: s.labels[rec.stream], Time: ts, Text: string(text), Truncated: trunc})
}

func (t *Tailer) restoreStream(s *podStream, entries []*dirEntry, byID map[fileID]*dirEntry) {
	st := s.restore
	for k, v := range st.Rotated {
		if n, err := strconv.Atoi(k); err == nil {
			s.rotated[n] = v
		}
	}
	for _, cs := range st.PrefixLost {
		s.asm[cs] = &assembler{active: true, truncated: true}
		s.group[cs] = groupPos{}
	}
	consumed := map[string]bool{}
	for _, fs := range st.Files {
		start := fs.start()
		if e := byID[fs.id()]; e != nil {
			tf, err := openTracked(e.path, e.name, start, false)
			if err == nil && fpMatches(tf.f, fs.fp()) {
				switch {
				case tf.size < fs.Offset:
					t.gap(s, e.path, GapOffsetBeyondSize, -1, "persisted offset beyond file size")
					tf.restart()
				case start < fs.Offset || len(fs.Pending) > 0:
					cp := fs
					tf.replayUntil, tf.replay, tf.restored = fs.Offset, fs.Pending, &cp
				}
				s.files[tf.id] = tf
				continue
			}
			if tf != nil {
				tf.close()
			}
		}
		if !t.restoreFromGzip(s, fs, entries, consumed) {
			for cs := range fs.Pending {
				s.asm[cs] = &assembler{active: true, truncated: true}
				s.group[cs] = groupPos{}
			}
			lost := int64(-1)
			if fs.Size > fs.Offset {
				lost = fs.Size - fs.Offset
			}
			t.gap(s, filepath.Join(s.dir, fs.Name), GapMissedRotation, lost, "file removed before its remainder was read")
		}
	}
	for _, e := range entries {
		if e.gz && e.rot > s.rotated[e.n] && !consumed[e.name] {
			t.gap(s, e.path, GapMissedRotation, -1, "rotated and compressed while not tailing")
		}
	}
}

func (t *Tailer) restoreFromGzip(s *podStream, fs fileState, entries []*dirEntry, consumed map[string]bool) bool {
	n, rot, _, ok := parseLogName(fs.Name)
	if !ok || fs.FPLen == 0 {
		return false
	}
	for _, e := range entries {
		if !e.gz || e.n != n || consumed[e.name] || !((rot != "" && e.rot == rot) || (rot == "" && e.rot > s.rotated[n])) {
			continue
		}
		pseudo := &tracked{name: e.name, path: e.path, replayUntil: fs.Offset, replay: fs.Pending}
		matched, err := readGzipRemainder(e.path, fs.fp(), fs.start(), t.physCap(), func(pl physLine) {
			pseudo.offset = pl.end
			t.handle(s, pseudo, pl)
		})
		if !matched {
			continue
		}
		consumed[e.name] = true
		if err != nil {
			t.gap(s, e.path, GapReadError, -1, err.Error())
		}
		return true
	}
	return false
}

// Checkpoint persists offsets of every tailed stream in one batch.
func (t *Tailer) Checkpoint() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	states := map[string]*streamState{}
	for key, s := range t.streams {
		if !s.tailing {
			continue
		}
		if s.restore != nil {
			continue
		}
		states[key] = t.streamStateOf(s)
	}
	if err := t.cp.commit(states, t.deleted); err != nil {
		return err
	}
	t.deleted = nil
	return nil
}

func (t *Tailer) streamStateOf(s *podStream) *streamState {
	st := &streamState{}
	if len(s.rotated) > 0 {
		st.Rotated = map[string]string{}
		for n, r := range s.rotated {
			st.Rotated[strconv.Itoa(n)] = r
		}
	}
	order := t.ordered(s)
	idx := map[*tracked]int{}
	for i, tf := range order {
		idx[tf] = i
	}
	for i, tf := range order {
		tf.refreshFP()
		pend := map[string]int64{}
		for cs, g := range s.group {
			gi, live := idx[g.f]
			switch {
			case g.f == tf:
				pend[cs] = g.off
			case !live || gi < i:
				pend[cs] = 0
			}
		}
		st.Files = append(st.Files, stateOf(tf, pend))
	}
	for cs, g := range s.group {
		if _, live := idx[g.f]; !live {
			st.PrefixLost = append(st.PrefixLost, cs)
		}
	}
	sort.Strings(st.PrefixLost)
	return st
}

// Close checkpoints and releases every open file.
func (t *Tailer) Close() error {
	err := t.Checkpoint()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.streams {
		for _, tf := range s.files {
			tf.close()
		}
	}
	return err
}
