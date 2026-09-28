package logs

import (
	"bytes"
	"compress/gzip"
	"errors"
	"hash/fnv"
	"io"
	"os"
	"syscall"
	"time"
)

const (
	fpBytes   = 1024
	tailKeep  = 512
	readChunk = 64 << 10
)

type fileID struct{ dev, ino uint64 }

func statID(fi os.FileInfo) fileID {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fileID{uint64(st.Dev), st.Ino}
	}
	return fileID{}
}

func unlinked(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 0
}

// fingerprint hashes the first n bytes of a file so inode reuse is detected on resume.
type fingerprint struct {
	n   int
	sum uint64
}

func fpOf(b []byte) fingerprint {
	h := fnv.New64a()
	h.Write(b)
	return fingerprint{len(b), h.Sum64()}
}

func readFP(r io.ReaderAt, size int64) (fingerprint, error) {
	n := min(size, fpBytes)
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
		return fingerprint{}, err
	}
	return fpOf(buf), nil
}

func fpMatches(r io.ReaderAt, fp fingerprint) bool {
	if fp.n == 0 {
		return true
	}
	buf := make([]byte, fp.n)
	if _, err := r.ReadAt(buf, 0); err != nil {
		return false
	}
	return fpOf(buf) == fp
}

// physLine is one newline-terminated line; head is cut at the physical cap and tail keeps its end.
type physLine struct {
	head, tail []byte
	cut        bool
	start, end int64
}

// splitter turns a byte stream into physical lines with a bounded buffer.
type splitter struct {
	line      []byte
	tail      []byte
	cut       bool
	lineStart int64
	skipFirst bool
}

func keepTail(b []byte) []byte {
	if len(b) > tailKeep {
		copy(b, b[len(b)-tailKeep:])
		b = b[:tailKeep]
	}
	return b
}

func (s *splitter) addSeg(seg []byte, physCap int) {
	if s.cut {
		s.tail = keepTail(append(s.tail, seg...))
		return
	}
	room := physCap - len(s.line)
	if len(seg) <= room {
		s.line = append(s.line, seg...)
		return
	}
	s.line = append(s.line, seg[:room]...)
	s.cut = true
	s.tail = keepTail(append(append(s.tail[:0], s.line[max(0, len(s.line)-tailKeep):]...), seg[room:]...))
}

// feed consumes data that starts at file offset pos.
func (s *splitter) feed(data []byte, pos int64, physCap int, fn func(physLine)) {
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		seg := data
		if i >= 0 {
			seg = data[:i]
		}
		if s.skipFirst {
			if i < 0 {
				return
			}
			s.skipFirst = false
			pos += int64(i) + 1
			s.lineStart = pos
			data = data[i+1:]
			continue
		}
		s.addSeg(seg, physCap)
		if i < 0 {
			return
		}
		pos += int64(i) + 1
		fn(physLine{head: s.line, tail: s.tail, cut: s.cut, start: s.lineStart, end: pos})
		s.reset(pos)
		data = data[i+1:]
	}
}

// flush emits an unterminated final line.
func (s *splitter) flush(end int64, fn func(physLine)) {
	if !s.skipFirst && (len(s.line) > 0 || s.cut) {
		fn(physLine{head: s.line, tail: s.tail, cut: s.cut, start: s.lineStart, end: end})
	}
	s.reset(end)
}

func (s *splitter) reset(pos int64) {
	s.line, s.tail, s.cut, s.lineStart, s.skipFirst = s.line[:0], s.tail[:0], false, pos, false
}

// tracked is one open log file identified by device and inode.
type tracked struct {
	f       *os.File
	id      fileID
	name    string
	path    string
	offset  int64
	readPos int64
	size    int64
	fp      fingerprint
	gone    bool
	sp      splitter

	rotatedAt time.Time
	lastGrow  time.Time

	replayUntil int64
	replay      map[string]int64
	restored    *fileState
}

func openTracked(path, name string, start int64, midLine bool) (*tracked, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	fp, err := readFP(f, fi.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	t := &tracked{f: f, id: statID(fi), name: name, path: path, size: fi.Size(), fp: fp, offset: start, readPos: start}
	t.sp.lineStart = start
	if midLine && start > 0 {
		b := make([]byte, 1)
		if _, err := f.ReadAt(b, start-1); err == nil && b[0] != '\n' {
			t.sp.skipFirst = true
		}
	}
	return t, nil
}

// read consumes up to budget bytes; eof reports whether the file end was reached.
func (t *tracked) read(scratch []byte, budget int64, physCap int, fn func(physLine)) (n int64, eof bool, err error) {
	emit := func(pl physLine) {
		t.offset = pl.end
		fn(pl)
	}
	for budget > 0 {
		want := min(int64(len(scratch)), budget)
		k, rerr := t.f.ReadAt(scratch[:want], t.readPos)
		if k > 0 {
			t.sp.feed(scratch[:k], t.readPos, physCap, emit)
			t.readPos += int64(k)
			if t.sp.skipFirst || (len(t.sp.line) == 0 && !t.sp.cut) {
				t.offset = max(t.offset, t.sp.lineStart)
			}
			n += int64(k)
			budget -= int64(k)
		}
		if errors.Is(rerr, io.EOF) || (rerr == nil && int64(k) < want) {
			return n, true, nil
		}
		if rerr != nil {
			return n, false, rerr
		}
	}
	return n, false, nil
}

// finish flushes an unterminated last line of a file that will not grow.
func (t *tracked) finish(fn func(physLine)) {
	t.sp.flush(t.readPos, func(pl physLine) {
		t.offset = pl.end
		fn(pl)
	})
}

// restart rereads from zero after truncation.
func (t *tracked) restart() {
	t.offset, t.readPos = 0, 0
	t.sp = splitter{}
	t.replayUntil, t.replay, t.restored = 0, nil, nil
	if fp, err := readFP(t.f, t.size); err == nil {
		t.fp = fp
	}
}

// rewritten reports truncation or in-place rewrite (copytruncate), then extends the fingerprint.
func (t *tracked) rewritten() bool {
	if t.size < t.readPos || !fpMatches(t.f, t.fp) {
		return true
	}
	t.refreshFP()
	return false
}

func (t *tracked) refreshFP() {
	if t.fp.n < fpBytes && t.size > int64(t.fp.n) {
		if fp, err := readFP(t.f, t.size); err == nil {
			t.fp = fp
		}
	}
}

func (t *tracked) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

// readGzipRemainder reads a compressed rotated file from start when its fingerprint matches.
func readGzipRemainder(path string, fp fingerprint, start int64, physCap int, fn func(physLine)) (matched bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	defer zr.Close()
	head := make([]byte, fp.n)
	if _, err := io.ReadFull(zr, head); err != nil || fpOf(head) != fp {
		return false, nil
	}
	pos := int64(fp.n)
	var sp splitter
	if start < pos {
		sp.lineStart = start
		sp.feed(head[start:], start, physCap, fn)
	} else {
		if _, err := io.CopyN(io.Discard, zr, start-pos); err != nil {
			return true, err
		}
		pos = start
		sp.lineStart = start
	}
	buf := make([]byte, readChunk)
	for {
		k, rerr := zr.Read(buf)
		if k > 0 {
			sp.feed(buf[:k], pos, physCap, fn)
			pos += int64(k)
		}
		if errors.Is(rerr, io.EOF) {
			sp.flush(pos, fn)
			return true, nil
		}
		if rerr != nil {
			return true, rerr
		}
	}
}
