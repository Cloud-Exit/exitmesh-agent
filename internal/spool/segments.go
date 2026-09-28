package spool

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const segSuffix = ".seg"

type segStat struct {
	f      *os.File
	size   int64 // bytes in the file
	live   int64 // framed bytes referenced by metadata
	maxEnd int64 // end of the last referenced frame, used during recovery
}

type loc struct {
	seg uint64
	off int64
}

// segments is the append-only body log. Callers serialize access.
type segments struct {
	dir    string
	max    int64
	segs   map[uint64]*segStat
	active uint64
	next   uint64
}

func segName(id uint64) string { return fmt.Sprintf("%016x%s", id, segSuffix) }

func openSegments(dir string, max int64) (*segments, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ss := &segments{dir: dir, max: max, segs: map[uint64]*segStat{}, next: 1}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, segSuffix) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 16, 64)
		if err != nil || id == 0 {
			continue
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR, 0o600)
		if err != nil {
			ss.close()
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			ss.close()
			return nil, err
		}
		ss.segs[id] = &segStat{f: f, size: fi.Size()}
		if id >= ss.next {
			ss.next = id + 1
		}
	}
	return ss, nil
}

func (ss *segments) close() error {
	var first error
	for _, st := range ss.segs {
		if err := st.f.Close(); err != nil && first == nil {
			first = err
		}
	}
	ss.segs = map[uint64]*segStat{}
	return first
}

func (ss *segments) ids() []uint64 {
	out := make([]uint64, 0, len(ss.segs))
	for id := range ss.segs {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (ss *segments) diskBytes() int64 {
	var n int64
	for _, st := range ss.segs {
		n += st.size
	}
	return n
}

// appendFrames writes and fsyncs frames, returning their locations and an undo that removes them.
func (ss *segments) appendFrames(frames [][]byte) ([]loc, func() error, error) {
	type touched struct {
		id      uint64
		st      *segStat
		start   int64
		buf     []byte
		created bool
	}
	var order []*touched
	byID := map[uint64]*touched{}
	prevActive := ss.active
	cur := ss.active
	locs := make([]loc, len(frames))
	undo := func() error {
		var first error
		for _, t := range order {
			if t.created {
				_ = t.st.f.Close()
				if err := os.Remove(filepath.Join(ss.dir, segName(t.id))); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
					first = err
				}
				delete(ss.segs, t.id)
				continue
			}
			if err := t.st.f.Truncate(t.start); err != nil && first == nil {
				first = err
			}
			t.st.size = t.start
		}
		ss.active = prevActive
		return first
	}
	for i, fr := range frames {
		var t *touched
		if cur != 0 {
			if t = byID[cur]; t == nil {
				st := ss.segs[cur]
				t = &touched{id: cur, st: st, start: st.size}
				byID[cur] = t
				order = append(order, t)
			}
		}
		if t == nil || (t.start+int64(len(t.buf)) > 0 && t.start+int64(len(t.buf))+int64(len(fr)) > ss.max) {
			id := ss.next
			ss.next++
			f, err := os.OpenFile(filepath.Join(ss.dir, segName(id)), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return nil, nil, errors.Join(err, undo())
			}
			st := &segStat{f: f}
			ss.segs[id] = st
			t = &touched{id: id, st: st, created: true}
			byID[id] = t
			order = append(order, t)
			cur = id
		}
		locs[i] = loc{seg: cur, off: t.start + int64(len(t.buf))}
		t.buf = append(t.buf, fr...)
	}
	created := false
	for _, t := range order {
		if len(t.buf) > 0 {
			if _, err := t.st.f.WriteAt(t.buf, t.start); err != nil {
				return nil, nil, errors.Join(err, undo())
			}
			t.st.size = t.start + int64(len(t.buf))
			if err := t.st.f.Sync(); err != nil {
				return nil, nil, errors.Join(err, undo())
			}
		}
		created = created || t.created
	}
	if created {
		if err := syncDir(ss.dir); err != nil {
			return nil, nil, errors.Join(err, undo())
		}
	}
	ss.active = cur
	return locs, undo, nil
}

func (ss *segments) read(id uint64, off int64, n uint32) ([]byte, error) {
	st := ss.segs[id]
	if st == nil {
		return nil, fmt.Errorf("%w: segment %s missing", ErrCorrupt, segName(id))
	}
	return readFrameAt(st.f, off, int(n))
}

// gc deletes segments without referenced frames and empties the active one when unreferenced.
func (ss *segments) gc() error {
	var first error
	for _, id := range ss.ids() {
		st := ss.segs[id]
		if st.live > 0 {
			continue
		}
		if id == ss.active {
			if st.size > 0 {
				if err := st.f.Truncate(0); err != nil && first == nil {
					first = err
				}
				st.size = 0
			}
			continue
		}
		_ = st.f.Close()
		if err := os.Remove(filepath.Join(ss.dir, segName(id))); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
		delete(ss.segs, id)
	}
	return first
}

// frameReader streams referenced frames, reusing a buffered reader for forward reads in one segment.
type frameReader struct {
	ss  *segments
	seg uint64
	pos int64
	br  *bufio.Reader
	buf []byte
}

func (r *frameReader) read(id uint64, off int64, n uint32) ([]byte, error) {
	st := r.ss.segs[id]
	if st == nil {
		return nil, fmt.Errorf("%w: segment %s missing", ErrCorrupt, segName(id))
	}
	end := off + frameLen(int(n))
	if end > st.size {
		return nil, fmt.Errorf("%w: frame at %d+%d beyond end of %s (%d bytes)", ErrCorrupt, off, frameLen(int(n)), segName(id), st.size)
	}
	if r.br == nil || r.seg != id || off < r.pos || off-r.pos > 1<<20 {
		r.br = bufio.NewReaderSize(io.NewSectionReader(st.f, off, st.size-off), 1<<20)
		r.seg, r.pos = id, off
	}
	if _, err := r.br.Discard(int(off - r.pos)); err != nil {
		return nil, err
	}
	need := int(frameLen(int(n)))
	if cap(r.buf) < need {
		r.buf = make([]byte, need)
	}
	buf := r.buf[:need]
	if _, err := io.ReadFull(r.br, buf); err != nil {
		return nil, fmt.Errorf("%w: reading %s at %d: %v", ErrCorrupt, segName(id), off, err)
	}
	r.pos = end
	p, err := checkFrame(buf, int(n))
	if err != nil {
		return nil, fmt.Errorf("%s at %d: %w", segName(id), off, err)
	}
	return p, nil
}
