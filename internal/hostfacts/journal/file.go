package journal

import (
	"errors"
	"fmt"
	"time"
)

const itemWindow = 512

type jfile struct {
	path    string
	obj     *objects
	started bool
	arr     uint64
	arrCap  uint64
	idx     uint64
	passed  uint64
	window  []uint64
	winBase uint64
	peek    *entryHead
	items   []uint64
	cache   map[uint64][2]string
	err     error
	stalled bool
}

func (f *jfile) finished() bool { return f.passed >= f.obj.h.nEntries }

// nextOffset returns the offset of the next entry in the global entry array, if it is available yet.
func (f *jfile) nextOffset() (uint64, bool, error) {
	if f.finished() {
		return 0, false, nil
	}
	if !f.started {
		if f.obj.h.entryArrayOffset == 0 {
			return 0, false, nil
		}
		_, capacity, err := f.obj.arrayHeader(f.obj.h.entryArrayOffset)
		if err != nil {
			return 0, false, err
		}
		f.arr, f.arrCap, f.idx, f.started = f.obj.h.entryArrayOffset, capacity, 0, true
		f.window = nil
	}
	for f.idx >= f.arrCap {
		next, _, err := f.obj.arrayHeader(f.arr)
		if err != nil {
			return 0, false, err
		}
		if next == 0 {
			return 0, false, nil
		}
		_, capacity, err := f.obj.arrayHeader(next)
		if err != nil {
			return 0, false, err
		}
		f.arr, f.arrCap, f.idx = next, capacity, 0
		f.window = nil
	}
	for fresh := false; ; fresh = true {
		if fresh || f.window == nil || f.idx < f.winBase || f.idx >= f.winBase+uint64(len(f.window)) {
			n := min(uint64(itemWindow), f.arrCap-f.idx)
			w, err := f.obj.arrayItems(f.arr, f.idx, n)
			if err != nil {
				return 0, false, err
			}
			f.window, f.winBase = w, f.idx
		}
		if off := f.window[f.idx-f.winBase]; off != 0 {
			return off, true, nil
		}
		if fresh {
			f.window = nil
			return 0, false, nil
		}
	}
}

func (f *jfile) advance() {
	f.idx++
	f.passed++
	f.peek, f.items = nil, nil
}

// load buffers the head of the next entry.
func (f *jfile) load() *entryHead {
	if f.peek != nil {
		return f.peek
	}
	off, ok, err := f.nextOffset()
	if err == nil && ok {
		var h entryHead
		h, f.items, err = f.obj.entryHead(off)
		if err == nil {
			f.peek = &h
		}
	}
	f.fail(err)
	return f.peek
}

func (f *jfile) fail(err error) {
	switch {
	case err == nil:
	case errors.Is(err, errBeyondEOF):
		f.stalled = true
	default:
		f.err = err
	}
}

// peekAfter returns the next entry past the reader's position, skipping older ones.
func (f *jfile) peekAfter(r *Reader) *entryHead {
	for {
		h := f.load()
		if h == nil || f.err != nil || f.stalled {
			return nil
		}
		if r.after(f, h) {
			return h
		}
		f.advance()
	}
}

// read decodes the buffered entry and advances past it.
func (f *jfile) read() (Entry, error) {
	h := f.peek
	fields := make(map[string]string, len(f.items))
	for _, off := range f.items {
		kv, ok := f.cache[off]
		if !ok {
			k, v, err := f.obj.data(off)
			if errors.Is(err, errTooLarge) {
				continue
			}
			if err != nil {
				return Entry{}, err
			}
			kv = [2]string{k, v}
			if len(f.cache) >= 8192 {
				clear(f.cache)
			}
			f.cache[off] = kv
		}
		if _, dup := fields[kv[0]]; !dup {
			fields[kv[0]] = kv[1]
		}
	}
	f.advance()
	return Entry{Realtime: time.UnixMicro(int64(h.realtime)), Fields: fields, Cursor: Cursor{Seqnum: h.seqnum, Realtime: h.realtime}}, nil
}

// seekEnd positions the file after its last entry by walking the entry array chain.
func (f *jfile) seekEnd() {
	remaining := f.obj.h.nEntries
	arr := f.obj.h.entryArrayOffset
	for arr != 0 {
		next, capacity, err := f.obj.arrayHeader(arr)
		if err != nil {
			f.fail(err)
			return
		}
		if remaining <= capacity {
			f.arr, f.arrCap, f.idx, f.started = arr, capacity, remaining, true
			f.passed = f.obj.h.nEntries
			f.window, f.peek, f.items = nil, nil, nil
			return
		}
		remaining -= capacity
		arr = next
	}
	if f.obj.h.nEntries == 0 {
		return
	}
	f.fail(fmt.Errorf("%w: entry array chain shorter than %d entries", ErrCorrupt, f.obj.h.nEntries))
}
