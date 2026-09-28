package journal

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"os"
	"sort"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

// jenkins64 is systemd's jenkins_hash64: lookup3 hashlittle2 with both seeds zero, (c << 32) | b.
func jenkins64(k []byte) uint64 {
	rot := func(x uint32, n int) uint32 { return bits.RotateLeft32(x, n) }
	a := 0xdeadbeef + uint32(len(k))
	b, c := a, a
	le := func(p []byte) uint32 {
		var v uint32
		for i := len(p) - 1; i >= 0; i-- {
			v = v<<8 | uint32(p[i])
		}
		return v
	}
	for len(k) > 12 {
		a += le(k[0:4])
		b += le(k[4:8])
		c += le(k[8:12])
		a -= c
		a ^= rot(c, 4)
		c += b
		b -= a
		b ^= rot(a, 6)
		a += c
		c -= b
		c ^= rot(b, 8)
		b += a
		a -= c
		a ^= rot(c, 16)
		c += b
		b -= a
		b ^= rot(a, 19)
		a += c
		c -= b
		c ^= rot(b, 4)
		b += a
		k = k[12:]
	}
	if len(k) == 0 {
		return uint64(c)<<32 | uint64(b)
	}
	var tail [12]byte
	copy(tail[:], k)
	a += le(tail[0:4])
	b += le(tail[4:8])
	c += le(tail[8:12])
	c ^= b
	c -= rot(b, 14)
	a ^= c
	a -= rot(c, 11)
	b ^= a
	b -= rot(a, 25)
	c ^= b
	c -= rot(b, 16)
	a ^= c
	a -= rot(c, 4)
	b ^= a
	b -= rot(a, 14)
	c ^= b
	c -= rot(b, 24)
	return uint64(c)<<32 | uint64(b)
}

// siphash24 is SipHash-2-4 with a 16 byte key, as systemd uses with the file ID in keyed hash mode.
func siphash24(msg []byte, key [16]byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573
	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}
	n := len(msg)
	for len(msg) >= 8 {
		m := binary.LittleEndian.Uint64(msg)
		v3 ^= m
		round()
		round()
		v0 ^= m
		msg = msg[8:]
	}
	var last [8]byte
	copy(last[:], msg)
	last[7] = byte(n)
	m := binary.LittleEndian.Uint64(last[:])
	v3 ^= m
	round()
	round()
	v0 ^= m
	v2 ^= 0xff
	round()
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}

type compression int

const (
	compNone compression = iota
	compXZ
	compLZ4
	compZSTD
)

type writerOptions struct {
	compact     bool
	keyed       bool
	comp        compression
	threshold   int
	headerSize  int
	fileID      ID128
	machineID   ID128
	bootID      ID128
	seqnumID    ID128
	dataBuckets uint64
	seq         *uint64
}

// testWriter builds a spec-conformant journal file in memory and writes objects before the header, never truncating.
type testWriter struct {
	o     writerOptions
	path  string
	buf   []byte
	state byte

	dataHT, fieldHT          uint64
	fieldBuckets             uint64
	nObjects, nEntries       uint64
	nData, nFields, nArrays  uint64
	tailObject               uint64
	headSeq, tailSeq         uint64
	headRT, tailRT, tailMono uint64
	entryArray               uint64
	tailArray, tailArrayN    uint64
	tailEntry                uint64
	dataDepth, fieldDepth    uint64
	data                     map[string]uint64
	fields                   map[string]uint64
	jenkins                  map[uint64]uint64
}

func newTestWriter(path string, o writerOptions) *testWriter {
	if o.headerSize == 0 {
		o.headerSize = 272
	}
	if o.dataBuckets == 0 {
		o.dataBuckets = 97
	}
	if o.threshold == 0 {
		o.threshold = 64
	}
	if o.seq == nil {
		o.seq = new(uint64)
	}
	w := &testWriter{o: o, path: path, buf: make([]byte, o.headerSize), state: stateOnline, fieldBuckets: 31,
		data: map[string]uint64{}, fields: map[string]uint64{}, jenkins: map[uint64]uint64{}}
	w.dataHT = w.appendObject(4, 0, 16+int(o.dataBuckets)*16) + 16
	w.fieldHT = w.appendObject(5, 0, 16+int(w.fieldBuckets)*16) + 16
	return w
}

func (w *testWriter) u64(off uint64) uint64 { return binary.LittleEndian.Uint64(w.buf[off:]) }
func (w *testWriter) put64(off, v uint64)   { binary.LittleEndian.PutUint64(w.buf[off:], v) }
func (w *testWriter) u32(off uint64) uint64 { return uint64(binary.LittleEndian.Uint32(w.buf[off:])) }
func (w *testWriter) put32(off uint64, v uint64) {
	binary.LittleEndian.PutUint32(w.buf[off:], uint32(v))
}

func (w *testWriter) appendObject(typ, flags byte, size int) uint64 {
	off := uint64(len(w.buf))
	w.buf = append(w.buf, make([]byte, (size+7)&^7)...)
	w.buf[off] = typ
	w.buf[off+1] = flags
	w.put64(off+8, uint64(size))
	w.nObjects++
	w.tailObject = off
	return off
}

func (w *testWriter) hash(p []byte) uint64 {
	if w.o.keyed {
		return siphash24(p, w.o.fileID)
	}
	return jenkins64(p)
}

func (w *testWriter) compress(p []byte) ([]byte, byte) {
	if w.o.comp == compNone || len(p) < w.o.threshold {
		return p, 0
	}
	var out []byte
	var flag byte
	switch w.o.comp {
	case compXZ:
		var b bytes.Buffer
		zw, err := xz.WriterConfig{NoCheckSum: true}.NewWriter(&b)
		if err != nil {
			panic(err)
		}
		zw.Write(p)
		zw.Close()
		out, flag = b.Bytes(), objCompressedXZ
	case compLZ4:
		dst := make([]byte, 8+lz4.CompressBlockBound(len(p)))
		binary.LittleEndian.PutUint64(dst, uint64(len(p)))
		n, err := lz4.CompressBlock(p, dst[8:], nil)
		if err != nil || n == 0 {
			return p, 0
		}
		out, flag = dst[:8+n], objCompressedLZ4
	case compZSTD:
		enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithSingleSegment(true))
		if err != nil {
			panic(err)
		}
		out, flag = enc.EncodeAll(p, nil), objCompressedZSTD
		enc.Close()
	}
	if len(out) >= len(p) {
		return p, 0
	}
	return out, flag
}

func (w *testWriter) bucketLink(ht, buckets, h, off uint64, nextField uint64) uint64 {
	b := ht + (h%buckets)*16
	depth := uint64(1)
	if tail := w.u64(b + 8); tail == 0 {
		w.put64(b, off)
	} else {
		w.put64(tail+nextField, off)
		for p := w.u64(b); p != off && p != 0; p = w.u64(p + nextField) {
			depth++
		}
	}
	w.put64(b+8, off)
	return depth
}

func (w *testWriter) addField(name []byte) uint64 {
	if off, ok := w.fields[string(name)]; ok {
		return off
	}
	h := w.hash(name)
	off := w.appendObject(2, 0, 40+len(name))
	w.put64(off+16, h)
	copy(w.buf[off+40:], name)
	w.fieldDepth = max(w.fieldDepth, w.bucketLink(w.fieldHT, w.fieldBuckets, h, off, 24))
	w.fields[string(name)] = off
	w.nFields++
	return off
}

func (w *testWriter) addData(p []byte) (uint64, uint64) {
	if off, ok := w.data[string(p)]; ok {
		return off, w.u64(off + 16)
	}
	h := w.hash(p)
	stored, flag := w.compress(p)
	start := 64
	if w.o.compact {
		start = 72
	}
	off := w.appendObject(1, flag, start+len(stored))
	w.put64(off+16, h)
	copy(w.buf[off+uint64(start):], stored)
	w.dataDepth = max(w.dataDepth, w.bucketLink(w.dataHT, w.o.dataBuckets, h, off, 24))
	name := p[:bytes.IndexByte(p, '=')]
	field := w.addField(name)
	w.put64(off+32, w.u64(field+32))
	w.put64(field+32, off)
	w.data[string(p)] = off
	w.jenkins[off] = jenkins64(p)
	w.nData++
	return off, h
}

type slot struct {
	get func() uint64
	set func(uint64)
}

func (w *testWriter) field64(off uint64) slot {
	return slot{func() uint64 { return w.u64(off) }, func(v uint64) { w.put64(off, v) }}
}

func (w *testWriter) field32(off uint64) slot {
	return slot{func() uint64 { return w.u32(off) }, func(v uint64) { w.put32(off, v) }}
}

func (w *testWriter) itemSize() uint64 {
	if w.o.compact {
		return 4
	}
	return 8
}

func (w *testWriter) writeItem(arr, i, p uint64) {
	if w.o.compact {
		w.put32(arr+24+i*4, p)
	} else {
		w.put64(arr+24+i*8, p)
	}
}

// linkEntryIntoArray mirrors journald's link_entry_into_array, including the tail shortcut.
func (w *testWriter) linkEntryIntoArray(first, idx slot, tail, tidx *slot, p uint64) {
	var n, ap uint64
	a := first.get()
	if tail != nil {
		a = tail.get()
	}
	hidx := idx.get()
	i := hidx
	if tidx != nil {
		i = tidx.get()
	}
	for a > 0 {
		n = (w.u64(a+8) - 24) / w.itemSize()
		if i < n {
			w.writeItem(a, i, p)
			idx.set(hidx + 1)
			if tidx != nil {
				tidx.set(tidx.get() + 1)
			}
			return
		}
		i -= n
		ap = a
		a = w.u64(a + 16)
	}
	if hidx > n {
		n = (hidx + 1) * 2
	} else {
		n = n * 2
	}
	if n < 4 {
		n = 4
	}
	q := w.appendObject(6, 0, 24+int(n*w.itemSize()))
	w.writeItem(q, 0, p)
	if ap == 0 {
		first.set(q)
	} else {
		w.put64(ap+16, q)
	}
	w.nArrays++
	idx.set(hidx + 1)
	if tail != nil {
		tail.set(q)
	}
	if tidx != nil {
		tidx.set(1)
	}
}

func (w *testWriter) linkPlusOne(extra, first, idx slot, tail, tidx *slot, p uint64) {
	hidx := idx.get()
	if hidx == 0 {
		extra.set(p)
	} else {
		i := hidx - 1
		iSlot := slot{func() uint64 { return i }, func(v uint64) { i = v }}
		w.linkEntryIntoArray(first, iSlot, tail, tidx, p)
	}
	idx.set(hidx + 1)
}

func (w *testWriter) hasTailFields() bool { return w.o.headerSize >= 264 }

// append adds one entry; fields are "NAME=value" strings.
func (w *testWriter) append(realtime, monotonic uint64, fields ...string) uint64 {
	type item struct{ off, hash uint64 }
	var items []item
	seen := map[uint64]bool{}
	for _, f := range fields {
		off, h := w.addData([]byte(f))
		if !seen[off] {
			seen[off] = true
			items = append(items, item{off, h})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].off < items[j].off })
	*w.o.seq++
	seq := *w.o.seq
	var xor uint64
	for _, it := range items {
		if w.o.keyed {
			xor ^= w.jenkins[it.off]
		} else {
			xor ^= it.hash
		}
	}
	isz := 16
	if w.o.compact {
		isz = 4
	}
	e := w.appendObject(3, 0, 64+len(items)*isz)
	w.put64(e+16, seq)
	w.put64(e+24, realtime)
	w.put64(e+32, monotonic)
	copy(w.buf[e+40:e+56], w.o.bootID[:])
	w.put64(e+56, xor)
	for i, it := range items {
		if w.o.compact {
			w.put32(e+64+uint64(i)*4, it.off)
		} else {
			w.put64(e+64+uint64(i)*16, it.off)
			w.put64(e+64+uint64(i)*16+8, it.hash)
		}
	}
	first := slot{func() uint64 { return w.entryArray }, func(v uint64) { w.entryArray = v }}
	idx := slot{func() uint64 { return w.nEntries }, func(v uint64) { w.nEntries = v }}
	if w.hasTailFields() {
		tail := slot{func() uint64 { return w.tailArray }, func(v uint64) { w.tailArray = v }}
		tidx := slot{func() uint64 { return w.tailArrayN }, func(v uint64) { w.tailArrayN = v }}
		w.linkEntryIntoArray(first, idx, &tail, &tidx, e)
	} else {
		w.linkEntryIntoArray(first, idx, nil, nil, e)
	}
	if w.headSeq == 0 {
		w.headSeq, w.headRT = seq, realtime
	}
	w.tailSeq, w.tailRT, w.tailMono, w.tailEntry = seq, realtime, monotonic, e
	for _, it := range items {
		d := it.off
		if w.o.compact {
			t, ti := w.field32(d+64), w.field32(d+68)
			w.linkPlusOne(w.field64(d+40), w.field64(d+48), w.field64(d+56), &t, &ti, e)
		} else {
			w.linkPlusOne(w.field64(d+40), w.field64(d+48), w.field64(d+56), nil, nil, e)
		}
	}
	return seq
}

func (w *testWriter) header() []byte {
	h := make([]byte, w.o.headerSize)
	le := binary.LittleEndian
	copy(h, signature)
	le.PutUint32(h[8:], 2)
	var inc uint32
	if w.o.keyed {
		inc |= incompatKeyedHash
	}
	if w.o.compact {
		inc |= incompatCompact
	}
	switch w.o.comp {
	case compXZ:
		inc |= incompatXZ
	case compLZ4:
		inc |= incompatLZ4
	case compZSTD:
		inc |= incompatZSTD
	}
	le.PutUint32(h[12:], inc)
	h[16] = w.state
	copy(h[24:], w.o.fileID[:])
	copy(h[40:], w.o.machineID[:])
	if w.nEntries > 0 {
		copy(h[56:], w.o.bootID[:])
	}
	copy(h[72:], w.o.seqnumID[:])
	vals := []uint64{uint64(w.o.headerSize), uint64(len(w.buf)) - uint64(w.o.headerSize), w.dataHT, w.o.dataBuckets * 16, w.fieldHT, w.fieldBuckets * 16,
		w.tailObject, w.nObjects, w.nEntries, w.tailSeq, w.headSeq, w.entryArray, w.headRT, w.tailRT, w.tailMono,
		w.nData, w.nFields, 0, w.nArrays, w.dataDepth, w.fieldDepth}
	for i, v := range vals {
		le.PutUint64(h[88+i*8:], v)
	}
	if w.hasTailFields() {
		le.PutUint32(h[256:], uint32(w.tailArray))
		le.PutUint32(h[260:], uint32(w.tailArrayN))
	}
	if w.o.headerSize >= 272 {
		le.PutUint64(h[264:], w.tailEntry)
	}
	return h
}

// flush writes the file in place: body first, header last.
func (w *testWriter) flush() error {
	f, err := os.OpenFile(w.path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(w.buf[w.o.headerSize:], int64(w.o.headerSize)); err != nil {
		return err
	}
	if _, err := f.WriteAt(w.header(), 0); err != nil {
		return err
	}
	return f.Sync()
}
