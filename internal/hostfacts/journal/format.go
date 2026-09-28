// Package journal is a pure-Go, read-only reader of the systemd journal file format.
package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

const (
	signature = "LPKSHHRH"

	stateOffline  = 0
	stateOnline   = 1
	stateArchived = 2

	incompatXZ        = 1 << 0
	incompatLZ4       = 1 << 1
	incompatKeyedHash = 1 << 2
	incompatZSTD      = 1 << 3
	incompatCompact   = 1 << 4
	incompatKnown     = incompatXZ | incompatLZ4 | incompatKeyedHash | incompatZSTD | incompatCompact

	objData       = 1
	objEntry      = 3
	objEntryArray = 6

	objCompressedXZ   = 1 << 0
	objCompressedLZ4  = 1 << 1
	objCompressedZSTD = 1 << 2

	objectHeaderSize = 16
	minHeaderSize    = 208
	compactHeader    = 264
	entryItemsOffset = 64
)

// ErrCorrupt reports a structurally invalid journal file.
var ErrCorrupt = errors.New("journal: corrupt file")

// ErrUnsupported reports a file using incompatible features this reader does not implement.
var ErrUnsupported = errors.New("journal: unsupported file")

// ID128 is a systemd 128-bit identifier.
type ID128 [16]byte

func (id ID128) String() string { return fmt.Sprintf("%x", id[:]) }

type header struct {
	compat, incompat uint32
	state            uint8
	fileID           ID128
	machineID        ID128
	seqnumID         ID128
	headerSize       uint64
	arenaSize        uint64
	nEntries         uint64
	tailSeqnum       uint64
	headSeqnum       uint64
	entryArrayOffset uint64
	headRealtime     uint64
	tailRealtime     uint64
}

func parseHeader(b []byte) (header, error) {
	var h header
	if len(b) < minHeaderSize || string(b[:8]) != signature {
		return h, fmt.Errorf("%w: bad signature", ErrCorrupt)
	}
	le := binary.LittleEndian
	h.compat = le.Uint32(b[8:])
	h.incompat = le.Uint32(b[12:])
	h.state = b[16]
	copy(h.fileID[:], b[24:40])
	copy(h.machineID[:], b[40:56])
	copy(h.seqnumID[:], b[72:88])
	h.headerSize = le.Uint64(b[88:])
	h.arenaSize = le.Uint64(b[96:])
	h.nEntries = le.Uint64(b[152:])
	h.tailSeqnum = le.Uint64(b[160:])
	h.headSeqnum = le.Uint64(b[168:])
	h.entryArrayOffset = le.Uint64(b[176:])
	h.headRealtime = le.Uint64(b[184:])
	h.tailRealtime = le.Uint64(b[192:])
	if h.incompat&^incompatKnown != 0 {
		return h, fmt.Errorf("%w: incompatible flags %#x", ErrUnsupported, h.incompat&^incompatKnown)
	}
	if h.headerSize < minHeaderSize || h.headerSize%8 != 0 {
		return h, fmt.Errorf("%w: header size %d", ErrCorrupt, h.headerSize)
	}
	if h.incompat&incompatCompact != 0 && h.headerSize < compactHeader {
		return h, fmt.Errorf("%w: compact file with a %d byte header", ErrCorrupt, h.headerSize)
	}
	if h.state > stateArchived {
		return h, fmt.Errorf("%w: state %d", ErrCorrupt, h.state)
	}
	return h, nil
}

func (h header) compact() bool { return h.incompat&incompatCompact != 0 }

// objects reads typed objects from one open journal file.
type objects struct {
	f        *os.File
	h        header
	size     int64
	maxBytes int64
	zstd     *zstd.Decoder
}

func (o *objects) readAt(off uint64, n int) ([]byte, error) {
	if off > uint64(o.size) || uint64(n) > uint64(o.size)-off {
		return nil, errBeyondEOF
	}
	b := make([]byte, n)
	if _, err := o.f.ReadAt(b, int64(off)); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errBeyondEOF
		}
		return nil, err
	}
	return b, nil
}

var errBeyondEOF = errors.New("journal: object beyond end of file")

// object reads the whole object at off after validating its header and type.
func (o *objects) object(off uint64, typ uint8) ([]byte, uint8, error) {
	if off%8 != 0 || off < o.h.headerSize {
		return nil, 0, fmt.Errorf("%w: object offset %d", ErrCorrupt, off)
	}
	hdr, err := o.readAt(off, objectHeaderSize)
	if err != nil {
		return nil, 0, err
	}
	size := binary.LittleEndian.Uint64(hdr[8:])
	if hdr[0] != typ {
		return nil, 0, fmt.Errorf("%w: object at %d has type %d, want %d", ErrCorrupt, off, hdr[0], typ)
	}
	if size < objectHeaderSize || int64(size) > o.maxBytes {
		return nil, 0, fmt.Errorf("%w: object at %d has size %d", ErrCorrupt, off, size)
	}
	b, err := o.readAt(off, int(size))
	if err != nil {
		return nil, 0, err
	}
	return b, hdr[1], nil
}

func (o *objects) payload(b []byte, flags uint8) ([]byte, error) {
	switch flags & (objCompressedXZ | objCompressedLZ4 | objCompressedZSTD) {
	case 0:
		return b, nil
	case objCompressedXZ:
		r, err := xz.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%w: xz: %v", ErrCorrupt, err)
		}
		out, err := io.ReadAll(io.LimitReader(r, o.maxBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%w: xz: %v", ErrCorrupt, err)
		}
		if int64(len(out)) > o.maxBytes {
			return nil, errTooLarge
		}
		return out, nil
	case objCompressedLZ4:
		if len(b) < 8 {
			return nil, fmt.Errorf("%w: lz4 payload", ErrCorrupt)
		}
		n := binary.LittleEndian.Uint64(b)
		if n > uint64(o.maxBytes) {
			return nil, errTooLarge
		}
		out := make([]byte, n)
		m, err := lz4.UncompressBlock(b[8:], out)
		if err != nil || uint64(m) != n {
			return nil, fmt.Errorf("%w: lz4: %v", ErrCorrupt, err)
		}
		return out, nil
	case objCompressedZSTD:
		out, err := o.zstd.DecodeAll(b, nil)
		if err != nil {
			if errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) {
				return nil, errTooLarge
			}
			return nil, fmt.Errorf("%w: zstd: %v", ErrCorrupt, err)
		}
		if int64(len(out)) > o.maxBytes {
			return nil, errTooLarge
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: several compression flags %#x", ErrCorrupt, flags)
}

var errTooLarge = errors.New("journal: data object exceeds the size limit")

// data returns the field name and value of the data object at off.
func (o *objects) data(off uint64) (string, string, error) {
	b, flags, err := o.object(off, objData)
	if errors.Is(err, ErrCorrupt) && o.oversize(off) {
		return "", "", errTooLarge
	}
	if err != nil {
		return "", "", err
	}
	start := 64
	if o.h.compact() {
		start = 72
	}
	if len(b) < start {
		return "", "", fmt.Errorf("%w: short data object at %d", ErrCorrupt, off)
	}
	p, err := o.payload(b[start:], flags)
	if err != nil {
		return "", "", err
	}
	k, v, ok := bytes.Cut(p, []byte{'='})
	if !ok || len(k) == 0 {
		return "", "", fmt.Errorf("%w: data object at %d is not FIELD=value", ErrCorrupt, off)
	}
	return string(k), string(v), nil
}

func (o *objects) oversize(off uint64) bool {
	hdr, err := o.readAt(off, objectHeaderSize)
	return err == nil && hdr[0] == objData && int64(binary.LittleEndian.Uint64(hdr[8:])) > o.maxBytes
}

type entryHead struct {
	offset    uint64
	seqnum    uint64
	realtime  uint64
	monotonic uint64
	bootID    ID128
}

func (o *objects) entryHead(off uint64) (entryHead, []uint64, error) {
	b, _, err := o.object(off, objEntry)
	if err != nil {
		return entryHead{}, nil, err
	}
	if len(b) < entryItemsOffset {
		return entryHead{}, nil, fmt.Errorf("%w: short entry at %d", ErrCorrupt, off)
	}
	le := binary.LittleEndian
	e := entryHead{offset: off, seqnum: le.Uint64(b[16:]), realtime: le.Uint64(b[24:]), monotonic: le.Uint64(b[32:])}
	copy(e.bootID[:], b[40:56])
	items := b[entryItemsOffset:]
	var offs []uint64
	if o.h.compact() {
		for i := 0; i+4 <= len(items); i += 4 {
			offs = append(offs, uint64(le.Uint32(items[i:])))
		}
	} else {
		for i := 0; i+16 <= len(items); i += 16 {
			offs = append(offs, le.Uint64(items[i:]))
		}
	}
	return e, offs, nil
}

// arrayHeader returns the next array offset and the item capacity of the entry array at off.
func (o *objects) arrayHeader(off uint64) (uint64, uint64, error) {
	if off%8 != 0 || off < o.h.headerSize {
		return 0, 0, fmt.Errorf("%w: entry array offset %d", ErrCorrupt, off)
	}
	b, err := o.readAt(off, 24)
	if err != nil {
		return 0, 0, err
	}
	size := binary.LittleEndian.Uint64(b[8:])
	if b[0] != objEntryArray || size < 24 || off+size > uint64(o.size) {
		return 0, 0, fmt.Errorf("%w: entry array at %d", ErrCorrupt, off)
	}
	return binary.LittleEndian.Uint64(b[16:]), (size - 24) / o.itemSize(), nil
}

func (o *objects) itemSize() uint64 {
	if o.h.compact() {
		return 4
	}
	return 8
}

// arrayItems reads n items starting at index from of the entry array at off.
func (o *objects) arrayItems(off, from, n uint64) ([]uint64, error) {
	sz := o.itemSize()
	b, err := o.readAt(off+24+from*sz, int(n*sz))
	if err != nil {
		return nil, err
	}
	out := make([]uint64, n)
	for i := range out {
		if sz == 4 {
			out[i] = uint64(binary.LittleEndian.Uint32(b[uint64(i)*4:]))
		} else {
			out[i] = binary.LittleEndian.Uint64(b[uint64(i)*8:])
		}
	}
	return out, nil
}
