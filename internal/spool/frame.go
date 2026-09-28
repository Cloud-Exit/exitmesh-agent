package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// ErrCorrupt reports damaged data, or metadata that points at a missing or damaged body.
var ErrCorrupt = errors.New("spool: corrupt data")

// Frame layout: payload length (uint32 BE), CRC32C of payload (uint32 BE), payload.
const (
	frameHeader = 8
	maxFrame    = 64 << 20
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func appendFrame(dst, payload []byte) []byte {
	var h [frameHeader]byte
	binary.BigEndian.PutUint32(h[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(h[4:8], crc32.Checksum(payload, castagnoli))
	dst = append(dst, h[:]...)
	return append(dst, payload...)
}

func frameLen(n int) int64 { return int64(frameHeader + n) }

// checkFrame validates a whole frame whose payload length is expected to be n.
func checkFrame(buf []byte, n int) ([]byte, error) {
	if len(buf) != frameHeader+n {
		return nil, fmt.Errorf("%w: short frame", ErrCorrupt)
	}
	if l := binary.BigEndian.Uint32(buf[0:4]); int(l) != n {
		return nil, fmt.Errorf("%w: frame length %d, expected %d", ErrCorrupt, l, n)
	}
	if crc32.Checksum(buf[frameHeader:], castagnoli) != binary.BigEndian.Uint32(buf[4:8]) {
		return nil, fmt.Errorf("%w: frame checksum mismatch", ErrCorrupt)
	}
	return buf[frameHeader:], nil
}

func readFrameAt(f *os.File, off int64, n int) ([]byte, error) {
	buf := make([]byte, frameHeader+n)
	if _, err := f.ReadAt(buf, off); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: frame at %d beyond end of %s", ErrCorrupt, off, f.Name())
		}
		return nil, err
	}
	p, err := checkFrame(buf, n)
	if err != nil {
		return nil, fmt.Errorf("%s at %d: %w", f.Name(), off, err)
	}
	return p, nil
}

// readFrame returns io.EOF at a clean end and errTorn for a partial or invalid frame.
func readFrame(r io.Reader) ([]byte, error) {
	var h [frameHeader]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, errTorn
	}
	n := binary.BigEndian.Uint32(h[0:4])
	if n > maxFrame {
		return nil, errTorn
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, errTorn
	}
	if crc32.Checksum(p, castagnoli) != binary.BigEndian.Uint32(h[4:8]) {
		return nil, errTorn
	}
	return p, nil
}

var errTorn = fmt.Errorf("%w: torn or invalid frame", ErrCorrupt)
