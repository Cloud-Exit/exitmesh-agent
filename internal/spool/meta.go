package spool

import (
	"encoding/binary"
	"fmt"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

var (
	bucketMeta    = []byte("meta")
	bucketRecords = []byte("records")
	bucketCursors = []byte("cursors")

	keyWriter      = []byte("writer_id")
	keyIncarnation = []byte("incarnation")
	keyIdentity    = []byte("identity")
	keyEpoch       = []byte("epoch")
	keyCommitted   = []byte("last_committed")
	keyHalt        = []byte("halt")
)

const kvBucketPrefix = "kv."

// RecordState is the delivery state of a spooled record (SPEC 8.1). Committed records are deleted.
type RecordState uint8

const (
	NeverTransmitted       RecordState = 1
	TransmittedUnconfirmed RecordState = 2
)

func (s RecordState) String() string {
	switch s {
	case NeverTransmitted:
		return "never-transmitted"
	case TransmittedUnconfirmed:
		return "transmitted-unconfirmed"
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

// Relief progress flags kept per record so repeated relief does not re-decode finished records.
const (
	flagEvicted   uint8 = 1 << 0
	flagCompacted uint8 = 1 << 1
)

type recMeta struct {
	Seq   uint64
	Type  protocol.RecordType
	State RecordState
	Flags uint8
	Hash  protocol.Hash
	Seg   uint64
	Off   int64
	Len   uint32
	Time  uint64 // emit time; for a range, the earliest time it covers
	From  uint64 // range span start; Seq for other records
}

const (
	metaVersion = 1
	metaSize    = 4 + 32 + 8 + 8 + 4 + 8 + 8
)

func seqKey(seq uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], seq)
	return k[:]
}

func (m *recMeta) encode() []byte {
	b := make([]byte, metaSize)
	b[0] = metaVersion
	b[1] = byte(m.Type)
	b[2] = byte(m.State)
	b[3] = m.Flags
	copy(b[4:36], m.Hash[:])
	binary.BigEndian.PutUint64(b[36:44], m.Seg)
	binary.BigEndian.PutUint64(b[44:52], uint64(m.Off))
	binary.BigEndian.PutUint32(b[52:56], m.Len)
	binary.BigEndian.PutUint64(b[56:64], m.Time)
	binary.BigEndian.PutUint64(b[64:72], m.From)
	return b
}

func decodeMeta(k, b []byte) (recMeta, error) {
	var m recMeta
	if len(k) != 8 || len(b) != metaSize || b[0] != metaVersion {
		return m, fmt.Errorf("%w: record metadata entry", ErrCorrupt)
	}
	m.Seq = binary.BigEndian.Uint64(k)
	m.Type = protocol.RecordType(b[1])
	m.State = RecordState(b[2])
	m.Flags = b[3]
	copy(m.Hash[:], b[4:36])
	m.Seg = binary.BigEndian.Uint64(b[36:44])
	m.Off = int64(binary.BigEndian.Uint64(b[44:52]))
	m.Len = binary.BigEndian.Uint32(b[52:56])
	m.Time = binary.BigEndian.Uint64(b[56:64])
	m.From = binary.BigEndian.Uint64(b[64:72])
	if m.State != NeverTransmitted && m.State != TransmittedUnconfirmed {
		return m, fmt.Errorf("%w: record %d has state %d", ErrCorrupt, m.Seq, b[2])
	}
	if m.Type < protocol.TypeCheckpoint || m.Type > protocol.TypeFinding {
		return m, fmt.Errorf("%w: record %d has type %d", ErrCorrupt, m.Seq, b[1])
	}
	if m.From == 0 || m.From > m.Seq || (m.Type != protocol.TypeRange && m.From != m.Seq) {
		return m, fmt.Errorf("%w: record %d has span start %d", ErrCorrupt, m.Seq, m.From)
	}
	return m, nil
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
