package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"
)

// Hash is a SHA-256 digest.
type Hash [32]byte

// ID is a 16-byte identifier used for writer IDs and epochs.
type ID [16]byte

// WriterID identifies a spool for its lifetime.
type WriterID = ID

// EpochID identifies an epoch; writers generate UUIDv7 values.
type EpochID = ID

func (h Hash) String() string { return hex.EncodeToString(h[:]) }
func (h Hash) IsZero() bool   { return h == Hash{} }

func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal(h.String()) }

func (h *Hash) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := ParseHash(s)
	if err != nil {
		return err
	}
	*h = p
	return nil
}

// ParseHash parses a lowercase or uppercase hex SHA-256 digest.
func ParseHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, fmt.Errorf("invalid hash %q", s)
	}
	copy(h[:], b)
	return h, nil
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }
func (id ID) IsZero() bool   { return id == ID{} }

func (id ID) MarshalJSON() ([]byte, error) { return json.Marshal(id.String()) }

func (id *ID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := ParseID(s)
	if err != nil {
		return err
	}
	*id = p
	return nil
}

// ParseID parses a 16-byte hex identifier.
func ParseID(s string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("invalid id %q", s)
	}
	copy(id[:], b)
	return id, nil
}

// NewWriterID returns a random writer ID.
func NewWriterID() (WriterID, error) {
	var id WriterID
	_, err := rand.Read(id[:])
	return id, err
}

// NewEpoch returns a UUIDv7 epoch identifier for time t.
func NewEpoch(t time.Time) (EpochID, error) {
	var id EpochID
	if _, err := rand.Read(id[6:]); err != nil {
		return id, err
	}
	ms := uint64(t.UnixMilli())
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(id[0:6], ts[2:8])
	id[6] = (id[6] & 0x0f) | 0x70
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

// UnixMilli returns the instant of a millisecond wire timestamp, saturating values beyond the int64 range.
func UnixMilli(ms uint64) time.Time { return time.UnixMilli(int64(min(ms, math.MaxInt64))) }

var targetIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidTargetID reports whether s is a well-formed target_id.
func ValidTargetID(s string) bool { return targetIDPattern.MatchString(s) }
