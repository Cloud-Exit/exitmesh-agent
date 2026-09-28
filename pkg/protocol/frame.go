package protocol

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	zstdEncOnce sync.Once
	zstdEnc     *zstd.Encoder
	zstdDec     *zstd.Decoder
)

func zstdCodecs() (*zstd.Encoder, *zstd.Decoder) {
	zstdEncOnce.Do(func() {
		var err error
		if zstdEnc, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault)); err != nil {
			panic(err)
		}
		if zstdDec, err = zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxFramePayload), zstd.WithDecoderConcurrency(1)); err != nil {
			panic(err)
		}
	})
	return zstdEnc, zstdDec
}

// EncodeBatchFrame builds a record batch binary frame (SPEC 9.3) from exact record bytes.
func EncodeBatchFrame(records [][]byte, compress bool) ([]byte, error) {
	arr := make([]any, len(records))
	for i, r := range records {
		arr[i] = r
	}
	payload, err := Marshal(arr)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxFramePayload {
		return nil, fmt.Errorf("%w: batch payload %d bytes", ErrTooLarge, len(payload))
	}
	comp := CompressionNone
	if compress {
		enc, _ := zstdCodecs()
		payload = enc.EncodeAll(payload, nil)
		comp = CompressionZstd
	}
	return append([]byte{FrameRecordBatch, comp}, payload...), nil
}

// DecodeBatchFrame returns the record byte strings of a batch frame.
func DecodeBatchFrame(frame []byte) ([][]byte, error) {
	if len(frame) < 2 {
		return nil, fmt.Errorf("%w: short frame", ErrMalformed)
	}
	if frame[0] != FrameRecordBatch {
		return nil, fmt.Errorf("%w: frame type %#x", ErrUnsupportedField, frame[0])
	}
	payload := frame[2:]
	switch frame[1] {
	case CompressionNone:
	case CompressionZstd:
		_, dec := zstdCodecs()
		out, err := dec.DecodeAll(payload, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: zstd: %w", ErrMalformed, err)
		}
		payload = out
	default:
		return nil, fmt.Errorf("%w: compression %#x", ErrUnsupportedField, frame[1])
	}
	if len(payload) > MaxFramePayload {
		return nil, fmt.Errorf("%w: batch payload", ErrTooLarge)
	}
	var arr []any
	rest, err := decMode.UnmarshalFirst(payload, &arr)
	if err != nil || len(rest) != 0 || len(arr) == 0 {
		return nil, fmt.Errorf("%w: batch payload", ErrMalformed)
	}
	out := make([][]byte, len(arr))
	for i, x := range arr {
		b, ok := x.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: batch element %d is not a byte string", ErrMalformed, i)
		}
		out[i] = b
	}
	return out, nil
}

// Token kinds of enrollment tokens (SPEC 9.2).
const (
	TokenCluster   = "c"
	TokenHost      = "h"
	TokenHostGroup = "g"
)

// EnrollmentToken is a parsed enrollment token.
type EnrollmentToken struct {
	Kind   string
	ID     string
	Secret string
}

// TargetID returns the embedded target_id for cluster and host tokens.
func (t EnrollmentToken) TargetID() (string, bool) {
	if t.Kind == TokenCluster || t.Kind == TokenHost {
		return t.ID, true
	}
	return "", false
}

// ParseEnrollmentToken parses emx1_<kind>_<id>_<secret>.
func ParseEnrollmentToken(s string) (EnrollmentToken, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "emx1_") {
		return EnrollmentToken{}, errors.New("enrollment token: missing emx1_ prefix")
	}
	rest := s[len("emx1_"):]
	if len(rest) < 2 || rest[1] != '_' {
		return EnrollmentToken{}, errors.New("enrollment token: malformed kind")
	}
	kind := rest[:1]
	rest = rest[2:]
	i := strings.LastIndexByte(rest, '_')
	if i <= 0 || i == len(rest)-1 {
		return EnrollmentToken{}, errors.New("enrollment token: malformed id or secret")
	}
	t := EnrollmentToken{Kind: kind, ID: rest[:i], Secret: rest[i+1:]}
	switch kind {
	case TokenCluster, TokenHost, TokenHostGroup:
	default:
		return EnrollmentToken{}, fmt.Errorf("enrollment token: unknown kind %q", kind)
	}
	if !ValidTargetID(t.ID) {
		return EnrollmentToken{}, errors.New("enrollment token: invalid id")
	}
	if len(t.Secret) < 16 {
		return EnrollmentToken{}, errors.New("enrollment token: secret too short")
	}
	return t, nil
}

// ExportMagic starts an air-gap export file (SPEC 10).
const ExportMagic = "EMHPX1\n"

// ExportHeader is the first item of an export file.
type ExportHeader struct {
	TargetID      string `cbor:"target_id"`
	WriterID      []byte `cbor:"writer_id"`
	Incarnation   uint64 `cbor:"incarnation"`
	Epoch         []byte `cbor:"epoch"`
	LastCommitted uint64 `cbor:"last_committed"`
	ExportedAt    uint64 `cbor:"exported_at"`
	AgentVersion  string `cbor:"agent_version"`
}

// ExportWriter writes an export file.
type ExportWriter struct {
	w io.Writer
}

// NewExportWriter writes the magic and header.
func NewExportWriter(w io.Writer, h ExportHeader) (*ExportWriter, error) {
	if _, err := io.WriteString(w, ExportMagic); err != nil {
		return nil, err
	}
	b, err := Marshal(h)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	return &ExportWriter{w: w}, nil
}

// Write appends one record's exact bytes.
func (e *ExportWriter) Write(record []byte) error {
	b, err := Marshal(record)
	if err != nil {
		return err
	}
	_, err = e.w.Write(b)
	return err
}

// ReadExport parses an export file, decoding and chain-checking every record.
func ReadExport(r io.Reader) (ExportHeader, []*Record, error) {
	var h ExportHeader
	br := bufio.NewReader(r)
	magic := make([]byte, len(ExportMagic))
	if _, err := io.ReadFull(br, magic); err != nil || !bytes.Equal(magic, []byte(ExportMagic)) {
		return h, nil, fmt.Errorf("%w: not an export file", ErrMalformed)
	}
	dec := decMode.NewDecoder(br)
	if err := dec.Decode(&h); err != nil {
		return h, nil, fmt.Errorf("%w: export header: %w", ErrMalformed, err)
	}
	var out []*Record
	for {
		var b []byte
		err := dec.Decode(&b)
		if errors.Is(err, io.EOF) {
			return h, out, nil
		}
		if err != nil {
			return h, out, fmt.Errorf("%w: export record: %w", ErrMalformed, err)
		}
		rec, err := Decode(b)
		if err != nil {
			return h, out, err
		}
		out = append(out, rec)
	}
}
