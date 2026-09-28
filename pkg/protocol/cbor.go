package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// Decoding limits from SPEC section 3.2.
const (
	MaxRecordBytes   = 4 << 20
	MaxNestingDepth  = 32
	MaxContainerSize = 1 << 20
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	eo := cbor.CoreDetEncOptions()
	eo.NilContainers = cbor.NilContainerAsEmpty
	var err error
	if encMode, err = eo.EncMode(); err != nil {
		panic(err)
	}
	var rejected []func(*cbor.SimpleValueRegistry) error
	for v := 0; v < 256; v++ {
		if v < 20 || v == 23 || v >= 32 {
			rejected = append(rejected, cbor.WithRejectedSimpleValue(cbor.SimpleValue(v)))
		}
	}
	sv, err := cbor.NewSimpleValueRegistryFromDefaults(rejected...)
	if err != nil {
		panic(err)
	}
	do := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  MaxNestingDepth,
		MaxArrayElements: MaxContainerSize,
		MaxMapPairs:      MaxContainerSize,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		IntDec:           cbor.IntDecConvertNone,
		UTF8:             cbor.UTF8RejectInvalid,
		SimpleValues:     sv,
		NaN:              cbor.NaNDecodeForbidden,
		Inf:              cbor.InfDecodeForbidden,
	}
	if decMode, err = do.DecMode(); err != nil {
		panic(err)
	}
}

// Marshal encodes v with core deterministic encoding.
func Marshal(v any) ([]byte, error) { return encMode.Marshal(v) }

// decodeStrict decodes b into a generic tree and applies the re-encode check.
func decodeStrict(b []byte) (any, error) {
	if len(b) > MaxRecordBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(b))
	}
	var v any
	rest, err := decMode.UnmarshalFirst(b, &v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(rest))
	}
	re, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if !bytes.Equal(re, b) {
		return nil, fmt.Errorf("%w: not deterministically encoded", ErrMalformed)
	}
	return v, nil
}

// NormalizeValue converts a Go value to the canonical SPEC 3.3 representation; nil is rejected unless allowNull.
func NormalizeValue(v any, allowNull bool) (any, error) {
	return normalizeValue(v, allowNull, 0)
}

func normalizeValue(v any, allowNull bool, depth int) (any, error) {
	if depth > MaxNestingDepth {
		return nil, fmt.Errorf("%w: value nested too deeply", ErrInvalidValue)
	}
	switch x := v.(type) {
	case nil:
		if allowNull {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: null", ErrInvalidValue)
	case string:
		if !utf8.ValidString(x) {
			return nil, fmt.Errorf("%w: invalid utf-8", ErrInvalidValue)
		}
		return x, nil
	case []byte:
		return append([]byte(nil), x...), nil
	case bool:
		return x, nil
	case int:
		return int64(x), nil
	case int8:
		return int64(x), nil
	case int16:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint:
		return normUint(uint64(x)), nil
	case uint8:
		return int64(x), nil
	case uint16:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint64:
		return normUint(x), nil
	case float32:
		return checkFloat(float64(x))
	case float64:
		return checkFloat(x)
	case []any:
		if len(x) > MaxContainerSize {
			return nil, fmt.Errorf("%w: array too large", ErrInvalidValue)
		}
		out := make([]any, len(x))
		for i, e := range x {
			n, err := normalizeValue(e, false, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return normalizeValue(out, false, depth)
	case map[string]any:
		return normalizeMap(x, false, depth+1)
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = e
		}
		return normalizeMap(out, false, depth+1)
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%w: non-text map key %T", ErrInvalidValue, k)
			}
			out[ks] = e
		}
		return normalizeMap(out, false, depth+1)
	default:
		return nil, fmt.Errorf("%w: unsupported type %T", ErrInvalidValue, v)
	}
}

func normalizeMap(m map[string]any, allowNull bool, depth int) (map[string]any, error) {
	if len(m) > MaxContainerSize {
		return nil, fmt.Errorf("%w: map too large", ErrInvalidValue)
	}
	out := make(map[string]any, len(m))
	for k, e := range m {
		if !utf8.ValidString(k) {
			return nil, fmt.Errorf("%w: invalid utf-8 key", ErrInvalidValue)
		}
		n, err := normalizeValue(e, allowNull, depth)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out[k] = n
	}
	return out, nil
}

// NormalizeFields normalizes a field map. With allowNull, nil values (field removals) are kept.
func NormalizeFields(m map[string]any, allowNull bool) (map[string]any, error) {
	if m == nil {
		return map[string]any{}, nil
	}
	return normalizeMap(m, allowNull, 1)
}

func normUint(u uint64) any {
	if u <= math.MaxInt64 {
		return int64(u)
	}
	return u
}

func checkFloat(f float64) (any, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("%w: non-finite float", ErrInvalidValue)
	}
	return f, nil
}

// ValueEqual reports whether two values have identical deterministic encodings.
func ValueEqual(a, b any) bool {
	ea, err1 := encMode.Marshal(a)
	eb, err2 := encMode.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(ea, eb)
}

// CloneValue deep-copies a normalized value.
func CloneValue(v any) any {
	switch x := v.(type) {
	case []byte:
		return append([]byte(nil), x...)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = CloneValue(e)
		}
		return out
	case map[string]any:
		return CloneFields(x)
	default:
		return v
	}
}

// CloneFields deep-copies a field map; nil becomes an empty map.
func CloneFields(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = CloneValue(v)
	}
	return out
}

// fromDecoded converts a decoded generic value (map[any]any etc.) into canonical form.
func fromDecoded(v any, allowNull bool) (any, error) {
	switch x := v.(type) {
	case uint64:
		return normUint(x), nil
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%w: non-text map key", ErrInvalidValue)
			}
			n, err := fromDecoded(e, false)
			if err != nil {
				return nil, err
			}
			out[ks] = n
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			n, err := fromDecoded(e, false)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case nil:
		if allowNull {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: null", ErrInvalidValue)
	case string, []byte, bool, int64, float64:
		return x, nil
	default:
		return nil, fmt.Errorf("%w: unsupported decoded type %T", ErrInvalidValue, v)
	}
}

func fieldsFromDecoded(v any, allowNull bool) (map[string]any, error) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: expected map", ErrMalformed)
	}
	out := make(map[string]any, len(m))
	for k, e := range m {
		ks, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("%w: non-text field key", ErrMalformed)
		}
		n, err := fromDecoded(e, allowNull)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ks, err)
		}
		out[ks] = n
	}
	return out, nil
}

// intKeyMap is a decoded map with unsigned integer keys, with unknown-key accounting.
type intKeyMap struct {
	m    map[uint64]any
	used map[uint64]bool
}

func asIntKeyMap(v any) (*intKeyMap, error) {
	raw, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: expected map", ErrMalformed)
	}
	m := make(map[uint64]any, len(raw))
	for k, e := range raw {
		ku, ok := k.(uint64)
		if !ok {
			return nil, fmt.Errorf("%w: expected unsigned integer key, got %T", ErrMalformed, k)
		}
		m[ku] = e
	}
	return &intKeyMap{m: m, used: map[uint64]bool{}}, nil
}

func (k *intKeyMap) has(key uint64) bool { _, ok := k.m[key]; return ok }

func (k *intKeyMap) get(key uint64) (any, bool) {
	v, ok := k.m[key]
	if ok {
		k.used[key] = true
	}
	return v, ok
}

func (k *intKeyMap) require(key uint64) (any, error) {
	v, ok := k.get(key)
	if !ok {
		return nil, fmt.Errorf("%w: missing key %d", ErrMalformed, key)
	}
	return v, nil
}

func (k *intKeyMap) uint(key uint64) (uint64, error) {
	v, err := k.require(key)
	if err != nil {
		return 0, err
	}
	u, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w: key %d: expected uint", ErrMalformed, key)
	}
	return u, nil
}

func (k *intKeyMap) optUint(key uint64) (uint64, bool, error) {
	if !k.has(key) {
		return 0, false, nil
	}
	u, err := k.uint(key)
	return u, true, err
}

func (k *intKeyMap) text(key uint64) (string, error) {
	v, err := k.require(key)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: key %d: expected text", ErrMalformed, key)
	}
	return s, nil
}

func (k *intKeyMap) bytesN(key uint64, n int) ([]byte, error) {
	v, err := k.require(key)
	if err != nil {
		return nil, err
	}
	b, ok := v.([]byte)
	if !ok || len(b) != n {
		return nil, fmt.Errorf("%w: key %d: expected %d-byte string", ErrMalformed, key, n)
	}
	return b, nil
}

func (k *intKeyMap) array(key uint64) ([]any, error) {
	v, err := k.require(key)
	if err != nil {
		return nil, err
	}
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: key %d: expected array", ErrMalformed, key)
	}
	return a, nil
}

// unknown returns the first unused key below the extension range.
func (k *intKeyMap) unknown() error {
	keys := make([]uint64, 0)
	for key := range k.m {
		if !k.used[key] && key < ExtensionKeyMin {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return fmt.Errorf("%w: key %d", ErrUnsupportedField, keys[0])
}

func (k *intKeyMap) extensions() map[uint64]any {
	var out map[uint64]any
	for key, v := range k.m {
		if key >= ExtensionKeyMin {
			if out == nil {
				out = map[uint64]any{}
			}
			out[key] = v
		}
	}
	return out
}

var errNotArray = errors.New("expected array")
