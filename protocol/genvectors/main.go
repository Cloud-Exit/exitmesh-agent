// Command genvectors deterministically writes the language-neutral vectors under protocol/vectors.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/fxamacker/cbor/v2"

	p "github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func main() {
	out := flag.String("out", filepath.Join("protocol", "vectors"), "output directory")
	check := flag.Bool("check", false, "verify the files in the output directory instead of writing them")
	flag.Parse()
	files := generate()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	if !*check {
		if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // committed protocol vectors use normal source tree permissions
			fatal(err)
		}
	}
	stale := false
	for _, n := range names {
		path := filepath.Join(*out, n)
		if *check {
			have, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(have, files[n]) {
				fmt.Fprintf(os.Stderr, "%s is out of date\n", path)
				stale = true
			}
			continue
		}
		if err := os.WriteFile(path, files[n], 0o644); err != nil { //nolint:gosec // committed protocol vectors use normal source tree permissions
			fatal(err)
		}
	}
	if stale {
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// generate returns every vector file by name.
func generate() map[string][]byte {
	return map[string][]byte{
		"encoding.json":       toJSON(encodingVectors()),
		"rejection.json":      toJSON(rejectionVectors()),
		"fold.json":           toJSON(foldVectors()),
		"reconstruction.json": toJSON(reconstructionVectors()),
		"ids.json":            toJSON(idVectors()),
		"ownership.json":      toJSON(ownershipVectors()),
	}
}

func toJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func marshal(v any) []byte { return must(p.Marshal(v)) }

// generic decodes CBOR into map[any]any trees for mutation.
func generic(b []byte) map[any]any {
	var v any
	check(cbor.Unmarshal(b, &v))
	return v.(map[any]any)
}

func replaceOnce(b, old, repl []byte) []byte {
	if n := bytes.Count(b, old); n != 1 {
		panic(fmt.Sprintf("pattern %x occurs %d times", old, n))
	}
	return bytes.Replace(b, old, repl, 1)
}

// pad describes an input that continues with Byte repeated up to Length total bytes.
type pad struct {
	Byte   string `json:"byte"`
	Length int    `json:"length"`
}

func expand(h string, pd *pad) []byte {
	b := must(hex.DecodeString(h))
	if pd == nil {
		return b
	}
	fill := must(hex.DecodeString(pd.Byte))
	return append(b, bytes.Repeat(fill, pd.Length-len(b))...)
}

// Typed JSON values of encoding.json.

type tv = map[string]any

func tUint(u uint64) tv     { return tv{"uint": strconv.FormatUint(u, 10)} }
func tNint(s string) tv     { return tv{"nint": s} }
func tFloat(f float64) tv   { return tv{"float": fmt.Sprintf("%016x", math.Float64bits(f))} }
func tText(s string) tv     { return tv{"text": s} }
func tBytes(b []byte) tv    { return tv{"bytes": hx(b)} }
func tBool(b bool) tv       { return tv{"bool": b} }
func tNull() tv             { return tv{"null": true} }
func tArray(items ...tv) tv { return tv{"array": append([]tv{}, items...)} }
func tMap(pairs ...[2]tv) tv {
	out := make([][2]tv, len(pairs))
	copy(out, pairs)
	return tv{"map": out}
}

func goValue(t tv, key bool) any {
	for k, v := range t {
		switch k {
		case "uint":
			return must(strconv.ParseUint(v.(string), 10, 64))
		case "nint":
			n, ok := new(big.Int).SetString(v.(string), 10)
			if !ok {
				panic("bad nint")
			}
			if n.IsInt64() {
				return n.Int64()
			}
			if key {
				panic("big negative key")
			}
			return *n
		case "float":
			return math.Float64frombits(must(strconv.ParseUint(v.(string), 16, 64)))
		case "text":
			return v.(string)
		case "bytes":
			b := must(hex.DecodeString(v.(string)))
			if key {
				return cbor.ByteString(b)
			}
			return b
		case "bool":
			return v.(bool)
		case "null":
			return nil
		case "array":
			items := v.([]tv)
			out := make([]any, len(items))
			for i, e := range items {
				out[i] = goValue(e, false)
			}
			return out
		case "map":
			out := map[any]any{}
			for _, pr := range v.([][2]tv) {
				out[goValue(pr[0], true)] = goValue(pr[1], false)
			}
			return out
		}
	}
	panic("empty typed value")
}
