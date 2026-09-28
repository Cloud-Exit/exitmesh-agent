package logs

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

// record is one parsed physical line of a container log file.
type record struct {
	ts        time.Time
	stream    string
	partial   bool
	text      []byte
	truncated bool
}

var dockerTail = regexp.MustCompile(`"stream":"([a-z]+)","time":"([^"]+)"\}\s*$`)

// parseContainerLine decodes a CRI or docker json-file line; tail is the line end when head was cut.
func parseContainerLine(head, tail []byte, cut bool) (record, bool) {
	if len(head) > 0 && head[0] == '{' {
		return parseDocker(head, tail, cut)
	}
	return parseCRI(head, cut)
}

func parseCRI(b []byte, cut bool) (record, bool) {
	sp := bytes.IndexByte(b, ' ')
	if sp <= 0 {
		return record{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, string(b[:sp]))
	if err != nil {
		return record{}, false
	}
	rest := b[sp+1:]
	sp = bytes.IndexByte(rest, ' ')
	if sp <= 0 {
		return record{}, false
	}
	stream := string(rest[:sp])
	rest = rest[sp+1:]
	tag := rest
	var text []byte
	if sp = bytes.IndexByte(rest, ' '); sp >= 0 {
		tag, text = rest[:sp], rest[sp+1:]
	}
	if i := bytes.IndexByte(tag, ':'); i >= 0 {
		tag = tag[:i]
	}
	var partial bool
	switch string(tag) {
	case "P":
		partial = true
	case "F":
	default:
		return record{}, false
	}
	return record{ts: ts, stream: stream, partial: partial, text: text, truncated: cut}, true
}

type dockerLine struct {
	Log    string    `json:"log"`
	Stream string    `json:"stream"`
	Time   time.Time `json:"time"`
}

func parseDocker(head, tail []byte, cut bool) (record, bool) {
	if !cut {
		var d dockerLine
		if err := json.Unmarshal(head, &d); err != nil || d.Stream == "" {
			return record{}, false
		}
		text := []byte(d.Log)
		partial := true
		if n := len(text); n > 0 && text[n-1] == '\n' {
			text, partial = text[:n-1], false
		}
		return record{ts: d.Time, stream: d.Stream, partial: partial, text: text}, true
	}
	const prefix = `{"log":"`
	if !bytes.HasPrefix(head, []byte(prefix)) {
		return record{}, false
	}
	m := dockerTail.FindSubmatch(tail)
	if m == nil {
		return record{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, string(m[2]))
	if err != nil {
		return record{}, false
	}
	partial := !bytes.HasSuffix(tail[:len(tail)-len(m[0])], []byte(`\n",`))
	return record{ts: ts, stream: string(m[1]), partial: partial, text: decodeJSONPrefix(head[len(prefix):]), truncated: true}, true
}

// decodeJSONPrefix decodes a JSON string body up to its closing quote or the end of b.
func decodeJSONPrefix(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '"' {
			break
		}
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+1 >= len(b) {
			break
		}
		i++
		switch b[i] {
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case 'r':
			out = append(out, '\r')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'u':
			if i+4 >= len(b) {
				return out
			}
			v, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 32)
			if err != nil {
				return out
			}
			out = utf8.AppendRune(out, rune(v))
			i += 4
		default:
			out = append(out, b[i])
		}
	}
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out
}

// assembler joins CRI and docker partial records of one stream up to a byte cap.
type assembler struct {
	buf       []byte
	ts        time.Time
	truncated bool
	active    bool
}

// add returns a completed line when r is final.
func (a *assembler) add(r record, maxBytes int) (text []byte, ts time.Time, truncated, done bool) {
	if !a.active {
		a.active, a.ts, a.buf, a.truncated = true, r.ts, a.buf[:0], false
	}
	room := maxBytes - len(a.buf)
	switch {
	case room <= 0:
		a.truncated = a.truncated || len(r.text) > 0
	case len(r.text) > room:
		a.buf = append(a.buf, r.text[:room]...)
		a.truncated = true
	default:
		a.buf = append(a.buf, r.text...)
	}
	a.truncated = a.truncated || r.truncated
	if r.partial {
		return nil, time.Time{}, false, false
	}
	text, ts, truncated = a.buf, a.ts, a.truncated
	a.active, a.truncated = false, false
	a.buf = nil
	if ts.IsZero() {
		ts = r.ts
	}
	return text, ts, truncated, true
}
