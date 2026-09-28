package logql

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/prometheus/prometheus/model/labels"
)

const (
	errorLabel    = "__error__"
	errJSON       = "JSONParserErr"
	errLabelFilt  = "LabelFilterErr"
	extractSuffix = "_extracted"
)

// lineState carries the labels of one line through the pipeline, as Loki's LabelsBuilder does.
type lineState struct {
	base   map[string]string
	parsed map[string]string
	err    string
}

func (s *lineState) get(name string) (string, bool) {
	if name == errorLabel {
		return s.err, s.err != ""
	}
	if v, ok := s.parsed[name]; ok {
		return v, true
	}
	v, ok := s.base[name]
	return v, ok && v != ""
}

func (s *lineState) setParsed(name, value string) {
	if name == "" {
		return
	}
	if _, ok := s.base[name]; ok {
		name += extractSuffix
	}
	if s.parsed == nil {
		s.parsed = make(map[string]string, 8)
	}
	s.parsed[name] = value
}

// labels keeps parsed labels with empty values because Loki distinguishes them from absent ones in series identity.
func (s *lineState) labels() labels.Labels {
	b := labels.NewScratchBuilder(len(s.base) + len(s.parsed) + 1)
	for k, v := range s.base {
		if _, over := s.parsed[k]; !over && v != "" {
			b.Add(k, v)
		}
	}
	for k, v := range s.parsed {
		b.Add(k, v)
	}
	if s.err != "" {
		b.Add(errorLabel, s.err)
	}
	b.Sort()
	return b.Labels()
}

type stageFunc func(line string, st *lineState) bool

type pipeline struct {
	matchers []*labels.Matcher
	stages   []stageFunc
	// refsError is set when a label filter references __error__.
	refsError bool
	// preserveErr keeps __error__ samples in metric evaluation instead of failing it.
	preserveErr bool
}

// preserveErrors follows Loki: only a directly enclosing sum referencing __error__ keeps error samples.
func (p *pipeline) preserveErrors(g *Grouping, preSum bool) bool {
	if !preSum || (g != nil && g.Without) {
		return false
	}
	if g != nil {
		for _, l := range g.Labels {
			if l == errorLabel {
				return true
			}
		}
	}
	return p.refsError
}

func newPipeline(e *LogExpr) (*pipeline, error) {
	p := &pipeline{matchers: e.Matchers}
	for _, s := range e.Stages {
		f, err := compileStage(s)
		if err != nil {
			return nil, err
		}
		p.stages = append(p.stages, f)
		if lf, ok := s.(*LabelFilterStage); ok && filterReferences(lf.Filter, errorLabel) {
			p.refsError = true
		}
	}
	return p, nil
}

func filterReferences(f LabelFilter, name string) bool {
	switch n := f.(type) {
	case *LabelFilterBinary:
		return filterReferences(n.Left, name) || filterReferences(n.Right, name)
	case *LabelFilterString:
		return n.Matcher.Name == name
	case *LabelFilterNumeric:
		return n.Name == name
	}
	return false
}

func (p *pipeline) matchStream(ls map[string]string) bool {
	for _, m := range p.matchers {
		if !m.Matches(ls[m.Name]) {
			return false
		}
	}
	return true
}

// process runs the stages on one line; the line itself is never retained.
func (p *pipeline) process(streamLabels map[string]string, line string) (*lineState, bool) {
	st := &lineState{base: streamLabels}
	for _, s := range p.stages {
		if !s(line, st) {
			return nil, false
		}
	}
	return st, true
}

func compileStage(s Stage) (stageFunc, error) {
	switch n := s.(type) {
	case *LineFilter:
		return compileLineFilter(n)
	case *JSONStage:
		if len(n.Params) == 0 {
			return jsonStage, nil
		}
		return compileJSONParams(n.Params)
	case *LogfmtStage:
		return logfmtStage, nil
	case *PatternStage:
		nodes, err := parsePattern(n.Pattern)
		if err != nil {
			return nil, err
		}
		return func(line string, st *lineState) bool {
			matchPattern(nodes, line, st.setParsed)
			return true
		}, nil
	case *RegexpStage:
		re, names, err := compileRegexpStage(n.Pattern)
		if err != nil {
			return nil, err
		}
		return func(line string, st *lineState) bool {
			m := re.FindStringSubmatchIndex(line)
			if m == nil {
				return true
			}
			for i := 1; i < len(names); i++ {
				if names[i] == "" {
					continue
				}
				v := ""
				if m[2*i] >= 0 {
					v = line[m[2*i]:m[2*i+1]]
				}
				st.setParsed(names[i], v)
			}
			return true
		}, nil
	case *LabelFilterStage:
		f, err := compileLabelFilter(n.Filter)
		if err != nil {
			return nil, err
		}
		return func(_ string, st *lineState) bool { return f(st) }, nil
	}
	return nil, &ParseError{Msg: "unknown pipeline stage"}
}

func compileLineFilter(f *LineFilter) (stageFunc, error) {
	switch f.Op {
	case LineContains:
		m := f.Match
		return func(line string, _ *lineState) bool { return strings.Contains(line, m) }, nil
	case LineNotContains:
		m := f.Match
		return func(line string, _ *lineState) bool { return !strings.Contains(line, m) }, nil
	}
	re, err := regexp.Compile(f.Match)
	if err != nil {
		return nil, err
	}
	want := f.Op == LineMatchRegexp
	return func(line string, _ *lineState) bool { return re.MatchString(line) == want }, nil
}

type labelPred func(st *lineState) bool

func compileLabelFilter(f LabelFilter) (labelPred, error) {
	switch n := f.(type) {
	case *LabelFilterBinary:
		l, err := compileLabelFilter(n.Left)
		if err != nil {
			return nil, err
		}
		r, err := compileLabelFilter(n.Right)
		if err != nil {
			return nil, err
		}
		if n.Or {
			return func(st *lineState) bool { return l(st) || r(st) }, nil
		}
		return func(st *lineState) bool {
			lok := l(st)
			rok := r(st)
			return lok && rok
		}, nil
	case *LabelFilterString:
		m := n.Matcher
		return func(st *lineState) bool {
			v, _ := st.get(m.Name)
			return m.Matches(v)
		}, nil
	case *LabelFilterNumeric:
		return compileNumericFilter(n), nil
	}
	return nil, &ParseError{Msg: "unknown label filter"}
}

func compileNumericFilter(n *LabelFilterNumeric) labelPred {
	var parse func(string) (float64, bool)
	switch n.Kind {
	case NumericDuration:
		parse = func(s string) (float64, bool) {
			d, err := time.ParseDuration(s)
			return float64(d), err == nil
		}
	case NumericBytes:
		parse = func(s string) (float64, bool) {
			b, err := parseBytes(s)
			return float64(b), err == nil
		}
	default:
		parse = func(s string) (float64, bool) {
			v, err := strconv.ParseFloat(s, 64)
			return v, err == nil
		}
	}
	return func(st *lineState) bool {
		s, ok := st.get(n.Name)
		if !ok {
			return false
		}
		v, ok := parse(s)
		if !ok {
			if st.err == "" {
				st.err = errLabelFilt
			}
			return true
		}
		return compare(n.Op, v, n.Value)
	}
}

func compare(op CompareOp, a, b float64) bool {
	switch op {
	case CmpEq:
		return a == b
	case CmpNeq:
		return a != b
	case CmpGt:
		return a > b
	case CmpGte:
		return a >= b
	case CmpLt:
		return a < b
	case CmpLte:
		return a <= b
	}
	return false
}

// sanitizeKey follows Loki: invalid label characters become '_' and a leading digit gets a '_' prefix.
func sanitizeKey(key string, top bool) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	var b strings.Builder
	if top && isDigit(key[0]) {
		b.WriteByte('_')
	}
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func jsonStage(line string, st *lineState) bool {
	data := []byte(line)
	w := &jsonWalker{data: data}
	w.ws()
	if w.i >= len(data) || data[w.i] != '{' || !json.Valid(data) {
		st.err = errJSON
		return true
	}
	w.object("", st)
	return true
}

// jsonWalker walks JSON already checked by json.Valid, so it needs no error handling.
type jsonWalker struct {
	data []byte
	i    int
}

func (w *jsonWalker) ws() {
	for w.i < len(w.data) && (w.data[w.i] == ' ' || w.data[w.i] == '\t' || w.data[w.i] == '\r' || w.data[w.i] == '\n') {
		w.i++
	}
}

// object flattens an object at w.i, joining nested keys with '_' and skipping arrays and nulls as Loki does.
func (w *jsonWalker) object(prefix string, st *lineState) {
	w.i++
	for {
		w.ws()
		if w.data[w.i] == '}' {
			w.i++
			return
		}
		if w.data[w.i] == ',' {
			w.i++
			w.ws()
		}
		key := sanitizeKey(w.str(), prefix == "")
		if prefix != "" && key != "" {
			key = prefix + "_" + key
		}
		w.ws()
		w.i++
		w.ws()
		switch c := w.data[w.i]; {
		case c == '{' && key != "":
			w.object(key, st)
		case c == '{' || c == '[':
			w.skip()
		case c == '"':
			st.setParsed(key, w.str())
		default:
			start := w.i
			w.skip()
			if v := string(w.data[start:w.i]); v != "null" {
				st.setParsed(key, v)
			}
		}
	}
}

func (w *jsonWalker) str() string {
	start := w.i
	w.i++
	for w.data[w.i] != '"' {
		if w.data[w.i] == '\\' {
			w.i++
		}
		w.i++
	}
	w.i++
	var s string
	_ = json.Unmarshal(w.data[start:w.i], &s)
	return s
}

func (w *jsonWalker) skip() {
	depth := 0
	for w.i < len(w.data) {
		switch c := w.data[w.i]; c {
		case '"':
			w.str()
			if depth == 0 {
				return
			}
			continue
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return
			}
			depth--
			if depth == 0 {
				w.i++
				return
			}
		case ',':
			if depth == 0 {
				return
			}
		case ' ', '\t', '\r', '\n':
			if depth == 0 {
				return
			}
		}
		w.i++
	}
}

func compileJSONParams(params []JSONParam) (stageFunc, error) {
	type param struct {
		label string
		path  []pathElem
	}
	ps := make([]param, len(params))
	for i, p := range params {
		path, err := parseJSONPath(p.Path)
		if err != nil {
			return nil, err
		}
		ps[i] = param{label: p.Label, path: path}
	}
	return func(line string, st *lineState) bool {
		if line == "" {
			return true
		}
		if c := line[0]; (c != '{' && c != '[' && c != '"') || !json.Valid([]byte(line)) {
			st.err = errJSON
			return true
		}
		for _, p := range ps {
			st.setParsed(p.label, jsonPathValue([]byte(line), p.path))
		}
		return true
	}, nil
}

func jsonPathValue(data []byte, path []pathElem) string {
	cur := json.RawMessage(data)
	for _, e := range path {
		if e.isIdx {
			var arr []json.RawMessage
			if json.Unmarshal(cur, &arr) != nil || e.index >= len(arr) {
				return ""
			}
			cur = arr[e.index]
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(cur, &obj) != nil {
			return ""
		}
		v, ok := obj[e.key]
		if !ok {
			return ""
		}
		cur = v
	}
	cur = bytes.TrimSpace(cur)
	switch {
	case len(cur) == 0 || string(cur) == "null":
		return ""
	case cur[0] == '{':
		return string(cur)
	case cur[0] == '"':
		cur = cur[1 : len(cur)-1]
	}
	return dropRuneErrors(unescapeJSON(string(cur)))
}

// unescapeJSON decodes JSON backslash escapes anywhere in s, as Loki does for extracted values; invalid escapes yield "".
func unescapeJSON(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return ""
		}
		i++
		switch s[i] {
		case '"', '\\', '/':
			b.WriteByte(s[i])
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, n := decodeUnicodeEscape(s[i-1:])
			if n == 0 {
				return ""
			}
			b.WriteRune(r)
			i += n - 2
		default:
			return ""
		}
	}
	return b.String()
}

// decodeUnicodeEscape decodes a \uXXXX escape, joining surrogate pairs, and returns the bytes consumed.
func decodeUnicodeEscape(s string) (rune, int) {
	hex := func(s string) (rune, bool) {
		if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(s[2:6], 16, 16)
		return rune(v), err == nil
	}
	r, ok := hex(s)
	if !ok {
		return 0, 0
	}
	if utf16.IsSurrogate(r) {
		if r2, ok := hex(s[6:]); ok {
			if d := utf16.DecodeRune(r, r2); d != utf8.RuneError {
				return d, 12
			}
		}
		return utf8.RuneError, 6
	}
	return r, 6
}

func dropRuneErrors(s string) string {
	if !strings.ContainsRune(s, utf8.RuneError) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
}

func logfmtStage(line string, st *lineState) bool {
	decodeLogfmt(line, func(k, v string) {
		v = dropRuneErrors(v)
		if v == "" {
			return
		}
		st.setParsed(sanitizeKey(k, true), v)
	})
	return true
}

// decodeLogfmt follows Loki's non-strict decoder: malformed pairs skip to whitespace, an unterminated quote ends the line.
func decodeLogfmt(s string, emit func(k, v string)) {
	pos := 0
	skip := func() {
		for pos < len(s) && s[pos] > ' ' {
			pos++
		}
	}
	for pos < len(s) {
		for pos < len(s) && s[pos] <= ' ' {
			pos++
		}
		if pos >= len(s) {
			return
		}
		start := pos
		for pos < len(s) && s[pos] > ' ' && s[pos] != '=' && s[pos] != '"' {
			pos++
		}
		key := s[start:pos]
		badKey := strings.ContainsRune(key, utf8.RuneError)
		switch {
		case pos < len(s) && s[pos] == '"':
			skip()
			continue
		case pos >= len(s) || s[pos] <= ' ':
			if !badKey {
				emit(key, "")
			}
			continue
		case key == "" || badKey:
			skip()
			continue
		}
		pos++
		if pos >= len(s) || s[pos] <= ' ' {
			emit(key, "")
			continue
		}
		if s[pos] == '"' {
			end, esc := -1, false
			for j := pos + 1; j < len(s); j++ {
				if s[j] == '\\' {
					esc = true
					j++
					continue
				}
				if s[j] == '"' {
					end = j + 1
					break
				}
			}
			if end < 0 {
				return
			}
			raw := s[pos:end]
			pos = end
			if !esc {
				emit(key, raw[1:len(raw)-1])
				continue
			}
			var v string
			if json.Unmarshal([]byte(raw), &v) == nil {
				emit(key, v)
			}
			continue
		}
		vs := pos
		for pos < len(s) && s[pos] > ' ' && s[pos] != '=' && s[pos] != '"' {
			pos++
		}
		if pos < len(s) && s[pos] > ' ' {
			skip()
			continue
		}
		emit(key, s[vs:pos])
	}
}

// matchPattern follows Loki's pattern matcher: a leading literal anchors the line, a missing literal ends matching and the pending capture takes the rest.
func matchPattern(nodes []patNode, line string, set func(name, value string)) {
	if len(line) == 0 || len(nodes) == 0 {
		return
	}
	in := line
	expr := nodes
	if !expr[0].capture {
		if !strings.HasPrefix(in, expr[0].lit) {
			return
		}
		in = in[len(expr[0].lit):]
		expr = expr[1:]
	}
	for len(expr) > 0 {
		c := expr[0]
		if len(expr) == 1 {
			if c.name != "" {
				set(c.name, in)
			}
			return
		}
		lit := expr[1].lit
		expr = expr[2:]
		i := strings.Index(in, lit)
		if i < 0 {
			if c.name != "" {
				set(c.name, in)
			}
			return
		}
		if c.name != "" {
			set(c.name, in[:i])
		}
		in = in[i+len(lit):]
	}
}
