package logql

import (
	"html"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
)

// LogsQLValueField is the field holding the sample value in translated metric queries.
const LogsQLValueField = "value"

const (
	skipFieldPrefix = "exitmesh.skip."
	// jsonField holds the line without leading whitespace, which LogQL's json parser skips and unpack_json rejects.
	jsonField = "exitmesh.json"
	rowsField = "exitmesh.rows"
)

type vlQuery struct {
	filters []string
	pipes   []string
	parser  string
	present map[string]bool
}

func (q *vlQuery) String() string {
	var b strings.Builder
	b.WriteString(strings.Join(q.filters, " "))
	for _, p := range q.pipes {
		b.WriteString(" | ")
		b.WriteString(p)
	}
	return b.String()
}

func reject(construct, reason string) error {
	return &TranslationError{Construct: construct, Reason: reason}
}

// ToLogsQL translates the subset to LogsQL (metric queries as instant stats queries) or returns a TranslationError.
func ToLogsQL(query string) (string, error) {
	e, err := ParseExpr(query)
	if err != nil {
		return "", err
	}
	var q *vlQuery
	if log, ok := e.(*LogExpr); ok {
		q, err = translateLog(log)
	} else {
		q, err = translateMetric(e)
	}
	if err != nil {
		return "", err
	}
	return q.String(), nil
}

func quoteField(name string) string { return strconv.Quote(name) }

func streamFilter(ms []*labels.Matcher) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = quoteField(m.Name) + m.Type.String() + strconv.Quote(m.Value)
	}
	return "_stream:{" + strings.Join(parts, ",") + "}"
}

func translateLog(log *LogExpr) (*vlQuery, error) {
	q := &vlQuery{present: map[string]bool{}}
	for _, m := range log.Matchers {
		if !m.Matches("") {
			q.present[m.Name] = true
		}
	}
	q.filters = append(q.filters, streamFilter(log.Matchers))
	var pending []string
	add := func(f string) {
		if len(q.pipes) == 0 {
			q.filters = append(q.filters, f)
		} else {
			pending = append(pending, f)
		}
	}
	flush := func() {
		if len(pending) > 0 {
			q.pipes = append(q.pipes, "filter "+strings.Join(pending, " "))
			pending = nil
		}
	}
	parserStage := func(kind string) error {
		if q.parser != "" {
			return reject("a second parser stage", "chained LogQL parsers overwrite earlier extracted labels, which LogsQL unpack and extract pipes do not reproduce")
		}
		flush()
		q.parser = kind
		return nil
	}
	for _, s := range log.Stages {
		switch n := s.(type) {
		case *LineFilter:
			if f, ok := lineFilterLogsQL(n); ok {
				add(f)
			}
		case *JSONStage:
			if len(n.Params) > 0 {
				return nil, reject("json extraction parameters", "LogsQL unpack_json has no JSON path extraction into renamed fields")
			}
			if err := parserStage("json"); err != nil {
				return nil, err
			}
			tmp := quoteField(jsonField)
			q.pipes = append(q.pipes,
				"copy _msg as "+tmp,
				`replace_regexp ("^[ \\t\\r\\n]+", "") at `+tmp,
				"unpack_json from "+tmp+" keep_original_fields",
				"delete "+tmp)
		case *LogfmtStage:
			if err := parserStage("logfmt"); err != nil {
				return nil, err
			}
			q.pipes = append(q.pipes, "unpack_logfmt keep_original_fields")
		case *PatternStage:
			if err := parserStage("pattern"); err != nil {
				return nil, err
			}
			pipes, err := patternPipes(n.Pattern)
			if err != nil {
				return nil, err
			}
			q.pipes = append(q.pipes, pipes...)
		case *RegexpStage:
			if err := parserStage("regexp"); err != nil {
				return nil, err
			}
			_, names, err := compileRegexpStage(n.Pattern)
			if err != nil {
				return nil, err
			}
			for _, name := range names[1:] {
				if strings.HasPrefix(name, "_") {
					return nil, reject("regexp capture "+strconv.Quote(name), "LogsQL reserves field names beginning with '_'")
				}
			}
			q.pipes = append(q.pipes, "extract_regexp "+strconv.Quote("(?-s:"+n.Pattern+")")+" keep_original_fields")
		case *LabelFilterStage:
			f, err := q.labelFilter(n.Filter)
			if err != nil {
				return nil, err
			}
			add(f)
		}
	}
	flush()
	return q, nil
}

// regexLiteral disables dot-matches-newline, which LogsQL regexp filters enable but LogQL line filters do not.
func regexLiteral(re string) string {
	return strconv.Quote("(?-s:" + re + ")")
}

func lineFilterLogsQL(f *LineFilter) (string, bool) {
	switch f.Op {
	case LineContains:
		if f.Match == "" {
			return "", false
		}
		return "*" + strconv.Quote(f.Match) + "*", true
	case LineNotContains:
		if f.Match == "" {
			return "!~\".*\"", true
		}
		return "!*" + strconv.Quote(f.Match) + "*", true
	case LineMatchRegexp:
		return "~" + regexLiteral(f.Match), true
	}
	return "!~" + regexLiteral(f.Match), true
}

func (q *vlQuery) checkName(name string) error {
	switch {
	case name == errorLabel:
		return reject("label filter on __error__", "LogsQL records no parser errors, so __error__ has no field to filter")
	case name == LogsQLValueField:
		return reject("label "+strconv.Quote(name), "the name is reserved for the translated sample value")
	case strings.HasPrefix(name, "_"):
		return reject("label "+strconv.Quote(name), "LogsQL reserves field names beginning with '_'")
	case (q.parser == "json" || q.parser == "logfmt") && strings.Contains(name, "_") && !q.present[name]:
		return reject("extracted label "+strconv.Quote(name), "LogQL "+q.parser+" sanitizes keys (invalid characters and nested JSON keys become '_'), so the label may come from several LogsQL fields")
	}
	return nil
}

func (q *vlQuery) labelFilter(f LabelFilter) (string, error) {
	switch n := f.(type) {
	case *LabelFilterBinary:
		l, err := q.labelFilter(n.Left)
		if err != nil {
			return "", err
		}
		r, err := q.labelFilter(n.Right)
		if err != nil {
			return "", err
		}
		if _, ok := n.Left.(*LabelFilterBinary); ok {
			l = "(" + l + ")"
		}
		if _, ok := n.Right.(*LabelFilterBinary); ok {
			r = "(" + r + ")"
		}
		if n.Or {
			return l + " or " + r, nil
		}
		return l + " " + r, nil
	case *LabelFilterString:
		m := n.Matcher
		if err := q.checkName(m.Name); err != nil {
			return "", err
		}
		field := quoteField(m.Name)
		switch m.Type {
		case labels.MatchEqual:
			return field + ":=" + strconv.Quote(m.Value), nil
		case labels.MatchNotEqual:
			return "!" + field + ":=" + strconv.Quote(m.Value), nil
		case labels.MatchRegexp:
			return field + ":~" + strconv.Quote("^(?s:"+m.Value+")$"), nil
		}
		return "!" + field + ":~" + strconv.Quote("^(?s:"+m.Value+")$"), nil
	case *LabelFilterNumeric:
		if n.Name == errorLabel {
			return "", q.checkName(n.Name)
		}
		return "", reject(string(n.Kind)+" label filter "+strconv.Quote(n.String()),
			"LogQL keeps lines whose value does not parse and marks them with __error__, while LogsQL range filters drop them and also parse timestamps, IPv4 addresses and other units")
	}
	return "", reject("label filter", "unknown label filter")
}

func patternPipes(pattern string) ([]string, error) {
	nodes, err := parsePattern(pattern)
	if err != nil {
		return nil, err
	}
	l0 := ""
	rest := nodes
	if !nodes[0].capture {
		l0, rest = nodes[0].lit, nodes[1:]
	}
	var temps []string
	names := make([]string, len(rest))
	for i, n := range rest {
		if !n.capture {
			continue
		}
		if n.name == "" {
			names[i] = skipFieldPrefix + strconv.Itoa(len(temps))
			temps = append(temps, names[i])
			continue
		}
		if strings.HasPrefix(n.name, "_") {
			return nil, reject("pattern capture "+strconv.Quote(n.name), "LogsQL reserves field names beginning with '_'")
		}
		names[i] = n.name
	}
	render := func(upto int) string {
		var b strings.Builder
		b.WriteString(html.EscapeString(l0))
		for i, n := range rest[:upto] {
			if n.capture {
				b.WriteString("<plain:" + names[i] + ">")
			} else {
				b.WriteString(html.EscapeString(n.lit))
			}
		}
		return strconv.Quote(b.String())
	}
	guard := ""
	if l0 != "" {
		guard = "if (_msg:=" + strconv.Quote(l0) + "*) "
	}
	pipes := []string{"extract " + guard + render(len(rest)) + " keep_original_fields"}
	chain := "^" + regexp.QuoteMeta(l0)
	for i, n := range rest {
		if !n.capture {
			chain += "(?s:.*)" + regexp.QuoteMeta(n.lit)
			continue
		}
		if n.name == "" || i+1 >= len(rest) {
			continue
		}
		cond := "!_msg:~" + strconv.Quote(chain+"(?s:.*)"+regexp.QuoteMeta(rest[i+1].lit))
		if chain != "^" {
			cond = "_msg:~" + strconv.Quote(chain) + " " + cond
		}
		pipes = append(pipes, "extract if ("+cond+") "+render(i+1)+" keep_original_fields")
	}
	if len(temps) > 0 {
		q := make([]string, len(temps))
		for i, t := range temps {
			q[i] = quoteField(t)
		}
		pipes = append(pipes, "delete "+strings.Join(q, ", "))
	}
	return pipes, nil
}

func statsBy(by []string) string {
	if len(by) == 0 {
		return "stats"
	}
	q := make([]string, len(by))
	for i, l := range by {
		q[i] = quoteField(l)
	}
	return "stats by (" + strings.Join(q, ", ") + ")"
}

// statsPipes emits a stats pipe; a global one drops the zero row LogsQL returns for no input, since LogQL returns no sample.
func statsPipes(by []string, fn string) []string {
	if len(by) > 0 {
		return []string{statsBy(by) + " " + fn + " as " + LogsQLValueField}
	}
	rows := quoteField(rowsField)
	return []string{
		"stats count() as " + rows + ", " + fn + " as " + LogsQLValueField,
		"filter " + rows + ":>0",
		"delete " + rows,
	}
}

func rangeStatsFunc(op RangeOp) string {
	if op == RangeBytes {
		return "sum_len(_msg)"
	}
	return "count()"
}

func ratePipe(ra *RangeAggregation) []string {
	if ra.Op != RangeRate {
		return nil
	}
	return []string{"math (" + LogsQLValueField + " / " + strconv.FormatFloat(ra.Range.Seconds(), 'f', -1, 64) + ") as " + LogsQLValueField}
}

func translateRangeBase(ra *RangeAggregation) (*vlQuery, error) {
	q, err := translateLog(ra.Log)
	if err != nil {
		return nil, err
	}
	window := "_time:(now-" + formatDuration(ra.Range) + ",now]"
	q.filters = append([]string{window}, q.filters...)
	return q, nil
}

func outerStatsFunc(op AggOp) string {
	if op == AggCount {
		return "count()"
	}
	return string(op) + "(" + LogsQLValueField + ")"
}

func translateMetric(e Expr) (*vlQuery, error) {
	switch n := e.(type) {
	case *RangeAggregation:
		q, err := translateRangeBase(n)
		if err != nil {
			return nil, err
		}
		if q.parser != "" {
			return nil, reject(string(n.Op)+" with a parser and no enclosing sum by", "LogQL series include every extracted label, which a LogsQL stats pipe cannot group by")
		}
		q.pipes = append(q.pipes, "stats by (_stream) "+rangeStatsFunc(n.Op)+" as "+LogsQLValueField)
		q.pipes = append(q.pipes, ratePipe(n)...)
		return q, nil
	case *VectorAggregation:
		if n.Op == AggTopK {
			return nil, reject("topk", "LogsQL has no per-group top-k over series with LogQL tie semantics")
		}
		if n.Grouping != nil && n.Grouping.Without {
			return nil, reject("without grouping", "LogsQL stats group by listed fields only, not by all fields except a list")
		}
		var by []string
		if n.Grouping != nil {
			by = n.Grouping.Labels
		}
		if ra, ok := n.Expr.(*RangeAggregation); ok {
			q, err := translateRangeBase(ra)
			if err != nil {
				return nil, err
			}
			for _, l := range by {
				if err := q.checkName(l); err != nil {
					return nil, err
				}
			}
			if n.Op == AggSum {
				q.pipes = append(q.pipes, statsPipes(by, rangeStatsFunc(ra.Op))...)
				q.pipes = append(q.pipes, ratePipe(ra)...)
				return q, nil
			}
			if q.parser != "" {
				return nil, reject(string(n.Op)+" over a range aggregation with a parser", "LogQL series identity includes every extracted label, which a LogsQL stats pipe cannot group by")
			}
			inner := append([]string{"_stream"}, by...)
			for i := 1; i < len(inner); i++ {
				inner[i] = quoteField(inner[i])
			}
			q.pipes = append(q.pipes, "stats by ("+strings.Join(inner, ", ")+") "+rangeStatsFunc(ra.Op)+" as "+LogsQLValueField)
			q.pipes = append(q.pipes, ratePipe(ra)...)
			q.pipes = append(q.pipes, statsPipes(by, outerStatsFunc(n.Op))...)
			return q, nil
		}
		q, err := translateMetric(n.Expr)
		if err != nil {
			return nil, err
		}
		for _, l := range by {
			if err := q.checkName(l); err != nil {
				return nil, err
			}
		}
		q.pipes = append(q.pipes, statsPipes(by, outerStatsFunc(n.Op))...)
		return q, nil
	case *BinaryExpr:
		return translateBinary(n)
	}
	return nil, reject("expression", "not a metric expression")
}

func foldScalar(e Expr) float64 {
	v, _ := (&evaluator{}).eval(e)
	return float64(v.(scalar))
}

var flipCmp = map[BinaryOp]BinaryOp{OpGt: OpLt, OpGte: OpLte, OpLt: OpGt, OpLte: OpGte, OpEq: OpEq, OpNeq: OpNeq}

func translateBinary(n *BinaryExpr) (*vlQuery, error) {
	vec, sc, swap := n.LHS, n.RHS, false
	if isScalar(n.LHS) {
		vec, sc, swap = n.RHS, n.LHS, true
	}
	s := foldScalar(sc)
	num := strconv.FormatFloat(s, 'f', -1, 64)
	if n.Op.isComparison() {
		if n.ReturnBool {
			return nil, reject("bool modifier", "LogsQL filters rows and has no boolean comparison result")
		}
	} else {
		switch {
		case n.Op == OpMod || n.Op == OpPow:
			return nil, reject("operator "+strconv.Quote(string(n.Op)), "no verified LogsQL math equivalent")
		case n.Op == OpDiv && swap:
			return nil, reject("division by a sample value", "LogQL division by zero yields infinities, which LogsQL math does not reproduce")
		case n.Op == OpDiv && s == 0:
			return nil, reject("division by zero", "LogQL yields infinities, which LogsQL math does not reproduce")
		}
	}
	q, err := translateMetric(vec)
	if err != nil {
		return nil, err
	}
	v := LogsQLValueField
	if !n.Op.isComparison() {
		expr := v + " " + string(n.Op) + " " + num
		if swap {
			expr = num + " " + string(n.Op) + " " + v
		}
		q.pipes = append(q.pipes, "math ("+expr+") as "+v)
		return q, nil
	}
	op := n.Op
	if swap {
		op = flipCmp[op]
	}
	var f string
	switch op {
	case OpEq:
		f = v + ":>=" + num + " " + v + ":<=" + num
	case OpNeq:
		f = "!(" + v + ":>=" + num + " " + v + ":<=" + num + ")"
	default:
		f = v + ":" + string(op) + num
	}
	q.pipes = append(q.pipes, "filter "+f)
	return q, nil
}
