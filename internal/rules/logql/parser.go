package logql

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
)

var unsupportedRangeFuncs = map[string]bool{
	"sum_over_time": true, "avg_over_time": true, "max_over_time": true, "min_over_time": true,
	"first_over_time": true, "last_over_time": true, "stdvar_over_time": true, "stddev_over_time": true,
	"quantile_over_time": true, "absent_over_time": true, "bytes_rate": true, "rate_counter": true,
}

var unsupportedAggs = map[string]bool{
	"bottomk": true, "stddev": true, "stdvar": true, "sort": true, "sort_desc": true,
	"approx_topk": true, "group": true, "quantile": true, "count_values": true,
}

var unsupportedStages = map[string]bool{
	"line_format": true, "label_format": true, "unwrap": true, "drop": true, "keep": true,
	"decolorize": true, "unpack": true, "distinct": true,
}

type parser struct {
	toks []token
	i    int
}

// ParseExpr parses a LogQL query in the supported subset.
func ParseExpr(s string) (Expr, error) {
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	e, err := p.parseExpr(0)
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, p.unexpected(t)
	}
	if isScalar(e) {
		return nil, &ParseError{Pos: 0, Msg: "a query must select log streams; scalar-only expressions are not queries"}
	}
	return e, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) peekAt(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) errf(pos int, format string, args ...any) error {
	return &ParseError{Pos: pos, Msg: fmt.Sprintf(format, args...)}
}

func (p *parser) unexpected(t token) error {
	return p.errf(t.pos, "unexpected %s", t.describe())
}

func (p *parser) unsupported(pos int, construct string) error {
	return &UnsupportedError{Pos: pos, Construct: construct}
}

func (p *parser) expect(k tokKind, context string) (token, error) {
	t := p.next()
	if t.kind != k {
		return t, p.errf(t.pos, "expected %s %s, found %s", tokNames[k], context, t.describe())
	}
	return t, nil
}

func (p *parser) isIdent(text string) bool {
	t := p.peek()
	return t.kind == tIdent && t.text == text
}

func binaryOpOf(t token) (BinaryOp, bool) {
	switch t.kind {
	case tAdd:
		return OpAdd, true
	case tSub:
		return OpSub, true
	case tMul:
		return OpMul, true
	case tDiv:
		return OpDiv, true
	case tMod:
		return OpMod, true
	case tPow:
		return OpPow, true
	case tEqEq:
		return OpEq, true
	case tNeq:
		return OpNeq, true
	case tGt:
		return OpGt, true
	case tGte:
		return OpGte, true
	case tLt:
		return OpLt, true
	case tLte:
		return OpLte, true
	}
	return "", false
}

func isScalar(e Expr) bool {
	switch n := e.(type) {
	case *NumberLiteral:
		return true
	case *BinaryExpr:
		return isScalar(n.LHS) && isScalar(n.RHS)
	}
	return false
}

func isVector(e Expr) bool {
	switch n := e.(type) {
	case *RangeAggregation, *VectorAggregation:
		return true
	case *BinaryExpr:
		return isVector(n.LHS) || isVector(n.RHS)
	}
	return false
}

func (p *parser) parseExpr(minPrec int) (Expr, error) {
	lhs, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind == tIdent {
			switch t.text {
			case "and", "or", "unless":
				return nil, p.unsupported(t.pos, "set operator "+strconv.Quote(t.text))
			}
		}
		op, ok := binaryOpOf(t)
		if !ok || op.precedence() < minPrec {
			return lhs, nil
		}
		p.next()
		returnBool := false
		if p.isIdent("bool") {
			if !op.isComparison() {
				return nil, p.errf(p.peek().pos, "bool modifier is only allowed on comparison operators")
			}
			p.next()
			returnBool = true
		}
		if n := p.peek(); n.kind == tIdent {
			switch n.text {
			case "on", "ignoring":
				return nil, p.unsupported(n.pos, "vector matching "+strconv.Quote(n.text))
			case "group_left", "group_right":
				return nil, p.unsupported(n.pos, "vector matching "+strconv.Quote(n.text))
			}
		}
		next := op.precedence() + 1
		if op == OpPow {
			next = op.precedence()
		}
		rhs, err := p.parseExpr(next)
		if err != nil {
			return nil, err
		}
		if _, ok := lhs.(*LogExpr); ok {
			return nil, p.errf(t.pos, "a log query cannot be an operand of %q; wrap it in a range aggregation", op)
		}
		if _, ok := rhs.(*LogExpr); ok {
			return nil, p.errf(t.pos, "a log query cannot be an operand of %q; wrap it in a range aggregation", op)
		}
		if isVector(lhs) && isVector(rhs) {
			return nil, p.unsupported(t.pos, "binary operation "+strconv.Quote(string(op))+" between two vectors")
		}
		if op.isComparison() && !returnBool && isScalar(lhs) && isScalar(rhs) {
			return nil, p.errf(t.pos, "comparisons between scalars must use the bool modifier")
		}
		lhs = &BinaryExpr{Op: op, ReturnBool: returnBool, LHS: lhs, RHS: rhs}
	}
}

func (p *parser) parseUnary() (Expr, error) {
	t := p.peek()
	if t.kind == tAdd || t.kind == tSub {
		n := p.peekAt(1)
		if n.kind != tNumber {
			return nil, p.unsupported(t.pos, "unary "+strconv.Quote(t.text)+" on a non-literal expression")
		}
		p.next()
		p.next()
		v, err := parseNumberLiteral(n)
		if err != nil {
			return nil, err
		}
		if t.kind == tSub {
			v = -v
		}
		return &NumberLiteral{Value: v}, nil
	}
	return p.parsePrimary()
}

func parseNumberLiteral(t token) (float64, error) {
	v, err := strconv.ParseFloat(t.text, 64)
	if err != nil || math.IsInf(v, 0) || math.IsNaN(v) || strings.ContainsAny(t.text, "_xXpP") {
		return 0, &ParseError{Pos: t.pos, Msg: "invalid number " + strconv.Quote(t.text)}
	}
	return v, nil
}

func (p *parser) parsePrimary() (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tNumber:
		p.next()
		v, err := parseNumberLiteral(t)
		if err != nil {
			return nil, err
		}
		return &NumberLiteral{Value: v}, nil
	case tLParen:
		p.next()
		e, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen, "to close '('"); err != nil {
			return nil, err
		}
		return e, nil
	case tLBrace:
		return p.parseLogExpr()
	case tIdent:
		name := t.text
		switch {
		case name == string(RangeCount) || name == string(RangeRate) || name == string(RangeBytes):
			return p.parseRangeAgg()
		case unsupportedRangeFuncs[name]:
			return nil, p.unsupported(t.pos, "range aggregation "+strconv.Quote(name))
		case name == string(AggSum) || name == string(AggCount) || name == string(AggMin) ||
			name == string(AggMax) || name == string(AggAvg) || name == string(AggTopK):
			return p.parseVectorAgg()
		case unsupportedAggs[name]:
			return nil, p.unsupported(t.pos, "vector aggregation "+strconv.Quote(name))
		case p.peekAt(1).kind == tLParen:
			return nil, p.unsupported(t.pos, "function "+strconv.Quote(name))
		}
	}
	return nil, p.unexpected(t)
}

func (p *parser) parseRangeAgg() (Expr, error) {
	name := p.next()
	if _, err := p.expect(tLParen, "after "+name.text); err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind == tNumber {
		return nil, p.errf(t.pos, "%s does not take a parameter", name.text)
	}
	log, rng, err := p.parseLogRange()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind == tIdent && t.text == "offset" {
		return nil, p.unsupported(t.pos, "offset modifier")
	}
	if _, err := p.expect(tRParen, "to close "+name.text); err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind == tIdent && (t.text == "by" || t.text == "without") {
		return nil, p.unsupported(t.pos, "grouping on range aggregation "+strconv.Quote(name.text))
	}
	return &RangeAggregation{Op: RangeOp(name.text), Log: log, Range: rng}, nil
}

func (p *parser) parseLogRange() (*LogExpr, time.Duration, error) {
	if p.peek().kind == tLParen {
		p.next()
		log, err := p.parseLogExpr()
		if err != nil {
			return nil, 0, err
		}
		if _, err := p.expect(tRParen, "to close '('"); err != nil {
			return nil, 0, err
		}
		rng, err := p.parseRange()
		return log, rng, err
	}
	if t := p.peek(); t.kind != tLBrace {
		return nil, 0, p.errf(t.pos, "expected a log stream selector, found %s", t.describe())
	}
	log, err := p.parseSelector()
	if err != nil {
		return nil, 0, err
	}
	if p.peek().kind == tLBrack {
		rng, err := p.parseRange()
		if err != nil {
			return nil, 0, err
		}
		if err := p.parsePipeline(log); err != nil {
			return nil, 0, err
		}
		return log, rng, nil
	}
	if err := p.parsePipeline(log); err != nil {
		return nil, 0, err
	}
	rng, err := p.parseRange()
	return log, rng, err
}

func (p *parser) parseRange() (time.Duration, error) {
	if _, err := p.expect(tLBrack, "for the range of a log range aggregation"); err != nil {
		return 0, err
	}
	t := p.next()
	if t.kind != tNumber {
		return 0, p.errf(t.pos, "expected a range duration, found %s", t.describe())
	}
	d, ok := parseDurationLiteral(t.text)
	if !ok || d <= 0 {
		return 0, p.errf(t.pos, "invalid range duration %q", t.text)
	}
	if n := p.peek(); n.kind == tColon {
		return 0, p.unsupported(n.pos, "subquery")
	}
	if _, err := p.expect(tRBrack, "to close the range"); err != nil {
		return 0, err
	}
	return d, nil
}

func parseDurationLiteral(s string) (time.Duration, bool) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, true
	}
	if d, err := model.ParseDuration(s); err == nil {
		return time.Duration(d), true
	}
	return 0, false
}

func (p *parser) parseVectorAgg() (Expr, error) {
	name := p.next()
	agg := &VectorAggregation{Op: AggOp(name.text)}
	if p.isIdent("by") || p.isIdent("without") {
		g, err := p.parseGrouping()
		if err != nil {
			return nil, err
		}
		agg.Grouping = g
	}
	if _, err := p.expect(tLParen, "after "+name.text); err != nil {
		return nil, err
	}
	if agg.Op == AggTopK {
		t := p.next()
		if t.kind != tNumber {
			return nil, p.errf(t.pos, "topk requires an integer parameter, found %s", t.describe())
		}
		k, err := strconv.Atoi(t.text)
		if err != nil || k < 1 {
			return nil, p.errf(t.pos, "topk parameter must be a positive integer, found %q", t.text)
		}
		agg.Param = k
		if _, err := p.expect(tComma, "after the topk parameter"); err != nil {
			return nil, err
		}
	} else if t := p.peek(); t.kind == tNumber && p.peekAt(1).kind == tComma {
		return nil, p.errf(t.pos, "%s does not take a parameter", name.text)
	}
	start := p.peek()
	inner, err := p.parseExpr(0)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tRParen, "to close "+name.text); err != nil {
		return nil, err
	}
	if p.isIdent("by") || p.isIdent("without") {
		if agg.Grouping != nil {
			return nil, p.errf(p.peek().pos, "duplicate grouping clause on %s", name.text)
		}
		g, err := p.parseGrouping()
		if err != nil {
			return nil, err
		}
		agg.Grouping = g
	}
	if _, ok := inner.(*LogExpr); ok {
		return nil, p.errf(start.pos, "%s requires a metric expression; wrap the log query in a range aggregation", name.text)
	}
	if !isVector(inner) {
		return nil, p.errf(start.pos, "%s requires a vector expression, found a scalar", name.text)
	}
	agg.Expr = inner
	return agg, nil
}

func (p *parser) parseGrouping() (*Grouping, error) {
	kw := p.next()
	g := &Grouping{Without: kw.text == "without"}
	if _, err := p.expect(tLParen, "after "+kw.text); err != nil {
		return nil, err
	}
	for p.peek().kind != tRParen {
		t := p.next()
		if t.kind != tIdent {
			return nil, p.errf(t.pos, "expected a label name in %s clause, found %s", kw.text, t.describe())
		}
		g.Labels = append(g.Labels, t.text)
		if p.peek().kind == tComma {
			p.next()
			continue
		}
		if p.peek().kind != tRParen {
			return nil, p.unexpected(p.peek())
		}
	}
	p.next()
	return g, nil
}

func (p *parser) parseLogExpr() (*LogExpr, error) {
	log, err := p.parseSelector()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind == tLBrack {
		return nil, p.errf(t.pos, "a range is only allowed inside a range aggregation such as count_over_time")
	}
	if err := p.parsePipeline(log); err != nil {
		return nil, err
	}
	return log, nil
}

func (p *parser) parseSelector() (*LogExpr, error) {
	open, err := p.expect(tLBrace, "to start a stream selector")
	if err != nil {
		return nil, err
	}
	log := &LogExpr{}
	for p.peek().kind != tRBrace {
		m, err := p.parseMatcher("stream selector")
		if err != nil {
			return nil, err
		}
		log.Matchers = append(log.Matchers, m)
		if p.peek().kind == tComma {
			p.next()
			continue
		}
		if p.peek().kind != tRBrace {
			return nil, p.unexpected(p.peek())
		}
	}
	p.next()
	if err := validateSelector(log.Matchers); err != nil {
		return nil, p.errf(open.pos, "%s", err.Error())
	}
	return log, nil
}

func validateSelector(ms []*labels.Matcher) error {
	for _, m := range ms {
		if (m.Type == labels.MatchEqual || m.Type == labels.MatchRegexp) && !m.Matches("") {
			return nil
		}
	}
	return fmt.Errorf("a stream selector requires at least one = or =~ matcher that does not match the empty string")
}

func matchTypeOf(k tokKind) (labels.MatchType, bool) {
	switch k {
	case tEq:
		return labels.MatchEqual, true
	case tNeq:
		return labels.MatchNotEqual, true
	case tRe:
		return labels.MatchRegexp, true
	case tNre:
		return labels.MatchNotRegexp, true
	}
	return 0, false
}

func (p *parser) parseMatcher(context string) (*labels.Matcher, error) {
	name := p.next()
	if name.kind != tIdent {
		return nil, p.errf(name.pos, "expected a label name in %s, found %s", context, name.describe())
	}
	opTok := p.next()
	mt, ok := matchTypeOf(opTok.kind)
	if !ok {
		return nil, p.errf(opTok.pos, "expected =, !=, =~ or !~ after label %q, found %s", name.text, opTok.describe())
	}
	val := p.next()
	if val.kind != tString {
		return nil, p.errf(val.pos, "expected a string value for label %q, found %s", name.text, val.describe())
	}
	m, err := labels.NewMatcher(mt, name.text, val.val)
	if err != nil {
		return nil, p.errf(val.pos, "invalid regular expression for label %q: %v", name.text, err)
	}
	return m, nil
}

func (p *parser) parsePipeline(log *LogExpr) error {
	for {
		t := p.peek()
		switch t.kind {
		case tPipeEq, tPipeRe, tNeq, tNre:
			n := p.peekAt(1)
			if n.kind == tIdent && n.text == "ip" {
				return p.unsupported(n.pos, "ip line filter")
			}
			if n.kind != tString {
				if t.kind == tNeq || t.kind == tNre {
					return nil
				}
				return p.errf(n.pos, "expected a string after %s, found %s", tokNames[t.kind], n.describe())
			}
			p.next()
			p.next()
			f := &LineFilter{Op: LineFilterOp(t.text), Match: n.val}
			if f.Op == LineMatchRegexp || f.Op == LineNotRegexp {
				if _, err := regexp.Compile(n.val); err != nil {
					return p.errf(n.pos, "invalid line filter regular expression: %v", err)
				}
			}
			if o := p.peek(); o.kind == tIdent && o.text == "or" && p.peekAt(1).kind == tString {
				return p.unsupported(o.pos, "line filter or-chain")
			}
			log.Stages = append(log.Stages, f)
		case tPipeGt, tNotGt:
			return p.unsupported(t.pos, "pattern line filter "+strconv.Quote(t.text))
		case tPipe:
			p.next()
			s, err := p.parseStage()
			if err != nil {
				return err
			}
			log.Stages = append(log.Stages, s)
		default:
			return nil
		}
	}
}

func (p *parser) parseStage() (Stage, error) {
	t := p.peek()
	if t.kind == tLParen {
		f, err := p.parseLabelOr()
		if err != nil {
			return nil, err
		}
		return &LabelFilterStage{Filter: f}, nil
	}
	if t.kind != tIdent {
		return nil, p.errf(t.pos, "expected a pipeline stage after '|', found %s", t.describe())
	}
	switch {
	case t.text == "json":
		p.next()
		return p.parseJSONStage()
	case t.text == "logfmt":
		p.next()
		if n := p.peek(); n.kind == tSub {
			return nil, p.unsupported(n.pos, "logfmt flags")
		}
		if n := p.peek(); n.kind == tIdent {
			return nil, p.unsupported(n.pos, "logfmt extraction parameters")
		}
		return &LogfmtStage{}, nil
	case t.text == "pattern":
		p.next()
		s, err := p.expect(tString, "after pattern")
		if err != nil {
			return nil, err
		}
		if _, err := parsePattern(s.val); err != nil {
			return nil, p.errf(s.pos, "invalid pattern: %v", err)
		}
		return &PatternStage{Pattern: s.val}, nil
	case t.text == "regexp":
		p.next()
		s, err := p.expect(tString, "after regexp")
		if err != nil {
			return nil, err
		}
		if _, _, err := compileRegexpStage(s.val); err != nil {
			return nil, p.errf(s.pos, "invalid regexp parser: %v", err)
		}
		return &RegexpStage{Pattern: s.val}, nil
	case unsupportedStages[t.text]:
		return nil, p.unsupported(t.pos, "pipeline stage "+strconv.Quote(t.text))
	}
	f, err := p.parseLabelOr()
	if err != nil {
		return nil, err
	}
	return &LabelFilterStage{Filter: f}, nil
}

func (p *parser) parseJSONStage() (Stage, error) {
	s := &JSONStage{}
	for p.peek().kind == tIdent {
		name := p.next()
		path := name.text
		if p.peek().kind == tEq {
			p.next()
			v, err := p.expect(tString, "for the json extraction path")
			if err != nil {
				return nil, err
			}
			if _, err := parseJSONPath(v.val); err != nil {
				return nil, p.errf(v.pos, "invalid json path %q: %v", v.val, err)
			}
			path = v.val
		}
		s.Params = append(s.Params, JSONParam{Label: name.text, Path: path})
		if p.peek().kind != tComma {
			break
		}
		p.next()
		if p.peek().kind != tIdent {
			return nil, p.errf(p.peek().pos, "expected a json extraction parameter after ','")
		}
	}
	return s, nil
}

func (p *parser) parseLabelOr() (LabelFilter, error) {
	l, err := p.parseLabelAnd()
	if err != nil {
		return nil, err
	}
	for p.isIdent("or") {
		p.next()
		r, err := p.parseLabelAnd()
		if err != nil {
			return nil, err
		}
		l = &LabelFilterBinary{Or: true, Left: l, Right: r}
	}
	return l, nil
}

func (p *parser) parseLabelAnd() (LabelFilter, error) {
	l, err := p.parseLabelPrimary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		switch {
		case t.kind == tIdent && t.text == "and", t.kind == tComma:
			p.next()
		case t.kind == tLParen:
		case t.kind == tIdent && t.text != "or" && t.text != "unless" && t.text != "offset":
		default:
			return l, nil
		}
		r, err := p.parseLabelPrimary()
		if err != nil {
			return nil, err
		}
		l = &LabelFilterBinary{Left: l, Right: r}
	}
}

func (p *parser) parseLabelPrimary() (LabelFilter, error) {
	if p.peek().kind == tLParen {
		p.next()
		f, err := p.parseLabelOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen, "to close the label filter group"); err != nil {
			return nil, err
		}
		return f, nil
	}
	name := p.next()
	if name.kind != tIdent {
		return nil, p.errf(name.pos, "expected a label filter, found %s", name.describe())
	}
	opTok := p.peek()
	val := p.peekAt(1)
	if val.kind == tIdent && val.text == "ip" {
		return nil, p.unsupported(val.pos, "ip label filter")
	}
	if val.kind == tString {
		mt, ok := matchTypeOf(opTok.kind)
		if !ok {
			return nil, p.errf(opTok.pos, "operator %s cannot compare label %q with a string", opTok.describe(), name.text)
		}
		p.next()
		p.next()
		m, err := labels.NewMatcher(mt, name.text, val.val)
		if err != nil {
			return nil, p.errf(val.pos, "invalid regular expression for label %q: %v", name.text, err)
		}
		return &LabelFilterString{Matcher: m}, nil
	}
	var op CompareOp
	switch opTok.kind {
	case tEq, tEqEq:
		op = CmpEq
	case tNeq:
		op = CmpNeq
	case tGt:
		op = CmpGt
	case tGte:
		op = CmpGte
	case tLt:
		op = CmpLt
	case tLte:
		op = CmpLte
	default:
		return nil, p.errf(opTok.pos, "expected a label filter operator after %q, found %s", name.text, opTok.describe())
	}
	p.next()
	neg := false
	if t := p.peek(); t.kind == tSub || t.kind == tAdd {
		neg = t.kind == tSub
		p.next()
	}
	num := p.next()
	if num.kind != tNumber {
		return nil, p.errf(num.pos, "expected a string, number, duration or byte size for label %q, found %s", name.text, num.describe())
	}
	kind, v, err := classifyNumeric(num)
	if err != nil {
		return nil, err
	}
	if neg {
		if kind == NumericBytes {
			return nil, p.errf(num.pos, "byte sizes cannot be negative")
		}
		v = -v
	}
	return &LabelFilterNumeric{Name: name.text, Op: op, Kind: kind, Value: v}, nil
}

func classifyNumeric(t token) (NumericKind, float64, error) {
	if v, err := parseNumberLiteral(t); err == nil {
		return NumericNumber, v, nil
	}
	if d, ok := parseDurationLiteral(t.text); ok {
		return NumericDuration, float64(d), nil
	}
	if b, err := parseBytes(t.text); err == nil {
		return NumericBytes, float64(b), nil
	}
	return "", 0, &ParseError{Pos: t.pos, Msg: "invalid number, duration or byte size " + strconv.Quote(t.text)}
}

var bytesUnits = map[string]uint64{
	"b": 1, "": 1,
	"kib": 1 << 10, "kb": 1e3, "ki": 1 << 10, "k": 1e3,
	"mib": 1 << 20, "mb": 1e6, "mi": 1 << 20, "m": 1e6,
	"gib": 1 << 30, "gb": 1e9, "gi": 1 << 30, "g": 1e9,
	"tib": 1 << 40, "tb": 1e12, "ti": 1 << 40, "t": 1e12,
	"pib": 1 << 50, "pb": 1e15, "pi": 1 << 50, "p": 1e15,
	"eib": 1 << 60, "eb": 1e18, "ei": 1 << 60, "e": 1e18,
}

// parseBytes follows go-humanize ParseBytes, which Loki uses for byte-size label filters.
func parseBytes(s string) (uint64, error) {
	n := 0
	comma := false
	for n < len(s) && (isDigit(s[n]) || s[n] == '.' || s[n] == ',') {
		if s[n] == ',' {
			comma = true
		}
		n++
	}
	num := s[:n]
	if comma {
		num = strings.ReplaceAll(num, ",", "")
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, err
	}
	m, ok := bytesUnits[strings.ToLower(strings.TrimSpace(s[n:]))]
	if !ok {
		return 0, fmt.Errorf("unknown byte size unit in %q", s)
	}
	f *= float64(m)
	if f >= math.MaxUint64 {
		return 0, fmt.Errorf("byte size %q too large", s)
	}
	return uint64(f), nil
}

type pathElem struct {
	key   string
	index int
	isIdx bool
}

func parseJSONPath(s string) ([]pathElem, error) {
	var out []pathElem
	i := 0
	for i < len(s) {
		switch {
		case s[i] == '[':
			end := strings.IndexByte(s[i:], ']')
			if i+1 < len(s) && s[i+1] == '"' {
				q, ok := scanQuoted(s, i+1)
				if !ok || q >= len(s) || s[q] != ']' {
					return nil, fmt.Errorf("unterminated quoted key")
				}
				k, err := strconv.Unquote(s[i+1 : q])
				if err != nil {
					return nil, fmt.Errorf("invalid quoted key")
				}
				out = append(out, pathElem{key: k})
				i = q + 1
				continue
			}
			if end < 0 {
				return nil, fmt.Errorf("missing ']'")
			}
			idx, err := strconv.Atoi(s[i+1 : i+end])
			if err != nil || idx < 0 {
				return nil, fmt.Errorf("invalid array index %q", s[i+1:i+end])
			}
			out = append(out, pathElem{index: idx, isIdx: true})
			i += end + 1
		case s[i] == '.' && len(out) > 0:
			i++
			fallthrough
		default:
			j := i
			for j < len(s) && (isIdentChar(s[j]) || s[j] == '-') {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("expected a field name at offset %d", i)
			}
			out = append(out, pathElem{key: s[i:j]})
			i = j
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty path")
	}
	return out, nil
}

type patNode struct {
	lit     string
	capture bool
	name    string
}

// parsePattern follows Loki's pattern syntax: <name> captures, <_> skips, anything else is literal.
func parsePattern(s string) ([]patNode, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("pattern is not valid UTF-8")
	}
	var nodes []patNode
	var lit strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '<' {
			j := i + 1
			for j < len(s) && isIdentChar(s[j]) {
				j++
			}
			if j < len(s) && s[j] == '>' && j > i+1 && isIdentStart(s[i+1]) {
				if lit.Len() > 0 {
					nodes = append(nodes, patNode{lit: lit.String()})
					lit.Reset()
				}
				name := s[i+1 : j]
				if name == "_" {
					name = ""
				}
				nodes = append(nodes, patNode{capture: true, name: name})
				i = j + 1
				continue
			}
		}
		lit.WriteByte(s[i])
		i++
	}
	if lit.Len() > 0 {
		nodes = append(nodes, patNode{lit: lit.String()})
	}
	named := map[string]bool{}
	for i, n := range nodes {
		if !n.capture {
			continue
		}
		if i+1 < len(nodes) && nodes[i+1].capture {
			return nil, fmt.Errorf("consecutive captures are not allowed")
		}
		if n.name != "" {
			if named[n.name] {
				return nil, fmt.Errorf("duplicate capture name %q", n.name)
			}
			named[n.name] = true
		}
	}
	if len(named) == 0 {
		return nil, fmt.Errorf("at least one named capture is required")
	}
	return nodes, nil
}

func compileRegexpStage(s string) (*regexp.Regexp, []string, error) {
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, nil, err
	}
	names := re.SubexpNames()
	seen := map[string]bool{}
	for _, n := range names[1:] {
		if n == "" {
			continue
		}
		if !isLabelName(n) {
			return nil, nil, fmt.Errorf("capture name %q is not a valid label name", n)
		}
		if seen[n] {
			return nil, nil, fmt.Errorf("duplicate capture name %q", n)
		}
		seen[n] = true
	}
	if len(seen) == 0 {
		return nil, nil, fmt.Errorf("at least one named capture group is required")
	}
	return re, names, nil
}
