package logql

import (
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
)

// Expr is a parsed LogQL expression. String returns the canonical form, which re-parses to an identical AST.
type Expr interface {
	String() string
	isExpr()
}

// LogExpr is a stream selector followed by a pipeline.
type LogExpr struct {
	Matchers []*labels.Matcher
	Stages   []Stage
}

// Stage is one pipeline stage.
type Stage interface {
	String() string
	isStage()
}

// LineFilterOp is a line filter operator.
type LineFilterOp string

const (
	LineContains    LineFilterOp = "|="
	LineNotContains LineFilterOp = "!="
	LineMatchRegexp LineFilterOp = "|~"
	LineNotRegexp   LineFilterOp = "!~"
)

// LineFilter keeps lines containing (or matching) Match.
type LineFilter struct {
	Op    LineFilterOp
	Match string
}

// JSONParam extracts the value at Path into label Label.
type JSONParam struct {
	Label string
	Path  string
}

// JSONStage is the json parser, extracting all fields or only Params.
type JSONStage struct {
	Params []JSONParam
}

// LogfmtStage is the logfmt parser.
type LogfmtStage struct{}

// PatternStage is the pattern parser.
type PatternStage struct {
	Pattern string
}

// RegexpStage is the regexp parser.
type RegexpStage struct {
	Pattern string
}

// LabelFilterStage filters lines by labels.
type LabelFilterStage struct {
	Filter LabelFilter
}

// LabelFilter is a label filter expression.
type LabelFilter interface {
	String() string
	isLabelFilter()
}

// LabelFilterBinary combines two label filters with and (Or false) or or (Or true).
type LabelFilterBinary struct {
	Or          bool
	Left, Right LabelFilter
}

// LabelFilterString compares a label with a string matcher.
type LabelFilterString struct {
	Matcher *labels.Matcher
}

// NumericKind selects how a numeric label filter parses label values.
type NumericKind string

const (
	NumericNumber   NumericKind = "number"
	NumericDuration NumericKind = "duration"
	NumericBytes    NumericKind = "bytes"
)

// CompareOp is a comparison operator.
type CompareOp string

const (
	CmpEq  CompareOp = "=="
	CmpNeq CompareOp = "!="
	CmpGt  CompareOp = ">"
	CmpGte CompareOp = ">="
	CmpLt  CompareOp = "<"
	CmpLte CompareOp = "<="
)

// LabelFilterNumeric compares a label parsed as Kind with Value (nanoseconds for durations, bytes for sizes).
type LabelFilterNumeric struct {
	Name  string
	Op    CompareOp
	Kind  NumericKind
	Value float64
}

// RangeOp is a log range aggregation.
type RangeOp string

const (
	RangeCount RangeOp = "count_over_time"
	RangeRate  RangeOp = "rate"
	RangeBytes RangeOp = "bytes_over_time"
)

// RangeAggregation aggregates a log query over a range window.
type RangeAggregation struct {
	Op    RangeOp
	Log   *LogExpr
	Range time.Duration
}

// AggOp is a vector aggregation operator.
type AggOp string

const (
	AggSum   AggOp = "sum"
	AggCount AggOp = "count"
	AggMin   AggOp = "min"
	AggMax   AggOp = "max"
	AggAvg   AggOp = "avg"
	AggTopK  AggOp = "topk"
)

// Grouping is a by or without clause; Labels is nil when empty.
type Grouping struct {
	Without bool
	Labels  []string
}

// VectorAggregation aggregates a vector; Param is k for topk.
type VectorAggregation struct {
	Op       AggOp
	Param    int
	Grouping *Grouping
	Expr     Expr
}

// BinaryOp is an arithmetic or comparison operator.
type BinaryOp string

const (
	OpAdd BinaryOp = "+"
	OpSub BinaryOp = "-"
	OpMul BinaryOp = "*"
	OpDiv BinaryOp = "/"
	OpMod BinaryOp = "%"
	OpPow BinaryOp = "^"
	OpEq  BinaryOp = "=="
	OpNeq BinaryOp = "!="
	OpGt  BinaryOp = ">"
	OpGte BinaryOp = ">="
	OpLt  BinaryOp = "<"
	OpLte BinaryOp = "<="
)

// BinaryExpr applies Op between a vector and a scalar or two scalars.
type BinaryExpr struct {
	Op         BinaryOp
	ReturnBool bool
	LHS, RHS   Expr
}

// NumberLiteral is a scalar literal.
type NumberLiteral struct {
	Value float64
}

func (*LogExpr) isExpr()           {}
func (*RangeAggregation) isExpr()  {}
func (*VectorAggregation) isExpr() {}
func (*BinaryExpr) isExpr()        {}
func (*NumberLiteral) isExpr()     {}

func (*LineFilter) isStage()       {}
func (*JSONStage) isStage()        {}
func (*LogfmtStage) isStage()      {}
func (*PatternStage) isStage()     {}
func (*RegexpStage) isStage()      {}
func (*LabelFilterStage) isStage() {}

func (*LabelFilterBinary) isLabelFilter()  {}
func (*LabelFilterString) isLabelFilter()  {}
func (*LabelFilterNumeric) isLabelFilter() {}

func (op BinaryOp) isComparison() bool {
	switch op {
	case OpEq, OpNeq, OpGt, OpGte, OpLt, OpLte:
		return true
	}
	return false
}

func (op BinaryOp) precedence() int {
	switch op {
	case OpEq, OpNeq, OpGt, OpGte, OpLt, OpLte:
		return 3
	case OpAdd, OpSub:
		return 4
	case OpMul, OpDiv, OpMod:
		return 5
	case OpPow:
		return 6
	}
	return 0
}

func matcherString(m *labels.Matcher) string {
	return m.Name + m.Type.String() + strconv.Quote(m.Value)
}

func (e *LogExpr) String() string {
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range e.Matchers {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(matcherString(m))
	}
	b.WriteByte('}')
	for _, s := range e.Stages {
		b.WriteByte(' ')
		b.WriteString(s.String())
	}
	return b.String()
}

func (f *LineFilter) String() string { return string(f.Op) + " " + strconv.Quote(f.Match) }

func (s *JSONStage) String() string {
	if len(s.Params) == 0 {
		return "| json"
	}
	parts := make([]string, len(s.Params))
	for i, p := range s.Params {
		parts[i] = p.Label + "=" + strconv.Quote(p.Path)
	}
	return "| json " + strings.Join(parts, ", ")
}

func (*LogfmtStage) String() string        { return "| logfmt" }
func (s *PatternStage) String() string     { return "| pattern " + strconv.Quote(s.Pattern) }
func (s *RegexpStage) String() string      { return "| regexp " + strconv.Quote(s.Pattern) }
func (s *LabelFilterStage) String() string { return "| " + s.Filter.String() }

func (f *LabelFilterBinary) String() string {
	op := " and "
	if f.Or {
		op = " or "
	}
	l, r := f.Left.String(), f.Right.String()
	if lb, ok := f.Left.(*LabelFilterBinary); ok && lb.Or && !f.Or {
		l = "(" + l + ")"
	}
	if rb, ok := f.Right.(*LabelFilterBinary); ok && (rb.Or || !f.Or) {
		r = "(" + r + ")"
	}
	return l + op + r
}

func (f *LabelFilterString) String() string { return matcherString(f.Matcher) }

func (f *LabelFilterNumeric) String() string {
	return f.Name + " " + string(f.Op) + " " + formatNumeric(f.Kind, f.Value)
}

func formatNumeric(k NumericKind, v float64) string {
	switch k {
	case NumericDuration:
		return formatDuration(time.Duration(v))
	case NumericBytes:
		return strconv.FormatUint(uint64(v), 10) + "B"
	}
	return formatFloat(v)
}

func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

func formatDuration(d time.Duration) string {
	if d > 0 && d%time.Millisecond == 0 {
		return model.Duration(d).String()
	}
	return d.String()
}

func (e *RangeAggregation) String() string {
	return string(e.Op) + "(" + e.Log.String() + " [" + formatDuration(e.Range) + "])"
}

func (g *Grouping) String() string {
	kw := "by"
	if g.Without {
		kw = "without"
	}
	return kw + " (" + strings.Join(g.Labels, ", ") + ")"
}

func (e *VectorAggregation) String() string {
	var b strings.Builder
	b.WriteString(string(e.Op))
	if e.Grouping != nil {
		b.WriteString(" " + e.Grouping.String() + " ")
	}
	b.WriteByte('(')
	if e.Op == AggTopK {
		b.WriteString(strconv.Itoa(e.Param) + ", ")
	}
	b.WriteString(e.Expr.String())
	b.WriteByte(')')
	return b.String()
}

func exprPrecedence(e Expr) int {
	if b, ok := e.(*BinaryExpr); ok {
		return b.Op.precedence()
	}
	return 100
}

func (e *BinaryExpr) String() string {
	p := e.Op.precedence()
	l, r := e.LHS.String(), e.RHS.String()
	lp, rp := exprPrecedence(e.LHS), exprPrecedence(e.RHS)
	if e.Op == OpPow {
		if lp <= p {
			l = "(" + l + ")"
		}
		if rp < p {
			r = "(" + r + ")"
		}
	} else {
		if lp < p {
			l = "(" + l + ")"
		}
		if rp <= p {
			r = "(" + r + ")"
		}
	}
	op := " " + string(e.Op) + " "
	if e.ReturnBool {
		op += "bool "
	}
	return l + op + r
}

func (e *NumberLiteral) String() string { return formatFloat(e.Value) }
