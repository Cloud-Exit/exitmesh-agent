package logql

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

// dump renders an AST structurally so re-parsed trees can be compared for identity.
func dump(v any) string {
	var b strings.Builder
	dumpValue(&b, reflect.ValueOf(v))
	return b.String()
}

func dumpValue(b *strings.Builder, v reflect.Value) {
	if !v.IsValid() {
		b.WriteString("nil")
		return
	}
	if m, ok := v.Interface().(*labels.Matcher); ok {
		if m == nil {
			b.WriteString("nil")
			return
		}
		fmt.Fprintf(b, "Matcher{%d %q %q}", m.Type, m.Name, m.Value)
		return
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			b.WriteString("nil")
			return
		}
		dumpValue(b, v.Elem())
	case reflect.Struct:
		b.WriteString(v.Type().Name() + "{")
		for i := 0; i < v.NumField(); i++ {
			b.WriteString(v.Type().Field(i).Name + ":")
			dumpValue(b, v.Field(i))
			b.WriteString(" ")
		}
		b.WriteString("}")
	case reflect.Slice:
		b.WriteString("[")
		for i := 0; i < v.Len(); i++ {
			dumpValue(b, v.Index(i))
			b.WriteString(",")
		}
		b.WriteString("]")
	case reflect.Float64:
		fmt.Fprintf(b, "%x", math.Float64bits(v.Float()))
	default:
		fmt.Fprintf(b, "%v", v.Interface())
	}
}

func assertRoundTrip(t *testing.T, e Expr) {
	t.Helper()
	s := e.String()
	e2, err := ParseExpr(s)
	if err != nil {
		t.Fatalf("canonical form %q does not re-parse: %v", s, err)
	}
	if dump(e) != dump(e2) {
		t.Fatalf("round trip changed the AST for %q:\n%s\n%s", s, dump(e), dump(e2))
	}
	if e2.String() != s {
		t.Fatalf("printing is not idempotent: %q then %q", s, e2.String())
	}
}

var validQueries = []struct{ in, want string }{
	{`{app="api"}`, `{app="api"}`},
	{`{app="api",env!="dev", ns=~"prod-.*", pod!~"canary.*"}`, `{app="api", env!="dev", ns=~"prod-.*", pod!~"canary.*"}`},
	{"{app=`a\\b`}", `{app="a\\b"}`},
	{`{app="api", app="web"}`, `{app="api", app="web"}`},
	{`{app="api"} |= "error" != "timeout" |~ "code=5.." !~ "(?i)health"`, `{app="api"} |= "error" != "timeout" |~ "code=5.." !~ "(?i)health"`},
	{"{app=\"api\"} |= `a \"quoted\" b`", `{app="api"} |= "a \"quoted\" b"`},
	{`{app="api"} | json`, `{app="api"} | json`},
	{`{app="api"} | json code="resp.code", first="servers[0]", ua="headers[\"User-Agent\"]", level`, `{app="api"} | json code="resp.code", first="servers[0]", ua="headers[\"User-Agent\"]", level="level"`},
	{`{app="api"} | logfmt`, `{app="api"} | logfmt`},
	{`{app="api"} | pattern "<ip> - <_> [<ts>] \"<method> <path> <_>\" <status>"`, `{app="api"} | pattern "<ip> - <_> [<ts>] \"<method> <path> <_>\" <status>"`},
	{`{app="api"} | regexp "(?P<method>\\w+) (?P<path>\\S+)"`, `{app="api"} | regexp "(?P<method>\\w+) (?P<path>\\S+)"`},
	{`{app="api"} | json | level="error"`, `{app="api"} | json | level="error"`},
	{`{app="api"} | logfmt | level=~"err|warn", caller!~"db.*" code!=""`, `{app="api"} | logfmt | level=~"err|warn" and caller!~"db.*" and code!=""`},
	{`{app="api"} | logfmt | status >= 500 or status == 429`, `{app="api"} | logfmt | status >= 500 or status == 429`},
	{`{app="api"} | logfmt | status = 200`, `{app="api"} | logfmt | status == 200`},
	{`{app="api"} | logfmt | (a="1" or b="2") and c="3"`, `{app="api"} | logfmt | (a="1" or b="2") and c="3"`},
	{`{app="api"} | logfmt | a="1" or (b="2" or c="3")`, `{app="api"} | logfmt | a="1" or (b="2" or c="3")`},
	{`{app="api"} | logfmt | a="1" and b="2" or c="3"`, `{app="api"} | logfmt | a="1" and b="2" or c="3"`},
	{`{app="api"} | logfmt | latency > 250ms and latency <= 1m30s`, `{app="api"} | logfmt | latency > 250ms and latency <= 1m30s`},
	{`{app="api"} | logfmt | latency > 1.5s`, `{app="api"} | logfmt | latency > 1s500ms`},
	{`{app="api"} | logfmt | latency > 250us`, `{app="api"} | logfmt | latency > 250µs`},
	{`{app="api"} | logfmt | size > 10KB and size < 2MiB`, `{app="api"} | logfmt | size > 10000B and size < 2097152B`},
	{`{app="api"} | logfmt | delta > -5 and delta < +7.5`, `{app="api"} | logfmt | delta > -5 and delta < 7.5`},
	{`{app="api"} | json | __error__=""`, `{app="api"} | json | __error__=""`},
	{`count_over_time({app="api"} |= "error" [5m])`, `count_over_time({app="api"} |= "error" [5m])`},
	{`count_over_time({app="api"}[5m] |= "error")`, `count_over_time({app="api"} |= "error" [5m])`},
	{`count_over_time(({app="api"} |= "error")[1h30m])`, `count_over_time({app="api"} |= "error" [1h30m])`},
	{`rate({app="api"}[1d])`, `rate({app="api"} [1d])`},
	{`bytes_over_time({app="api"}[90s])`, `bytes_over_time({app="api"} [1m30s])`},
	{`sum by (ns) (count_over_time({app="api"}[5m]))`, `sum by (ns) (count_over_time({app="api"} [5m]))`},
	{`sum(count_over_time({app="api"}[5m])) by (ns, pod)`, `sum by (ns, pod) (count_over_time({app="api"} [5m]))`},
	{`sum without (pod) (rate({app="api"}[5m]))`, `sum without (pod) (rate({app="api"} [5m]))`},
	{`sum by () (rate({app="api"}[5m]))`, `sum by () (rate({app="api"} [5m]))`},
	{`count(rate({app="api"}[5m]))`, `count(rate({app="api"} [5m]))`},
	{`min(rate({app="api"}[5m]))`, `min(rate({app="api"} [5m]))`},
	{`max by (ns) (rate({app="api"}[5m]))`, `max by (ns) (rate({app="api"} [5m]))`},
	{`avg(rate({app="api"}[5m]))`, `avg(rate({app="api"} [5m]))`},
	{`topk(3, sum by (pod) (rate({app="api"}[5m])))`, `topk(3, sum by (pod) (rate({app="api"} [5m])))`},
	{`topk by (ns) (2, rate({app="api"}[5m]))`, `topk by (ns) (2, rate({app="api"} [5m]))`},
	{`sum(count_over_time({app="api"}[5m])) > 10`, `sum(count_over_time({app="api"} [5m])) > 10`},
	{`sum(count_over_time({app="api"}[5m])) > bool 10`, `sum(count_over_time({app="api"} [5m])) > bool 10`},
	{`10 < sum(count_over_time({app="api"}[5m]))`, `10 < sum(count_over_time({app="api"} [5m]))`},
	{`sum(rate({app="api"}[5m])) * 60 > 2 + 3 * 4`, `sum(rate({app="api"} [5m])) * 60 > 2 + 3 * 4`},
	{`(sum(rate({app="api"}[5m])) + 1) * 2`, `(sum(rate({app="api"} [5m])) + 1) * 2`},
	{`sum(rate({app="api"}[5m])) - (1 - 2)`, `sum(rate({app="api"} [5m])) - (1 - 2)`},
	{`2 ^ 3 ^ 2 * sum(rate({app="api"}[5m]))`, `2 ^ 3 ^ 2 * sum(rate({app="api"} [5m]))`},
	{`(2 ^ 3) ^ 2 * sum(rate({app="api"}[5m]))`, `(2 ^ 3) ^ 2 * sum(rate({app="api"} [5m]))`},
	{`sum(rate({app="api"}[5m])) % 7 / 1e6`, `sum(rate({app="api"} [5m])) % 7 / 1e+06`},
	{`-1 * sum(rate({app="api"}[5m]))`, `-1 * sum(rate({app="api"} [5m]))`},
	{`sum(rate({app="api"}[5m])) > 1 == bool 1`, `sum(rate({app="api"} [5m])) > 1 == bool 1`},
	{`sum(rate({app="api"}[5m])) != 0`, `sum(rate({app="api"} [5m])) != 0`},
	{`sum(sum by (a) (rate({app="api"}[5m])))`, `sum(sum by (a) (rate({app="api"} [5m])))`},
	{`({app="api"} |= "x")`, `{app="api"} |= "x"`},
	{`1 > 2 + rate({a="b"}[1m])`, `1 > 2 + rate({a="b"} [1m])`},
}

func TestParseValid(t *testing.T) {
	for _, tc := range validQueries {
		e, err := ParseExpr(tc.in)
		if err != nil {
			t.Fatalf("ParseExpr(%q): %v", tc.in, err)
		}
		if got := e.String(); got != tc.want {
			t.Errorf("ParseExpr(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
		assertRoundTrip(t, e)
	}
}

func TestParseStructure(t *testing.T) {
	e, err := ParseExpr(`sum by (ns) (rate({app="api"} |= "x" | json | a="1" or b > 2 [5m])) > 10`)
	if err != nil {
		t.Fatal(err)
	}
	be := e.(*BinaryExpr)
	agg := be.LHS.(*VectorAggregation)
	ra := agg.Expr.(*RangeAggregation)
	if be.Op != OpGt || be.RHS.(*NumberLiteral).Value != 10 || agg.Op != AggSum || agg.Grouping.Labels[0] != "ns" {
		t.Fatalf("unexpected tree %s", dump(e))
	}
	if ra.Op != RangeRate || ra.Range.Minutes() != 5 || len(ra.Log.Stages) != 3 {
		t.Fatalf("unexpected range aggregation %s", dump(ra))
	}
	or := ra.Log.Stages[2].(*LabelFilterStage).Filter.(*LabelFilterBinary)
	if !or.Or || or.Right.(*LabelFilterNumeric).Kind != NumericNumber {
		t.Fatalf("unexpected label filter %s", dump(or))
	}
	e, err = ParseExpr(`{a="b"} | logfmt | a="1" or b="2" and c="3"`)
	if err != nil {
		t.Fatal(err)
	}
	top := e.(*LogExpr).Stages[1].(*LabelFilterStage).Filter.(*LabelFilterBinary)
	if !top.Or || top.Right.(*LabelFilterBinary).Or {
		t.Fatalf("and must bind tighter than or: %s", dump(top))
	}
	e, err = ParseExpr(`{a="b"} | logfmt | d > 1h`)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.(*LogExpr).Stages[1].(*LabelFilterStage).Filter.(*LabelFilterNumeric); n.Kind != NumericDuration || n.Value != 3600e9 {
		t.Fatalf("duration literal: %s", dump(n))
	}
}

var invalidQueries = []struct {
	in          string
	unsupported bool
	msg         string
}{
	{``, false, "unexpected end of input"},
	{`{}`, false, "at least one = or =~ matcher"},
	{`{app=~".*"}`, false, "does not match the empty string"},
	{`{app!="x"}`, false, "at least one = or =~ matcher"},
	{`{app="x"`, false, "unexpected end of input"},
	{`{app=x}`, false, "expected a string value"},
	{`{app=~"("}`, false, "invalid regular expression"},
	{`{app="x"} |= `, false, "expected a string after '|='"},
	{`{app="x"} |~ "("`, false, "invalid line filter regular expression"},
	{`{app="x"} | `, false, "expected a pipeline stage"},
	{`{app="x"} | pattern "<a><b>"`, false, "consecutive captures"},
	{`{app="x"} | pattern "<_> x"`, false, "at least one named capture"},
	{`{app="x"} | pattern "<a> <a>"`, false, "duplicate capture name"},
	{`{app="x"} | regexp "(\\w+)"`, false, "at least one named capture group"},
	{`{app="x"} | regexp "(?P<a>x)(?P<a>y)"`, false, "duplicate capture name"},
	{`{app="x"} | json a="b..c"`, false, "invalid json path"},
	{`{app="x"} | logfmt | a =~ 5`, false, "expected a label filter operator"},
	{`{app="x"} | logfmt | a > "5"`, false, "cannot compare label"},
	{`{app="x"} | logfmt | a > 5zz`, false, "invalid number, duration or byte size"},
	{`{app="x"} | logfmt | a > -5KB`, false, "byte sizes cannot be negative"},
	{`"unterminated`, false, "unterminated string"},
	{`{app="x"} # comment`, false, "unexpected character"},
	{`{app="x"}[5m]`, false, "only allowed inside a range aggregation"},
	{`count_over_time({app="x"})`, false, "expected '['"},
	{`count_over_time({app="x"}[0s])`, false, "invalid range duration"},
	{`count_over_time({app="x"}[5x])`, false, "invalid range duration"},
	{`count_over_time(sum(rate({a="b"}[1m]))[5m])`, false, "expected a log stream selector"},
	{`sum({app="x"})`, false, "requires a metric expression"},
	{`sum(5)`, false, "requires a vector expression"},
	{`sum(5, rate({a="b"}[1m]))`, false, "does not take a parameter"},
	{`topk(rate({a="b"}[1m]))`, false, "topk requires an integer parameter"},
	{`topk(0, rate({a="b"}[1m]))`, false, "positive integer"},
	{`sum by (a) (rate({a="b"}[1m])) by (b)`, false, "duplicate grouping"},
	{`1 + 1`, false, "must select log streams"},
	{`rate({a="b"}[1m]) > 1 > 2 > `, false, "unexpected end of input"},
	{`5 > 3`, false, "must use the bool modifier"},
	{`rate({a="b"}[1m]) + bool 1`, false, "bool modifier is only allowed on comparison"},
	{`{a="b"} + 1`, false, "cannot be an operand"},
	{`rate({a="b"}[1m]) > 1e999`, false, "invalid number"},
	{`{app="x"} | line_format "{{.a}}"`, true, `pipeline stage "line_format"`},
	{`{app="x"} | label_format a=b`, true, `pipeline stage "label_format"`},
	{`sum_over_time({app="x"} | logfmt | unwrap latency [5m])`, true, `range aggregation "sum_over_time"`},
	{`{app="x"} | logfmt | unwrap latency`, true, `pipeline stage "unwrap"`},
	{`{app="x"} | drop a`, true, `pipeline stage "drop"`},
	{`{app="x"} | keep a`, true, `pipeline stage "keep"`},
	{`{app="x"} | decolorize`, true, `pipeline stage "decolorize"`},
	{`{app="x"} | unpack`, true, `pipeline stage "unpack"`},
	{`quantile_over_time(0.99, {app="x"} | logfmt | unwrap d [5m])`, true, `range aggregation "quantile_over_time"`},
	{`count_over_time({app="x"}[5m] offset 1h)`, true, "offset modifier"},
	{`count_over_time({app="x"}[5m:1m])`, true, "subquery"},
	{`rate({a="b"}[1m]) / rate({a="c"}[1m])`, true, "between two vectors"},
	{`rate({a="b"}[1m]) and rate({a="c"}[1m])`, true, `set operator "and"`},
	{`rate({a="b"}[1m]) or rate({a="c"}[1m])`, true, `set operator "or"`},
	{`rate({a="b"}[1m]) / on(x) rate({a="c"}[1m])`, true, `vector matching "on"`},
	{`bottomk(2, rate({a="b"}[1m]))`, true, `vector aggregation "bottomk"`},
	{`stddev(rate({a="b"}[1m]))`, true, `vector aggregation "stddev"`},
	{`label_replace(rate({a="b"}[1m]), "x", "$1", "a", "(.*)")`, true, `function "label_replace"`},
	{`absent_over_time({a="b"}[1m])`, true, `range aggregation "absent_over_time"`},
	{`count_over_time({a="b"}[1m]) by (a)`, true, "grouping on range aggregation"},
	{`{app="x"} |> "<_> error"`, true, "pattern line filter"},
	{`{app="x"} |= ip("10.0.0.0/8")`, true, "ip line filter"},
	{`{app="x"} | logfmt | addr = ip("10.0.0.0/8")`, true, "ip label filter"},
	{`{app="x"} |= "a" or "b"`, true, "line filter or-chain"},
	{`{app="x"} | logfmt --strict`, true, "logfmt flags"},
	{`{app="x"} | logfmt a="b"`, true, "logfmt extraction parameters"},
	{`-rate({a="b"}[1m])`, true, "unary"},
}

func TestParseInvalid(t *testing.T) {
	for _, tc := range invalidQueries {
		_, err := ParseExpr(tc.in)
		if err == nil {
			t.Errorf("ParseExpr(%q) succeeded, want error", tc.in)
			continue
		}
		var ue *UnsupportedError
		if got := errors.As(err, &ue); got != tc.unsupported {
			t.Errorf("ParseExpr(%q) = %v; unsupported=%v, want %v", tc.in, err, got, tc.unsupported)
		}
		if tc.unsupported && !strings.Contains(err.Error(), SubsetDoc) {
			t.Errorf("ParseExpr(%q) = %v; unsupported errors must point to %s", tc.in, err, SubsetDoc)
		}
		if !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("ParseExpr(%q) = %v, want message containing %q", tc.in, err, tc.msg)
		}
	}
}

func TestParseErrorPosition(t *testing.T) {
	_, err := ParseExpr(`{app="x"} | line_format "x"`)
	var ue *UnsupportedError
	if !errors.As(err, &ue) || ue.Pos != 12 || ue.Construct != `pipeline stage "line_format"` {
		t.Fatalf("got %#v", err)
	}
	_, err = ParseExpr(`{app="x"} |= 5`)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Pos != 13 {
		t.Fatalf("got %#v", err)
	}
}

func FuzzParseExpr(f *testing.F) {
	f.Add(`{A="0"} | A > -0s`)
	for _, tc := range validQueries {
		f.Add(tc.in)
	}
	for _, tc := range invalidQueries {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseExpr(s)
		if err != nil {
			return
		}
		assertRoundTrip(t, e)
	})
}

func TestNegativeZeroDurationRoundTrip(t *testing.T) {
	for _, literal := range []string{"-0s", "-0ms", "-0.1ns", "0s", "+0s"} {
		t.Run(literal, func(t *testing.T) {
			e, err := ParseExpr(`{A="0"} | A > ` + literal)
			if err != nil {
				t.Fatal(err)
			}
			assertRoundTrip(t, e)
		})
	}
}
