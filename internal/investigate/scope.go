package investigate

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/logstorage"
	"github.com/VictoriaMetrics/metricsql"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
)

// Query languages.
const (
	LangPromQL    = "promql"
	LangMetricsQL = "metricsql"
	LangLogQL     = "logql"
	LangLogsQL    = "logsql"
)

var promParser = parser.NewParser(parser.Options{})

func parseErr(lang string, err error) error {
	return errorf(ClassInvalid, "%s parse: %v", lang, err)
}

// InjectPromQL ANDs m into every vector and matrix selector of a PromQL query and re-serializes it.
func InjectPromQL(query string, m []*labels.Matcher) (string, error) {
	expr, err := promParser.ParseExpr(query)
	if err != nil {
		return "", parseErr(LangPromQL, err)
	}
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if vs, ok := n.(*parser.VectorSelector); ok {
			for _, mm := range m {
				vs.LabelMatchers = append(vs.LabelMatchers, labels.MustNewMatcher(mm.Type, mm.Name, mm.Value))
			}
		}
		return nil
	})
	out := expr.String()
	re, err := promParser.ParseExpr(out)
	if err != nil {
		return "", errorf(ClassInternal, "promql re-parse after scope injection: %v", err)
	}
	var missing error
	parser.Inspect(re, func(n parser.Node, _ []parser.Node) error {
		if vs, ok := n.(*parser.VectorSelector); ok && missing == nil && !hasAllMatchers(vs.LabelMatchers, m) {
			missing = errorf(ClassInternal, "promql scope verification failed for selector %s", vs.String())
		}
		return nil
	})
	if missing != nil {
		return "", missing
	}
	return out, nil
}

func hasAllMatchers(have, want []*labels.Matcher) bool {
	for _, w := range want {
		if !slices.ContainsFunc(have, func(h *labels.Matcher) bool {
			return h.Type == w.Type && h.Name == w.Name && h.Value == w.Value
		}) {
			return false
		}
	}
	return true
}

// promReach is how far before the evaluation time a PromQL query reads (offsets, ranges, subqueries).
func promReach(query string) (time.Duration, error) {
	expr, err := promParser.ParseExpr(query)
	if err != nil {
		return 0, parseErr(LangPromQL, err)
	}
	var reach time.Duration
	var walk func(n parser.Node, extra time.Duration) error
	walk = func(n parser.Node, extra time.Duration) error {
		switch e := n.(type) {
		case *parser.VectorSelector:
			if e.Timestamp != nil || e.StartOrEnd != 0 {
				return errorf(ClassInvalid, "the @ modifier is not permitted in investigation queries")
			}
			reach = max(reach, extra+e.OriginalOffset)
			return nil
		case *parser.MatrixSelector:
			return walk(e.VectorSelector, extra+e.Range)
		case *parser.SubqueryExpr:
			if e.Timestamp != nil || e.StartOrEnd != 0 {
				return errorf(ClassInvalid, "the @ modifier is not permitted in investigation queries")
			}
			return walk(e.Expr, extra+e.Range+e.OriginalOffset)
		}
		var err error
		for c := range parser.ChildrenIter(n) {
			if err = walk(c, extra); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(expr, 0); err != nil {
		return 0, err
	}
	return reach, nil
}

func metricsqlFilters(m []*labels.Matcher) []metricsql.LabelFilter {
	out := make([]metricsql.LabelFilter, len(m))
	for i, mm := range m {
		out[i] = metricsql.LabelFilter{
			Label:      mm.Name,
			Value:      mm.Value,
			IsNegative: mm.Type == labels.MatchNotEqual || mm.Type == labels.MatchNotRegexp,
			IsRegexp:   mm.Type == labels.MatchRegexp || mm.Type == labels.MatchNotRegexp,
		}
	}
	return out
}

// InjectMetricsQL appends m to every or-group of every metric expression of a MetricsQL query.
func InjectMetricsQL(query string, m []*labels.Matcher) (string, error) {
	expr, err := metricsql.Parse(query)
	if err != nil {
		return "", parseErr(LangMetricsQL, err)
	}
	want := metricsqlFilters(m)
	metricsql.VisitAll(expr, func(e metricsql.Expr) {
		me, ok := e.(*metricsql.MetricExpr)
		if !ok || len(want) == 0 {
			return
		}
		if len(me.LabelFilterss) == 0 {
			me.LabelFilterss = [][]metricsql.LabelFilter{nil}
		}
		for i := range me.LabelFilterss {
			me.LabelFilterss[i] = append(me.LabelFilterss[i], want...)
		}
	})
	out := string(expr.AppendString(nil))
	re, err := metricsql.Parse(out)
	if err != nil {
		return "", errorf(ClassInternal, "metricsql re-parse after scope injection: %v", err)
	}
	ok := true
	metricsql.VisitAll(re, func(e metricsql.Expr) {
		me, isMetric := e.(*metricsql.MetricExpr)
		if !isMetric || len(want) == 0 {
			return
		}
		if len(me.LabelFilterss) == 0 {
			ok = false
		}
		for _, g := range me.LabelFilterss {
			for _, w := range want {
				if !slices.Contains(g, w) {
					ok = false
				}
			}
		}
	})
	if !ok {
		return "", errorf(ClassInternal, "metricsql scope verification failed")
	}
	return out, nil
}

func metricsqlReach(query string) (time.Duration, error) {
	expr, err := metricsql.Parse(query)
	if err != nil {
		return 0, parseErr(LangMetricsQL, err)
	}
	var reach time.Duration
	var walk func(e metricsql.Expr, extra time.Duration) error
	walk = func(e metricsql.Expr, extra time.Duration) error {
		switch x := e.(type) {
		case *metricsql.MetricExpr:
			reach = max(reach, extra)
		case *metricsql.RollupExpr:
			if x.At != nil {
				return errorf(ClassInvalid, "the @ modifier is not permitted in investigation queries")
			}
			if x.Window != nil {
				extra += time.Duration(x.Window.Duration(0)) * time.Millisecond
			}
			if x.Offset != nil {
				extra += time.Duration(x.Offset.Duration(0)) * time.Millisecond
			}
			return walk(x.Expr, extra)
		case *metricsql.BinaryOpExpr:
			if err := walk(x.Left, extra); err != nil {
				return err
			}
			return walk(x.Right, extra)
		case *metricsql.FuncExpr:
			for _, a := range x.Args {
				if err := walk(a, extra); err != nil {
					return err
				}
			}
		case *metricsql.AggrFuncExpr:
			for _, a := range x.Args {
				if err := walk(a, extra); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(expr, 0); err != nil {
		return 0, err
	}
	return reach, nil
}

// InjectLogQL ANDs m into every stream selector with logql.InjectScope and verifies the result.
func InjectLogQL(query string, m []*labels.Matcher) (string, error) {
	if _, err := logql.ParseExpr(query); err != nil {
		return "", parseErr(LangLogQL, err)
	}
	out, err := logql.InjectScope(query, m)
	if err != nil {
		return "", parseErr(LangLogQL, err)
	}
	re, err := logql.ParseExpr(out)
	if err != nil {
		return "", errorf(ClassInternal, "logql re-parse after scope injection: %v", err)
	}
	ok := true
	walkLogQL(re, func(le *logql.LogExpr, _ time.Duration) {
		if !hasAllMatchers(le.Matchers, m) {
			ok = false
		}
	})
	if !ok {
		return "", errorf(ClassInternal, "logql scope verification failed")
	}
	return out, nil
}

func walkLogQL(e logql.Expr, f func(le *logql.LogExpr, rng time.Duration)) {
	switch x := e.(type) {
	case *logql.LogExpr:
		f(x, 0)
	case *logql.RangeAggregation:
		f(x.Log, x.Range)
	case *logql.VectorAggregation:
		walkLogQL(x.Expr, f)
	case *logql.BinaryExpr:
		walkLogQL(x.LHS, f)
		walkLogQL(x.RHS, f)
	}
}

// logqlShape reports whether a LogQL query is a metric query, a bare stream selector, and its longest range.
func logqlShape(query string) (metric, bare bool, reach time.Duration, err error) {
	e, err := logql.ParseExpr(query)
	if err != nil {
		return false, false, 0, parseErr(LangLogQL, err)
	}
	le, isLog := e.(*logql.LogExpr)
	walkLogQL(e, func(_ *logql.LogExpr, rng time.Duration) { reach = max(reach, rng) })
	return !isLog, isLog && len(le.Stages) == 0, reach, nil
}

// logsqlScopeFilters builds stream filters from quoted literals and parses them with the LogsQL parser.
func logsqlScopeFilters(t telemetryScope) ([]*logstorage.Filter, []string, error) {
	var out []*logstorage.Filter
	var strs []string
	for _, f := range []struct {
		name   string
		values []string
	}{{NamespaceLabel, t.namespaces}, {PodLabel, t.pods}, {NodeLabel, t.nodes}} {
		if len(f.values) == 0 {
			continue
		}
		quoted := make([]string, len(f.values))
		for i, v := range f.values {
			quoted[i] = strconv.Quote(v)
		}
		pf, err := logstorage.ParseFilter(fmt.Sprintf("{%s in (%s)}", strconv.Quote(f.name), strings.Join(quoted, ",")))
		if err != nil {
			return nil, nil, errorf(ClassInternal, "logsql scope filter: %v", err)
		}
		out = append(out, pf)
		strs = append(strs, pf.String())
	}
	return out, strs, nil
}

// InjectLogsQL ANDs namespace, pod, and node stream filters and the window (unless start is zero) with the whole LogsQL query, including subqueries.
func InjectLogsQL(query string, namespaces, pods, nodes []string, start, end time.Time) (string, error) {
	t := telemetryScope{namespaces: namespaces, pods: pods, nodes: nodes}
	q, err := logstorage.ParseQuery(query)
	if err != nil {
		return "", parseErr(LangLogsQL, err)
	}
	filters, strs, err := logsqlScopeFilters(t)
	if err != nil {
		return "", err
	}
	for _, f := range filters {
		q.AddExtraFilters(f)
	}
	if !start.IsZero() {
		q.AddTimeFilter(start.UnixNano(), end.UnixNano())
	}
	re, err := logstorage.ParseQuery(q.String())
	if err != nil {
		return "", errorf(ClassInternal, "logsql re-parse after scope injection: %v", err)
	}
	out := re.String()
	if fix, err := logstorage.ParseQuery(out); err != nil || fix.String() != out {
		return "", errorf(ClassInternal, "logsql scope verification failed: serialization is not stable")
	}
	for _, s := range strs {
		if !strings.Contains(out, strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")) {
			return "", errorf(ClassInternal, "logsql scope verification failed: filter %s missing", s)
		}
	}
	return out, nil
}

// isLogsQLStats reports whether a LogsQL query ends with a stats pipe.
func isLogsQLStats(query string, ts time.Time) bool {
	_, err := logstorage.ParseStatsQuery(query, ts.UnixNano())
	return err == nil
}
