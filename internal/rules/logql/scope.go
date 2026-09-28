package logql

import (
	"fmt"

	"github.com/prometheus/prometheus/model/labels"
)

// InjectScope ANDs m into every stream selector of the parsed query and re-serializes it; nothing is replaced.
func InjectScope(query string, m []*labels.Matcher) (string, error) {
	e, err := ParseExpr(query)
	if err != nil {
		return "", err
	}
	for _, sm := range m {
		if sm == nil || !isLabelName(sm.Name) {
			return "", fmt.Errorf("logql: invalid scope matcher")
		}
	}
	for _, log := range logExprs(e) {
		for _, sm := range m {
			c, err := labels.NewMatcher(sm.Type, sm.Name, sm.Value)
			if err != nil {
				return "", fmt.Errorf("logql: invalid scope matcher %s: %w", sm.Name, err)
			}
			log.Matchers = append(log.Matchers, c)
		}
	}
	out := e.String()
	if _, err := ParseExpr(out); err != nil {
		return "", fmt.Errorf("logql: scoped query does not re-parse: %w", err)
	}
	return out, nil
}

func logExprs(e Expr) []*LogExpr {
	switch n := e.(type) {
	case *LogExpr:
		return []*LogExpr{n}
	case *RangeAggregation:
		return []*LogExpr{n.Log}
	case *VectorAggregation:
		return logExprs(n.Expr)
	case *BinaryExpr:
		return append(logExprs(n.LHS), logExprs(n.RHS)...)
	}
	return nil
}
