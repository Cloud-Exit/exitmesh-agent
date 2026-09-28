package logql

import (
	"math"
	"slices"
	"sort"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
)

// evaluator computes the metric expression above range aggregations, whose vectors come from leaf.
type evaluator struct {
	t    int64
	leaf func(*RangeAggregation) (promql.Vector, error)
}

type scalar float64

func (ev *evaluator) eval(e Expr) (any, error) {
	switch n := e.(type) {
	case *NumberLiteral:
		return scalar(n.Value), nil
	case *RangeAggregation:
		return ev.leaf(n)
	case *VectorAggregation:
		v, err := ev.eval(n.Expr)
		if err != nil {
			return nil, err
		}
		return aggregate(n, v.(promql.Vector), ev.t), nil
	case *BinaryExpr:
		l, err := ev.eval(n.LHS)
		if err != nil {
			return nil, err
		}
		r, err := ev.eval(n.RHS)
		if err != nil {
			return nil, err
		}
		return binary(n, l, r), nil
	}
	return nil, &ParseError{Msg: "log query is not a metric expression"}
}

func (ev *evaluator) vector(e Expr) (promql.Vector, error) {
	v, err := ev.eval(e)
	if err != nil {
		return nil, err
	}
	vec, _ := v.(promql.Vector)
	sortVector(vec)
	return vec, nil
}

func sortVector(v promql.Vector) {
	sort.SliceStable(v, func(i, j int) bool { return labels.Compare(v[i].Metric, v[j].Metric) < 0 })
}

func groupLabels(g *Grouping, ls labels.Labels) labels.Labels {
	if g == nil {
		return labels.EmptyLabels()
	}
	return filterLabels(ls, g.Labels, !g.Without)
}

// filterLabels keeps (or drops) the named labels; unlike labels.Builder it preserves empty values, which Loki keeps.
func filterLabels(ls labels.Labels, names []string, keep bool) labels.Labels {
	b := labels.NewScratchBuilder(ls.Len())
	ls.Range(func(l labels.Label) {
		if slices.Contains(names, l.Name) == keep {
			b.Add(l.Name, l.Value)
		}
	})
	return b.Labels()
}

type aggGroup struct {
	lbls  labels.Labels
	sum   float64
	count int
	val   float64
	top   promql.Vector
}

func aggregate(n *VectorAggregation, v promql.Vector, t int64) promql.Vector {
	groups := map[string]*aggGroup{}
	var order []string
	for _, s := range v {
		gl := groupLabels(n.Grouping, s.Metric)
		key := gl.String()
		g, ok := groups[key]
		if !ok {
			g = &aggGroup{lbls: gl, val: s.F}
			groups[key] = g
			order = append(order, key)
		}
		g.count++
		g.sum += s.F
		switch n.Op {
		case AggMin:
			if math.IsNaN(g.val) || s.F < g.val {
				g.val = s.F
			}
		case AggMax:
			if math.IsNaN(g.val) || s.F > g.val {
				g.val = s.F
			}
		case AggTopK:
			g.top = append(g.top, s)
		}
	}
	var out promql.Vector
	for _, key := range order {
		g := groups[key]
		switch n.Op {
		case AggSum:
			out = append(out, promql.Sample{T: t, F: g.sum, Metric: g.lbls})
		case AggCount:
			out = append(out, promql.Sample{T: t, F: float64(g.count), Metric: g.lbls})
		case AggAvg:
			out = append(out, promql.Sample{T: t, F: g.sum / float64(g.count), Metric: g.lbls})
		case AggMin, AggMax:
			out = append(out, promql.Sample{T: t, F: g.val, Metric: g.lbls})
		case AggTopK:
			sort.SliceStable(g.top, func(i, j int) bool {
				a, b := g.top[i].F, g.top[j].F
				if math.IsNaN(a) != math.IsNaN(b) {
					return !math.IsNaN(a)
				}
				if a != b {
					return a > b
				}
				return labels.Compare(g.top[i].Metric, g.top[j].Metric) < 0
			})
			if len(g.top) > n.Param {
				g.top = g.top[:n.Param]
			}
			out = append(out, g.top...)
		}
	}
	return out
}

func binary(n *BinaryExpr, l, r any) any {
	ls, lok := l.(scalar)
	rs, rok := r.(scalar)
	if lok && rok {
		v, keep := applyOp(n.Op, float64(ls), float64(rs))
		if n.Op.isComparison() {
			if keep {
				return scalar(1)
			}
			return scalar(0)
		}
		return scalar(v)
	}
	var vec promql.Vector
	var s float64
	swap := false
	if lok {
		vec, s, swap = r.(promql.Vector), float64(ls), true
	} else {
		vec, s = l.(promql.Vector), float64(rs)
	}
	out := make(promql.Vector, 0, len(vec))
	for _, smp := range vec {
		a, b := smp.F, s
		if swap {
			a, b = s, smp.F
		}
		v, keep := applyOp(n.Op, a, b)
		if n.Op.isComparison() {
			switch {
			case n.ReturnBool:
				v = 0
				if keep {
					v = 1
				}
			case !keep:
				continue
			default:
				v = smp.F
			}
		}
		out = append(out, promql.Sample{T: smp.T, F: v, Metric: smp.Metric})
	}
	return out
}

func applyOp(op BinaryOp, a, b float64) (float64, bool) {
	switch op {
	case OpAdd:
		return a + b, true
	case OpSub:
		return a - b, true
	case OpMul:
		return a * b, true
	case OpDiv:
		return a / b, true
	case OpMod:
		return math.Mod(a, b), true
	case OpPow:
		return math.Pow(a, b), true
	case OpEq:
		return a, a == b
	case OpNeq:
		return a, a != b
	case OpGt:
		return a, a > b
	case OpGte:
		return a, a >= b
	case OpLt:
		return a, a < b
	case OpLte:
		return a, a <= b
	}
	return 0, false
}

// findRange returns the single range aggregation and the sum grouping directly above it, if any.
func findRange(e Expr) (*RangeAggregation, *Grouping, bool) {
	var ra *RangeAggregation
	var pre *Grouping
	preSum := false
	var walk func(e Expr, parent *VectorAggregation)
	walk = func(e Expr, parent *VectorAggregation) {
		switch n := e.(type) {
		case *RangeAggregation:
			ra = n
			if parent != nil && parent.Op == AggSum {
				pre, preSum = parent.Grouping, true
			}
		case *VectorAggregation:
			walk(n.Expr, n)
		case *BinaryExpr:
			walk(n.LHS, nil)
			walk(n.RHS, nil)
		}
	}
	walk(e, nil)
	return ra, pre, preSum
}

// projection returns the labels used to key counters: pre-aggregated by a directly enclosing sum.
func projection(g *Grouping, preSum bool, ls labels.Labels) labels.Labels {
	if !preSum {
		return ls
	}
	return groupLabels(g, ls)
}

func countNodes(e Expr) int {
	switch n := e.(type) {
	case *RangeAggregation:
		c := 1 + len(n.Log.Matchers)
		for _, s := range n.Log.Stages {
			c++
			if lf, ok := s.(*LabelFilterStage); ok {
				c += countFilterNodes(lf.Filter)
			}
		}
		return c
	case *VectorAggregation:
		return 1 + countNodes(n.Expr)
	case *BinaryExpr:
		return 1 + countNodes(n.LHS) + countNodes(n.RHS)
	case *LogExpr:
		return 1 + len(n.Matchers) + len(n.Stages)
	}
	return 1
}

func countFilterNodes(f LabelFilter) int {
	if b, ok := f.(*LabelFilterBinary); ok {
		return 1 + countFilterNodes(b.Left) + countFilterNodes(b.Right)
	}
	return 1
}
