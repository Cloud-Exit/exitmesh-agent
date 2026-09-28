package engine

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

// ValidationError is a precise rejection of one rule.
type ValidationError struct {
	RuleID string
	Reason string
}

func (e *ValidationError) Error() string { return "rule " + e.RuleID + ": " + e.Reason }

func reject(id, format string, args ...any) error {
	return &ValidationError{RuleID: id, Reason: fmt.Sprintf(format, args...)}
}

// Split is a cluster rule's node and coordinator expressions; kube_*-only rules have no NodeExpr.
type Split struct {
	NodeExpr  string
	CoordExpr string
	Outer     string
	Grouping  []string
	Without   bool
}

type promAnalysis struct {
	expr       parser.Expr
	complexity int
	hasAbsent  bool
	split      *Split
}

var promParser = parser.NewParser(parser.Options{})

// ValidatePromQL checks grammar, complexity, the kube_* subset, and cluster decomposability.
func ValidatePromQL(rule bundle.AlertRule, opts Options) error {
	_, err := analyzePromQL(rule, opts)
	return err
}

// SplitPromQL validates a cluster rule and returns its node and coordinator expressions.
func SplitPromQL(rule bundle.AlertRule, opts Options) (*Split, error) {
	a, err := analyzePromQL(rule, opts)
	if err != nil {
		return nil, err
	}
	if a.split == nil {
		return nil, reject(rule.Meta.ID, "scope %q is node-local and has no cluster decomposition", scopeOf(rule.Meta.Scope))
	}
	return a.split, nil
}

func scopeOf(s string) string {
	if s == "" {
		return bundle.ScopeNode
	}
	return s
}

func selectorName(vs *parser.VectorSelector) string {
	if vs.Name != "" {
		return vs.Name
	}
	for _, m := range vs.LabelMatchers {
		if m.Name == labels.MetricName && m.Type == labels.MatchEqual {
			return m.Value
		}
	}
	return ""
}

func isAbsent(name string) bool { return name == "absent" || name == "absent_over_time" }

func nodeScopedKube(name string) bool {
	return strings.HasPrefix(name, "kube_pod_") || strings.HasPrefix(name, "kube_node_")
}

var kubeKinds = []struct{ prefix, kind string }{
	{"kube_horizontalpodautoscaler_", "HorizontalPodAutoscaler"},
	{"kube_persistentvolumeclaim_", "PersistentVolumeClaim"},
	{"kube_persistentvolume_", "PersistentVolume"},
	{"kube_pvc_", "PersistentVolumeClaim"},
	{"kube_deployment_", "Deployment"},
	{"kube_statefulset_", "StatefulSet"},
	{"kube_daemonset_", "DaemonSet"},
	{"kube_replicaset_", "ReplicaSet"},
	{"kube_cronjob_", "CronJob"},
	{"kube_job_", "Job"},
	{"kube_namespace_", "Namespace"},
	{"kube_service_", "Service"},
	{"kube_ingress_", "Ingress"},
	{"kube_endpoint_", "Endpoints"},
	{"kube_node_", "Node"},
	{"kube_pod_", "Pod"},
}

func kubeKind(name string) string {
	for _, k := range kubeKinds {
		if strings.HasPrefix(name, k.prefix) {
			return k.kind
		}
	}
	return ""
}

func stateRulePointer(name string) string {
	if k := kubeKind(name); k != "" {
		return fmt.Sprintf("express it as a state rule with kinds: [%s] over the normalized fields (docs/state-rules.md)", k)
	}
	return "express it as a state rule over the normalized fields (docs/state-rules.md)"
}

func analyzePromQL(rule bundle.AlertRule, opts Options) (*promAnalysis, error) {
	id := rule.Meta.ID
	expr, err := promParser.ParseExpr(rule.Expr)
	if err != nil {
		return nil, reject(id, "parse error: %v", err)
	}
	if t := expr.Type(); t != parser.ValueTypeVector && t != parser.ValueTypeScalar {
		return nil, reject(id, "expression returns %s, want a vector or scalar", t)
	}
	a := &promAnalysis{expr: expr}
	scope := scopeOf(rule.Meta.Scope)
	if scope != bundle.ScopeNode && scope != bundle.ScopeCluster {
		return nil, reject(id, "unknown scope %q", scope)
	}
	var kubeNames, nodeNames []string
	var walkErr error
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if n == nil {
			return nil
		}
		a.complexity++
		if walkErr != nil {
			return nil
		}
		switch x := n.(type) {
		case *parser.Call:
			if isAbsent(x.Func.Name) {
				a.hasAbsent = true
			}
		case *parser.SubqueryExpr:
			if x.Timestamp != nil || x.StartOrEnd != 0 {
				walkErr = reject(id, "the @ modifier is not supported in rules")
			} else if x.OriginalOffset < 0 {
				walkErr = reject(id, "negative offsets are not supported in rules")
			}
		case *parser.VectorSelector:
			if x.Timestamp != nil || x.StartOrEnd != 0 {
				walkErr = reject(id, "the @ modifier is not supported in rules")
				return nil
			}
			if x.OriginalOffset < 0 {
				walkErr = reject(id, "negative offsets are not supported in rules")
				return nil
			}
			name := selectorName(x)
			switch {
			case name == "":
				walkErr = reject(id, "selector %s must name its metric literally", x.String())
			case strings.HasPrefix(name, "kube_"):
				if !opts.KubeSubset[name] {
					walkErr = reject(id, "%s is not in the published kube_* subset; %s", name, stateRulePointer(name))
					return nil
				}
				if scope == bundle.ScopeNode && !nodeScopedKube(name) {
					walkErr = reject(id, "%s is not node-scoped: node-local rules may join only kube_pod_* and kube_node_* series; use a cluster rule over kube_* series only, or %s", name, stateRulePointer(name))
					return nil
				}
				kubeNames = append(kubeNames, name)
			default:
				nodeNames = append(nodeNames, name)
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if max := effectiveBudget(rule.Meta.Budget, opts.Policy).MaxComplexity; a.complexity > max {
		return nil, reject(id, "expression complexity %d exceeds the budget of %d nodes", a.complexity, max)
	}
	if scope == bundle.ScopeNode {
		return a, nil
	}
	if a.hasAbsent {
		return nil, reject(id, "absent and absent_over_time are not allowed in cluster rules: a missing series cannot be told apart from a node that did not contribute; evaluate it as a node-local rule")
	}
	if len(nodeNames) == 0 && len(kubeNames) == 0 {
		return nil, reject(id, "cluster rule selects no series")
	}
	if len(nodeNames) == 0 {
		a.split = &Split{CoordExpr: expr.String()}
		return a, nil
	}
	if len(kubeNames) > 0 {
		return nil, reject(id, "cluster rule joins node series (%s) with kube_* series (%s): such joins must be node-local over kube_pod_* and kube_node_* series", nodeNames[0], kubeNames[0])
	}
	d := &decomposer{id: id, version: rule.Meta.Version}
	coord, err := d.coord(expr)
	if err != nil {
		return nil, err
	}
	s := &Split{NodeExpr: d.node, CoordExpr: coord, Outer: d.agg.Op.String(), Grouping: slices.Clone(d.agg.Grouping), Without: d.agg.Without}
	for _, e := range []string{s.NodeExpr, s.CoordExpr} {
		if _, err := promParser.ParseExpr(e); err != nil {
			return nil, reject(id, "decomposition produced an invalid expression %q: %v", e, err)
		}
	}
	a.split = s
	return a, nil
}

type decomposer struct {
	id      string
	version int
	agg     *parser.AggregateExpr
	node    string
}

func unparen(e parser.Expr) parser.Expr {
	for {
		p, ok := e.(*parser.ParenExpr)
		if !ok {
			return e
		}
		e = p.Expr
	}
}

func selects(e parser.Node) bool {
	found := false
	parser.Inspect(e, func(n parser.Node, _ []parser.Node) error {
		switch n.(type) {
		case *parser.VectorSelector, *parser.MatrixSelector:
			found = true
		}
		return nil
	})
	return found
}

func (d *decomposer) coord(e parser.Expr) (string, error) {
	switch n := e.(type) {
	case *parser.ParenExpr:
		s, err := d.coord(n.Expr)
		return "(" + s + ")", err
	case *parser.BinaryExpr:
		lv, rv := n.LHS.Type() == parser.ValueTypeVector, n.RHS.Type() == parser.ValueTypeVector
		if lv && rv {
			return "", reject(d.id, "binary operation %q between two vectors is not decomposable: a cluster rule applies scalar arithmetic or a scalar comparison to one aggregation", n.Op.String())
		}
		if !n.Op.IsComparisonOperator() && !isArithmetic(n.Op) {
			return "", reject(d.id, "operator %q is not decomposable in a cluster rule", n.Op.String())
		}
		vec, sc := n.LHS, n.RHS
		if rv {
			vec, sc = n.RHS, n.LHS
		}
		if selects(sc) {
			return "", reject(d.id, "scalar operand %s must not select series in a cluster rule", sc.String())
		}
		vs, err := d.coord(vec)
		if err != nil {
			return "", err
		}
		op := n.Op.String()
		if n.ReturnBool {
			op += " bool"
		}
		if rv {
			return "(" + sc.String() + ") " + op + " (" + vs + ")", nil
		}
		return "(" + vs + ") " + op + " (" + sc.String() + ")", nil
	case *parser.Call:
		if n.Func.Name != "histogram_quantile" || d.agg != nil {
			return "", reject(d.id, "function %s is not decomposable across nodes; cluster rules aggregate per-node rate, increase, or *_over_time with sum, count, min, max, or avg", n.Func.Name)
		}
		if selects(n.Args[0]) {
			return "", reject(d.id, "histogram_quantile quantile %s must not select series", n.Args[0].String())
		}
		agg, ok := unparen(n.Args[1]).(*parser.AggregateExpr)
		if !ok || agg.Op != parser.SUM {
			return "", reject(d.id, "histogram_quantile in a cluster rule must apply to sum by (le, ...) of per-node rate or increase over bucket series")
		}
		if hasLe := slices.Contains(agg.Grouping, "le"); hasLe == agg.Without {
			return "", reject(d.id, "histogram buckets must be summed per bucket: the sum must keep the le label")
		}
		s, err := d.aggregate(agg)
		if err != nil {
			return "", err
		}
		return "histogram_quantile(" + n.Args[0].String() + ", " + s + ")", nil
	case *parser.AggregateExpr:
		return d.aggregate(n)
	case *parser.VectorSelector, *parser.MatrixSelector:
		return "", reject(d.id, "raw series %s cannot be evaluated across nodes: wrap it in an outer sum, count, min, max, or avg over rate, increase, or *_over_time", n.String())
	}
	return "", reject(d.id, "%s is not a decomposable cluster form", e.String())
}

func isArithmetic(op parser.ItemType) bool {
	switch op {
	case parser.ADD, parser.SUB, parser.MUL, parser.DIV, parser.MOD, parser.POW:
		return true
	}
	return false
}

func (d *decomposer) aggregate(a *parser.AggregateExpr) (string, error) {
	if d.agg != nil {
		return "", reject(d.id, "nested aggregation %s is not decomposable", a.Op.String())
	}
	switch a.Op {
	case parser.SUM, parser.COUNT, parser.MIN, parser.MAX, parser.AVG:
	case parser.QUANTILE:
		return "", reject(d.id, "quantile is not decomposable across nodes: per-node quantiles cannot be combined; use histogram_quantile over sum by (le) (rate(<bucket series>[range]))")
	case parser.TOPK, parser.BOTTOMK:
		return "", reject(d.id, "%s over raw series is not decomposable across nodes: the coordinator only sees per-node aggregates; evaluate it as a node-local rule", a.Op.String())
	case parser.STDDEV, parser.STDVAR:
		return "", reject(d.id, "%s is not decomposable across nodes; supported outer aggregations are sum, count, min, max, and avg", a.Op.String())
	default:
		return "", reject(d.id, "aggregation %s is not decomposable across nodes; supported outer aggregations are sum, count, min, max, and avg", a.Op.String())
	}
	inner := unparen(a.Expr)
	if err := d.checkInner(inner); err != nil {
		return "", err
	}
	d.agg = a
	grp := groupingClause(a.Grouping, a.Without)
	nodeAgg := func(op string) string { return op + " " + grp + "(" + inner.String() + ")" }
	cg := grp
	if a.Without {
		cg = groupingClause(append(slices.Clone(a.Grouping), LabelNode, LabelRule, LabelRuleVersion, LabelPart), true)
	}
	sel := func(part string) string { return d.selector(part) }
	switch a.Op {
	case parser.SUM:
		d.node = nodeAgg("sum")
		return "sum " + cg + "(" + sel("") + ")", nil
	case parser.COUNT:
		d.node = nodeAgg("count")
		return "sum " + cg + "(" + sel("") + ")", nil
	case parser.MIN:
		d.node = nodeAgg("min")
		return "min " + cg + "(" + sel("") + ")", nil
	case parser.MAX:
		d.node = nodeAgg("max")
		return "max " + cg + "(" + sel("") + ")", nil
	}
	part := strconv.Quote(LabelPart)
	d.node = "label_replace(" + nodeAgg("sum") + ", " + part + ", \"sum\", \"\", \"\") or label_replace(" + nodeAgg("count") + ", " + part + ", \"count\", \"\", \"\")"
	return "(sum " + cg + "(" + sel("sum") + ") / sum " + cg + "(" + sel("count") + "))", nil
}

func (d *decomposer) checkInner(e parser.Expr) error {
	call, ok := e.(*parser.Call)
	if !ok {
		return reject(d.id, "inner expression %s must be a per-node rate, increase, or *_over_time over a range selector", e.String())
	}
	name := call.Func.Name
	if name != "rate" && name != "increase" && (!strings.HasSuffix(name, "_over_time") || isAbsent(name)) {
		return reject(d.id, "inner function %s is not per-node decomposable; use rate, increase, or *_over_time", name)
	}
	for i, arg := range call.Args {
		if i == len(call.Args)-1 {
			if _, ok := arg.(*parser.MatrixSelector); !ok {
				return reject(d.id, "inner function %s must take a range selector, not %s", name, arg.String())
			}
			continue
		}
		if selects(arg) {
			return reject(d.id, "parameter %s of %s must not select series", arg.String(), name)
		}
	}
	return nil
}

func (d *decomposer) selector(part string) string {
	ms := []string{
		LabelRule + "=" + strconv.Quote(d.id),
		LabelRuleVersion + "=" + strconv.Quote(strconv.Itoa(d.version)),
	}
	if part != "" {
		ms = append(ms, LabelPart+"="+strconv.Quote(part))
	}
	return SplitMetric + "{" + strings.Join(ms, ",") + "}"
}

var legacyLabel = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func groupingClause(g []string, without bool) string {
	if len(g) == 0 && !without {
		return ""
	}
	q := make([]string, len(g))
	for i, l := range g {
		if legacyLabel.MatchString(l) {
			q[i] = l
		} else {
			q[i] = strconv.Quote(l)
		}
	}
	kw := "by"
	if without {
		kw = "without"
	}
	return kw + " (" + strings.Join(q, ", ") + ") "
}

// PartSeries labels a node's part with rule, version, and node for the coordinator's MemSeries.
func PartSeries(node string, p Part) []Series {
	out := make([]Series, 0, len(p.Vector))
	t := timestamp.FromTime(p.EvalTime)
	for _, s := range p.Vector {
		if s.H != nil {
			continue
		}
		lb := labels.NewBuilder(s.Metric)
		lb.Set(labels.MetricName, SplitMetric)
		lb.Set(LabelRule, p.RuleID)
		lb.Set(LabelRuleVersion, strconv.Itoa(p.RuleVersion))
		lb.Set(LabelNode, node)
		out = append(out, Series{Labels: lb.Labels(), Samples: []Sample{{T: t, F: s.F}}})
	}
	return out
}
