package engine

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// inFunc is the internal name of in(r, edgeType); in is a CEL keyword.
const inFunc = "_in"

type edgeRef struct {
	uid   string
	attrs map[string]any
}

// graph indexes one state snapshot for CEL evaluation.
type graph struct {
	st   *protocol.State
	out  map[string]map[string][]edgeRef
	in   map[string]map[string][]edgeRef
	vals map[string]ref.Val
}

func newGraph(st *protocol.State) *graph {
	g := &graph{st: st, out: map[string]map[string][]edgeRef{}, in: map[string]map[string][]edgeRef{}, vals: map[string]ref.Val{}}
	add := func(idx map[string]map[string][]edgeRef, from, typ, to string, attrs map[string]any) {
		m := idx[from]
		if m == nil {
			m = map[string][]edgeRef{}
			idx[from] = m
		}
		m[typ] = append(m[typ], edgeRef{uid: to, attrs: attrs})
	}
	for k, attrs := range st.Edges {
		add(g.out, k.From, k.Type, k.To, attrs)
		add(g.in, k.To, k.Type, k.From, attrs)
	}
	for _, idx := range []map[string]map[string][]edgeRef{g.out, g.in} {
		for _, m := range idx {
			for _, l := range m {
				sort.Slice(l, func(i, j int) bool { return l[i].uid < l[j].uid })
			}
		}
	}
	return g
}

func resourceMap(r *protocol.Resource) map[string]any {
	fields := r.Fields
	if fields == nil {
		fields = map[string]any{}
	}
	return map[string]any{"uid": r.UID, "kind": r.Kind, "namespace": r.Namespace, "name": r.Name, "fields": fields}
}

func (g *graph) value(r *protocol.Resource) ref.Val {
	if v, ok := g.vals[r.UID]; ok {
		return v
	}
	v := types.DefaultTypeAdapter.NativeToValue(resourceMap(r))
	g.vals[r.UID] = v
	return v
}

func (g *graph) related(rv, tv ref.Val, outgoing bool) ref.Val {
	m, ok := rv.(traits.Mapper)
	if !ok {
		return types.NewErr("related resources need a resource map, got %s", rv.Type())
	}
	uv, found := m.Find(types.String("uid"))
	if !found {
		return types.NewErr("resource map has no uid")
	}
	uid, _ := uv.Value().(string)
	typ, _ := tv.Value().(string)
	idx := g.in
	if outgoing {
		idx = g.out
	}
	var vals []ref.Val
	for _, e := range idx[uid][typ] {
		r, ok := g.st.Resources[e.uid]
		if !ok {
			continue
		}
		rm := resourceMap(r)
		attrs := e.attrs
		if attrs == nil {
			attrs = map[string]any{}
		}
		rm["edge"] = attrs
		vals = append(vals, types.DefaultTypeAdapter.NativeToValue(rm))
	}
	return types.NewRefValList(types.DefaultTypeAdapter, vals)
}

// graphHolder gives the CEL function bindings the snapshot of the running cycle.
type graphHolder struct{ g *graph }

func (h *graphHolder) related(rv, tv ref.Val, outgoing bool) ref.Val {
	if h.g == nil {
		return types.NewErr("no state snapshot is available")
	}
	return h.g.related(rv, tv, outgoing)
}

func fieldVal(args ...ref.Val) ref.Val {
	def := args[2]
	m, ok := args[0].(traits.Mapper)
	if !ok {
		return def
	}
	fv, found := m.Find(types.String("fields"))
	if !found {
		return def
	}
	cur, ok := fv.(traits.Mapper)
	if !ok {
		return def
	}
	path, _ := args[1].Value().(string)
	if v, found := cur.Find(types.String(path)); found {
		return v
	}
	parts := strings.Split(path, ".")
	for i, p := range parts {
		v, found := cur.Find(types.String(p))
		if !found {
			return def
		}
		if i == len(parts)-1 {
			return v
		}
		if cur, ok = v.(traits.Mapper); !ok {
			return def
		}
	}
	return def
}

// lookupField resolves a field path as an exact key first, then as a dotted path through nested maps.
func lookupField(fields map[string]any, path string) (any, bool) {
	if v, ok := fields[path]; ok {
		return v, true
	}
	cur := fields
	parts := strings.Split(path, ".")
	for i, p := range parts {
		v, ok := cur[p]
		if !ok {
			return nil, false
		}
		if i == len(parts)-1 {
			return v, true
		}
		if cur, ok = v.(map[string]any); !ok {
			return nil, false
		}
	}
	return nil, false
}

func newCELEnv(h *graphHolder) (*cel.Env, error) {
	res := cel.MapType(cel.StringType, cel.DynType)
	return cel.NewEnv(
		cel.Variable("r", res),
		cel.Variable("now", cel.TimestampType),
		cel.CrossTypeNumericComparisons(true),
		cel.DefaultUTCTimeZone(true),
		ext.Strings(),
		ext.Math(),
		cel.Function("out", cel.Overload("out_resource_string", []*cel.Type{res, cel.StringType}, cel.ListType(res),
			cel.BinaryBinding(func(r, t ref.Val) ref.Val { return h.related(r, t, true) }))),
		cel.Function(inFunc, cel.Overload("in_resource_string", []*cel.Type{res, cel.StringType}, cel.ListType(res),
			cel.BinaryBinding(func(r, t ref.Val) ref.Val { return h.related(r, t, false) }))),
		cel.Function("field", cel.Overload("field_resource_string_dyn", []*cel.Type{res, cel.StringType, cel.DynType}, cel.DynType,
			cel.FunctionBinding(fieldVal))),
	)
}

// rewriteIn renames in(r, t) calls, leaving the membership operator and string literals untouched.
func rewriteIn(src string) string {
	var b strings.Builder
	operand, afterDot := false, false
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case isSpace(c):
			b.WriteByte(c)
			i++
			continue
		case c == '"' || c == '\'':
			j := skipString(src, i, false)
			b.WriteString(src[i:j])
			i, operand = j, true
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			word := src[i:j]
			if j < len(src) && (src[j] == '"' || src[j] == '\'') && isStringPrefix(word) {
				k := skipString(src, j, strings.ContainsAny(word, "rR"))
				b.WriteString(src[i:k])
				i, operand, afterDot = k, true, false
				continue
			}
			k := j
			for k < len(src) && isSpace(src[k]) {
				k++
			}
			if word == "in" && !operand && !afterDot && k < len(src) && src[k] == '(' {
				b.WriteString(inFunc)
				operand = false
			} else {
				b.WriteString(word)
				operand = word != "in"
			}
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (isIdentPart(src[j]) || src[j] == '.') {
				j++
			}
			b.WriteString(src[i:j])
			i, operand = j, true
		default:
			b.WriteByte(c)
			i++
			operand = c == ')' || c == ']' || c == '}'
			afterDot = c == '.'
			continue
		}
		afterDot = false
	}
	return b.String()
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isIdentStart(c byte) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isIdentPart(c byte) bool  { return isIdentStart(c) || (c >= '0' && c <= '9') }

func isStringPrefix(w string) bool {
	switch strings.ToLower(w) {
	case "r", "b", "rb", "br":
		return true
	}
	return false
}

func skipString(src string, i int, raw bool) int {
	q := src[i]
	if strings.HasPrefix(src[i:], strings.Repeat(string(q), 3)) {
		end := strings.Repeat(string(q), 3)
		j := i + 3
		for j < len(src) {
			if !raw && src[j] == '\\' {
				j += 2
				continue
			}
			if strings.HasPrefix(src[j:], end) {
				return j + 3
			}
			j++
		}
		return len(src)
	}
	j := i + 1
	for j < len(src) {
		if !raw && src[j] == '\\' {
			j += 2
			continue
		}
		if src[j] == q {
			return j + 1
		}
		j++
	}
	return len(src)
}

type labelProg struct {
	name string
	lit  string
	prog cel.Program
}

type stateProgram struct {
	prog   cel.Program
	labels []labelProg
	cost   uint64
}

func celComplexity(a *cel.Ast) int {
	n := 0
	ast.PostOrderVisit(a.NativeRep().Expr(), ast.NewExprVisitor(func(ast.Expr) { n++ }))
	return n
}

func compileCEL(env *cel.Env, id, src string, b bundle.Budget, wantBool bool) (cel.Program, int, error) {
	a, iss := env.Compile(rewriteIn(src))
	if iss != nil && iss.Err() != nil {
		return nil, 0, reject(id, "CEL compile error in %q: %v", src, iss.Err())
	}
	if wantBool {
		if t := a.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
			return nil, 0, reject(id, "expression returns %s, want bool", t)
		}
	}
	n := celComplexity(a)
	if n > b.MaxComplexity {
		return nil, n, reject(id, "expression complexity %d exceeds the budget of %d nodes", n, b.MaxComplexity)
	}
	prog, err := env.Program(a, cel.CostLimit(uint64(b.MaxSamples)), cel.InterruptCheckFrequency(64))
	if err != nil {
		return nil, n, reject(id, "CEL program error: %v", err)
	}
	return prog, n, nil
}

func compileState(env *cel.Env, rule bundle.StateRule, b bundle.Budget) (*stateProgram, error) {
	id := stateID(rule)
	if len(rule.Kinds) == 0 {
		return nil, reject(id, "state rule lists no kinds")
	}
	if rule.For < 0 || rule.KeepFiringFor < 0 || rule.Interval < 0 {
		return nil, reject(id, "for, keep_firing_for, and interval must not be negative")
	}
	prog, total, err := compileCEL(env, id, rule.Expr, b, true)
	if err != nil {
		return nil, err
	}
	sp := &stateProgram{prog: prog, cost: uint64(b.MaxSamples)}
	names := make([]string, 0, len(rule.Labels))
	for k := range rule.Labels {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := rule.Labels[k]
		if !strings.HasPrefix(v, "=") {
			sp.labels = append(sp.labels, labelProg{name: k, lit: v})
			continue
		}
		p, n, err := compileCEL(env, id, v[1:], b, false)
		if err != nil {
			return nil, err
		}
		if total += n; total > b.MaxComplexity {
			return nil, reject(id, "expression complexity %d including label expressions exceeds the budget of %d nodes", total, b.MaxComplexity)
		}
		sp.labels = append(sp.labels, labelProg{name: k, prog: p})
	}
	return sp, nil
}

// ValidateCEL compiles a state rule and its label expressions and checks the complexity budget.
func ValidateCEL(rule bundle.StateRule) error {
	env, err := newCELEnv(&graphHolder{})
	if err != nil {
		return err
	}
	_, err = compileState(env, rule, effectiveBudget(rule.Meta.Budget, Policy{}))
	return err
}

var errBudget = errors.New("budget exceeded")

func isCELCancel(err error) bool {
	var c interpreter.EvalCancelledError
	return errors.As(err, &c)
}

func celString(v ref.Val) string {
	switch x := v.Value().(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case time.Duration:
		return x.String()
	}
	return fmt.Sprint(v.Value())
}
