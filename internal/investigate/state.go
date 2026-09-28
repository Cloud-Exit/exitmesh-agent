package investigate

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const (
	maxGraphDepth = 5
	sourceState   = "state"
)

// StateResource is one resource in a state.query result.
type StateResource struct {
	UID       string         `json:"uid"`
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace,omitempty"`
	Name      string         `json:"name"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// GraphEdge is one change-graph edge in a graph.query result.
type GraphEdge struct {
	From  string         `json:"from"`
	Type  string         `json:"type"`
	To    string         `json:"to"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

func (c *call) currentState() (*protocol.State, error) {
	if c.state == nil {
		return nil, errorf(ClassUnavailable, "no current state is available")
	}
	return c.state, nil
}

// stateLimitations reports collection scopes that are not complete for the kinds and namespaces asked about.
func stateLimitations(res *Result, st *protocol.State, rs *resolvedScope, kind string) {
	keys := make([]string, 0, len(st.Scopes))
	for k := range st.Scopes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		ss := st.Scopes[k]
		if ss.State == protocol.ScopeComplete {
			continue
		}
		sk, sns, _ := strings.Cut(k, "|")
		if kind != "" && sk != kind {
			continue
		}
		if sns != "" && !rs.cluster && !rs.namespaces[sns] {
			continue
		}
		what := "partial"
		if ss.State == protocol.ScopeUnavailable {
			what = "unavailable"
		}
		res.limit("collection scope %s is %s: %s", k, what, ss.Reason)
	}
}

func fieldAt(fields map[string]any, path string) (any, bool) {
	var cur any = fields
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func jsonEqual(a, b any) bool {
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(ja) == string(jb)
}

func (s *Service) stateQuery(_ context.Context, c *call) (*Result, error) {
	var a struct {
		Request
		Kind      string         `json:"kind,omitempty"`
		Namespace string         `json:"namespace,omitempty"`
		Name      string         `json:"name,omitempty"`
		Fields    map[string]any `json:"fields,omitempty"`
	}
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	st, err := c.currentState()
	if err != nil {
		return nil, err
	}
	if a.Namespace != "" && !c.scope.cluster && !c.scope.namespaces[a.Namespace] &&
		!slices.ContainsFunc(c.scope.resources, func(r *protocol.Resource) bool { return r.Namespace == a.Namespace }) {
		return nil, errorf(ClassUnauthorized, "namespace %s is outside the request scope", a.Namespace)
	}
	res := c.newResult(sourceState, "", "", "")
	if c.req.Window != nil && c.req.Window.End < c.now.UnixMilli()-60_000 {
		res.limit("state.query answers from current state; the requested window is not reconstructed")
	}
	var out []StateResource
	for _, r := range st.Resources {
		if !c.scope.contains(r) || (a.Kind != "" && r.Kind != a.Kind) || (a.Namespace != "" && r.Namespace != a.Namespace) || (a.Name != "" && r.Name != a.Name) {
			continue
		}
		match := true
		for path, want := range a.Fields {
			if got, ok := fieldAt(r.Fields, path); !ok || !jsonEqual(got, want) {
				match = false
				break
			}
		}
		if match {
			out = append(out, StateResource{UID: r.UID, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name, Fields: r.Fields})
		}
	}
	slices.SortFunc(out, func(x, y StateResource) int {
		return strings.Compare(x.Kind+"\x00"+x.Namespace+"\x00"+x.Name+"\x00"+x.UID, y.Kind+"\x00"+y.Namespace+"\x00"+y.Name+"\x00"+y.UID)
	})
	out = boundItems(res, out, "resources")
	stateLimitations(res, st, c.scope, a.Kind)
	res.Data = map[string]any{"resources": nonNil(out)}
	return res, nil
}

// boundItems applies the line and byte limits to structured items.
func boundItems[T any](res *Result, in []T, what string) []T {
	var size int64
	for i, it := range in {
		b, _ := json.Marshal(it)
		if i >= res.Limits.MaxLines || size+int64(len(b)) > res.Limits.MaxBytes {
			res.Truncated = true
			res.limit("result limit reached; %d %s omitted", len(in)-i, what)
			return in[:i]
		}
		size += int64(len(b))
	}
	return in
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (s *Service) graphQuery(_ context.Context, c *call) (*Result, error) {
	var a struct {
		Request
		From      []ResourceRef `json:"from,omitempty"`
		EdgeTypes []string      `json:"edge_types,omitempty"`
		Depth     int           `json:"depth,omitempty"`
		Direction string        `json:"direction,omitempty"`
	}
	if err := decodeStrict(c.raw, &a); err != nil {
		return nil, err
	}
	st, err := c.currentState()
	if err != nil {
		return nil, err
	}
	if a.Depth == 0 {
		a.Depth = 1
	}
	if a.Depth < 0 || a.Depth > maxGraphDepth {
		return nil, errorf(ClassInvalid, "depth must be between 1 and %d", maxGraphDepth)
	}
	out, in := true, true
	switch a.Direction {
	case "", "both":
	case "out":
		in = false
	case "in":
		out = false
	default:
		return nil, errorf(ClassInvalid, "direction must be out, in, or both")
	}
	starts := c.scope.resources
	if len(a.From) > 0 {
		starts = nil
		for _, ref := range a.From {
			if err := ref.validate(); err != nil {
				return nil, err
			}
			r, err := lookupResource(st, ref)
			if err != nil {
				return nil, err
			}
			if !c.scope.contains(r) {
				return nil, errorf(ClassUnauthorized, "resource %s is outside the request scope", r.UID)
			}
			starts = append(starts, r)
		}
	}
	if len(starts) == 0 {
		return nil, errorf(ClassInvalid, "graph.query needs from resources or scope resources")
	}
	visible := func(uid string) bool {
		if r := st.Resources[uid]; r != nil {
			return c.scope.contains(r)
		}
		return c.scope.cluster && len(c.scope.namespaces)+len(c.scope.nodes)+len(c.scope.uids) == 0
	}
	adj := map[string][]protocol.EdgeKey{}
	for k := range st.Edges {
		if len(a.EdgeTypes) > 0 && !slices.Contains(a.EdgeTypes, k.Type) {
			continue
		}
		if out {
			adj[k.From] = append(adj[k.From], k)
		}
		if in {
			adj[k.To] = append(adj[k.To], k)
		}
	}
	seen := map[string]bool{}
	frontier := []string{}
	for _, r := range starts {
		if !seen[r.UID] {
			seen[r.UID] = true
			frontier = append(frontier, r.UID)
		}
	}
	edges := map[protocol.EdgeKey]bool{}
	omitted := map[protocol.EdgeKey]bool{}
	for d := 0; d < a.Depth && len(frontier) > 0; d++ {
		var next []string
		for _, uid := range frontier {
			for _, k := range adj[uid] {
				other := k.To
				if other == uid {
					other = k.From
				}
				if !visible(k.From) || !visible(k.To) {
					omitted[k] = true
					continue
				}
				edges[k] = true
				if !seen[other] {
					seen[other] = true
					next = append(next, other)
				}
			}
		}
		frontier = next
	}
	res := c.newResult(sourceState, "", "", "")
	if len(omitted) > 0 {
		res.limit("%d edges lead outside the request scope and were omitted", len(omitted))
	}
	keys := make([]protocol.EdgeKey, 0, len(edges))
	for k := range edges {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y protocol.EdgeKey) int {
		if x.Less(y) {
			return -1
		}
		if y.Less(x) {
			return 1
		}
		return 0
	})
	ge := make([]GraphEdge, len(keys))
	for i, k := range keys {
		ge[i] = GraphEdge{From: k.From, Type: k.Type, To: k.To, Attrs: st.Edges[k]}
	}
	ge = boundItems(res, ge, "edges")
	kept := map[string]bool{}
	for _, r := range starts {
		kept[r.UID] = true
	}
	for _, e := range ge {
		kept[e.From], kept[e.To] = true, true
	}
	var rs []StateResource
	for _, uid := range setKeys(kept) {
		if r := st.Resources[uid]; r != nil {
			rs = append(rs, StateResource{UID: r.UID, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name})
		}
	}
	res.Data = map[string]any{"edges": nonNil(ge), "resources": nonNil(rs)}
	return res, nil
}
