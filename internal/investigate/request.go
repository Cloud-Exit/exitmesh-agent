package investigate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Error classes reported in results and audit records.
const (
	ClassInvalid        = "invalid_request"
	ClassUnauthorized   = "unauthorized"
	ClassUnavailable    = "unavailable"
	ClassTimeout        = "timeout"
	ClassBusy           = "busy"
	ClassSourceRejected = "source_rejected"
	ClassInternal       = "internal"
)

// Scope label names injected into telemetry queries.
const (
	NamespaceLabel = "namespace"
	PodLabel       = "pod"
	NodeLabel      = "node"
)

// Error is a rejected or failed tool call with a class for audit.
type Error struct {
	Class string
	Msg   string
}

func (e *Error) Error() string { return "investigate: " + e.Msg }

func errorf(class, format string, a ...any) *Error {
	return &Error{Class: class, Msg: fmt.Sprintf(format, a...)}
}

func errClass(err error) string {
	var e *Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &e):
		return e.Class
	case errors.Is(err, context.DeadlineExceeded):
		return ClassTimeout
	}
	return ClassInternal
}

// Scope binds a request to namespaces, resources, and nodes; Cluster asserts a cluster-wide requester.
type Scope struct {
	Cluster    bool          `json:"cluster,omitempty"`
	Namespaces []string      `json:"namespaces,omitempty"`
	Resources  []ResourceRef `json:"resources,omitempty"`
	Nodes      []string      `json:"nodes,omitempty"`
}

// ResourceRef names a resource by UID or by kind, namespace, and name.
type ResourceRef struct {
	UID       string `json:"uid,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// Window is an inclusive time range in Unix milliseconds.
type Window struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

// Limits are requested or effective bounds; zero requests the configured maximum.
type Limits struct {
	MaxLines   int   `json:"max_lines,omitempty"`
	MaxBytes   int64 `json:"max_bytes,omitempty"`
	MaxSeries  int   `json:"max_series,omitempty"`
	MaxSamples int   `json:"max_samples,omitempty"`
	TimeoutMs  int64 `json:"timeout_ms,omitempty"`
}

// Request holds the fields every tool call carries.
type Request struct {
	RequestID string  `json:"request_id,omitempty"`
	Requester string  `json:"requester"`
	Purpose   string  `json:"purpose"`
	Scope     Scope   `json:"scope"`
	Window    *Window `json:"window,omitempty"`
	Limits    Limits  `json:"limits"`
}

var (
	namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	nodeRE      = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9._]*[A-Za-z0-9])?$`)
	requestIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

const (
	maxScopeEntries = 256
	maxFutureSkew   = 5 * time.Minute
)

func defaultLimits(l config.Investigation) config.Investigation {
	set := func(p *int, d int) {
		if *p <= 0 {
			*p = d
		}
	}
	set(&l.MaxConcurrency, 4)
	set(&l.MaxLines, 5000)
	set(&l.MaxSeries, 1000)
	set(&l.MaxSamples, 500000)
	if l.Timeout <= 0 {
		l.Timeout = config.Duration(30 * time.Second)
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = 4 << 20
	}
	if l.MaxWindow <= 0 {
		l.MaxWindow = config.Duration(6 * time.Hour)
	}
	return l
}

// clampLimits applies configured maxima; zero means the maximum and negative is rejected.
func clampLimits(req Limits, max config.Investigation) (Limits, error) {
	if req.MaxLines < 0 || req.MaxBytes < 0 || req.MaxSeries < 0 || req.MaxSamples < 0 || req.TimeoutMs < 0 {
		return Limits{}, errorf(ClassInvalid, "limits must not be negative")
	}
	pick := func(v, m int64) int64 {
		if v == 0 || v > m {
			return m
		}
		return v
	}
	return Limits{
		MaxLines:   int(pick(int64(req.MaxLines), int64(max.MaxLines))),
		MaxBytes:   pick(req.MaxBytes, int64(max.MaxBytes)),
		MaxSeries:  int(pick(int64(req.MaxSeries), int64(max.MaxSeries))),
		MaxSamples: int(pick(int64(req.MaxSamples), int64(max.MaxSamples))),
		TimeoutMs:  pick(req.TimeoutMs, max.Timeout.D().Milliseconds()),
	}, nil
}

func (l Limits) timeout() time.Duration { return time.Duration(l.TimeoutMs) * time.Millisecond }

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (r *Request) validate() error {
	if r.RequestID == "" {
		r.RequestID = newRequestID()
	} else if !requestIDRE.MatchString(r.RequestID) {
		return errorf(ClassInvalid, "request_id must be 1 to 64 characters of [A-Za-z0-9_.:-]")
	}
	if strings.TrimSpace(r.Requester) == "" || len(r.Requester) > 256 {
		return errorf(ClassInvalid, "requester is required (at most 256 bytes)")
	}
	if strings.TrimSpace(r.Purpose) == "" || len(r.Purpose) > 1024 {
		return errorf(ClassInvalid, "purpose is required (at most 1024 bytes)")
	}
	sc := &r.Scope
	if len(sc.Namespaces)+len(sc.Resources)+len(sc.Nodes) > maxScopeEntries {
		return errorf(ClassInvalid, "scope has more than %d entries", maxScopeEntries)
	}
	if !sc.Cluster && len(sc.Namespaces)+len(sc.Resources)+len(sc.Nodes) == 0 {
		return errorf(ClassUnauthorized, "scope must name namespaces, resources, or nodes unless the requester's scope is cluster-wide")
	}
	for _, ns := range sc.Namespaces {
		if len(ns) > 63 || !namespaceRE.MatchString(ns) {
			return errorf(ClassInvalid, "scope namespace %q is not a valid namespace name", ns)
		}
	}
	for _, n := range sc.Nodes {
		if len(n) > 253 || !nodeRE.MatchString(n) {
			return errorf(ClassInvalid, "scope node %q is not a valid node name", n)
		}
	}
	for _, ref := range sc.Resources {
		if err := ref.validate(); err != nil {
			return err
		}
	}
	sc.Namespaces = sortedUnique(sc.Namespaces)
	sc.Nodes = sortedUnique(sc.Nodes)
	return nil
}

func (ref ResourceRef) validate() error {
	if ref.UID != "" {
		if len(ref.UID) > 128 {
			return errorf(ClassInvalid, "resource uid is too long")
		}
		return nil
	}
	if ref.Kind == "" || ref.Name == "" {
		return errorf(ClassInvalid, "a resource needs a uid or a kind and name")
	}
	if ref.Namespace != "" && !namespaceRE.MatchString(ref.Namespace) {
		return errorf(ClassInvalid, "resource namespace %q is not a valid namespace name", ref.Namespace)
	}
	return nil
}

func (w *Window) validate(maxWindow time.Duration, now time.Time) (time.Time, time.Time, error) {
	if w == nil {
		return time.Time{}, time.Time{}, errorf(ClassInvalid, "window is required")
	}
	if w.Start <= 0 || w.End <= 0 || w.Start > w.End {
		return time.Time{}, time.Time{}, errorf(ClassInvalid, "window needs 0 < start <= end in Unix milliseconds")
	}
	start, end := time.UnixMilli(w.Start), time.UnixMilli(w.End)
	if end.Sub(start) > maxWindow {
		return time.Time{}, time.Time{}, errorf(ClassInvalid, "window %s exceeds the maximum %s", end.Sub(start), maxWindow)
	}
	if end.After(now.Add(maxFutureSkew)) {
		return time.Time{}, time.Time{}, errorf(ClassInvalid, "window ends in the future")
	}
	return start, end, nil
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// resolvedScope is a validated scope with resources looked up in current state.
type resolvedScope struct {
	cluster    bool
	namespaces map[string]bool
	nodes      map[string]bool
	uids       map[string]bool
	resources  []*protocol.Resource
}

func resolveScope(sc Scope, st *protocol.State) (*resolvedScope, error) {
	rs := &resolvedScope{cluster: sc.Cluster, namespaces: map[string]bool{}, nodes: map[string]bool{}, uids: map[string]bool{}}
	for _, ns := range sc.Namespaces {
		rs.namespaces[ns] = true
	}
	for _, n := range sc.Nodes {
		rs.nodes[n] = true
	}
	for _, ref := range sc.Resources {
		r, err := lookupResource(st, ref)
		if err != nil {
			return nil, err
		}
		if !rs.uids[r.UID] {
			rs.uids[r.UID] = true
			rs.resources = append(rs.resources, r)
		}
	}
	return rs, nil
}

func lookupResource(st *protocol.State, ref ResourceRef) (*protocol.Resource, error) {
	if st == nil {
		return nil, errorf(ClassUnavailable, "resource scope cannot be resolved: no current state")
	}
	if ref.UID != "" {
		if r := st.Resources[ref.UID]; r != nil {
			return r, nil
		}
		return nil, errorf(ClassUnauthorized, "resource %s is not in current state", ref.UID)
	}
	for _, r := range st.Resources {
		if r.Kind == ref.Kind && r.Namespace == ref.Namespace && r.Name == ref.Name {
			return r, nil
		}
	}
	return nil, errorf(ClassUnauthorized, "resource %s %s/%s is not in current state", ref.Kind, ref.Namespace, ref.Name)
}

// telemetryBinding maps the scope to label values; namespaces, nodes, and pods intersect, so the binding never widens.
func (rs *resolvedScope) telemetryBinding(st *protocol.State) (telemetryScope, error) {
	nsSet := maps.Clone(rs.namespaces)
	var pods []*protocol.Resource
	var g *podGraph
	for _, r := range rs.resources {
		switch r.Kind {
		case kindNamespace:
			nsSet[r.Name] = true
		case kindNode:
		case kindPod:
			pods = append(pods, r)
		default:
			if g == nil {
				g = newPodGraph(st)
			}
			related := g.pods(r)
			if len(related) == 0 {
				return telemetryScope{}, errorf(ClassUnauthorized, "resource %s %s/%s relates to no pods in current state, so its telemetry cannot be bound to labels", r.Kind, r.Namespace, r.Name)
			}
			pods = append(pods, related...)
		}
	}
	t := telemetryScope{namespaces: setKeys(nsSet), nodes: rs.telemetryNodes()}
	if len(pods) == 0 {
		return t, nil
	}
	byNS := map[string]map[string]bool{}
	for _, p := range pods {
		if len(nsSet) > 0 && !nsSet[p.Namespace] {
			continue
		}
		if byNS[p.Namespace] == nil {
			byNS[p.Namespace] = map[string]bool{}
		}
		byNS[p.Namespace][p.Name] = true
	}
	switch {
	case len(byNS) == 0:
		return telemetryScope{}, errorf(ClassUnauthorized, "scope namespaces %v contain none of the scoped resources' pods", t.namespaces)
	case len(byNS) > 1:
		return telemetryScope{}, errorf(ClassUnauthorized, "scoped resources have pods in namespaces %v; a telemetry query binds the pods of one namespace", slices.Sorted(maps.Keys(byNS)))
	}
	for ns, names := range byNS {
		t.namespaces, t.pods = []string{ns}, setKeys(names)
	}
	if len(t.pods) > maxScopeEntries {
		return telemetryScope{}, errorf(ClassInvalid, "scoped resources relate to %d pods, more than %d", len(t.pods), maxScopeEntries)
	}
	return t, nil
}

// podEdges lead from a scoped resource toward pods: true follows an edge forward, false against it.
var podEdges = map[string]bool{
	"owns": true, "selects": true, "targets": true, "guards": true, "routes": true, "scales": true,
	"mounts": false, "binds": false,
}

const maxPodWalkDepth = 4

type podGraph struct {
	st  *protocol.State
	adj map[string][]string
}

func newPodGraph(st *protocol.State) *podGraph {
	g := &podGraph{st: st, adj: map[string][]string{}}
	for k := range st.Edges {
		forward, ok := podEdges[k.Type]
		switch {
		case !ok:
		case forward:
			g.adj[k.From] = append(g.adj[k.From], k.To)
		default:
			g.adj[k.To] = append(g.adj[k.To], k.From)
		}
	}
	return g
}

// pods walks owners, selectors, policies, routes, scale targets, and volume claims from r to its pods, never past a pod.
func (g *podGraph) pods(r *protocol.Resource) []*protocol.Resource {
	seen := map[string]bool{r.UID: true}
	frontier := []string{r.UID}
	var out []*protocol.Resource
	for d := 0; d < maxPodWalkDepth && len(frontier) > 0; d++ {
		var next []string
		for _, uid := range frontier {
			for _, n := range g.adj[uid] {
				if seen[n] {
					continue
				}
				seen[n] = true
				switch nr := g.st.Resources[n]; {
				case nr == nil:
				case nr.Kind == kindPod:
					out = append(out, nr)
				case nr.Kind != kindNamespace && nr.Kind != kindNode:
					next = append(next, n)
				}
			}
		}
		frontier = next
	}
	return out
}

func (rs *resolvedScope) telemetryNodes() []string {
	set := map[string]bool{}
	for n := range rs.nodes {
		set[n] = true
	}
	for _, r := range rs.resources {
		if r.Kind == kindNode {
			set[r.Name] = true
		}
	}
	return setKeys(set)
}

// contains reports whether a state resource is visible to the scope.
func (rs *resolvedScope) contains(r *protocol.Resource) bool {
	if rs.cluster && len(rs.namespaces) == 0 && len(rs.nodes) == 0 && len(rs.uids) == 0 {
		return true
	}
	if rs.uids[r.UID] || (r.Namespace != "" && rs.namespaces[r.Namespace]) {
		return true
	}
	switch r.Kind {
	case kindNamespace:
		return rs.namespaces[r.Name]
	case kindNode:
		return rs.nodes[r.Name]
	case kindPod:
		n, _ := r.Fields["nodeName"].(string)
		return n != "" && rs.nodes[n]
	}
	return false
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

const (
	kindNamespace = "Namespace"
	kindNode      = "Node"
	kindPod       = "Pod"
)

// scopeMatcher builds an equality or anchored alternation matcher over literal values.
func scopeMatcher(name string, values []string) *labels.Matcher {
	if len(values) == 1 {
		return labels.MustNewMatcher(labels.MatchEqual, name, values[0])
	}
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = regexp.QuoteMeta(v)
	}
	return labels.MustNewMatcher(labels.MatchRegexp, name, strings.Join(quoted, "|"))
}

// telemetryScope is the label binding for telemetry queries; pods are names within the one namespace.
type telemetryScope struct {
	namespaces []string
	pods       []string
	nodes      []string
}

func (t telemetryScope) matchers() []*labels.Matcher {
	var m []*labels.Matcher
	if len(t.namespaces) > 0 {
		m = append(m, scopeMatcher(NamespaceLabel, t.namespaces))
	}
	if len(t.pods) > 0 {
		m = append(m, scopeMatcher(PodLabel, t.pods))
	}
	if len(t.nodes) > 0 {
		m = append(m, scopeMatcher(NodeLabel, t.nodes))
	}
	return m
}

func decodeStrict(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errorf(ClassInvalid, "arguments: %v", err)
	}
	if dec.More() {
		return errorf(ClassInvalid, "arguments: trailing data")
	}
	return nil
}
