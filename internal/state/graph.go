package state

import (
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Edge types of the change graph.
const (
	EdgeOwns            = "owns"
	EdgeUsesSecret      = "uses-secret"
	EdgeProducesSecret  = "produces-secret"
	EdgeNeedsSecretSync = "needs-secret-sync"
	EdgeRunsOn          = "runs-on"
	EdgeSelects         = "selects"
	EdgeMounts          = "mounts"
	EdgeBinds           = "binds"
	EdgeRoutes          = "routes"
	EdgeTargets         = "targets"
	EdgeScales          = "scales"
	EdgeGuards          = "guards"
)

var edgeDocs = [][4]string{
	{EdgeNeedsSecretSync, "workload", "ExternalSecret targeting a referenced Secret", "none; exists even when the Secret is missing"},
	{EdgeUsesSecret, "workload", "Secret referenced by its pod spec", "none"},
	{EdgeProducesSecret, "ExternalSecret", "Secret named by spec.target.name", "none"},
	{EdgeOwns, "owner (ownerReferences[].uid)", "owned object", "`controller` (bool)"},
	{EdgeRunsOn, "Pod", "Node (by spec.nodeName)", "none"},
	{EdgeSelects, "Service", "Pod (spec.selector within the namespace)", "`ports`: sorted port names, or port/protocol when unnamed"},
	{EdgeMounts, "Pod", "PersistentVolumeClaim (volumes, ephemeral claims)", "none"},
	{EdgeBinds, "PersistentVolumeClaim", "PersistentVolume (spec.volumeName)", "none"},
	{EdgeRoutes, "networking.k8s.io/Ingress", "Service (backends)", "`ports`: sorted backend ports"},
	{EdgeTargets, "networking.k8s.io/NetworkPolicy", "Pod (spec.podSelector within the namespace)", "none"},
	{EdgeScales, "autoscaling/HorizontalPodAutoscaler", "scale target (spec.scaleTargetRef)", "none"},
	{EdgeGuards, "policy/PodDisruptionBudget", "Pod (spec.selector within the namespace)", "none"},
}

type index map[string]map[string]bool

func (ix index) add(k, uid string) {
	s := ix[k]
	if s == nil {
		s = map[string]bool{}
		ix[k] = s
	}
	s[uid] = true
}

func (ix index) del(k, uid string) {
	if s := ix[k]; s != nil {
		delete(s, uid)
		if len(s) == 0 {
			delete(ix, k)
		}
	}
}

func key2(a, b string) string    { return a + "\x00" + b }
func key3(a, b, c string) string { return a + "\x00" + b + "\x00" + c }

// graph holds the internal entries and the reverse indexes used to resolve edges incrementally.
type graph struct {
	entries         map[string]*entry
	byName          map[objKey]string
	children        index
	podsByNode      index
	podsByNS        index
	podsByLabel     index
	selectors       index
	claimUsers      index
	volumeUsers     index
	routeUsers      index
	scaleUsers      index
	secretUsers     index
	secretProducers index
}

func newGraph() *graph {
	return &graph{
		entries: map[string]*entry{}, byName: map[objKey]string{},
		children: index{}, podsByNode: index{}, podsByNS: index{}, podsByLabel: index{}, selectors: index{},
		claimUsers: index{}, volumeUsers: index{}, routeUsers: index{}, scaleUsers: index{}, secretUsers: index{}, secretProducers: index{},
	}
}

func keyOf(r *protocol.Resource) objKey { return objKey{r.Kind, r.Namespace, r.Name} }

func (g *graph) put(e *entry) {
	if old := g.entries[e.res.UID]; old != nil {
		g.unindex(old)
	}
	g.entries[e.res.UID] = e
	g.index(e)
}

func (g *graph) drop(uid string) {
	if old := g.entries[uid]; old != nil {
		g.unindex(old)
		delete(g.entries, uid)
	}
}

func (g *graph) index(e *entry) {
	uid, ns := e.res.UID, e.res.Namespace
	g.byName[keyOf(&e.res)] = uid
	for _, name := range secretRefs(e) {
		g.secretUsers.add(key2(ns, name), uid)
	}
	if name := secretTarget(e); name != "" {
		g.secretProducers.add(key2(ns, name), uid)
	}
	for _, o := range e.owners {
		g.children.add(o.uid, uid)
	}
	switch e.res.Kind {
	case KindPod:
		g.podsByNS.add(ns, uid)
		for k, v := range e.labels {
			g.podsByLabel.add(key3(ns, k, v), uid)
		}
		if e.nodeName != "" {
			g.podsByNode.add(e.nodeName, uid)
		}
		for _, c := range e.claims {
			g.claimUsers.add(key2(ns, c), uid)
		}
	case KindService, KindNetPol, KindPDB:
		if e.sel != nil {
			g.selectors.add(ns, uid)
		}
	case KindPVC:
		if e.volumeName != "" {
			g.volumeUsers.add(e.volumeName, uid)
		}
	case KindIngress:
		for svc := range e.backends {
			g.routeUsers.add(key2(ns, svc), uid)
		}
	case KindHPA:
		if e.target != nil {
			g.scaleUsers.add(key3(e.target.kind, e.target.ns, e.target.name), uid)
		}
	}
}

func (g *graph) unindex(e *entry) {
	uid, ns := e.res.UID, e.res.Namespace
	for _, name := range secretRefs(e) {
		g.secretUsers.del(key2(ns, name), uid)
	}
	if name := secretTarget(e); name != "" {
		g.secretProducers.del(key2(ns, name), uid)
	}
	if k := keyOf(&e.res); g.byName[k] == uid {
		delete(g.byName, k)
	}
	for _, o := range e.owners {
		g.children.del(o.uid, uid)
	}
	g.podsByNS.del(ns, uid)
	for k, v := range e.labels {
		g.podsByLabel.del(key3(ns, k, v), uid)
	}
	g.podsByNode.del(e.nodeName, uid)
	for _, c := range e.claims {
		g.claimUsers.del(key2(ns, c), uid)
	}
	g.selectors.del(ns, uid)
	g.volumeUsers.del(e.volumeName, uid)
	for svc := range e.backends {
		g.routeUsers.del(key2(ns, svc), uid)
	}
	if e.target != nil {
		g.scaleUsers.del(key3(e.target.kind, e.target.ns, e.target.name), uid)
	}
}

func selectorEdgeType(kind string) string {
	switch kind {
	case KindService:
		return EdgeSelects
	case KindNetPol:
		return EdgeTargets
	}
	return EdgeGuards
}

// matchPods returns the pods in ns selected by sel, narrowing candidates through the label index.
func (g *graph) matchPods(ns string, sel klabels.Selector) []string {
	var cands map[string]bool
	narrowed := false
	if reqs, ok := sel.Requirements(); ok {
		for _, r := range reqs {
			switch r.Operator() {
			case selection.Equals, selection.DoubleEquals, selection.In:
			default:
				continue
			}
			set := map[string]bool{}
			for _, v := range r.ValuesUnsorted() {
				for uid := range g.podsByLabel[key3(ns, r.Key(), v)] {
					set[uid] = true
				}
			}
			if !narrowed || len(set) < len(cands) {
				cands, narrowed = set, true
			}
		}
	}
	if !narrowed {
		cands = g.podsByNS[ns]
	}
	var out []string
	for uid := range cands {
		if p := g.entries[uid]; p != nil && sel.Matches(klabels.Set(p.labels)) {
			out = append(out, uid)
		}
	}
	return out
}

func attrs(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func (g *graph) routeAttrs(ing *entry, svc string) map[string]any {
	ports := ing.backends[svc]
	if len(ports) == 0 {
		return map[string]any{}
	}
	arr := make([]any, len(ports))
	for i, p := range ports {
		arr[i] = p
	}
	return map[string]any{"ports": arr}
}

// incident returns the desired edges touching uid given the current entries.
func (g *graph) incident(uid string) map[protocol.EdgeKey]map[string]any {
	out := map[protocol.EdgeKey]map[string]any{}
	e := g.entries[uid]
	if e == nil {
		return out
	}
	ns, name := e.res.Namespace, e.res.Name
	for _, ref := range secretRefs(e) {
		for producer := range g.secretProducers[key2(ns, ref)] {
			out[protocol.EdgeKey{From: uid, Type: EdgeNeedsSecretSync, To: producer}] = map[string]any{}
		}
		if dest := g.byName[objKey{KindSecret, ns, ref}]; dest != "" {
			out[protocol.EdgeKey{From: uid, Type: EdgeUsesSecret, To: dest}] = map[string]any{}
		}
	}
	if ref := secretTarget(e); ref != "" {
		for user := range g.secretUsers[key2(ns, ref)] {
			out[protocol.EdgeKey{From: user, Type: EdgeNeedsSecretSync, To: uid}] = map[string]any{}
		}
		if dest := g.byName[objKey{KindSecret, ns, ref}]; dest != "" {
			out[protocol.EdgeKey{From: uid, Type: EdgeProducesSecret, To: dest}] = map[string]any{}
		}
	}
	if e.res.Kind == KindSecret {
		for src := range g.secretUsers[key2(ns, name)] {
			out[protocol.EdgeKey{From: src, Type: EdgeUsesSecret, To: uid}] = map[string]any{}
		}
		for src := range g.secretProducers[key2(ns, name)] {
			out[protocol.EdgeKey{From: src, Type: EdgeProducesSecret, To: uid}] = map[string]any{}
		}
	}
	for _, o := range e.owners {
		if g.entries[o.uid] != nil && o.uid != uid {
			out[protocol.EdgeKey{From: o.uid, Type: EdgeOwns, To: uid}] = map[string]any{"controller": o.controller}
		}
	}
	for child := range g.children[uid] {
		if c := g.entries[child]; c != nil && child != uid {
			for _, o := range c.owners {
				if o.uid == uid {
					out[protocol.EdgeKey{From: uid, Type: EdgeOwns, To: child}] = map[string]any{"controller": o.controller}
				}
			}
		}
	}
	for h := range g.scaleUsers[key3(e.res.Kind, ns, name)] {
		if g.entries[h] != nil {
			out[protocol.EdgeKey{From: h, Type: EdgeScales, To: uid}] = map[string]any{}
		}
	}
	switch e.res.Kind {
	case KindPod:
		if node, ok := g.byName[objKey{KindNode, "", e.nodeName}]; ok && e.nodeName != "" {
			out[protocol.EdgeKey{From: uid, Type: EdgeRunsOn, To: node}] = map[string]any{}
		}
		for _, c := range e.claims {
			if pvc, ok := g.byName[objKey{KindPVC, ns, c}]; ok {
				out[protocol.EdgeKey{From: uid, Type: EdgeMounts, To: pvc}] = map[string]any{}
			}
		}
		set := klabels.Set(e.labels)
		for s := range g.selectors[ns] {
			if se := g.entries[s]; se != nil && se.sel != nil && se.sel.Matches(set) {
				out[protocol.EdgeKey{From: s, Type: selectorEdgeType(se.res.Kind), To: uid}] = attrs(se.selAttrs)
			}
		}
	case KindNode:
		for p := range g.podsByNode[name] {
			if g.entries[p] != nil {
				out[protocol.EdgeKey{From: p, Type: EdgeRunsOn, To: uid}] = map[string]any{}
			}
		}
	case KindService, KindNetPol, KindPDB:
		if e.sel != nil {
			t := selectorEdgeType(e.res.Kind)
			for _, p := range g.matchPods(ns, e.sel) {
				out[protocol.EdgeKey{From: uid, Type: t, To: p}] = attrs(e.selAttrs)
			}
		}
		if e.res.Kind == KindService {
			for i := range g.routeUsers[key2(ns, name)] {
				if ing := g.entries[i]; ing != nil {
					out[protocol.EdgeKey{From: i, Type: EdgeRoutes, To: uid}] = g.routeAttrs(ing, name)
				}
			}
		}
	case KindPVC:
		if pv, ok := g.byName[objKey{KindPV, "", e.volumeName}]; ok && e.volumeName != "" {
			out[protocol.EdgeKey{From: uid, Type: EdgeBinds, To: pv}] = map[string]any{}
		}
		for p := range g.claimUsers[key2(ns, name)] {
			if g.entries[p] != nil {
				out[protocol.EdgeKey{From: p, Type: EdgeMounts, To: uid}] = map[string]any{}
			}
		}
	case KindPV:
		for c := range g.volumeUsers[name] {
			if g.entries[c] != nil {
				out[protocol.EdgeKey{From: c, Type: EdgeBinds, To: uid}] = map[string]any{}
			}
		}
	case KindIngress:
		for svc := range e.backends {
			if s, ok := g.byName[objKey{KindService, ns, svc}]; ok {
				out[protocol.EdgeKey{From: uid, Type: EdgeRoutes, To: s}] = g.routeAttrs(e, svc)
			}
		}
	case KindHPA:
		if t := e.target; t != nil {
			if target, ok := g.byName[*t]; ok && target != uid {
				out[protocol.EdgeKey{From: uid, Type: EdgeScales, To: target}] = map[string]any{}
			}
		}
	}
	return out
}

func secretRefs(e *entry) []string {
	var out []string
	if refs, ok := e.res.Fields["refs.secrets"].([]any); ok {
		for _, v := range refs {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
func secretTarget(e *entry) string {
	if e.res.Kind != "external-secrets.io/ExternalSecret" {
		return ""
	}
	s, _ := e.res.Fields["targetSecret"].(string)
	return s
}
