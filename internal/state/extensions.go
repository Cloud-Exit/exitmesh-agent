package state

import (
	"strconv"
	"strings"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func secretFields() []Field {
	return append([]Field{
		f("apiVersion", "apiVersion", TypeString, RedactStructural, true),
		f("type", "type", TypeString, RedactStructural, true),
		f("immutable", "immutable", TypeBool, RedactStructural, true),
		f("data.<key>", "data keys with values replaced by a constant redaction marker", TypeString, RedactStructural, true),
		f("stringData.<key>", "stringData keys with values replaced by a constant redaction marker", TypeString, RedactStructural, true),
	}, helmFields()...)
}

func (n *Normalizer) secret(em *emitter, obj *unstructured.Unstructured) {
	em.put("apiVersion", obj.GetAPIVersion())
	em.put("type", stringAt(obj, "type"))
	if v, ok, _ := unstructured.NestedBool(obj.Object, "immutable"); ok {
		em.put("immutable", v)
	}
	for _, field := range []string{"data", "stringData"} {
		values, _ := obj.Object[field].(map[string]any)
		for key := range values {
			em.set(field+".<key>", field+"."+key, redact.Placeholder)
		}
	}
	n.helm(em, obj)
}

func helmFields() []Field {
	return []Field{
		f("helm.name", "metadata.labels.name when owner=helm", TypeString, RedactReference, true),
		f("helm.revision", "metadata.labels.version when owner=helm", TypeInt, RedactStructural, true),
		f("helm.status", "metadata.labels.status when owner=helm", TypeString, RedactStructural, true),
	}
}

// Gateway API kinds whose references are projected (custom resources discovered from CRDs).
const (
	gatewayGroup  = "gateway.networking.k8s.io"
	KindGateway   = gatewayGroup + "/Gateway"
	KindHTTPRoute = gatewayGroup + "/HTTPRoute"
	KindTLSRoute  = gatewayGroup + "/TLSRoute"
)

func isGatewayRoute(kind string) bool { return kind == KindHTTPRoute || kind == KindTLSRoute }

var routeFieldPaths = []string{"parentRefs", "backends", "hostnames"}

func extensionFields() []Field {
	return concat(workloadMeta(), conditionFields("status.conditions", nil), []Field{
		f("apiVersion", "apiVersion", TypeString, RedactStructural, true),
		f("projectionVersion", "generic custom-resource projection version", TypeInt, RedactStructural, true),
		f("conditions.<type>.observedGeneration", "status.conditions[].observedGeneration", TypeInt, RedactStructural, true),
		f("targetSecret", "ExternalSecret spec.target.name (defaults to metadata.name)", TypeString, RedactReference, true),
		f("secretStore.name", "ExternalSecret spec.secretStoreRef.name", TypeString, RedactReference, true),
		f("secretStore.kind", "ExternalSecret spec.secretStoreRef.kind", TypeString, RedactReference, true),
		f("parentRefs", "HTTPRoute and TLSRoute spec.parentRefs[] as Kind[.group]:namespace/name[#sectionName] (Kind defaults to Gateway, namespace to the route's)", TypeStringList, RedactReference, true),
		f("backends", "HTTPRoute and TLSRoute spec.rules[].backendRefs[] as service:port, namespace/service:port in another namespace, or Kind.group:namespace/name for other kinds", TypeStringList, RedactReference, true),
		f("hostnames", "HTTPRoute and TLSRoute spec.hostnames", TypeStringList, RedactStructural, true),
		f("crd.group", "CustomResourceDefinition spec.group", TypeString, RedactStructural, true),
		f("crd.kind", "CustomResourceDefinition spec.names.kind", TypeString, RedactStructural, true),
		f("crd.plural", "CustomResourceDefinition spec.names.plural", TypeString, RedactStructural, true),
		f("crd.scope", "CustomResourceDefinition spec.scope", TypeString, RedactStructural, true),
		f("crd.servedVersions", "CustomResourceDefinition spec.versions[].name where served", TypeStringList, RedactStructural, true),
	})
}

func (n *Normalizer) kindSpec(kind string) *KindSpec {
	if s := catalogByKind[kind]; s != nil {
		return s
	}
	n.customMu.RLock()
	defer n.customMu.RUnlock()
	return n.custom[kind]
}

func (n *Normalizer) registerCustom(gvr schema.GroupVersionResource, kind string, namespaced bool) *KindSpec {
	s := &KindSpec{Kind: ProtocolKind(gvr.Group, kind), GVR: gvr, APIKind: kind, Namespaced: namespaced,
		Fields: concat(commonFields(), extensionFields()), byPath: map[string]*Field{}}
	for i := range s.Fields {
		s.byPath[s.Fields[i].Path] = &s.Fields[i]
	}
	n.customMu.Lock()
	defer n.customMu.Unlock()
	if n.custom == nil {
		n.custom = map[string]*KindSpec{}
	}
	n.custom[s.Kind] = s
	return s
}

func (n *Normalizer) helm(em *emitter, obj *unstructured.Unstructured) {
	labels := obj.GetLabels()
	if labels["owner"] != "helm" || labels["name"] == "" {
		return
	}
	rev, err := strconv.ParseInt(labels["version"], 10, 64)
	if err != nil || rev < 1 {
		return
	}
	switch labels["status"] {
	case "unknown", "deployed", "uninstalled", "superseded", "failed", "uninstalling", "pending-install", "pending-upgrade", "pending-rollback":
	default:
		return
	}
	em.put("helm.name", labels["name"])
	em.put("helm.revision", rev)
	em.put("helm.status", labels["status"])
}

func stringAt(u *unstructured.Unstructured, p ...string) string {
	s, _, _ := unstructured.NestedString(u.Object, p...)
	return s
}

func (n *Normalizer) extension(em *emitter, obj *unstructured.Unstructured, e *entry) {
	em.put("apiVersion", obj.GetAPIVersion())
	em.put("projectionVersion", int64(1))
	em.put("generation", obj.GetGeneration())
	if v, ok, _ := unstructured.NestedInt64(obj.Object, "status", "observedGeneration"); ok {
		em.put("observedGeneration", v)
	}
	em.conditions(obj, nil)
	for _, item := range nestedList(obj.Object, "status", "conditions") {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		if !conditionTypeRe.MatchString(typ) {
			continue
		}
		if _, exists := em.out["conditions."+typ+".status"]; !exists {
			continue
		}
		if v, ok := m["observedGeneration"].(int64); ok {
			em.set("conditions.<type>.observedGeneration", "conditions."+typ+".observedGeneration", v)
		}
	}
	if KindOf(obj) == "external-secrets.io/ExternalSecret" {
		target := stringAt(obj, "spec", "target", "name")
		if target == "" {
			target = obj.GetName()
		}
		em.put("targetSecret", target)
		em.put("secretStore.name", stringAt(obj, "spec", "secretStoreRef", "name"))
		em.put("secretStore.kind", stringAt(obj, "spec", "secretStoreRef", "kind"))
	}
	if isGatewayRoute(KindOf(obj)) {
		gatewayRoute(em, obj, e)
	}
	if KindOf(obj) == KindCRD {
		for key, path := range map[string][]string{"crd.group": {"spec", "group"}, "crd.kind": {"spec", "names", "kind"}, "crd.plural": {"spec", "names", "plural"}, "crd.scope": {"spec", "scope"}} {
			em.put(key, stringAt(obj, path...))
		}
		var served []string
		eachMap(nestedList(obj.Object, "spec", "versions"), func(m map[string]any) {
			if m["served"] == true {
				if s, ok := m["name"].(string); ok {
					served = append(served, s)
				}
			}
		})
		em.put("crd.servedVersions", sortedUnique(served))
	}
}

func (n *Normalizer) stripExtension(kind string, u *unstructured.Unstructured) {
	out := map[string]any{"apiVersion": u.GetAPIVersion(), "kind": u.GetKind()}
	meta := map[string]any{}
	for _, key := range []string{"name", "namespace", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "ownerReferences"} {
		if v, ok, _ := unstructured.NestedFieldCopy(u.Object, "metadata", key); ok {
			meta[key] = v
		}
	}
	labels := map[string]any{}
	for k, v := range u.GetLabels() {
		if n.labelAllowed(k) || (kind == KindSecret && contains([]string{"owner", "name", "version", "status"}, k)) {
			labels[k] = n.red.KeyValue(k, v)
		}
	}
	meta["labels"] = labels
	// Secret annotations can contain copied values, even when an allowlist is broad.
	if kind != KindSecret {
		ann := map[string]any{}
		for k, v := range u.GetAnnotations() {
			if n.annotationAllowed(k) {
				ann[k] = n.red.KeyValue(k, v)
			}
		}
		meta["annotations"] = ann
	}
	out["metadata"] = meta
	if kind == KindSecret {
		if v, ok, _ := unstructured.NestedString(u.Object, "type"); ok {
			out["type"] = v
		}
		if v, ok, _ := unstructured.NestedBool(u.Object, "immutable"); ok {
			out["immutable"] = v
		}
		for _, field := range []string{"data", "stringData"} {
			if values, ok := u.Object[field].(map[string]any); ok {
				safe := make(map[string]any, len(values))
				for key := range values {
					safe[key] = redact.Placeholder
				}
				out[field] = safe
			}
		}
	}
	if kind != KindSecret {
		status := map[string]any{}
		if v, ok, _ := unstructured.NestedInt64(u.Object, "status", "observedGeneration"); ok {
			status["observedGeneration"] = v
		}
		var conditions []any
		eachMap(nestedList(u.Object, "status", "conditions"), func(m map[string]any) {
			typ, _ := m["type"].(string)
			st, _ := m["status"].(string)
			if len(conditions) >= maxConditions || !conditionTypeRe.MatchString(typ) || !contains([]string{"True", "False", "Unknown"}, st) {
				return
			}
			c := map[string]any{"type": typ, "status": st}
			if reason, ok := m["reason"].(string); ok {
				c["reason"] = n.red.String(reason)
			}
			if v, ok := m["observedGeneration"].(int64); ok {
				c["observedGeneration"] = v
			}
			conditions = append(conditions, c)
		})
		status["conditions"] = conditions
		out["status"] = status
		paths := [][]string{}
		if kind == KindCRD {
			paths = [][]string{{"spec", "group"}, {"spec", "scope"}, {"spec", "names", "kind"}, {"spec", "names", "plural"}}
		}
		if kind == "external-secrets.io/ExternalSecret" {
			paths = [][]string{{"spec", "target", "name"}, {"spec", "secretStoreRef", "name"}, {"spec", "secretStoreRef", "kind"}}
		}
		if isGatewayRoute(kind) {
			stripGatewayRoute(u.Object, out)
		}
		for _, p := range paths {
			if s := stringAt(u, p...); s != "" {
				_ = unstructured.SetNestedField(out, s, p...)
			}
		}
		if kind == KindCRD {
			var versions []any
			eachMap(nestedList(u.Object, "spec", "versions"), func(m map[string]any) {
				name, _ := m["name"].(string)
				if name == "" || strings.Contains(name, "/") {
					return
				}
				versions = append(versions, map[string]any{"name": name, "served": m["served"] == true, "storage": m["storage"] == true})
			})
			_ = unstructured.SetNestedSlice(out, versions, "spec", "versions")
		}
	}
	u.Object = out
}

func crdFields() []Field {
	var out []Field
	for _, fd := range extensionFields() {
		if fd.Path != "targetSecret" && !strings.HasPrefix(fd.Path, "secretStore.") && !contains(routeFieldPaths, fd.Path) {
			out = append(out, fd)
		}
	}
	return out
}

var (
	refKeys     = []string{"group", "kind", "namespace", "name", "sectionName", "port"}
	backendKeys = []string{"group", "kind", "namespace", "name", "port"}
)

// stripGatewayRoute keeps only parent references, hostnames, and backend references; filters can carry header values.
func stripGatewayRoute(src, out map[string]any) {
	spec := map[string]any{}
	keep := func(m map[string]any, keys []string) map[string]any {
		r := map[string]any{}
		for _, k := range keys {
			if v, ok := m[k]; ok {
				r[k] = v
			}
		}
		return r
	}
	var parents []any
	eachMap(nestedList(src, "spec", "parentRefs"), func(m map[string]any) { parents = append(parents, keep(m, refKeys)) })
	if parents != nil {
		spec["parentRefs"] = parents
	}
	if hosts := nestedList(src, "spec", "hostnames"); hosts != nil {
		spec["hostnames"] = hosts
	}
	var rules []any
	eachMap(nestedList(src, "spec", "rules"), func(r map[string]any) {
		var refs []any
		eachMap(nestedList(r, "backendRefs"), func(m map[string]any) { refs = append(refs, keep(m, backendKeys)) })
		rules = append(rules, map[string]any{"backendRefs": refs})
	})
	if rules != nil {
		spec["rules"] = rules
	}
	out["spec"] = spec
}

func refPort(v any) string {
	switch p := v.(type) {
	case int64:
		return strconv.FormatInt(p, 10)
	case float64:
		return strconv.FormatInt(int64(p), 10)
	}
	return ""
}

// refKind renders a reference kind, omitting the core group and the group of the defaulted kind.
func refKind(group, kind, defGroup string) string {
	if group == defGroup || group == "" {
		return kind
	}
	return kind + "." + group
}

// gatewayRoute projects parent and backend references and records them for routes edges.
func gatewayRoute(em *emitter, obj *unstructured.Unstructured, e *entry) {
	ns := obj.GetNamespace()
	var parents, backends []string
	eachMap(nestedList(obj.Object, "spec", "parentRefs"), func(m map[string]any) {
		group, kind, name, pns, section := refString(m, "group", gatewayGroup), refString(m, "kind", "Gateway"), refString(m, "name", ""), refString(m, "namespace", ns), refString(m, "sectionName", "")
		if name == "" {
			return
		}
		p := refKind(group, kind, gatewayGroup) + ":" + pns + "/" + name
		if section != "" {
			p += "#" + section
		}
		parents = append(parents, p)
		if ProtocolKind(group, kind) == KindGateway {
			e.parents = append(e.parents, objKey{KindGateway, pns, name})
		}
	})
	e.routeTo = map[objKey][]string{}
	eachMap(nestedList(obj.Object, "spec", "rules"), func(r map[string]any) {
		eachMap(nestedList(r, "backendRefs"), func(m map[string]any) {
			group, kind, name, bns, port := refString(m, "group", ""), refString(m, "kind", "Service"), refString(m, "name", ""), refString(m, "namespace", ns), refPort(m["port"])
			if name == "" {
				return
			}
			if group != "" || kind != "Service" {
				backends = append(backends, refKind(group, kind, "")+":"+bns+"/"+name)
				return
			}
			b := name
			if bns != ns {
				b = bns + "/" + name
			}
			if port != "" {
				b += ":" + port
			}
			backends = append(backends, b)
			k := objKey{KindService, bns, name}
			if port != "" {
				e.routeTo[k] = sortedUnique(append(e.routeTo[k], port))
			} else if e.routeTo[k] == nil {
				e.routeTo[k] = []string{}
			}
		})
	})
	var hosts []string
	for _, h := range nestedList(obj.Object, "spec", "hostnames") {
		if s, ok := h.(string); ok {
			hosts = append(hosts, s)
		}
	}
	em.put("parentRefs", sortedUnique(parents))
	em.put("backends", sortedUnique(backends))
	em.put("hostnames", sortedUnique(hosts))
}

func refString(m map[string]any, key, def string) string {
	v, ok := m[key].(string)
	if !ok || (v == "" && key != "group") {
		return def
	}
	return v
}
