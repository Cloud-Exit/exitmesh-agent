package state

import (
	"context"
	"path"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type customWorker struct {
	scopes  []*scope
	cancel  context.CancelFunc
	done    chan struct{}
	version schema.GroupVersionResource
}

func (c *Collector) wakeDiscovery(sc *scope) {
	if sc != c.crdScope || c.discoveryWake == nil {
		return
	}
	select {
	case c.discoveryWake <- struct{}{}:
	default:
	}
}

func matchesKind(patterns []string, s *KindSpec) bool {
	for _, p := range patterns {
		for _, name := range []string{s.Kind, s.GVR.GroupResource().String()} {
			if ok, _ := path.Match(p, name); ok {
				return true
			}
		}
	}
	return false
}

func (c *Collector) customNamespaces(s *KindSpec) []string {
	if !s.Namespaced || len(c.o.Namespaces) == 0 {
		return []string{""}
	}
	var out []string
	for _, ns := range sortedUnique(c.o.Namespaces) {
		if !c.exclude[ns] {
			out = append(out, ns)
		}
	}
	return out
}

// desiredCustom uses only the stripped CRD informer inventory; failures preserve existing workers.
func (c *Collector) desiredCustom(workers map[string]*customWorker) (map[string]*KindSpec, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.crdScope.mu.Lock()
	state, reason := c.crdScope.state, c.crdScope.reason
	c.crdScope.mu.Unlock()
	if state != protocol.ScopeComplete {
		c.report(c.discoveryStatus, state, reason, nil)
		if state == protocol.ScopeUnavailable {
			c.emit(c.o.Tracker.ScopeLost(c.discoveryStatus.kind, "", reason), false, nil)
		} else {
			c.emit(c.o.Tracker.ScopePartial(c.discoveryStatus.kind, "", reason), false, nil)
		}
		return nil, false
	}
	specs := map[string]*KindSpec{}
	for _, s := range c.crds {
		if s == nil || catalogByKind[s.Kind] != nil || matchesKind(c.o.CustomResources.Exclude, s) {
			continue
		}
		if len(c.o.CustomResources.Include) > 0 && !matchesKind(c.o.CustomResources.Include, s) {
			continue
		}
		specs[s.Kind] = s
	}
	kinds := make([]string, 0, len(specs))
	for kind := range specs {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool {
		iRunning, jRunning := workers[kinds[i]] != nil, workers[kinds[j]] != nil
		if iRunning != jRunning {
			return iRunning
		}
		return kinds[i] < kinds[j]
	})
	selected := map[string]*KindSpec{}
	scopes := 0
	limited := false
	for _, kind := range kinds {
		s := specs[kind]
		n := len(c.customNamespaces(s))
		if len(selected) >= c.o.CustomResources.MaxKinds || scopes+n > c.o.CustomResources.MaxScopes {
			limited = true
			continue
		}
		selected[kind] = s
		scopes += n
	}
	if limited {
		reason = "custom-resource collection limit reached"
		c.report(c.discoveryStatus, protocol.ScopePartial, reason, nil)
		c.emit(c.o.Tracker.ScopePartial(c.discoveryStatus.kind, "", reason), false, nil)
	} else {
		c.report(c.discoveryStatus, protocol.ScopeComplete, "", nil)
		c.emit(c.o.Tracker.ScopeRestored(c.discoveryStatus.kind, ""), false, nil)
	}
	return selected, true
}

func (c *Collector) discoverCustom(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-c.syncedCh:
	}
	workers := map[string]*customWorker{}
	defer func() {
		for _, w := range workers {
			w.cancel()
		}
		for _, w := range workers {
			<-w.done
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.discoveryWake:
		}
		specs, ready := c.desiredCustom(workers)
		if !ready {
			continue
		}
		for kind, w := range workers {
			next, exists := specs[kind]
			if exists && next.GVR == w.version {
				continue
			}
			w.cancel()
			<-w.done
			c.mu.Lock()
			for _, sc := range w.scopes {
				sc.retired = true
				if !exists {
					c.emit(c.o.Tracker.RemoveScope(sc.kind, sc.ns), false, nil)
				}
			}
			keep := c.scopes[:0]
			for _, sc := range c.scopes {
				if !sc.retired {
					keep = append(keep, sc)
				}
			}
			c.scopes = keep
			c.mu.Unlock()
			delete(workers, kind)
		}
		kinds := make([]string, 0, len(specs))
		for kind := range specs {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			if workers[kind] != nil {
				continue
			}
			s := specs[kind]
			spec := c.o.Tracker.Normalizer().registerCustom(s.GVR, s.APIKind, s.Namespaced)
			wctx, cancel := context.WithCancel(ctx)
			w := &customWorker{cancel: cancel, done: make(chan struct{}), version: s.GVR}
			c.mu.Lock()
			for _, ns := range c.customNamespaces(s) {
				sc := &scope{kind: kind, ns: ns, spec: spec, tf: Transform(c.o.Tracker.Normalizer(), kind), background: true, state: protocol.ScopePartial, reason: "initial collection"}
				c.scopes = append(c.scopes, sc)
				w.scopes = append(w.scopes, sc)
				c.emit(c.o.Tracker.ScopePartial(kind, ns, sc.reason), false, nil)
			}
			c.mu.Unlock()
			workers[kind] = w
			go func() {
				defer close(w.done)
				done := make(chan struct{}, len(w.scopes))
				for _, sc := range w.scopes {
					go func() { c.runScope(wctx, sc); done <- struct{}{} }()
				}
				for range w.scopes {
					<-done
				}
			}()
		}
	}
}

func customSpec(u *unstructured.Unstructured) *KindSpec {
	group, kind, plural := stringAt(u, "spec", "group"), stringAt(u, "spec", "names", "kind"), stringAt(u, "spec", "names", "plural")
	if group == "" || kind == "" || plural == "" {
		return nil
	}
	version := ""
	eachMap(nestedList(u.Object, "spec", "versions"), func(m map[string]any) {
		if m["served"] != true {
			return
		}
		v, _ := m["name"].(string)
		if version == "" || m["storage"] == true {
			version = v
		}
	})
	if version == "" {
		return nil
	}
	return &KindSpec{Kind: ProtocolKind(group, kind), APIKind: kind, GVR: schema.GroupVersionResource{Group: group, Version: version, Resource: plural}, Namespaced: stringAt(u, "spec", "scope") == "Namespaced"}
}
