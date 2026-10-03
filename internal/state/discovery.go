package state

import (
	"context"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type customWorker struct {
	scopes  []*scope
	cancel  context.CancelFunc
	done    chan struct{}
	version schema.GroupVersionResource
}

func (c *Collector) discoverCustom(ctx context.Context) {
	workers := map[string]*customWorker{}
	c.mu.Lock()
	c.discoveryStatus = &scope{kind: "inventory.exitmesh.io/CustomResourceDiscovery"}
	c.mu.Unlock()
	defer func() {
		for _, w := range workers {
			w.cancel()
		}
		for _, w := range workers {
			<-w.done
		}
	}()
	first := true
	for ctx.Err() == nil {
		specs, err := c.customSpecs(ctx)
		c.mu.Lock()
		if err == nil {
			c.emit(c.o.Tracker.ScopeRestored(c.discoveryStatus.kind, ""), false, nil)
			c.report(c.discoveryStatus, protocol.ScopeComplete, "", nil)
		} else if ctx.Err() == nil {
			c.emit(c.o.Tracker.ScopeLost(c.discoveryStatus.kind, "", reasonFor(err)), false, nil)
			c.report(c.discoveryStatus, protocol.ScopeUnavailable, reasonFor(err), nil)
		}
		c.mu.Unlock()
		if err == nil {
			for kind, w := range workers {
				next, exists := specs[kind]
				if exists && next.GVR == w.version {
					continue
				}
				w.cancel()
				<-w.done
				c.mu.Lock()
				for _, sc := range w.scopes {
					c.firstAttemptLocked(sc)
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
				nss := []string{""}
				if s.Namespaced && len(c.o.Namespaces) > 0 {
					nss = sortedUnique(c.o.Namespaces)
				}
				wctx, cancel := context.WithCancel(ctx)
				w := &customWorker{cancel: cancel, done: make(chan struct{}), version: s.GVR}
				c.mu.Lock()
				for _, ns := range nss {
					if c.exclude[ns] {
						continue
					}
					sc := &scope{kind: kind, ns: ns, spec: spec, tf: Transform(c.o.Tracker.Normalizer(), kind)}
					c.scopes = append(c.scopes, sc)
					c.pending++
					w.scopes = append(w.scopes, sc)
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
		} else if ctx.Err() == nil {
			c.log.Warn("state: custom-resource discovery failed; retrying", "reason", reasonFor(err))
		}
		if first {
			c.mu.Lock()
			c.pending--
			if c.pending == 0 && !c.synced {
				c.markSyncedLocked()
			}
			c.mu.Unlock()
			first = false
		}
		if !c.o.Wait(ctx, 30*time.Second) {
			return
		}
	}
}

func (c *Collector) customSpecs(ctx context.Context) (map[string]*KindSpec, error) {
	out := map[string]*KindSpec{}
	opts := metav1.ListOptions{Limit: 500}
	for {
		list, err := c.o.Dynamic.Resource(catalogByKind[KindCRD].GVR).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			u := &list.Items[i]
			group, kind, plural := stringAt(u, "spec", "group"), stringAt(u, "spec", "names", "kind"), stringAt(u, "spec", "names", "plural")
			if group == "" || kind == "" || plural == "" {
				continue
			}
			pk := ProtocolKind(group, kind)
			if catalogByKind[pk] != nil {
				continue
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
				continue
			}
			out[pk] = &KindSpec{Kind: pk, APIKind: kind, GVR: schema.GroupVersionResource{Group: group, Version: version, Resource: plural}, Namespaced: stringAt(u, "spec", "scope") == "Namespaced"}
		}
		opts.Continue = list.GetContinue()
		if opts.Continue == "" {
			return out, nil
		}
	}
}
