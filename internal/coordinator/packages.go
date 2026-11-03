package coordinator

import (
	"slices"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// ReasonCapabilityDisabled marks a node inventory kept from before the packages capability was turned off.
const ReasonCapabilityDisabled = "capability_disabled"

var scopeNames = map[protocol.ScopeState]string{protocol.ScopeComplete: "complete", protocol.ScopePartial: "partial", protocol.ScopeUnavailable: "unavailable"}

func inventoryAttrs(st protocol.ScopeState, reason string) map[string]any {
	a := map[string]any{"state": scopeNames[st]}
	if reason != "" {
		a["reason"] = reason
	}
	return a
}

func nodeUID(st *protocol.State, node string) string {
	for uid, r := range st.Resources {
		if r.Kind == state.KindNode && r.Name == node {
			return uid
		}
	}
	return ""
}

// inventoryEdges returns the installed_on edges from package sets to the node.
func inventoryEdges(st *protocol.State, to string) []protocol.EdgeKey {
	var out []protocol.EdgeKey
	for k := range st.Edges {
		if k.Type == hostfacts.EdgeInstalledOn && k.To == to {
			if r := st.Resources[k.From]; r != nil && r.Kind == hostfacts.KindPackageSet {
				out = append(out, k)
			}
		}
	}
	slices.SortFunc(out, func(a, b protocol.EdgeKey) int {
		switch {
		case a.From < b.From:
			return -1
		case a.From > b.From:
			return 1
		}
		return 0
	})
	return out
}

func setEdgeCount(st *protocol.State, set string) int {
	n := 0
	for k := range st.Edges {
		if k.From == set && k.Type == hostfacts.EdgeInstalledOn {
			n++
		}
	}
	return n
}

// packageOps links the node to the package set of its inventory, creating the set and deleting the one it leaves when no node uses it.
// It returns false when the node is not in the chain head.
func packageOps(st *protocol.State, node string, w *nodeapi.Inventory) ([]protocol.Op, bool) {
	to := nodeUID(st, node)
	if to == "" {
		return nil, false
	}
	inv := w.Facts()
	inv.Normalize()
	attrs := inventoryAttrs(inv.State, inv.Reason)
	cur := inventoryEdges(st, to)
	var ops []protocol.Op
	if inv.State == protocol.ScopeUnavailable {
		for _, k := range cur {
			if prev := st.Edges[k]; !protocol.ValueEqual(prev, attrs) {
				ops = append(ops, protocol.EdgeReplace(k.From, k.Type, k.To, attrs, protocol.CloneFields(prev)))
			}
		}
		return ops, true
	}
	set := inv.PackageSetUID()
	if st.Resources[set] == nil {
		ops = append(ops, protocol.Create(set, hostfacts.KindPackageSet, "", set[len("host:packageset:"):], inv.Fields()))
	}
	linked := false
	for _, k := range cur {
		prev := st.Edges[k]
		if k.From == set {
			linked = true
			if !protocol.ValueEqual(prev, attrs) {
				ops = append(ops, protocol.EdgeReplace(k.From, k.Type, k.To, attrs, protocol.CloneFields(prev)))
			}
			continue
		}
		ops = append(ops, protocol.EdgeRemove(k.From, k.Type, k.To, protocol.CloneFields(prev)))
		if setEdgeCount(st, k.From) == 1 {
			ops = append(ops, protocol.Delete(k.From, protocol.DeleteDeleted))
		}
	}
	if !linked {
		ops = append(ops, protocol.EdgeAdd(set, hostfacts.EdgeInstalledOn, to, attrs))
	}
	protocol.SortOps(ops)
	return ops, true
}

// prunePackageOps drops links to nodes that left the cluster, deletes unused package sets, and marks
// the inventory of nodes registered without the packages capability unavailable.
func prunePackageOps(st *protocol.State, disabled func(node string) bool) []protocol.Op {
	var ops []protocol.Op
	remaining := map[string]int{}
	for k, a := range st.Edges {
		from := st.Resources[k.From]
		if k.Type != hostfacts.EdgeInstalledOn || from == nil || from.Kind != hostfacts.KindPackageSet {
			continue
		}
		n := st.Resources[k.To]
		if n == nil {
			ops = append(ops, protocol.EdgeRemove(k.From, k.Type, k.To, protocol.CloneFields(a)))
			continue
		}
		remaining[k.From]++
		if want := inventoryAttrs(protocol.ScopeUnavailable, ReasonCapabilityDisabled); disabled(n.Name) && !protocol.ValueEqual(a, want) {
			ops = append(ops, protocol.EdgeReplace(k.From, k.Type, k.To, want, protocol.CloneFields(a)))
		}
	}
	for uid, r := range st.Resources {
		if r.Kind == hostfacts.KindPackageSet && remaining[uid] == 0 {
			ops = append(ops, protocol.Delete(uid, protocol.DeleteDeleted))
		}
	}
	protocol.SortOps(ops)
	return ops
}

// prunePackageSets applies prunePackageOps to the chain head.
func (c *Coordinator) prunePackageSets() {
	c.sinkMu.Lock()
	defer c.sinkMu.Unlock()
	st := c.headState()
	if st == nil || c.observed != nil {
		return
	}
	ops := prunePackageOps(st, c.nodes.packagesDisabled)
	if len(ops) == 0 {
		return
	}
	if err := c.do(func(t *txn) error { return t.delta(ops, protocol.FlagSynthetic, nil) }); err != nil {
		c.appendFailed(err)
	}
}

// packagesDisabled reports whether the node agent registered without the packages capability.
func (r *registry) packagesDisabled(node string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.nodes[node]
	return n != nil && n.registered && !slices.Contains(n.Capabilities, config.CapPackages)
}

// carryPackageSets keeps package sets and their links to nodes still present, which a relist cannot observe.
func carryPackageSets(rec, out *protocol.State) {
	for uid, r := range rec.Resources {
		if r.Kind != hostfacts.KindPackageSet {
			continue
		}
		if _, ok := out.Resources[uid]; ok {
			continue
		}
		var keep []protocol.EdgeKey
		for k := range rec.Edges {
			if k.From == uid && k.Type == hostfacts.EdgeInstalledOn && out.Resources[k.To] != nil {
				keep = append(keep, k)
			}
		}
		if len(keep) == 0 {
			continue
		}
		cp := *r
		cp.Fields = protocol.CloneFields(r.Fields)
		out.Resources[uid] = &cp
		for _, k := range keep {
			out.Edges[k] = protocol.CloneFields(rec.Edges[k])
		}
	}
}
