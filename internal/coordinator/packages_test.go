package coordinator

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func wireInventory(brotli string) *nodeapi.Inventory {
	return &nodeapi.Inventory{OS: map[string]string{"id": "ubuntu", "version_id": "24.04"}, Packages: []nodeapi.InventoryPackage{
		{Manager: "dpkg", Name: "libbrotli1", Version: brotli, Arch: "amd64", State: "installed", Source: "brotli", SourceVersion: brotli},
		{Manager: "dpkg", Name: "bash", Version: "5.2.21-2ubuntu4", Arch: "amd64", State: "installed", Source: "bash", SourceVersion: "5.2.21-2ubuntu4"},
	}}
}

func setUID(w *nodeapi.Inventory) string {
	inv := w.Facts()
	inv.Normalize()
	return inv.PackageSetUID()
}

func nodesState() *protocol.State {
	st := protocol.NewState()
	for _, n := range []string{"node-1", "node-2"} {
		st.Resources["uid-"+n] = &protocol.Resource{UID: "uid-" + n, Kind: state.KindNode, Name: n, Fields: map[string]any{}}
	}
	return st
}

func applyPackages(t *testing.T, st *protocol.State, node string, w *nodeapi.Inventory) []protocol.Op {
	t.Helper()
	ops, ok := packageOps(st, node, w)
	if !ok {
		t.Fatalf("node %s not resolved", node)
	}
	if err := st.ApplyOps(ops); err != nil {
		t.Fatalf("ops %v do not apply: %v", ops, err)
	}
	return ops
}

func edgeAttrs(st *protocol.State, set, node string) (map[string]any, bool) {
	a, ok := st.Edges[protocol.EdgeKey{From: set, Type: hostfacts.EdgeInstalledOn, To: "uid-" + node}]
	return a, ok
}

func TestPackageOpsShareMoveAndDeleteSets(t *testing.T) {
	st := nodesState()
	a, b := wireInventory("1.1.0-2build2"), wireInventory("1.1.0-2ubuntu0.1")
	sa, sb := setUID(a), setUID(b)

	ops := applyPackages(t, st, "node-1", a)
	if len(ops) != 2 || ops[0].Kind != protocol.OpCreate || ops[1].Kind != protocol.OpEdgeAdd {
		t.Fatalf("first inventory ops %v", ops)
	}
	r := st.Resources[sa]
	if r.Kind != hostfacts.KindPackageSet || r.Namespace != "" || r.Fields["package_count"] != int64(2) {
		t.Fatalf("set %+v", r)
	}
	pkgs := r.Fields["packages"].([]any)
	if p := pkgs[1].(map[string]any); p["name"] != "libbrotli1" || p["source"] != "brotli" || p["version"] != "1.1.0-2build2" {
		t.Fatalf("canonical package order %v", pkgs)
	}
	if ops := applyPackages(t, st, "node-2", a); len(ops) != 1 || ops[0].Kind != protocol.OpEdgeAdd {
		t.Fatalf("identical inventory on another node must only link: %v", ops)
	}
	if ops := applyPackages(t, st, "node-1", a); len(ops) != 0 {
		t.Fatalf("unchanged inventory produced %v", ops)
	}

	applyPackages(t, st, "node-1", b)
	if _, ok := edgeAttrs(st, sa, "node-1"); ok {
		t.Fatal("node-1 still linked to its old set")
	}
	if attrs, ok := edgeAttrs(st, sb, "node-1"); !ok || attrs["state"] != "complete" {
		t.Fatalf("node-1 new set edge %v", attrs)
	}
	if st.Resources[sa] == nil {
		t.Fatal("set still used by node-2 deleted")
	}
	ops = applyPackages(t, st, "node-2", b)
	if st.Resources[sa] != nil {
		t.Fatal("unused set kept")
	}
	if !hasOp(ops, protocol.OpDelete, sa) {
		t.Fatalf("ops %v", ops)
	}

	partial := wireInventory("1.1.0-2ubuntu0.1")
	partial.State, partial.Reason = uint64(protocol.ScopePartial), "read_failed"
	applyPackages(t, st, "node-1", partial)
	if attrs, _ := edgeAttrs(st, sb, "node-1"); attrs["state"] != "partial" || attrs["reason"] != "read_failed" {
		t.Fatalf("partial attrs %v", attrs)
	}

	gone := &nodeapi.Inventory{State: uint64(protocol.ScopeUnavailable), Reason: "permission_denied"}
	applyPackages(t, st, "node-2", gone)
	if attrs, _ := edgeAttrs(st, sb, "node-2"); attrs["state"] != "unavailable" || attrs["reason"] != "permission_denied" || st.Resources[sb] == nil {
		t.Fatalf("unavailable inventory must keep the last set: %v", attrs)
	}
	fresh := protocol.NewState()
	fresh.Resources["uid-node-1"] = st.Resources["uid-node-1"]
	if ops := applyPackages(t, fresh, "node-1", gone); len(ops) != 0 {
		t.Fatalf("unavailable inventory without a previous set produced %v", ops)
	}
	if _, ok := packageOps(st, "node-9", a); ok {
		t.Fatal("inventory of a node outside the cluster state resolved")
	}
}

func hasOp(ops []protocol.Op, kind protocol.OpKind, uid string) bool {
	for _, op := range ops {
		if op.Kind == kind && op.UID == uid {
			return true
		}
	}
	return false
}

func TestPrunePackageOps(t *testing.T) {
	st := nodesState()
	a, b := wireInventory("1"), wireInventory("2")
	applyPackages(t, st, "node-1", a)
	applyPackages(t, st, "node-2", b)
	if ops := prunePackageOps(st, func(string) bool { return false }); len(ops) != 0 {
		t.Fatalf("prune of a consistent state %v", ops)
	}
	ops := prunePackageOps(st, func(n string) bool { return n == "node-1" })
	if err := st.ApplyOps(ops); err != nil {
		t.Fatal(err)
	}
	if attrs, _ := edgeAttrs(st, setUID(a), "node-1"); attrs["state"] != "unavailable" || attrs["reason"] != ReasonCapabilityDisabled {
		t.Fatalf("disabled attrs %v", attrs)
	}
	if ops := prunePackageOps(st, func(n string) bool { return n == "node-1" }); len(ops) != 0 {
		t.Fatalf("prune is not idempotent: %v", ops)
	}
	delete(st.Resources, "uid-node-2")
	if err := st.ApplyOps(prunePackageOps(st, func(string) bool { return false })); err != nil {
		t.Fatal(err)
	}
	if _, ok := edgeAttrs(st, setUID(b), "node-2"); ok || st.Resources[setUID(b)] != nil {
		t.Fatal("set of a removed node kept")
	}
	if st.Resources[setUID(a)] == nil {
		t.Fatal("set of a present node deleted")
	}
}

func TestCarryOverKeepsPackageSets(t *testing.T) {
	rec := nodesState()
	a, b := wireInventory("1"), wireInventory("2")
	applyPackages(t, rec, "node-1", a)
	applyPackages(t, rec, "node-2", b)
	observed := protocol.NewState()
	observed.Resources["uid-node-1"] = rec.Resources["uid-node-1"]
	out := carryOver(rec, observed)
	if out.Resources[setUID(a)] == nil {
		t.Fatal("package set of a present node dropped by relist")
	}
	if _, ok := out.Edges[protocol.EdgeKey{From: setUID(a), Type: hostfacts.EdgeInstalledOn, To: "uid-node-1"}]; !ok {
		t.Fatal("installed_on edge dropped by relist")
	}
	if out.Resources[setUID(b)] != nil {
		t.Fatal("package set of a removed node carried over")
	}
	if len(rec.Diff(out, protocol.DeleteDeleted)) == 0 {
		t.Fatal("removed node not diffed")
	}
}

var nodeGVR = schema.GroupVersionResource{Version: "v1", Resource: "nodes"}

func TestNodePackageInventoryEndToEnd(t *testing.T) {
	e := newEnv(t)
	cfg := e.config()
	r := e.start(cfg)
	id, _ := e.committed(r)
	ctx := context.Background()
	n1, n2 := e.nodeClient(t, r, "node-1", "node-1"), e.nodeClient(t, r, "node-2", "node-2")
	for _, c := range []struct {
		cl   *nodeapi.Client
		name string
	}{{n1, "node-1"}, {n2, "node-2"}} {
		if _, err := c.cl.Register(ctx, nodeapi.RegisterRequest{Node: c.name, AgentVersion: "test", Capabilities: []string{"metrics", "packages"}}); err != nil {
			t.Fatal(err)
		}
	}
	a, b, c := wireInventory("1.1.0-2build2"), wireInventory("1.1.0-2ubuntu0.1"), wireInventory("1.1.0-2ubuntu0.2")
	if acked, err := n1.Submit(ctx, "q", []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindPackages, Inventory: a}}); err != nil || acked != 1 {
		t.Fatalf("submit %d %v", acked, err)
	}
	if _, err := n2.Submit(ctx, "q", []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindPackages, Inventory: a}}); err != nil {
		t.Fatal(err)
	}
	if acked, err := n1.Submit(ctx, "q", []nodeapi.Item{{Seq: 2, Kind: nodeapi.KindPackages, Inventory: b}, {Seq: 3, Kind: nodeapi.KindPackages, Inventory: c}}); err != nil || acked != 3 {
		t.Fatalf("batch submit %d %v", acked, err)
	}
	st := r.c.stateView()
	if st.Resources[setUID(b)] != nil || st.Resources[setUID(c)] == nil || st.Resources[setUID(a)] == nil {
		t.Fatal("only the last inventory of a batch applies")
	}
	if _, ok := edgeAttrs(st, setUID(a), "node-2"); !ok {
		t.Fatal("node-2 link lost")
	}
	if _, ok := edgeAttrs(st, setUID(c), "node-1"); !ok {
		t.Fatal("node-1 not linked to its latest inventory")
	}
	if acked, err := n1.Submit(ctx, "q", []nodeapi.Item{{Seq: 3, Kind: nodeapi.KindPackages, Inventory: a}}); err != nil || acked != 3 {
		t.Fatalf("replayed item %d %v", acked, err)
	}
	if _, ok := edgeAttrs(r.c.stateView(), setUID(c), "node-1"); !ok {
		t.Fatal("an already acknowledged item was applied again")
	}
	gone := e.nodeClient(t, r, "node-9", "node-9")
	if _, err := gone.Submit(ctx, "q", []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindPackages, Inventory: a}}); err != nil {
		t.Fatal(err)
	}
	dropped := uint64(0)
	for _, n := range r.c.nodes.list() {
		if n.Name == "node-9" {
			dropped = n.InventoriesDropped
		}
	}
	if dropped != 1 {
		t.Fatalf("dropped inventories %d", dropped)
	}

	e.committed(r)
	created := false
	for _, rec := range e.records(id) {
		if rec.Delta == nil {
			continue
		}
		for _, op := range rec.Delta.Ops {
			if op.Kind == protocol.OpCreate && op.ResourceKind == hostfacts.KindPackageSet {
				created = true
				if rec.Delta.Flags&protocol.FlagSynthetic != 0 {
					t.Fatal("node inventory recorded as synthetic")
				}
			}
		}
	}
	if !created {
		t.Fatal("no package set reached the control plane")
	}

	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	r = e.start(cfg)
	e.committed(r)
	st = r.c.stateView()
	if _, ok := edgeAttrs(st, setUID(c), "node-1"); !ok || st.Resources[setUID(a)] == nil {
		t.Fatal("package sets lost across a restart and relist")
	}

	if err := e.cl.dyn.Tracker().Delete(nodeGVR, "", "node-2"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "node-2 removed from state", func() bool { return r.c.stateView().Resources["uid-node-2"] == nil })
	r.c.prunePackageSets()
	st = r.c.stateView()
	if st.Resources[setUID(a)] != nil {
		t.Fatal("set only used by a removed node kept")
	}
	n1 = e.nodeClient(t, r, "node-1", "node-1")
	if _, err := n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test", Capabilities: []string{"metrics"}}); err != nil {
		t.Fatal(err)
	}
	r.c.prunePackageSets()
	if attrs, _ := edgeAttrs(r.c.stateView(), setUID(c), "node-1"); attrs["reason"] != ReasonCapabilityDisabled {
		t.Fatalf("capability disabled attrs %v", attrs)
	}
}
