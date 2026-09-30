package coordinator

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rulesdefault"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// The published default bundle must activate on a coordinator that runs the default configuration.
func TestDefaultBundleRunsUnderDefaultPolicy(t *testing.T) {
	archive, err := rulesdefault.Archive(bundle.TargetKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(archive)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	sig, err := bundle.Sign(archive, e.trust.sign)
	if err != nil {
		t.Fatal(err)
	}
	r := e.start(e.config())
	if err := e.cp.PublishBundle(protocol.TargetKubernetes, b.Manifest.Version, archive, sig, e.trust.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "default bundle active", func() bool {
		if v := r.c.convergence(); v.Rejected != nil {
			t.Fatalf("default bundle rejected under the default policy: %s", v.Rejected.Reason)
		}
		return r.c.eng.BundleVersion() == b.Manifest.Version
	})
	for _, s := range r.c.eng.RuleStates() {
		if s.State == engine.StateFailed || s.State == engine.StateUnsupported {
			t.Errorf("default rule %s is %s under the default policy: %s", s.RuleID, s.State, s.Reason)
		}
	}
}

func TestNodeProcessIdentityInHealth(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	e.committed(r)
	n1 := e.nodeClient(t, r, "node-1", "node-1")
	ctx := context.Background()
	proc := &nodeapi.Process{UID: 0, GID: 0, Capabilities: []string{"CAP_DAC_READ_SEARCH"}}
	if _, err := n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test", Process: proc}); err != nil {
		t.Fatal(err)
	}
	nodeProcess := func() *nodeapi.Process {
		for _, n := range r.c.nodes.list() {
			if n.Name == "node-1" {
				return n.Process
			}
		}
		return nil
	}
	if p := nodeProcess(); p == nil || !reflect.DeepEqual(*p, *proc) {
		t.Fatalf("node process %+v", p)
	}
	eventually(t, "root node agent visible in the health report", func() bool {
		hs, _ := e.cp.HealthReports(e.targetID)
		return len(hs) > 0 && strings.Contains(string(hs[len(hs)-1]), `"process":{"uid":0,"gid":0,"capabilities":["CAP_DAC_READ_SEARCH"]}`)
	})
	if _, err := n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	if p := nodeProcess(); p != nil {
		t.Fatalf("stale process identity %+v after a registration without one", p)
	}
}
