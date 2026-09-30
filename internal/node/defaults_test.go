package node

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/privdrop"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rulesdefault"
)

// The published default bundle must activate on a node agent that runs the default configuration.
func TestDefaultBundleRunsUnderDefaultPolicy(t *testing.T) {
	archive, err := rulesdefault.Archive(bundle.TargetKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(archive)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, options{})
	sig, err := bundle.Sign(archive, h.trust.signing)
	if err != nil {
		t.Fatal(err)
	}
	a := h.start()
	h.coord.setBundle(&nodeapi.BundlePayload{Version: b.Manifest.Version, Archive: archive, Signature: sig, KeyManifest: h.trust.manifest})
	h.waitFor("default bundle active", func() bool {
		if s := a.Status(); s.BundleError != "" {
			t.Fatalf("default bundle rejected under the default policy: %s", s.BundleError)
		}
		return a.eng.BundleVersion() == b.Manifest.Version
	})
	states := a.eng.RuleStates()
	if len(states) == 0 {
		t.Fatal("no rule states")
	}
	for _, s := range states {
		if s.State == engine.StateFailed || s.State == engine.StateUnsupported {
			t.Errorf("default rule %s is %s under the default policy: %s", s.RuleID, s.State, s.Reason)
		}
	}
}

func TestRegistrationReportsProcessIdentity(t *testing.T) {
	h := newHarness(t, options{})
	h.start()
	h.waitFor("registered", func() bool { _, ok := h.coord.lastRegister(); return ok })
	req, _ := h.coord.lastRegister()
	if p := req.Process; p == nil || p.UID != os.Geteuid() || p.GID != os.Getegid() {
		t.Fatalf("registration process %+v, want the running identity", req.Process)
	}
	if err := h.shutdown(); err != nil {
		t.Fatal(err)
	}

	root := newHarness(t, options{})
	root.deps.Process = &privdrop.Identity{UID: 0, GID: 0, Capabilities: []string{"CAP_DAC_READ_SEARCH"}}
	a := root.start()
	root.waitFor("root registration", func() bool {
		req, ok := root.coord.lastRegister()
		return ok && req.Process != nil && req.Process.UID == 0 && slices.Equal(req.Process.Capabilities, []string{"CAP_DAC_READ_SEARCH"})
	})
	if s := a.Status(); s.Process.UID != 0 {
		t.Fatalf("status process %+v", s.Process)
	}
	if !strings.Contains(root.logb.String(), "node agent runs as root") {
		t.Fatal("a root node agent is not logged")
	}
}
