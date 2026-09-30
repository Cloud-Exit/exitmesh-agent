package host

import (
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rulesdefault"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// The published default bundle must activate on a host that runs the default configuration.
func TestDefaultBundleRunsUnderDefaultPolicy(t *testing.T) {
	archive, err := rulesdefault.Archive(bundle.TargetHost)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(archive)
	if err != nil {
		t.Fatal(err)
	}
	f := enrolledFixture(t, fixtureOpts{})
	sig, err := bundle.Sign(archive, f.signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.cp.srv.PublishBundle(protocol.TargetHost, b.Manifest.Version, archive, sig, f.signer.manifest); err != nil {
		t.Fatal(err)
	}
	f.start()
	defer f.stop()
	f.waitTicking("default bundle active", func() bool {
		st := f.status().Bundle
		if st.Error != "" {
			t.Fatalf("default bundle rejected under the default policy: %s", st.Error)
		}
		return st.Version == b.Manifest.Version
	})
	for _, s := range f.host.eng.RuleStates() {
		if s.State == engine.StateFailed || s.State == engine.StateUnsupported {
			t.Errorf("default rule %s is %s under the default policy: %s", s.RuleID, s.State, s.Reason)
		}
	}
}
