package config

import (
	"strings"
	"testing"
	"time"
)

const trust = "trust:\n  roots: [\"r1:AAAA\"]\n"

func TestTrustRequired(t *testing.T) {
	if _, err := Parse([]byte("role: coordinator\nairgap:\n  enabled: true\n")); err == nil || !strings.Contains(err.Error(), "trust.roots") {
		t.Fatalf("missing trust accepted: %v", err)
	}
	if _, err := Parse([]byte("role: coordinator\nairgap:\n  enabled: true\n" + trust + "  threshold: 2\n")); err == nil {
		t.Fatal("threshold above root count accepted")
	}
}

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte("role: coordinator\nendpoint: https://cp.example.com\nenrollmentTokenFile: /t\n" + trust))
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != "/data" || c.Spool.Capacity != 10<<30 || c.Spool.Window != 8<<20 || c.Node.EvidenceRing != 16<<20 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.Policy.LateThreshold.D() != 15*time.Minute || !c.HasCapability(CapLogs) {
		t.Fatal("policy defaults")
	}
}

func TestParseSizes(t *testing.T) {
	c, err := Parse([]byte("role: node\ncoordinator:\n  serviceURL: https://c:8443\nnode:\n  diskCap: 512Mi\n  scrapeInterval: 15s\n" + trust))
	if err != nil {
		t.Fatal(err)
	}
	if c.Node.DiskCap != 512<<20 || c.Node.ScrapeInterval.D() != 15*time.Second {
		t.Fatal("sizes")
	}
}

func TestValidate(t *testing.T) {
	bad := []string{
		"role: bogus\n",
		"role: coordinator\nendpoint: http://x\nenrollmentTokenFile: /t\n",
		"role: node\n",
		"role: host\nendpoint: https://x\nenrollmentTokenFile: /t\nhost:\n  diskCap: 1Gi\n",
		"role: coordinator\nairgap:\n  enabled: true\nlookback:\n- name: a\n  type: graphite\n  url: http://x\n",
		"role: coordinator\nairgap:\n  enabled: true\nunknownField: 1\n",
		"role: coordinator\nairgap:\n  enabled: true\nkubernetes:\n  scope: namespaces\n",
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b + trust)); err == nil {
			t.Errorf("accepted %q", strings.TrimSpace(b))
		}
	}
	if _, err := Parse([]byte("role: coordinator\nairgap:\n  enabled: true\n" + trust)); err != nil {
		t.Fatalf("airgap without endpoint: %v", err)
	}
}
