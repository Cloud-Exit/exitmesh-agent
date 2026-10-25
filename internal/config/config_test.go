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
		"role: coordinator\nendpoint: https://:18443\nenrollmentTokenFile: /t\n",
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

func TestCustomDiscoveryConfig(t *testing.T) {
	base := "role: coordinator\nairgap:\n  enabled: true\n" + trust
	for _, enabled := range []string{"true", "false"} {
		c, err := Parse([]byte(base + "kubernetes:\n  resources: [pods]\n  customResources:\n    enabled: " + enabled + "\n    maxKinds: 7\n    maxScopes: 12\n    include: ['example.com/*']\n    exclude: ['example.com/Skip']\n"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Kubernetes.CustomResources.Active() != (enabled == "true") || c.Kubernetes.CustomResources.MaxKinds != 7 || c.Kubernetes.CustomResources.MaxScopes != 12 {
			t.Fatal("independent discovery settings not preserved")
		}
	}
	c, err := Parse([]byte(base + "kubernetes:\n  resources: [pods]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Kubernetes.CustomResources.Active() || c.Kubernetes.CustomResources.MaxKinds != 100 || c.Kubernetes.CustomResources.MaxScopes != 256 {
		t.Fatal("default discovery unexpectedly changed")
	}
	for _, setting := range []string{"maxKinds: -1", "maxScopes: -1", "include: ['[']", "exclude: ['[']"} {
		if _, err := Parse([]byte(base + "kubernetes:\n  customResources:\n    " + setting + "\n")); err == nil {
			t.Fatalf("invalid setting accepted: %s", setting)
		}
	}
}

func TestImageInventoryConfig(t *testing.T) {
	base := "role: node\ncoordinator:\n  serviceURL: https://c:8443\n" + trust
	c, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	ii := c.ImageInventory
	if !ii.Active() || ii.ContentStore != "/var/lib/containerd/io.containerd.content.v1.content" || ii.MaxLayerBytes != 4<<30 || ii.MaxFiles != 500_000 ||
		ii.MaxStagedBytes != 128<<20 || ii.MaxPackages != 20_000 || ii.Timeout.D() != 10*time.Minute || ii.CacheEntries != 256 || ii.CacheBytes != 64<<20 {
		t.Fatalf("defaults %+v", ii)
	}
	c, err = Parse([]byte(base + "imageInventory:\n  enabled: false\n  contentStore: /var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content\n  maxLayerBytes: 1Gi\n  timeout: 1m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ImageInventory.Active() || c.ImageInventory.ContentStore != "/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content" || c.ImageInventory.MaxLayerBytes != 1<<30 || c.ImageInventory.Timeout.D() != time.Minute {
		t.Fatalf("settings %+v", c.ImageInventory)
	}
	for _, setting := range []string{"contentStore: relative/path", "maxFiles: -1", "maxPackages: -2", "cacheEntries: -1"} {
		if _, err := Parse([]byte(base + "imageInventory:\n  " + setting + "\n")); err == nil || !strings.Contains(err.Error(), "imageInventory") {
			t.Fatalf("invalid setting accepted: %s (%v)", setting, err)
		}
	}
}
