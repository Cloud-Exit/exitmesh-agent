package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

const manifestYAML = `version: "2026.09.2"
engine_version: 2
schema_version: 1
target_type: host
created_at: 2026-09-01T00:00:00Z
rules:
  - id: disk-full
    version: 1
    class: promql
    target: host
    scope: node
    file: prometheus/host.yaml
    group: host
    alert: DiskFull
    category: capacity
    severity: high
    capabilities: [metrics]
  - id: future-rule
    version: 1
    class: promql
    target: host
    scope: node
    file: prometheus/host.yaml
    group: host
    alert: FutureAlert
    min_engine: 2
    category: capacity
    severity: low
    capabilities: [metrics]
`

const hostRules = `groups:
  - name: host
    rules:
      - alert: DiskFull
        expr: node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.05
        for: 5m
      - alert: FutureAlert
        expr: some_future_function(up)
`

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, errb.String())
	}
	return out.String()
}

func runFail(t *testing.T, want int, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != want {
		t.Fatalf("%v: exit %d, want %d: %s", args, code, want, errb.String())
	}
	return errb.String()
}

func TestOperatorFlow(t *testing.T) {
	d := t.TempDir()
	p := func(n string) string { return filepath.Join(d, n) }
	src := p("src")
	if err := os.MkdirAll(filepath.Join(src, "prometheus"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "bundle.yaml"), []byte(manifestYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "prometheus", "host.yaml"), []byte(hostRules), 0o644); err != nil {
		t.Fatal(err)
	}

	runOK(t, "keygen", "-id", "root-1", "-out", p("root"))
	runOK(t, "keygen", "-id", "sign-1", "-out", p("sign"))
	runOK(t, "keygen", "-id", "root-2", "-out", p("root2"))
	if fi, err := os.Stat(p("root.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode: %v", err)
	}
	runOK(t, "roots", "-pub", p("root.pub"), "-out", p("roots.json"))
	out := runOK(t, "manifest", "-seq", "1", "-issued-at", "2026-09-01T00:00:00Z",
		"-key", p("sign.pub")+",2026-09-01T00:00:00Z,2027-09-01T00:00:00Z",
		"-successor", p("root2.pub")+",2026-12-01T00:00:00Z",
		"-root", p("root.key"), "-out", p("keymanifest.json"))
	if !strings.Contains(out, "sequence 1") {
		t.Fatal(out)
	}
	if out := runOK(t, "build", "-dir", src, "-out", p("bundle.tar.gz")); !strings.Contains(out, "2026.09.2") {
		t.Fatal(out)
	}
	runOK(t, "sign", "-bundle", p("bundle.tar.gz"), "-key", p("sign.key"), "-out", p("bundle.sig"))

	out = runOK(t, "verify", "-bundle", p("bundle.tar.gz"), "-sig", p("bundle.sig"), "-manifest", p("keymanifest.json"), "-roots", p("roots.json"), "-at", "2026-10-01T00:00:00Z")
	if !strings.Contains(out, `signed by "sign-1"`) || !strings.Contains(out, "1 active, 1 unsupported") {
		t.Fatal(out)
	}
	runOK(t, "verify", "-dir", d, "-root-pub", p("root.pub"), "-at", "2026-10-01T00:00:00Z")
	if e := runFail(t, 1, "verify", "-dir", d, "-root-pub", p("root.pub"), "-at", "2028-01-01T00:00:00Z"); !strings.Contains(e, "validity window") {
		t.Fatal(e)
	}
	if e := runFail(t, 1, "verify", "-dir", d, "-root-pub", p("root2.pub")); !strings.Contains(e, "root signature") {
		t.Fatal(e)
	}
	if e := runFail(t, 1, "verify", "-dir", d); !strings.Contains(e, "no trust roots") {
		t.Fatal(e)
	}
	runOK(t, "sign", "-bundle", p("bundle.tar.gz"), "-key", p("root.key"), "-out", p("bundle.sig"))
	if e := runFail(t, 1, "verify", "-dir", d, "-root-pub", p("root.pub"), "-at", "2026-10-01T00:00:00Z"); !strings.Contains(e, "not in the verified key manifest") {
		t.Fatal(e)
	}

	runOK(t, "manifest", "-seq", "2", "-issued-at", "2026-09-02T00:00:00Z",
		"-key", p("sign.pub")+",2026-09-01T00:00:00Z,2027-09-01T00:00:00Z,2026-09-02T00:00:00Z",
		"-root", p("root.key"), "-out", p("keymanifest.json"))
	runOK(t, "sign", "-bundle", p("bundle.tar.gz"), "-key", p("sign.key"), "-out", p("bundle.sig"))
	if e := runFail(t, 1, "verify", "-dir", d, "-root-pub", p("root.pub"), "-at", "2026-10-01T00:00:00Z"); !strings.Contains(e, "revoked") {
		t.Fatal(e)
	}

	out = runOK(t, "inspect", "-bundle", p("bundle.tar.gz"))
	for _, want := range []string{"target_type:    host", "disk-full", "active", "future-rule", "unsupported: " + bundle.ReasonUpgradeRequired, "prometheus/host.yaml#host/DiskFull"} {
		if !strings.Contains(out, want) {
			t.Fatalf("inspect output lacks %q:\n%s", want, out)
		}
	}
}

func TestBuildRejectsInvalidBundle(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "prometheus"), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(manifestYAML, "severity: high", "severity: extreme", 1)
	if err := os.WriteFile(filepath.Join(src, "bundle.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "prometheus", "host.yaml"), []byte(hostRules), 0o644); err != nil {
		t.Fatal(err)
	}
	if e := runFail(t, 1, "build", "-dir", src, "-out", filepath.Join(src, "out.tar.gz")); !strings.Contains(e, "unknown severity") {
		t.Fatal(e)
	}
}

func TestUsageErrors(t *testing.T) {
	runFail(t, 2)
	runFail(t, 2, "explode")
	runFail(t, 1, "keygen", "-id", "x")
	runFail(t, 1, "sign", "-bundle", "missing", "-key", "k", "-out", "o")
	runFail(t, 1, "manifest", "-seq", "1", "-key", "only-one-part", "-out", filepath.Join(t.TempDir(), "m.json"))
	runFail(t, 1, "keygen", "-bogus")
}
