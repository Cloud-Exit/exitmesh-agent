package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

const fixtureManifest = `version: "2026.09.1"
engine_version: 1
schema_version: 1
target_type: kubernetes
created_at: 2026-09-01T00:00:00Z
rules:
  - id: pod-crashloop
    version: 1
    class: state
    target: kubernetes
    scope: cluster
    category: availability
    severity: high
    capabilities: [inventory]
    dedup_key: namespace, pod
  - id: node-high-cpu
    version: 2
    class: promql
    target: kubernetes
    scope: node
    file: prometheus/node.yaml
    group: node
    alert: NodeHighCPU
    category: saturation
    severity: medium
    capabilities: [metrics]
    budget:
      max_eval_time: 30s
  - id: oom-logs
    version: 1
    class: logql
    target: kubernetes
    scope: node
    file: loki/app.yaml
    group: app
    alert: OOMLogged
    category: errors
    severity: critical
    capabilities: [logs]
    evidence:
      max_samples: 100
`

const fixtureState = `- id: pod-crashloop
  version: 1
  target: kubernetes
  kinds: [Pod]
  expr: object.status.restarts > 5
  for: 5m
`

const fixtureProm = `groups:
  - name: node
    interval: 30s
    labels:
      team: infra
    rules:
      - alert: NodeHighCPU
        expr: avg by (node) (rate(node_cpu_seconds_total{mode!="idle"}[5m])) > 0.9
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "CPU high on {{ $labels.node }}"
          runbook_url: https://runbooks.example/cpu
`

const fixtureLoki = `groups:
  - name: app
    rules:
      - alert: OOMLogged
        expr: sum by (namespace, pod) (count_over_time({namespace="prod"} |= "OutOfMemory" [5m])) > 0
`

func fixtureFiles() map[string]string {
	return map[string]string{
		"bundle.yaml":          fixtureManifest,
		"state/pods.yaml":      fixtureState,
		"prometheus/node.yaml": fixtureProm,
		"loki/app.yaml":        fixtureLoki,
	}
}

func writeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for n, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func buildFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()
	a, err := Build(writeDir(t, files))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return a
}

func withFile(files map[string]string, name, body string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	if body == "" {
		delete(out, name)
	} else {
		out[name] = body
	}
	return out
}

func replaceIn(s, old, new string) string {
	if !strings.Contains(s, old) {
		panic("fixture does not contain " + old)
	}
	return strings.Replace(s, old, new, 1)
}

type member struct {
	hdr  tar.Header
	body []byte
}

func rawTar(t *testing.T, members []member) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range members {
		h := m.hdr
		if h.Typeflag == tar.TypeReg || h.Typeflag == 0 {
			h.Size = int64(len(m.body))
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if len(m.body) > 0 {
			if _, err := tw.Write(m.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func reg(name, body string) member {
	return member{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg}, body: []byte(body)}
}

var t0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

type trustFixture struct {
	root    SigningKey
	signing SigningKey
	store   *kv.Memory
	v       *Verifier
	now     time.Time
}

func newTrust(t *testing.T) *trustFixture {
	t.Helper()
	f := &trustFixture{store: kv.NewMemory(), now: t0}
	var err error
	if f.root, err = GenerateKey("root-1"); err != nil {
		t.Fatal(err)
	}
	if f.signing, err = GenerateKey("sign-1"); err != nil {
		t.Fatal(err)
	}
	f.v = f.verifier(t)
	f.accept(t, 1, f.window(f.signing, -time.Hour, 90*24*time.Hour))
	return f
}

func (f *trustFixture) roots() Roots { return Roots{Keys: []RootKey{f.root.Public()}} }

func (f *trustFixture) verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(f.roots(), f.store)
	if err != nil {
		t.Fatal(err)
	}
	v.SetClock(func() time.Time { return f.now })
	return v
}

func (f *trustFixture) window(k SigningKey, from, to time.Duration) ManifestKey {
	return ManifestKey{ID: k.ID, PublicKey: k.Public().PublicKey, NotBefore: t0.Add(from), NotAfter: t0.Add(to)}
}

func (f *trustFixture) signed(t *testing.T, seq uint64, keys ...ManifestKey) []byte {
	t.Helper()
	m, err := NewKeyManifest(seq, t0, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignManifest(m, f.root)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *trustFixture) accept(t *testing.T, seq uint64, keys ...ManifestKey) {
	t.Helper()
	if _, err := f.v.AcceptManifest(f.signed(t, seq, keys...)); err != nil {
		t.Fatalf("accept manifest %d: %v", seq, err)
	}
}

func sign(t *testing.T, archive []byte, k SigningKey) []byte {
	t.Helper()
	s, err := Sign(archive, k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
