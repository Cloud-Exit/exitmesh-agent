package deploytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
)

type object = map[string]any

type manifest struct {
	objects []object
}

const testRoot = "root-1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

var baseArgs = []string{"--set", "endpoint=https://cp.example.com", "--set", "enrollment.token=emx1_c_t-123_secret"}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func chartDir(t *testing.T) string {
	return filepath.Join(repoRoot(t), "deploy", "helm", "exitmesh-agent")
}

func helmBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	return p
}

// runHelm runs helm and returns its combined output.
func runHelm(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(helmBin(t), args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// helmTemplate runs helm template and returns stdout, or an error carrying stderr.
func helmTemplate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"template", "exitmesh-agent", chartDir(t), "--namespace", "default"}, args...)
	if !mentionsTrust(args) {
		full = append(full, "--set-json", `trust.roots=["`+testRoot+`"]`)
	}
	cmd := exec.Command(helmBin(t), full...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, errb.String())
	}
	return out.String(), nil
}

// mentionsTrust reports whether a test sets trust itself (inline or in a values file).
func mentionsTrust(args []string) bool {
	for i, a := range args {
		if strings.Contains(a, "trust.") {
			return true
		}
		if a == "-f" && i+1 < len(args) {
			if b, err := os.ReadFile(args[i+1]); err == nil && strings.Contains(string(b), "trust:") {
				return true
			}
		}
	}
	return false
}

func render(t *testing.T, args ...string) *manifest {
	t.Helper()
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template %v: %v", args, err)
	}
	m, err := parseManifest(out)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func renderFails(t *testing.T, want string, args ...string) {
	t.Helper()
	_, err := helmTemplate(t, args...)
	if err == nil {
		t.Fatalf("helm template %v succeeded, want failure containing %q", args, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("helm template %v failed with %v, want message containing %q", args, err, want)
	}
}

// schemaFails expects a values schema pattern rejection naming field, in the wording of any helm 3 release.
func schemaFails(t *testing.T, field string, args ...string) {
	t.Helper()
	_, err := helmTemplate(t, args...)
	if err == nil {
		t.Fatalf("helm template %v succeeded, want a schema rejection of %s", args, field)
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "does not match pattern") || !strings.Contains(msg, strings.ToLower(field)) {
		t.Fatalf("helm template %v failed with %v, want a pattern rejection of %s", args, err, field)
	}
}

func parseManifest(s string) (*manifest, error) {
	dec := yaml.NewDecoder(strings.NewReader(s))
	m := &manifest{}
	for {
		var o object
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			return m, nil
		}
		if err != nil {
			return nil, err
		}
		if o != nil {
			m.objects = append(m.objects, o)
		}
	}
}

func (m *manifest) all(kind string) []object {
	var r []object
	for _, o := range m.objects {
		if o["kind"] == kind {
			r = append(r, o)
		}
	}
	return r
}

func (m *manifest) find(t *testing.T, kind, name string) object {
	t.Helper()
	for _, o := range m.all(kind) {
		if str(o, "metadata", "name") == name {
			return o
		}
	}
	t.Fatalf("%s %s not rendered", kind, name)
	return nil
}

func (m *manifest) has(kind, name string) bool {
	for _, o := range m.all(kind) {
		if str(o, "metadata", "name") == name {
			return true
		}
	}
	return false
}

func get(v any, path ...string) any {
	for _, p := range path {
		mv, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mv[p]
	}
	return v
}

func str(v any, path ...string) string {
	s, _ := get(v, path...).(string)
	return s
}

// typed decodes a rendered object strictly into a Kubernetes API type, rejecting unknown fields.
func typed(t *testing.T, o object, into any) {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%s %s does not match the API schema: %v", o["kind"], str(o, "metadata", "name"), err)
	}
}

func daemonSet(t *testing.T, m *manifest, name string) *appsv1.DaemonSet {
	var ds appsv1.DaemonSet
	typed(t, m.find(t, "DaemonSet", name), &ds)
	return &ds
}

func statefulSet(t *testing.T, m *manifest) *appsv1.StatefulSet {
	var s appsv1.StatefulSet
	typed(t, m.find(t, "StatefulSet", "exitmesh-agent-coordinator"), &s)
	return &s
}

func testCA(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func valuesFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type valueSet struct {
	name string
	args []string
}

func valueSets(t *testing.T) []valueSet {
	ca := testCA(t)
	indented := "    " + strings.ReplaceAll(strings.TrimSpace(ca), "\n", "\n    ")
	full := valuesFile(t, `
endpoint: https://cp.example.com
trust:
  roots: ["root-1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="]
  threshold: 1
endpointCA: |
`+indented+`
enrollment:
  existingSecret: exitmesh-enrollment
  existingSecretKey: token
tls:
  mode: certManager
  caBundle: |
`+indented+`
  certManager:
    issuerRef: {name: cluster-ca, kind: ClusterIssuer}
lookback:
  - name: mimir
    type: mimir
    url: http://mimir-query-frontend.monitoring.svc:8080/prometheus
    tenant: team-a
    retention: 720h
    bearerToken: {secretName: mimir-reader, key: token}
    egress: {namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: monitoring}}}
  - name: logs
    type: victorialogs
    url: https://logs.example.com
    basicAuth: {secretName: vl-auth}
    ca: {configMapName: vl-ca}
    egress: {cidrs: [203.0.113.0/24]}
policy:
  maxRuleEvalTime: 1s
  disabledRules: [noisy-rule]
investigation:
  maxConcurrency: 2
  maxWindow: 3h
kubernetes:
  labelAllowlist: [app, team]
  clusterName: prod-eu
`)
	return []valueSet{
		{"default", baseArgs},
		{"namespaces", append([]string{"--set", "kubernetes.scope=namespaces", "--set", "kubernetes.namespaces={team-a,team-b}"}, baseArgs...)},
		{"namespaces-no-cluster-reads", append([]string{"--set", "kubernetes.scope=namespaces", "--set", "kubernetes.namespaces={team-a}", "--set", "rbac.clusterReads=false"}, baseArgs...)},
		{"airgap", []string{"--set", "enrollment.token=emx1_c_t-9_secret", "--set", "airgap.enabled=true", "--set", "airgap.bundles.configMap=exitmesh-bundles"}},
		{"metrics-only", append([]string{"--set", "capabilities.inventory=false", "--set", "capabilities.logs=false"}, baseArgs...)},
		{"root-fallback-rwo", append([]string{"--set", "node.runAsRootFallback=true", "--set", "coordinator.persistence.accessMode=ReadWriteOnce", "--set", "coordinator.persistence.storageClassName=fast"}, baseArgs...)},
		{"precreated-namespaces", append([]string{"--set", "createNamespaces=false", "--set", "namespaces.skipLookupValidation=true"}, baseArgs...)},
		{"full", []string{"-f", full}},
	}
}
