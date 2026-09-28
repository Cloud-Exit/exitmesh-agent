package coordinator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/metricfacts"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

const (
	testIssuer = "https://kubernetes.default.svc.cluster.local"
	nodeNS     = "exitmesh-node"
	nodeSA     = "exitmesh-node"
	apiToken   = "coordinator-api-token"
	coordNS    = "exitmesh"
	coordPod   = "exitmesh-agent-coordinator-0"
)

var (
	podGVR  = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	depGVR  = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	fastRef = &wait.Backoff{Duration: 5 * time.Millisecond, Cap: 5 * time.Millisecond, Factor: 1, Steps: 1 << 20}
)

// testClock is wall time plus an offset tests can advance.
type testClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

type cluster struct {
	dyn  *dynamicfake.FakeDynamicClient
	meta *metadatafake.FakeMetadataClient
	disc *discoveryfake.FakeDiscovery
	kube *kubefake.Clientset
}

func toU(t testing.TB, obj runtime.Object, apiVersion, kind string) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	return u
}

func testPod(name, uid, node, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop", UID: types.UID(uid), ResourceVersion: "1", Labels: map[string]string{"app": "web"}},
		Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "app", Image: image,
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resourceQty("256Mi")}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func testObjects(t testing.TB) []*unstructured.Unstructured {
	rep := int32(2)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop", UID: "dep-1", ResourceVersion: "1", Labels: map[string]string{"app": "web"}},
		Spec: appsv1.DeploymentSpec{Replicas: &rep, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx:1.27"}}}}},
		Status: appsv1.DeploymentStatus{Replicas: 2, AvailableReplicas: 2},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop", UID: "svc-1", ResourceVersion: "1"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Name: "http", Port: 80}}},
	}
	var out []*unstructured.Unstructured
	for _, n := range []string{"node-1", "node-2"} {
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: n, UID: types.UID("uid-" + n), ResourceVersion: "1"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Capacity: corev1.ResourceList{corev1.ResourceMemory: resourceQty("8Gi")}},
		}
		out = append(out, toU(t, node, "v1", "Node"))
	}
	out = append(out,
		toU(t, testPod("web-1", "pod-1", "node-1", "nginx:1.27"), "v1", "Pod"),
		toU(t, testPod("web-2", "pod-2", "node-2", "nginx:1.27"), "v1", "Pod"),
		toU(t, dep, "apps/v1", "Deployment"),
		toU(t, svc, "v1", "Service"),
	)
	return out
}

func newCluster(t testing.TB) *cluster {
	listKinds := map[schema.GroupVersionResource]string{}
	for _, s := range state.Catalog() {
		listKinds[s.GVR] = s.APIKind + "List"
	}
	var objs []runtime.Object
	for _, o := range testObjects(t) {
		objs = append(objs, o)
	}
	ms := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(ms); err != nil {
		t.Fatal(err)
	}
	c := &cluster{
		dyn:  dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...),
		meta: metadatafake.NewSimpleMetadataClient(ms),
		disc: &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{}},
	}
	byGV := map[string]*metav1.APIResourceList{}
	for _, s := range state.Catalog() {
		gv := s.GVR.GroupVersion().String()
		if byGV[gv] == nil {
			byGV[gv] = &metav1.APIResourceList{GroupVersion: gv}
			c.disc.Resources = append(c.disc.Resources, byGV[gv])
		}
		byGV[gv].APIResources = append(byGV[gv].APIResources, metav1.APIResource{Name: s.GVR.Resource, Kind: s.APIKind, Namespaced: s.Namespaced, Verbs: metav1.Verbs{"get", "list", "watch"}})
	}
	sc := "local-nvme"
	c.kube = kubefake.NewSimpleClientset(
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: ClaimTemplateName + "-" + coordPod, Namespace: coordNS},
			Spec:   corev1.PersistentVolumeClaimSpec{VolumeName: "pv-1", StorageClassName: &sc, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod}},
			Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}, Spec: corev1.PersistentVolumeSpec{
			StorageClassName: sc, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			PersistentVolumeSource: corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: "/mnt/disk"}},
			NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
				MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-1"}}}}}}}}},
	)
	return c
}

func (c *cluster) setImage(t testing.TB, name, image string) {
	t.Helper()
	u, err := c.dyn.Tracker().Get(podGVR, "shop", name)
	if err != nil {
		t.Fatal(err)
	}
	obj := u.(*unstructured.Unstructured).DeepCopy()
	cs, _, _ := unstructured.NestedSlice(obj.Object, "spec", "containers")
	cs[0].(map[string]any)["image"] = image
	_ = unstructured.SetNestedSlice(obj.Object, cs, "spec", "containers")
	obj.SetResourceVersion(fmt.Sprint(time.Now().UnixNano()))
	if err := c.dyn.Tracker().Update(podGVR, obj, "shop"); err != nil {
		t.Fatal(err)
	}
}

// jwks is a fake API server serving issuer discovery and the service account signing keys.
type jwks struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
}

func newJWKS(t testing.TB) *jwks {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := &jwks{key: k}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+apiToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": testIssuer, "jwks_uri": "https://203.0.113.1/openid/v1/jwks", "id_token_signing_alg_values_supported": []string{"ES256"}})
		}
	})
	mux.HandleFunc("GET /openid/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k.Public(), KeyID: "sa-1", Algorithm: "ES256", Use: "sig"}}})
		}
	})
	j.srv = httptest.NewTLSServer(mux)
	t.Cleanup(j.srv.Close)
	return j
}

type bearer struct{ rt http.RoundTripper }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+apiToken)
	return b.rt.RoundTrip(r)
}

func (j *jwks) client() *http.Client {
	return &http.Client{Transport: bearer{rt: j.srv.Client().Transport}}
}

func (j *jwks) mint(t testing.TB, now time.Time, node string) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: j.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "sa-1"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": testIssuer, "aud": []string{nodeapi.DefaultAudience}, "sub": "system:serviceaccount:" + nodeNS + ":" + nodeSA,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(600 * time.Second).Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      nodeNS,
			"pod":            map[string]any{"name": "agent-" + node, "uid": "pod-uid-" + node},
			"serviceaccount": map[string]any{"name": nodeSA, "uid": "sa-uid"},
			"node":           map[string]any{"name": node, "uid": "node-uid-" + node},
		},
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type trust struct {
	root, sign bundle.SigningKey
	manifest   []byte
}

func newTrust(t testing.TB) *trust {
	root, err := bundle.GenerateKey("root-1")
	if err != nil {
		t.Fatal(err)
	}
	sign, err := bundle.GenerateKey("sign-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m, err := bundle.NewKeyManifest(1, now.Add(-time.Hour), []bundle.ManifestKey{{ID: sign.ID, PublicKey: sign.Public().PublicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := bundle.SignManifest(m, root)
	if err != nil {
		t.Fatal(err)
	}
	return &trust{root: root, sign: sign, manifest: signed}
}

func (tr *trust) rootEntry() string {
	return tr.root.ID + ":" + base64.StdEncoding.EncodeToString(tr.root.Public().PublicKey)
}

const stateRuleBundle = `version: "%s"
engine_version: 1
schema_version: 1
target_type: kubernetes
created_at: 2026-09-01T00:00:00Z
rules:
  - id: bad-image
    version: 1
    class: state
    target: kubernetes
    scope: cluster
    category: change
    severity: high
    capabilities: [inventory]
    summary: Pod runs a forbidden image
`

func buildBundle(t testing.TB, version, expr string) []byte {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"bundle.yaml":     fmt.Sprintf(stateRuleBundle, version),
		"state/pods.yaml": "- id: bad-image\n  version: 1\n  target: kubernetes\n  kinds: [Pod]\n  expr: '" + expr + "'\n",
	}
	for n, b := range files {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, err := bundle.Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const badImageExpr = `field(r, "containers.app.image", "") == "nginx:bad"`

func (tr *trust) signed(t testing.TB, version, expr string) (archive, sig []byte) {
	t.Helper()
	archive = buildBundle(t, version, expr)
	sig, err := bundle.Sign(archive, tr.sign)
	if err != nil {
		t.Fatal(err)
	}
	return archive, sig
}

func selfSigned(t testing.TB, dir string) (certFile, keyFile string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "exitmesh-coordinator"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

type env struct {
	t        *testing.T
	cp       *refcp.Server
	srv      *httptest.Server
	caFile   string
	targetID string
	token    string
	stateDir string
	aux      string
	cl       *cluster
	api      *jwks
	trust    *trust
	clock    *testClock
	airgap   bool
	capacity string
	tune     func(*Tuning)
}

type envOpt func(*env)

func withAirgap() envOpt           { return func(e *env) { e.airgap = true } }
func withCapacity(c string) envOpt { return func(e *env) { e.capacity = c } }

func newEnv(t *testing.T, opts ...envOpt) *env {
	e := &env{t: t, cl: newCluster(t), api: newJWKS(t), trust: newTrust(t), clock: &testClock{}, capacity: "10Gi"}
	for _, o := range opts {
		o(e)
	}
	var err error
	if e.stateDir, err = os.MkdirTemp("", "cx"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(e.stateDir) })
	e.aux = t.TempDir()
	e.cp = refcp.New(refcp.Options{Now: e.clock.Now})
	e.srv = httptest.NewTLSServer(e.cp)
	t.Cleanup(func() { e.cp.Close(); e.srv.Close() })
	e.caFile = filepath.Join(e.aux, "cp-ca.pem")
	if err := os.WriteFile(e.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if e.targetID, e.token, err = e.cp.CreateTarget(protocol.TargetKubernetes); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.aux, "token"), []byte(e.token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) config() *config.Config {
	e.t.Helper()
	cert, key := filepath.Join(e.aux, "tls.crt"), filepath.Join(e.aux, "tls.key")
	if _, err := os.Stat(cert); err != nil {
		cert, key = selfSigned(e.t, e.aux)
	}
	y := fmt.Sprintf(`role: coordinator
endpoint: %s
endpointCAFile: %s
enrollmentTokenFile: %s
stateDir: %s
kubernetes:
  resources: [pods, deployments, nodes, services]
coordinator:
  listen: 127.0.0.1:0
  tlsCertFile: %s
  tlsKeyFile: %s
  namespace: %s
  podName: %s
spool:
  capacity: %s
trust:
  roots: [%q]
`, e.srv.URL, e.caFile, filepath.Join(e.aux, "token"), e.stateDir, cert, key, coordNS, coordPod, e.capacity, e.trust.rootEntry())
	if e.airgap {
		y += fmt.Sprintf("airgap:\n  enabled: true\n  bundleDir: %s\n  exportDir: %s\n", filepath.Join(e.aux, "bundles"), filepath.Join(e.aux, "export"))
	}
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		e.t.Fatal(err)
	}
	return cfg
}

type running struct {
	c      *Coordinator
	cancel context.CancelFunc
	done   chan error
}

func (e *env) start(cfg *config.Config) *running {
	e.t.Helper()
	tun := Tuning{
		EvalInterval: 30 * time.Millisecond, SnapshotEvery: 20 * time.Millisecond, HousekeepEvery: 20 * time.Millisecond,
		NodeTimeout: 1500 * time.Millisecond, ExportEvery: 40 * time.Millisecond, BundleEvery: 60 * time.Millisecond,
		RetryBase: 10 * time.Millisecond, BackoffBase: 5 * time.Millisecond, BackoffMax: 40 * time.Millisecond,
		HealthInterval: 50 * time.Millisecond, LongPollMax: 300 * time.Millisecond, FlushInterval: 20 * time.Millisecond,
		ReflectorBackoff: fastRef,
	}
	if e.tune != nil {
		e.tune(&tun)
	}
	c, err := New(cfg, Deps{
		Dynamic: e.cl.dyn, Metadata: e.cl.meta, Discovery: e.cl.disc, Kube: e.cl.kube, Clock: e.clock.Now,
		APIServer: e.api.srv.URL, JWKSClient: e.api.client(),
		Getenv: func(k string) string {
			return map[string]string{EnvNodeNamespace: nodeNS, EnvNodeSA: nodeSA}[k]
		},
		Tuning: tun,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{c: c, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-r.done:
		e.t.Fatalf("coordinator exited before ready: %v", err)
	case <-time.After(15 * time.Second):
		cancel()
		e.t.Fatal("coordinator not ready")
	}
	e.t.Cleanup(func() { r.stop() })
	return r
}

func (r *running) stop() error {
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(20 * time.Second):
		return fmt.Errorf("coordinator did not stop")
	}
}

// advancing waits for cond while moving the clock past rule intervals (the bundle policy minimum is 10s).
func (e *env) advancing(what string, step time.Duration, cond func() bool) {
	e.t.Helper()
	eventually(e.t, what, func() bool {
		if cond() {
			return true
		}
		e.clock.Advance(step)
		time.Sleep(40 * time.Millisecond)
		return cond()
	})
}

func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (e *env) epochs() []refcp.EpochView {
	es, err := e.cp.Epochs(e.targetID)
	if err != nil {
		return nil
	}
	return es
}

func (e *env) records(id protocol.EpochID) []*protocol.Record {
	rs, err := e.cp.Records(e.targetID, id)
	if err != nil {
		return nil
	}
	return rs
}

// committed waits until the control plane committed the writer's whole chain and returns the head.
func (e *env) committed(r *running) (protocol.EpochID, uint64) {
	e.t.Helper()
	var id protocol.EpochID
	var head uint64
	eventually(e.t, "chain committed", func() bool {
		ep, ok := r.c.sp.Epoch()
		if !ok {
			return false
		}
		heads, err := e.cp.Heads(e.targetID)
		if err != nil {
			return false
		}
		id, head = ep.ID, ep.Chain.Head
		return heads[ep.ID].Seq == ep.Chain.Head && ep.Chain.Head > 0
	})
	return id, head
}

func (e *env) findings() []refcp.FindingState {
	fs, _ := e.cp.Findings(e.targetID)
	return fs
}

func (e *env) nodeClient(t testing.TB, r *running, node, claimed string) *nodeapi.Client {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(e.api.mint(t, e.clock.Now(), node)), 0o600); err != nil {
		t.Fatal(err)
	}
	nc, err := nodeapi.NewClient(nodeapi.ClientOptions{BaseURL: "https://" + r.c.NodeAPIAddr(), CAFile: filepath.Join(e.aux, "tls.crt"), TokenFile: tok, Node: claimed})
	if err != nil {
		t.Fatal(err)
	}
	return nc
}

func hasFieldUpdate(rs []*protocol.Record, uid, field string, want any) bool {
	for _, r := range rs {
		if r.Delta == nil {
			continue
		}
		for _, op := range r.Delta.Ops {
			if op.UID == uid && op.Kind == protocol.OpUpdate && protocol.ValueEqual(op.Fields[field], want) {
				return true
			}
		}
	}
	return false
}

func findingsFor(fs []refcp.FindingState, rule string) []refcp.FindingState {
	var out []refcp.FindingState
	for _, f := range fs {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

func healthOf(t testing.TB, raw json.RawMessage) Health {
	t.Helper()
	var h Health
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

type metricFact = metricfacts.Fact

func resourceQty(s string) resource.Quantity { return resource.MustParse(s) }
