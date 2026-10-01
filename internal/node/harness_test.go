package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const (
	testNode   = "node-a"
	otherNode  = "node-b"
	testIssuer = "https://kubernetes.default.svc.cluster.local"
	testNS     = "exitmesh-node"
	testSA     = "exitmesh-node"
	apiToken   = "coordinator-api-token"
	kubeToken  = "kubelet-sa-token"
	selfPod    = "exitmesh-node-self"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeCoord is the coordinator side of the node API.
type fakeCoord struct {
	mu        sync.Mutex
	regs      []nodeapi.RegisterRequest
	items     map[uint64]nodeapi.Item
	submitErr error
	reject    func(nodeapi.Item) bool
	bundle    *nodeapi.BundlePayload
	bundleCh  chan struct{}
	kube      nodeapi.KubeUpdate
	kubeCh    chan struct{}
	tasks     []nodeapi.Task
	tasksCh   chan struct{}
	results   map[string]nodeapi.TaskResult
	accepted  map[uint64]int
	queueSeqs []string
}

func newFakeCoord() *fakeCoord {
	return &fakeCoord{items: map[uint64]nodeapi.Item{}, results: map[string]nodeapi.TaskResult{}, accepted: map[uint64]int{},
		bundleCh: make(chan struct{}), kubeCh: make(chan struct{}), tasksCh: make(chan struct{})}
}

func (c *fakeCoord) Register(_ context.Context, node string, req nodeapi.RegisterRequest) (nodeapi.RegisterResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.regs = append(c.regs, req)
	var target string
	if c.bundle != nil {
		target = c.bundle.Version
	}
	return nodeapi.RegisterResponse{TargetBundle: target, ServerTimeMs: time.Now().UnixMilli()}, nil
}

func (c *fakeCoord) Submit(_ context.Context, node, queue string, items []nodeapi.Item) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.submitErr != nil {
		return 0, c.submitErr
	}
	for _, it := range items {
		if c.reject != nil && c.reject(it) {
			return 0, fmt.Errorf("%w: item %d refused", nodeapi.ErrInvalid, it.Seq)
		}
	}
	for _, it := range items {
		c.items[it.Seq] = it
		c.accepted[it.Seq]++
		c.queueSeqs = append(c.queueSeqs, fmt.Sprintf("%s/%d", queue, it.Seq))
	}
	return items[len(items)-1].Seq, nil
}

func (c *fakeCoord) Bundle(_ context.Context, node, have string) (*nodeapi.BundlePayload, <-chan struct{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bundle != nil && c.bundle.Version != have {
		p := *c.bundle
		return &p, c.bundleCh, nil
	}
	return nil, c.bundleCh, nil
}

func (c *fakeCoord) Kube(_ context.Context, node string, since uint64) (nodeapi.KubeUpdate, <-chan struct{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kube, c.kubeCh, nil
}

func (c *fakeCoord) Tasks(_ context.Context, node string) ([]nodeapi.Task, <-chan struct{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]nodeapi.Task(nil), c.tasks...), c.tasksCh, nil
}

func (c *fakeCoord) TaskResult(_ context.Context, node string, res nodeapi.TaskResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, t := range c.tasks {
		if t.ID == res.ID {
			c.tasks = append(c.tasks[:i], c.tasks[i+1:]...)
			c.results[res.ID] = res
			return nil
		}
	}
	return fmt.Errorf("%w: %s", nodeapi.ErrUnknownTask, res.ID)
}

func (c *fakeCoord) set(fn func(*fakeCoord)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(c)
}

func (c *fakeCoord) setBundle(p *nodeapi.BundlePayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bundle = p
	close(c.bundleCh)
	c.bundleCh = make(chan struct{})
}

func (c *fakeCoord) setKube(u nodeapi.KubeUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kube = u
	close(c.kubeCh)
	c.kubeCh = make(chan struct{})
}

func (c *fakeCoord) addTask(t nodeapi.Task) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tasks = append(c.tasks, t)
	close(c.tasksCh)
	c.tasksCh = make(chan struct{})
}

func (c *fakeCoord) result(id string) (nodeapi.TaskResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.results[id]
	return r, ok
}

func (c *fakeCoord) received(kind nodeapi.ItemKind) []nodeapi.Item {
	c.mu.Lock()
	defer c.mu.Unlock()
	seqs := make([]uint64, 0, len(c.items))
	for s := range c.items {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var out []nodeapi.Item
	for _, s := range seqs {
		if it := c.items[s]; it.Kind == kind {
			out = append(out, it)
		}
	}
	return out
}

func (c *fakeCoord) findings(t *testing.T) []*protocol.Finding {
	t.Helper()
	var out []*protocol.Finding
	for _, it := range c.received(nodeapi.KindFinding) {
		f, err := protocol.DecodeFinding(it.Finding)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func (c *fakeCoord) lastRegister() (nodeapi.RegisterRequest, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.regs) == 0 {
		return nodeapi.RegisterRequest{}, false
	}
	return c.regs[len(c.regs)-1], true
}

// fakeKubelet serves kubelet and cadvisor metrics behind bearer authentication.
type fakeKubelet struct {
	mu       sync.Mutex
	cadvisor string
	metrics  string
	srv      *httptest.Server
	scrapes  int
}

func (k *fakeKubelet) set(cadvisor string) {
	k.mu.Lock()
	k.cadvisor = cadvisor
	k.mu.Unlock()
}

func (k *fakeKubelet) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.scrapes
}

func (k *fakeKubelet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+kubeToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	k.mu.Lock()
	body := k.metrics
	if r.URL.Path == "/metrics/cadvisor" {
		body = k.cadvisor
		k.scrapes++
	}
	k.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(body))
}

func memFixture(v float64) string {
	return fmt.Sprintf("# TYPE container_memory_working_set_bytes gauge\n"+
		"container_memory_working_set_bytes{container=\"app\",namespace=\"prod\",pod=\"web-1\",id=\"/kubepods/web-1/app\"} %g\n"+
		"# TYPE container_cpu_usage_seconds_total counter\n"+
		"container_cpu_usage_seconds_total{container=\"app\",namespace=\"prod\",pod=\"web-1\",id=\"/kubepods/web-1/app\"} %g\n", v, v/1000)
}

type trust struct {
	root, signing bundle.SigningKey
	manifest      []byte
}

func newTrust(t *testing.T) *trust {
	t.Helper()
	root, err := bundle.GenerateKey("root-1")
	if err != nil {
		t.Fatal(err)
	}
	signing, err := bundle.GenerateKey("sign-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m, err := bundle.NewKeyManifest(1, now.Add(-time.Hour), []bundle.ManifestKey{{
		ID: signing.ID, PublicKey: signing.Public().PublicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sm, err := bundle.SignManifest(m, root)
	if err != nil {
		t.Fatal(err)
	}
	return &trust{root: root, signing: signing, manifest: sm}
}

func (tr *trust) rootEntry() string {
	return tr.root.ID + ":" + base64.StdEncoding.EncodeToString(tr.root.Public().PublicKey)
}

// payload builds and signs a bundle from its files.
func (tr *trust) payload(t *testing.T, files map[string]string) *nodeapi.BundlePayload {
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
	archive, err := bundle.Build(dir)
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	sig, err := bundle.Sign(archive, tr.signing)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(archive)
	if err != nil {
		t.Fatal(err)
	}
	return &nodeapi.BundlePayload{Version: b.Manifest.Version, Archive: archive, Signature: sig, KeyManifest: tr.manifest}
}

type ruleSpec struct {
	id, class, scope, file, group, alert, extra string
	caps                                        string
}

// bundleFiles renders bundle.yaml for rules plus the given rule-group files.
func bundleFiles(version string, rules []ruleSpec, groups map[string]string) map[string]string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %q\nengine_version: 1\nschema_version: 1\ntarget_type: kubernetes\ncreated_at: 2026-09-01T00:00:00Z\nrules:\n", version)
	for _, r := range rules {
		fmt.Fprintf(&b, "  - id: %s\n    version: 1\n    class: %s\n    target: kubernetes\n    scope: %s\n    file: %s\n    group: %s\n    alert: %s\n    category: saturation\n    severity: high\n    capabilities: [%s]\n",
			r.id, r.class, r.scope, r.file, r.group, r.alert, r.caps)
		if r.extra != "" {
			b.WriteString(r.extra)
		}
	}
	out := map[string]string{"bundle.yaml": b.String()}
	for k, v := range groups {
		out[k] = v
	}
	return out
}

type jwksServer struct {
	key *ecdsa.PrivateKey
	srv *httptest.Server
}

func newJWKS(t *testing.T) *jwksServer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := &jwksServer{key: k}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": testIssuer, "jwks_uri": "https://203.0.113.1:6443/openid/v1/jwks", "id_token_signing_alg_values_supported": []string{"ES256"}})
	})
	mux.HandleFunc("GET /openid/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k.Public(), KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	})
	j.srv = httptest.NewTLSServer(mux)
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwksServer) mint(t *testing.T, node string) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: j.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": testIssuer, "aud": []string{nodeapi.DefaultAudience}, "sub": "system:serviceaccount:" + testNS + ":" + testSA,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(600 * time.Second).Unix(), "jti": "id-1",
		"kubernetes.io": map[string]any{
			"namespace": testNS, "pod": map[string]any{"name": selfPod, "uid": "self-uid"},
			"serviceaccount": map[string]any{"name": testSA, "uid": "sa-uid"}, "node": map[string]any{"name": node, "uid": "node-uid"},
		},
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type bearer struct{ rt http.RoundTripper }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+apiToken)
	return b.rt.RoundTrip(r)
}

type options struct {
	caps      string
	ring      string
	diskCap   string
	realClock bool
	facts     time.Duration
	disk      time.Duration
	tsdbBlock time.Duration
	tsdbWAL   int
	extraNode string
	// extraTop is appended to the configuration at the top level.
	extraTop string
}

type harness struct {
	t       *testing.T
	o       options
	dir     string
	logs    string
	clock   *testClock
	coord   *fakeCoord
	kubelet *fakeKubelet
	kube    *fake.Clientset
	trust   *trust
	cfgYAML string
	deps    Deps

	mu    sync.Mutex
	agent *Agent
	stop  context.CancelFunc
	done  chan error
	logb  *syncBuf

	api       *jwksServer
	tokenFile string
	// intercept answers node API requests with its status code instead of the server while it returns non-zero.
	intercept atomic.Pointer[func(*http.Request) int]
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func writeCA(t *testing.T, dir, name string, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newHarness(t *testing.T, o options) *harness {
	t.Helper()
	if o.caps == "" {
		o.caps = "metrics, logs"
	}
	if o.ring == "" {
		o.ring = "1Mi"
	}
	if o.diskCap == "" {
		o.diskCap = "1Gi"
	}
	base := t.TempDir()
	h := &harness{t: t, o: o, dir: filepath.Join(base, "state"), logs: filepath.Join(base, "pods"), clock: &testClock{t: time.Now()},
		coord: newFakeCoord(), trust: newTrust(t), logb: &syncBuf{}}
	secrets := filepath.Join(base, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.logs, 0o755); err != nil {
		t.Fatal(err)
	}
	h.api = newJWKS(t)
	auth, err := nodeapi.NewAuthenticator(nodeapi.AuthOptions{
		APIServer: h.api.srv.URL + "/", HTTPClient: &http.Client{Transport: bearer{rt: h.api.srv.Client().Transport}},
		Namespace: testNS, ServiceAccount: testSA,
	})
	if err != nil {
		t.Fatal(err)
	}
	api := nodeapi.NewServer(nodeapi.Options{Auth: auth, Backend: h.coord, LongPollMax: 500 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(h.logb, nil))})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := h.intercept.Load(); f != nil {
			if code := (*f)(r); code != 0 {
				http.Error(w, http.StatusText(code), code)
				return
			}
		}
		api.ServeHTTP(w, r)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	coordCA := writeCA(t, secrets, "coordinator-ca.crt", srv)
	tokenFile := filepath.Join(secrets, "token")
	h.tokenFile = tokenFile
	if err := os.WriteFile(tokenFile, []byte(h.api.mint(t, testNode)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.kubelet = &fakeKubelet{cadvisor: memFixture(900), metrics: "# TYPE kubelet_running_pods gauge\nkubelet_running_pods 2\n"}
	h.kubelet.srv = httptest.NewTLSServer(h.kubelet)
	t.Cleanup(h.kubelet.srv.Close)
	kubeletCA := writeCA(t, secrets, "kubelet-ca.crt", h.kubelet.srv)
	kubeletToken := filepath.Join(secrets, "kubelet-token")
	if err := os.WriteFile(kubeletToken, []byte(kubeToken), 0o600); err != nil {
		t.Fatal(err)
	}
	podMetrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# TYPE app_requests_total counter\napp_requests_total 5\n"))
	}))
	t.Cleanup(podMetrics.Close)
	h.kube = fake.NewClientset(testPods(podMetrics.Listener.Addr().(*net.TCPAddr).Port)...)
	h.cfgYAML = fmt.Sprintf(`role: node
stateDir: %s
capabilities: [%s]
coordinator:
  serviceURL: %s
  caFile: %s
  tokenFile: %s
trust:
  roots: [%q]
node:
  name: %s
  logsPath: %s
  scrapeInterval: 200ms
  evidenceRing: %s
  diskCap: %s
%sinvestigation:
  maxConcurrency: 2
  timeout: 10s
`, h.dir, o.caps, srv.URL, coordCA, tokenFile, h.trust.rootEntry(), testNode, h.logs, o.ring, o.diskCap, o.extraNode) + o.extraTop
	clock := h.clock.Now
	if o.realClock {
		clock = time.Now
	}
	h.deps = Deps{
		Kube: h.kube, Clock: clock, PodName: selfPod, KubeletURL: h.kubelet.srv.URL, KubeletTokenFile: kubeletToken, KubeletCAFile: kubeletCA,
		Coordinator: nodeapi.ClientOptions{Timeout: 5 * time.Second, LongPollTimeout: 5 * time.Second},
		Logger:      slog.New(slog.NewTextHandler(h.logb, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Timing: Timing{
			EvalTick: 10 * time.Millisecond, Register: 150 * time.Millisecond, Facts: o.facts, KubeRefresh: 100 * time.Millisecond,
			DiskCheck: o.disk, RetryMin: 20 * time.Millisecond, RetryMax: 200 * time.Millisecond, LogPoll: 20 * time.Millisecond,
			LogCheckpoint: 100 * time.Millisecond, TSDBBlock: o.tsdbBlock, TSDBWALBytes: o.tsdbWAL,
		},
	}
	if h.deps.Timing.Facts == 0 {
		h.deps.Timing.Facts = time.Hour
	}
	if h.deps.Timing.DiskCheck == 0 {
		h.deps.Timing.DiskCheck = time.Hour
	}
	return h
}

func pod(ns, name, uid, node string, containers ...string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid), Labels: map[string]string{"app": name, "pod-template-hash": "7d9f"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: strings.TrimSuffix(name, "-1") + "-7d9f", UID: "rs-" + types.UID(uid), Controller: new(true)}}},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1", HostIP: "10.1.0.1"},
	}
	for _, c := range containers {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c, Image: "registry.example/" + c + ":1", Resources: corev1.ResourceRequirements{
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1000")},
			Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("500")},
		}})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: c, Ready: true, Image: "registry.example/" + c + ":1"})
	}
	return p
}

func testPods(metricsPort int) []runtime.Object {
	chatty := pod("other", "chatty-1", "uid-chatty-1", testNode, "main")
	chatty.Status.PodIP = "127.0.0.1"
	chatty.Annotations = map[string]string{"prometheus.io/scrape": "true", "prometheus.io/port": fmt.Sprint(metricsPort)}
	return []runtime.Object{
		pod("prod", "web-1", "uid-web-1", testNode, "app", "sidecar"),
		chatty,
		pod("prod", "db-1", "uid-db-1", otherNode, "db"),
	}
}

func (h *harness) config() *config.Config {
	h.t.Helper()
	cfg, err := config.Parse([]byte(h.cfgYAML))
	if err != nil {
		h.t.Fatalf("config: %v", err)
	}
	return cfg
}

// start runs a new agent over the state directory.
func (h *harness) start() *Agent {
	h.t.Helper()
	a, err := New(h.config(), h.deps)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	h.mu.Lock()
	h.agent, h.stop, h.done = a, cancel, done
	h.mu.Unlock()
	h.t.Cleanup(func() { h.shutdown() })
	h.waitFor("agent opened", func() bool { return a.cov.evaluatedCycles() > 0 })
	return a
}

func (h *harness) shutdown() error {
	h.mu.Lock()
	stop, done := h.stop, h.done
	h.stop, h.done = nil, nil
	h.mu.Unlock()
	if stop == nil {
		return nil
	}
	stop()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		h.t.Fatal("agent did not stop")
		return nil
	}
}

func (h *harness) waitFor(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s\nagent log:\n%s", what, tail(h.logb.String(), 4000))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// step advances the test clock and waits for two full evaluation cycles at the new time.
func (h *harness) step(d time.Duration) {
	h.t.Helper()
	h.clock.Advance(d)
	a := h.agent
	n := a.cov.evaluatedCycles()
	h.waitFor("evaluation cycles", func() bool { return a.cov.evaluatedCycles() >= n+2 })
}

func (h *harness) waitBundle(version string) {
	h.t.Helper()
	h.waitFor("bundle "+version, func() bool { return h.agent.eng.BundleVersion() == version })
}

func (h *harness) waitScrapes(n int) {
	h.t.Helper()
	start := h.kubelet.count()
	h.waitFor("kubelet scrapes", func() bool { return h.kubelet.count() >= start+n })
	time.Sleep(50 * time.Millisecond)
}

// waitDelivered waits until the coordinator acknowledged every queued item.
func (h *harness) waitDelivered() {
	h.t.Helper()
	h.waitFor("queue drained", func() bool {
		u := h.agent.queue.Usage()
		return u.Items == 0
	})
}

func (h *harness) rule(id string) (st ruleStateView) {
	for _, r := range h.agent.eng.RuleStates() {
		if r.RuleID == id {
			return ruleStateView{State: r.State, Pending: r.Pending, Firing: r.Firing, Reason: r.Reason, Found: true}
		}
	}
	return ruleStateView{}
}

type ruleStateView struct {
	State, Reason   string
	Pending, Firing int
	Found           bool
}

// writeLog appends CRI lines to a container log file.
func (h *harness) writeLog(ns, podName, uid, container string, lines ...string) {
	h.t.Helper()
	dir := filepath.Join(h.logs, ns+"_"+podName+"_"+uid, container)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		h.t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "0.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := fmt.Fprintf(f, "%s stdout F %s\n", h.deps.Clock().UTC().Format(time.RFC3339Nano), l); err != nil {
			h.t.Fatal(err)
		}
	}
}

// preopenStreams writes a backlog line to each test stream so tests can wait for open files before writing their own lines.
func (h *harness) preopenStreams() {
	h.t.Helper()
	h.writeLog("prod", "web-1", "uid-web-1", "app", "starting")
	h.writeLog("prod", "web-1", "uid-web-1", "sidecar", "starting")
	h.writeLog("other", "chatty-1", "uid-chatty-1", "main", "starting")
}

// scanState reports every file under the state directory containing needle.
func scanState(t *testing.T, dir string, needle string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(needle)) {
			hits = append(hits, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func transitions(fs []*protocol.Finding, rule string) []string {
	var out []string
	for _, f := range fs {
		if f.Provenance.RuleID == rule {
			out = append(out, f.Transition.String())
		}
	}
	return out
}
