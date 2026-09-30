// Package e2e runs the real coordinator and two real node agents against the reference control plane.
package e2e

import (
	"bytes"
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
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/coordinator"
	"github.com/cloud-exit/exitmesh-agent/internal/node"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/scrape"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

const (
	issuer   = "https://kubernetes.default.svc.cluster.local"
	nodeNS   = "exitmesh-node"
	nodeSA   = "exitmesh-node"
	apiToken = "api-server-token"
	version  = "2026.09.28"
	// catchUp is how far the shared clock starts behind wall time, so node agents leave their rule warm-up (the 5m rate window) with fresh samples.
	catchUp = 5*time.Minute + 10*time.Second
	step    = 10 * time.Second
	waitMax = 20 * time.Second
)

// clock is wall time plus an offset that tests move forward.
type clock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
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

// apiServer is the fake Kubernetes API server serving issuer discovery and the service account JWKS.
type apiServer struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
}

func newAPIServer(t *testing.T) *apiServer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &apiServer{key: k}
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+apiToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": "https://203.0.113.1:6443/openid/v1/jwks", "id_token_signing_alg_values_supported": []string{"ES256"}})
		}
	})
	mux.HandleFunc("GET /openid/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k.Public(), KeyID: "sa-1", Algorithm: "ES256", Use: "sig"}}})
		}
	})
	a.srv = httptest.NewTLSServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

type bearer struct{ rt http.RoundTripper }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+apiToken)
	return b.rt.RoundTrip(r)
}

func (a *apiServer) client() *http.Client {
	return &http.Client{Transport: bearer{rt: a.srv.Client().Transport}}
}

// mint issues a projected node agent token bound to its pod and node.
func (a *apiServer) mint(t *testing.T, now time.Time, nodeName string) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: a.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "sa-1"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": issuer, "aud": []string{nodeapi.DefaultAudience}, "sub": "system:serviceaccount:" + nodeNS + ":" + nodeSA,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(59 * time.Minute).Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      nodeNS,
			"pod":            map[string]any{"name": "exitmesh-node-" + nodeName, "uid": "agent-uid-" + nodeName},
			"serviceaccount": map[string]any{"name": nodeSA, "uid": "sa-uid"},
			"node":           map[string]any{"name": nodeName, "uid": "uid-" + nodeName},
		},
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// trust holds test roots; the bundle signing key is only reachable through a key manifest signed by the rotated root.
type trust struct {
	root1, root2, sign1, sign2 bundle.SigningKey
	m1, m2                     []byte
}

func newTrust(t *testing.T) *trust {
	tr := &trust{}
	for _, k := range []struct {
		p  *bundle.SigningKey
		id string
	}{{&tr.root1, "root-1"}, {&tr.root2, "root-2"}, {&tr.sign1, "sign-1"}, {&tr.sign2, "sign-2"}} {
		var err error
		if *k.p, err = bundle.GenerateKey(k.id); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	key := func(k bundle.SigningKey) bundle.ManifestKey {
		return bundle.ManifestKey{ID: k.ID, PublicKey: k.Public().PublicKey, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}
	}
	m1, err := bundle.NewKeyManifest(1, now.Add(-2*time.Hour), []bundle.ManifestKey{key(tr.sign1)},
		[]bundle.SuccessorRoot{{ID: tr.root2.ID, PublicKey: tr.root2.Public().PublicKey, NotBefore: now.Add(-2 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if tr.m1, err = bundle.SignManifest(m1, tr.root1); err != nil {
		t.Fatal(err)
	}
	m2, err := bundle.NewKeyManifest(2, now.Add(-time.Hour), []bundle.ManifestKey{key(tr.sign2)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr.m2, err = bundle.SignManifest(m2, tr.root2); err != nil {
		t.Fatal(err)
	}
	return tr
}

func (tr *trust) rootEntry() string {
	return tr.root1.ID + ":" + base64.StdEncoding.EncodeToString(tr.root1.Public().PublicKey)
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (tr *trust) bundle(t *testing.T) (archive, sig []byte) {
	t.Helper()
	dir := t.TempDir()
	for n, body := range bundleFiles {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(n)), []byte(body))
	}
	archive, err := bundle.Build(dir)
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	if sig, err = bundle.Sign(archive, tr.sign2); err != nil {
		t.Fatal(err)
	}
	return archive, sig
}

func selfSigned(t *testing.T, dir string) (certFile, keyFile string) {
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
	writeFile(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return certFile, keyFile
}

func caFile(t *testing.T, dir, name string, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(dir, name)
	writeFile(t, p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return p
}

type coordRun struct {
	c      *coordinator.Coordinator
	cancel context.CancelFunc
	done   chan error
}

type agent struct {
	name, dir, logs string
	pod, uid        string
	kubelet         *kubelet
	log             *syncBuf
	a               *node.Agent
	cancel          context.CancelFunc
	done            chan error
}

type env struct {
	t             *testing.T
	clk           *clock
	cp            *refcp.Server
	cpSrv         *httptest.Server
	target, token string
	aux, coordDir string
	cert, key     string
	listen        string
	cl            *cluster
	api           *apiServer
	tr            *trust
	archive, sig  []byte
	coordLog      *syncBuf
	coord         *coordRun
	nodes         map[string]*agent
}

// newEnv starts refcp, the coordinator, and both node agents, and waits until the bundle converged and warm-up ended.
func newEnv(t *testing.T) *env {
	e := &env{t: t, clk: &clock{off: -catchUp}, cl: newCluster(t), api: newAPIServer(t), tr: newTrust(t), aux: t.TempDir(),
		listen: "127.0.0.1:0", coordLog: &syncBuf{}, nodes: map[string]*agent{}}
	var err error
	if e.coordDir, err = os.MkdirTemp("", "e2e"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(e.coordDir) })
	e.cp = refcp.New(refcp.Options{Now: e.clk.Now})
	e.cpSrv = httptest.NewTLSServer(e.cp)
	t.Cleanup(func() { e.cp.Close(); e.cpSrv.Close() })
	if e.target, e.token, err = e.cp.CreateTarget(protocol.TargetKubernetes); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.aux, "enroll-token"), []byte(e.token+"\n"))
	e.archive, e.sig = e.tr.bundle(t)
	if err := e.cp.PublishBundle(protocol.TargetKubernetes, version, e.archive, e.sig, e.tr.m2); err != nil {
		t.Fatal(err)
	}
	if err := e.cp.PublishKeyManifestChain(protocol.TargetKubernetes, [][]byte{e.tr.m1}); err != nil {
		t.Fatal(err)
	}
	e.cert, e.key = selfSigned(t, e.aux)
	e.startCoordinator()
	e.waitFor("initial checkpoint committed", func() bool {
		rs := e.records()
		return len(rs) > 0 && rs[0].Checkpoint != nil
	})
	for _, n := range []string{nodeA, nodeB} {
		e.startNode(n)
	}
	e.waitFor("both node agents registered on the bundle", func() bool {
		h, ok := e.health()
		return ok && len(h.Nodes) == 2 && h.Nodes[0].BundleVersion == version && h.Nodes[1].BundleVersion == version && h.Bundle.State == "converged"
	})
	for _, a := range e.nodes {
		e.waitFor(a.name+" tails its app stream and scrapes", func() bool {
			st := a.a.Status()
			return st.BundleVersion == version && st.Logs.Files >= 1 && a.kubelet.count() >= 5
		})
	}
	e.clk.Advance(catchUp)
	e.waitFor("node agents warm and covered", func() bool {
		for _, a := range e.nodes {
			if st := a.a.Status(); st.Warming || st.Coverage["metrics"] != "available" || st.Coverage["logs"] != "available" {
				return false
			}
		}
		h, ok := e.health()
		if !ok || !h.Time.After(e.clk.Now().Add(-time.Second)) {
			return false
		}
		for _, n := range h.Nodes {
			if n.Warming || !n.Covered {
				return false
			}
		}
		return true
	})
	return e
}

func (e *env) coordConfig() *config.Config {
	e.t.Helper()
	y := fmt.Sprintf(`role: coordinator
endpoint: %s
endpointCAFile: %s
enrollmentTokenFile: %s
stateDir: %s
kubernetes:
  resources: [pods, deployments, replicasets, nodes, services]
coordinator:
  listen: %s
  tlsCertFile: %s
  tlsKeyFile: %s
  namespace: exitmesh
  podName: exitmesh-agent-coordinator-0
spool:
  capacity: 1Gi
trust:
  roots: [%q]
investigation:
  timeout: 10s
`, e.cpSrv.URL, caFile(e.t, e.aux, "cp-ca.pem", e.cpSrv), filepath.Join(e.aux, "enroll-token"), e.coordDir, e.listen, e.cert, e.key, e.tr.rootEntry())
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		e.t.Fatal(err)
	}
	return cfg
}

func (e *env) startCoordinator() {
	e.t.Helper()
	c, err := coordinator.New(e.coordConfig(), coordinator.Deps{
		Dynamic: e.cl.dyn, Metadata: e.cl.meta, Discovery: e.cl.disc, Kube: e.cl.kube, Clock: e.clk.Now,
		APIServer: e.api.srv.URL, JWKSClient: e.api.client(),
		Logger: slog.New(slog.NewTextHandler(e.coordLog, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Getenv: func(k string) string {
			return map[string]string{coordinator.EnvNodeNamespace: nodeNS, coordinator.EnvNodeSA: nodeSA}[k]
		},
		Tuning: coordinator.Tuning{
			EvalInterval: 30 * time.Millisecond, SnapshotEvery: 20 * time.Millisecond, HousekeepEvery: 20 * time.Millisecond,
			NodeTimeout: 15 * time.Second, BundleEvery: 60 * time.Millisecond, RetryBase: 10 * time.Millisecond,
			BackoffBase: 5 * time.Millisecond, BackoffMax: 40 * time.Millisecond, HealthInterval: 50 * time.Millisecond,
			LongPollMax: 300 * time.Millisecond, FlushInterval: 20 * time.Millisecond,
			ReflectorBackoff: &wait.Backoff{Duration: 5 * time.Millisecond, Cap: 5 * time.Millisecond, Factor: 1, Steps: 1 << 20},
		},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &coordRun{c: c, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-r.done:
		e.t.Fatalf("coordinator exited before ready: %v\n%s", err, tail(e.coordLog.String()))
	case <-time.After(waitMax):
		cancel()
		e.t.Fatal("coordinator not ready")
	}
	e.coord = r
	e.listen = c.NodeAPIAddr()
	e.t.Cleanup(func() { e.stopCoordinator() })
}

func (e *env) stopCoordinator() {
	r := e.coord
	if r == nil {
		return
	}
	e.coord = nil
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			e.t.Errorf("coordinator stopped with %v", err)
		}
	case <-time.After(waitMax):
		e.t.Error("coordinator did not stop")
	}
}

// startNode starts a node agent on a fresh state directory; extra is appended to its configuration.
func (e *env) startNode(name string, extra ...string) *agent {
	t := e.t
	t.Helper()
	p := podOf[name]
	base := t.TempDir()
	a := &agent{name: name, dir: filepath.Join(base, "state"), logs: filepath.Join(base, "pods"), pod: p.name, uid: p.uid,
		kubelet: newKubelet(t, p.name), log: &syncBuf{}}
	for _, c := range []string{"app", "sidecar"} {
		writeFile(t, a.logPath(c), nil)
	}
	secrets := filepath.Join(base, "secrets")
	token := filepath.Join(secrets, "token")
	writeFile(t, token, []byte(e.api.mint(t, e.clk.Now(), name)+"\n"))
	kubeletTok := filepath.Join(secrets, "kubelet-token")
	writeFile(t, kubeletTok, []byte(kubeToken))
	y := fmt.Sprintf(`role: node
stateDir: %s
capabilities: [metrics, logs]
coordinator:
  serviceURL: https://%s
  caFile: %s
  tokenFile: %s
trust:
  roots: [%q]
node:
  name: %s
  logsPath: %s
  scrapeInterval: 200ms
  evidenceRing: 1Mi
  diskCap: 1Gi
investigation:
  maxConcurrency: 4
  timeout: 10s
`, a.dir, e.listen, e.cert, token, e.tr.rootEntry(), name, a.logs) + strings.Join(extra, "")
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	ag, err := node.New(cfg, node.Deps{
		Kube: e.cl.kube, Clock: e.clk.Now, PodName: "exitmesh-node-" + name,
		KubeletURL: a.kubelet.srv.URL, KubeletTokenFile: kubeletTok, KubeletCAFile: caFile(t, secrets, "kubelet-ca.crt", a.kubelet.srv),
		Coordinator: nodeapi.ClientOptions{Timeout: 5 * time.Second, LongPollTimeout: 5 * time.Second},
		Logger:      slog.New(slog.NewTextHandler(a.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Timing: node.Timing{EvalTick: 10 * time.Millisecond, Register: 150 * time.Millisecond, Facts: time.Hour, KubeRefresh: 100 * time.Millisecond,
			DiskCheck: time.Hour, RetryMin: 20 * time.Millisecond, RetryMax: 200 * time.Millisecond, LogPoll: 20 * time.Millisecond, LogCheckpoint: 100 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.a, a.cancel, a.done = ag, cancel, make(chan error, 1)
	go func() { a.done <- ag.Run(ctx) }()
	e.nodes[name] = a
	t.Cleanup(func() { e.stopNode(name) })
	e.waitFor(name+" registered", func() bool {
		h, ok := e.health()
		if !ok {
			return false
		}
		for _, n := range h.Nodes {
			if n.Name == name && !n.LastSeen.IsZero() {
				return true
			}
		}
		return false
	})
	return a
}

func (e *env) stopNode(name string) {
	a := e.nodes[name]
	if a == nil {
		return
	}
	delete(e.nodes, name)
	a.cancel()
	select {
	case err := <-a.done:
		if err != nil {
			e.t.Errorf("node agent %s stopped with %v", name, err)
		}
	case <-time.After(waitMax):
		e.t.Errorf("node agent %s did not stop", name)
	}
}

func (a *agent) logPath(container string) string {
	return filepath.Join(a.logs, ns+"_"+a.pod+"_"+a.uid, container, "0.log")
}

// writeLog appends CRI lines stamped with the shared clock.
func (a *agent) writeLog(t *testing.T, now time.Time, container string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(a.logPath(container), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := fmt.Fprintf(f, "%s stdout F %s\n", now.UTC().Format(time.RFC3339Nano), l); err != nil {
			t.Fatal(err)
		}
	}
}

func tail(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.Contains(l, "node agent registered") {
			keep = append(keep, l)
		}
	}
	s = strings.Join(keep, "\n")
	if len(s) > 6000 {
		return s[len(s)-6000:]
	}
	return s
}

func (e *env) waitFor(what string, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(waitMax)
	for !cond() {
		if time.Now().After(deadline) {
			var b strings.Builder
			fmt.Fprintf(&b, "timed out waiting for %s\ncoordinator log:\n%s", what, tail(e.coordLog.String()))
			for _, n := range []string{nodeA, nodeB} {
				if a := e.nodes[n]; a != nil {
					fmt.Fprintf(&b, "\n%s log:\n%s", n, tail(a.log.String()))
				}
			}
			e.t.Fatal(b.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// health returns the latest agent.health report the coordinator sent to refcp.
func (e *env) health() (coordinator.Health, bool) {
	hs, err := e.cp.HealthReports(e.target)
	if err != nil || len(hs) == 0 {
		return coordinator.Health{}, false
	}
	var h coordinator.Health
	if err := json.Unmarshal(hs[len(hs)-1], &h); err != nil {
		e.t.Fatal(err)
	}
	return h, true
}

// freshHealth waits for a health report generated after the given clock time.
func (e *env) freshHealth(after time.Time, what string, cond func(coordinator.Health) bool) coordinator.Health {
	e.t.Helper()
	var h coordinator.Health
	e.waitFor(what, func() bool {
		var ok bool
		h, ok = e.health()
		return ok && !h.Time.Before(after) && (cond == nil || cond(h))
	})
	return h
}

// advance moves the clock by d and waits until every running role evaluated at the new time and delivered.
func (e *env) advance(d time.Duration) {
	e.t.Helper()
	e.clk.Advance(d)
	target := e.clk.Now()
	e.waitFor("node agents evaluated and delivered", func() bool {
		for _, a := range e.nodes {
			st := a.a.Status()
			for _, r := range st.Rules {
				if !r.LastEval.IsZero() && r.LastEval.Before(target) {
					return false
				}
			}
			if e.coord != nil && st.Queue.Items != 0 {
				return false
			}
		}
		return true
	})
	if e.coord == nil {
		return
	}
	e.freshHealth(e.clk.Now(), "coordinator evaluated and committed", func(h coordinator.Health) bool {
		for _, r := range h.Rules {
			if !r.LastEval.IsZero() && r.LastEval.Before(target) {
				return false
			}
		}
		return h.Session.Connected && h.Session.CommittedHead == h.Chain.Head
	})
}

// stored reports whether the node agent stored a cadvisor scrape that started after at; a served scrape can still time out client-side.
func (a *agent) stored(at time.Time) bool {
	for _, ts := range a.a.Status().Targets {
		if strings.HasSuffix(ts.URL, "/metrics/cadvisor") && ts.Health == scrape.HealthUp && ts.LastScrape.After(at) {
			return true
		}
	}
	return false
}

// kubeletChange applies change to the node's kubelet fixture and waits until the agent stored a scrape that reflects it.
func (e *env) kubeletChange(name string, change func(*kubelet)) {
	e.t.Helper()
	a := e.nodes[name]
	change(a.kubelet)
	at := time.Now()
	e.waitFor(name+" stored a cadvisor scrape after the change", func() bool { return a.stored(at) })
}

// until advances the clock in rule intervals until cond holds, at most n times.
func (e *env) until(what string, n int, cond func() bool) {
	e.t.Helper()
	for i := 0; i < n; i++ {
		if cond() {
			return
		}
		e.advance(step)
	}
	if !cond() {
		e.t.Fatalf("%s: not reached after %d rule intervals\ncoordinator log:\n%s", what, n, tail(e.coordLog.String()))
	}
}

func (e *env) epochs() []refcp.EpochView {
	es, err := e.cp.Epochs(e.target)
	if err != nil {
		return nil
	}
	return es
}

// records returns every committed record of every epoch in order.
func (e *env) records() []*protocol.Record {
	var out []*protocol.Record
	for _, ep := range e.epochs() {
		rs, err := e.cp.Records(e.target, ep.ID)
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, rs...)
	}
	return out
}

func (e *env) findingRecords(rule string) []*protocol.Finding {
	var out []*protocol.Finding
	for _, r := range e.records() {
		if r.Finding != nil && r.Finding.Provenance.RuleID == rule {
			out = append(out, r.Finding)
		}
	}
	return out
}

func (e *env) findingState(rule string) []refcp.FindingState {
	fs, err := e.cp.Findings(e.target)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []refcp.FindingState
	for _, f := range fs {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

func (e *env) state() (*protocol.State, protocol.EpochID, uint64) {
	e.t.Helper()
	es := e.epochs()
	if len(es) != 1 {
		e.t.Fatalf("epochs %+v, want exactly one", es)
	}
	head := es[0].Head.Seq
	st, err := e.cp.StateAt(e.target, es[0].ID, head)
	if err != nil {
		e.t.Fatal(err)
	}
	return st, es[0].ID, head
}

func (e *env) callTool(name string, args map[string]any) map[string]any {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitMax)
	defer cancel()
	res, err := e.cp.CallTool(ctx, e.target, name, args)
	if err != nil {
		e.t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		e.t.Fatalf("%s failed: %+v", name, res)
	}
	var out map[string]any
	if err := json.Unmarshal(res.StructuredContent, &out); err != nil {
		e.t.Fatalf("%s result %s: %v", name, res.StructuredContent, err)
	}
	return out
}

// scanDir reports every file under dir containing needle.
func scanDir(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSocket != 0 {
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
	sort.Strings(hits)
	return hits
}
