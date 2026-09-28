package nodeapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testIssuer = "https://kubernetes.default.svc.cluster.local"
	testNS     = "exitmesh-node"
	testSA     = "exitmesh-node"
	apiToken   = "coordinator-token"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock { return &testClock{t: time.Now().Truncate(time.Second)} }

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

type testKey struct {
	kid  string
	alg  jose.SignatureAlgorithm
	priv crypto.Signer
}

func newECKey(t *testing.T, kid string) *testKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{kid: kid, alg: jose.ES256, priv: k}
}

func newRSAKey(t *testing.T, kid string) *testKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{kid: kid, alg: jose.RS256, priv: k}
}

func (k *testKey) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: k.alg, Key: k.priv}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.kid))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type fakeAPI struct {
	srv             *httptest.Server
	mu              sync.Mutex
	keys            []jose.JSONWebKey
	algs            []string
	discoveryStatus int
	jwksStatus      int
	discoveries     atomic.Int32
	fetches         atomic.Int32
}

func newFakeAPI(t *testing.T, keys ...*testKey) *fakeAPI {
	f := &fakeAPI{algs: []string{"RS256", "ES256", "HS256"}}
	f.publish(keys...)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.discoveries.Add(1)
		if !f.authorized(w, r) {
			return
		}
		f.mu.Lock()
		status, algs := f.discoveryStatus, f.algs
		f.mu.Unlock()
		if status != 0 {
			http.Error(w, "unavailable", status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": testIssuer, "jwks_uri": "https://203.0.113.1:6443/openid/v1/jwks", "id_token_signing_alg_values_supported": algs,
		})
	})
	mux.HandleFunc("GET /openid/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.fetches.Add(1)
		if !f.authorized(w, r) {
			return
		}
		f.mu.Lock()
		status, set := f.jwksStatus, jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey(nil), f.keys...)}
		f.mu.Unlock()
		if status != 0 {
			http.Error(w, "unavailable", status)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(set)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+apiToken {
		http.Error(w, "forbidden", http.StatusUnauthorized)
		return false
	}
	return true
}

func (f *fakeAPI) publish(keys ...*testKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = nil
	for _, k := range keys {
		f.keys = append(f.keys, jose.JSONWebKey{Key: k.priv.Public(), KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"})
	}
}

func (f *fakeAPI) set(fn func(*fakeAPI)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type bearerTransport struct{ rt http.RoundTripper }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+apiToken)
	return b.rt.RoundTrip(r)
}

func (f *fakeAPI) client() *http.Client {
	return &http.Client{Transport: bearerTransport{rt: f.srv.Client().Transport}}
}

func newAuth(t *testing.T, f *fakeAPI, clock *testClock, resolve NodeResolver) *Authenticator {
	t.Helper()
	a, err := NewAuthenticator(AuthOptions{
		APIServer: f.srv.URL + "/", HTTPClient: f.client(), Namespace: testNS, ServiceAccount: testSA,
		ResolvePod: resolve, Clock: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func claimsFor(now time.Time, node string) map[string]any {
	k := map[string]any{
		"namespace":      testNS,
		"pod":            map[string]any{"name": "agent-abc", "uid": "pod-uid-1"},
		"serviceaccount": map[string]any{"name": testSA, "uid": "sa-uid"},
	}
	if node != "" {
		k["node"] = map[string]any{"name": node, "uid": "node-uid"}
	}
	return map[string]any{
		"iss": testIssuer, "aud": []string{DefaultAudience}, "sub": "system:serviceaccount:" + testNS + ":" + testSA,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(600 * time.Second).Unix(), "jti": "id-1", "kubernetes.io": k,
	}
}

func TestAuthenticateValid(t *testing.T) {
	key := newECKey(t, "k1")
	api := newFakeAPI(t, key)
	clock := newClock()
	a := newAuth(t, api, clock, nil)
	tok := key.mint(t, claimsFor(clock.Now(), "node-1"))
	for range 3 {
		id, err := a.Authenticate(context.Background(), tok)
		if err != nil {
			t.Fatal(err)
		}
		want := Identity{Node: "node-1", Namespace: testNS, ServiceAccount: testSA, Pod: "agent-abc", PodUID: "pod-uid-1", Expiry: clock.Now().Add(600 * time.Second)}
		if !id.Expiry.Equal(want.Expiry) {
			t.Fatalf("expiry = %v, want %v", id.Expiry, want.Expiry)
		}
		id.Expiry = want.Expiry
		if id != want {
			t.Fatalf("identity = %+v", id)
		}
	}
	if d, f := api.discoveries.Load(), api.fetches.Load(); d != 1 || f != 1 {
		t.Fatalf("discoveries = %d, key fetches = %d, want 1 and 1", d, f)
	}
	rsaKey := newRSAKey(t, "r1")
	api.publish(key, rsaKey)
	if _, err := a.Authenticate(context.Background(), rsaKey.mint(t, claimsFor(clock.Now(), "node-1"))); err != nil {
		t.Fatalf("RS256 token: %v", err)
	}
}

func TestAuthenticateRejects(t *testing.T) {
	key := newECKey(t, "k1")
	stranger := newECKey(t, "k9")
	api := newFakeAPI(t, key)
	clock := newClock()
	a := newAuth(t, api, clock, nil)
	now := clock.Now()
	kube := func(c map[string]any) map[string]any { return c["kubernetes.io"].(map[string]any) }
	cases := map[string]struct {
		key    *testKey
		mutate func(map[string]any)
	}{
		"wrong audience": {key, func(c map[string]any) { c["aud"] = []string{"https://kubernetes.default.svc"} }},
		"expired": {key, func(c map[string]any) {
			c["iat"], c["exp"] = now.Add(-20*time.Minute).Unix(), now.Add(-10*time.Minute).Unix()
		}},
		"not yet valid":           {key, func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }},
		"wrong issuer":            {key, func(c map[string]any) { c["iss"] = "https://evil.example" }},
		"unknown key":             {stranger, func(map[string]any) {}},
		"wrong service account":   {key, func(c map[string]any) { kube(c)["serviceaccount"] = map[string]any{"name": "default", "uid": "x"} }},
		"wrong namespace":         {key, func(c map[string]any) { kube(c)["namespace"] = "tenant" }},
		"subject mismatch":        {key, func(c map[string]any) { c["sub"] = "system:serviceaccount:tenant:" + testSA }},
		"no service account":      {key, func(c map[string]any) { delete(kube(c), "serviceaccount") }},
		"not bound to pod":        {key, func(c map[string]any) { delete(kube(c), "pod") }},
		"pod without uid":         {key, func(c map[string]any) { kube(c)["pod"] = map[string]any{"name": "agent-abc"} }},
		"no iat":                  {key, func(c map[string]any) { delete(c, "iat") }},
		"lifetime too long":       {key, func(c map[string]any) { c["exp"] = now.Add(48 * time.Hour).Unix() }},
		"no node, no resolver":    {key, func(c map[string]any) { delete(kube(c), "node") }},
		"node claim without name": {key, func(c map[string]any) { kube(c)["node"] = map[string]any{"uid": "u"} }},
	}
	for name, c := range cases {
		claims := claimsFor(now, "node-1")
		c.mutate(claims)
		if _, err := a.Authenticate(context.Background(), c.key.mint(t, claims)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		}
	}
	for _, tok := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err := a.Authenticate(context.Background(), tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("token %q: err = %v", tok, err)
		}
	}
	api.set(func(f *fakeAPI) { f.algs = []string{"HS256"} })
	b := newAuth(t, api, clock, nil)
	if _, err := b.Authenticate(context.Background(), key.mint(t, claimsFor(now, "node-1"))); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ES256 token accepted although discovery allows only symmetric algorithms: %v", err)
	}
}

func TestAuthenticatePodResolver(t *testing.T) {
	key := newECKey(t, "k1")
	api := newFakeAPI(t, key)
	clock := newClock()
	type pod struct{ node, uid string }
	var mu sync.Mutex
	pods := map[string]pod{testNS + "/agent-abc": {"node-7", "pod-uid-1"}}
	resolve := PodNodeResolver(func(ns, name string) (string, string, bool) {
		mu.Lock()
		defer mu.Unlock()
		p, ok := pods[ns+"/"+name]
		return p.node, p.uid, ok
	})
	a := newAuth(t, api, clock, resolve)
	tok := key.mint(t, claimsFor(clock.Now(), ""))
	id, err := a.Authenticate(context.Background(), tok)
	if err != nil || id.Node != "node-7" {
		t.Fatalf("identity = %+v, err = %v", id, err)
	}
	withNode, err := a.Authenticate(context.Background(), key.mint(t, claimsFor(clock.Now(), "node-1")))
	if err != nil || withNode.Node != "node-1" {
		t.Fatalf("node claim must take precedence: %+v %v", withNode, err)
	}
	for name, p := range map[string]*pod{"recreated pod": {"node-7", "pod-uid-2"}, "unscheduled pod": {"", "pod-uid-1"}, "deleted pod": nil} {
		mu.Lock()
		if p == nil {
			delete(pods, testNS+"/agent-abc")
		} else {
			pods[testNS+"/agent-abc"] = *p
		}
		mu.Unlock()
		if _, err := a.Authenticate(context.Background(), tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		}
	}
}

func TestAuthenticateKeyRotation(t *testing.T) {
	k1, k2 := newECKey(t, "k1"), newRSAKey(t, "k2")
	api := newFakeAPI(t, k1)
	clock := newClock()
	a := newAuth(t, api, clock, nil)
	if _, err := a.Authenticate(context.Background(), k1.mint(t, claimsFor(clock.Now(), "node-1"))); err != nil {
		t.Fatal(err)
	}
	api.publish(k1, k2)
	if _, err := a.Authenticate(context.Background(), k2.mint(t, claimsFor(clock.Now(), "node-1"))); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if n := api.fetches.Load(); n != 2 {
		t.Fatalf("key fetches = %d, want 2 (one refresh for the new kid)", n)
	}
	if _, err := a.Authenticate(context.Background(), k1.mint(t, claimsFor(clock.Now(), "node-1"))); err != nil || api.fetches.Load() != 2 {
		t.Fatalf("cached old key: err = %v, fetches = %d", err, api.fetches.Load())
	}
}

func TestAuthenticateUnavailable(t *testing.T) {
	key := newECKey(t, "k1")
	api := newFakeAPI(t, key)
	clock := newClock()
	a := newAuth(t, api, clock, nil)
	tok := key.mint(t, claimsFor(clock.Now(), "node-1"))
	api.set(func(f *fakeAPI) { f.discoveryStatus = http.StatusInternalServerError })
	for range 2 {
		if _, err := a.Authenticate(context.Background(), tok); !errors.Is(err, ErrAuthUnavailable) {
			t.Fatalf("err = %v, want ErrAuthUnavailable", err)
		}
	}
	if n := api.discoveries.Load(); n != 1 {
		t.Fatalf("discovery attempts = %d, want 1 inside the retry window", n)
	}
	api.set(func(f *fakeAPI) { f.discoveryStatus, f.jwksStatus = 0, http.StatusServiceUnavailable })
	clock.Advance(discoveryRetry)
	if _, err := a.Authenticate(context.Background(), tok); !errors.Is(err, ErrAuthUnavailable) {
		t.Fatalf("key fetch failure: err = %v, want ErrAuthUnavailable", err)
	}
	api.set(func(f *fakeAPI) { f.jwksStatus = 0 })
	if _, err := a.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if n := api.discoveries.Load(); n != 2 {
		t.Fatalf("discovery attempts = %d, want 2", n)
	}
}

func TestNewAuthenticatorValidation(t *testing.T) {
	c := http.DefaultClient
	for name, o := range map[string]AuthOptions{
		"no api server":      {HTTPClient: c, Namespace: "a", ServiceAccount: "b"},
		"no client":          {APIServer: "https://x", Namespace: "a", ServiceAccount: "b"},
		"no namespace":       {APIServer: "https://x", HTTPClient: c, ServiceAccount: "b"},
		"no service account": {APIServer: "https://x", HTTPClient: c, Namespace: "a"},
	} {
		if _, err := NewAuthenticator(o); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
