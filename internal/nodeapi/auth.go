package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// DefaultAudience is the projected token audience the coordinator accepts.
const DefaultAudience = "exitmesh-coordinator"

// DefaultMaxTokenLifetime bounds exp minus iat; the chart projects 600 s tokens.
const DefaultMaxTokenLifetime = time.Hour

const (
	discoveryRetry   = 5 * time.Second
	discoveryTimeout = 10 * time.Second
	maxDiscoveryBody = 1 << 20
)

var (
	// ErrUnauthenticated reports a missing or invalid bearer token.
	ErrUnauthenticated = errors.New("nodeapi: unauthenticated")
	// ErrAuthUnavailable reports that issuer discovery or key retrieval failed.
	ErrAuthUnavailable = errors.New("nodeapi: token verification unavailable")
)

var asymmetricAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA,
}

// NodeResolver maps a pod claim to the pod's node; it must return false when the pod's UID differs.
type NodeResolver func(namespace, name, uid string) (nodeName string, ok bool)

// PodNodeResolver builds a NodeResolver from a pod lookup, enforcing the UID match and a scheduled pod.
func PodNodeResolver(lookup func(namespace, name string) (nodeName, uid string, ok bool)) NodeResolver {
	return func(namespace, name, uid string) (string, bool) {
		node, got, ok := lookup(namespace, name)
		if !ok || got != uid || node == "" {
			return "", false
		}
		return node, true
	}
}

// AuthOptions configures an Authenticator.
type AuthOptions struct {
	// APIServer is the API server base URL serving issuer discovery and /openid/v1/jwks.
	APIServer string
	// HTTPClient carries the API server transport and credentials.
	HTTPClient     *http.Client
	Audience       string
	Namespace      string
	ServiceAccount string
	ResolvePod     NodeResolver
	MaxLifetime    time.Duration
	Clock          func() time.Time
}

// Identity is an authenticated node agent.
type Identity struct {
	Node           string
	Namespace      string
	ServiceAccount string
	Pod            string
	PodUID         string
	Expiry         time.Time
}

// Authenticator verifies projected tokens offline, so a token outlives its pod until expiry.
type Authenticator struct {
	o        AuthOptions
	base     string
	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	failAt   time.Time
	failErr  error
}

// NewAuthenticator validates options; discovery runs on first use and is retried after failures.
func NewAuthenticator(o AuthOptions) (*Authenticator, error) {
	if o.APIServer == "" || o.HTTPClient == nil {
		return nil, errors.New("nodeapi: authenticator requires an API server URL and HTTP client")
	}
	if o.Namespace == "" || o.ServiceAccount == "" {
		return nil, errors.New("nodeapi: authenticator requires the node agent ServiceAccount namespace and name")
	}
	if o.Audience == "" {
		o.Audience = DefaultAudience
	}
	if o.MaxLifetime <= 0 {
		o.MaxLifetime = DefaultMaxTokenLifetime
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Authenticator{o: o, base: strings.TrimRight(o.APIServer, "/")}, nil
}

type discoveryDoc struct {
	Issuer string   `json:"issuer"`
	Algs   []string `json:"id_token_signing_alg_values_supported"`
}

func (a *Authenticator) discover(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.o.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer discovery: %s", resp.Status)
	}
	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("issuer discovery: %w", err)
	}
	if doc.Issuer == "" {
		return nil, errors.New("issuer discovery: empty issuer")
	}
	var algs []string
	for _, alg := range doc.Algs {
		if slices.Contains(asymmetricAlgs, alg) {
			algs = append(algs, alg)
		}
	}
	if len(algs) == 0 {
		algs = []string{oidc.RS256}
	}
	// The issuer's jwks_uri may name an external address, so keys are read from the API server itself.
	keys := keySet{inner: oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), a.o.HTTPClient), a.base+"/openid/v1/jwks")}
	return oidc.NewVerifier(doc.Issuer, keys, &oidc.Config{ClientID: a.o.Audience, SupportedSigningAlgs: algs, Now: a.o.Clock}), nil
}

func (a *Authenticator) verifierFor(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.verifier != nil {
		return a.verifier, nil
	}
	now := a.o.Clock()
	if a.failErr != nil && now.Sub(a.failAt) < discoveryRetry {
		return nil, a.failErr
	}
	v, err := a.discover(ctx)
	if err != nil {
		a.failAt, a.failErr = now, fmt.Errorf("%w: %w", ErrAuthUnavailable, err)
		return nil, a.failErr
	}
	a.verifier, a.failErr = v, nil
	return v, nil
}

type fetchFlag struct{ failed bool }

type fetchFlagKey struct{}

type keySet struct{ inner *oidc.RemoteKeySet }

// VerifySignature marks the call when the key set failed to fetch keys, which RemoteKeySet reports as a wrapped error.
func (k keySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	p, err := k.inner.VerifySignature(ctx, jwt)
	if err != nil && errors.Unwrap(err) != nil {
		if f, ok := ctx.Value(fetchFlagKey{}).(*fetchFlag); ok {
			f.failed = true
		}
	}
	return p, err
}

type objectRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type kubeClaims struct {
	K8s struct {
		Namespace      string     `json:"namespace"`
		Node           *objectRef `json:"node"`
		Pod            *objectRef `json:"pod"`
		ServiceAccount *objectRef `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func unauthenticated(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnauthenticated, fmt.Sprintf(format, a...))
}

// Authenticate verifies a bearer token and returns the node agent identity it proves.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (Identity, error) {
	if token == "" {
		return Identity{}, unauthenticated("missing bearer token")
	}
	v, err := a.verifierFor(ctx)
	if err != nil {
		return Identity{}, err
	}
	flag := &fetchFlag{}
	idt, err := v.Verify(context.WithValue(ctx, fetchFlagKey{}, flag), token)
	if err != nil {
		if flag.failed {
			return Identity{}, fmt.Errorf("%w: %w", ErrAuthUnavailable, err)
		}
		return Identity{}, unauthenticated("%v", err)
	}
	if idt.IssuedAt.IsZero() {
		return Identity{}, unauthenticated("token has no iat")
	}
	if life := idt.Expiry.Sub(idt.IssuedAt); life > a.o.MaxLifetime {
		return Identity{}, unauthenticated("token lifetime %s exceeds %s", life, a.o.MaxLifetime)
	}
	var c kubeClaims
	if err := idt.Claims(&c); err != nil {
		return Identity{}, unauthenticated("claims: %v", err)
	}
	k := c.K8s
	ns, sa := a.o.Namespace, a.o.ServiceAccount
	if k.ServiceAccount == nil || k.Namespace != ns || k.ServiceAccount.Name != sa || idt.Subject != "system:serviceaccount:"+ns+":"+sa {
		return Identity{}, unauthenticated("token subject %q is not the node agent ServiceAccount", idt.Subject)
	}
	if k.Pod == nil || k.Pod.Name == "" || k.Pod.UID == "" {
		return Identity{}, unauthenticated("token is not bound to a pod")
	}
	id := Identity{Namespace: ns, ServiceAccount: sa, Pod: k.Pod.Name, PodUID: k.Pod.UID, Expiry: idt.Expiry}
	switch {
	case k.Node != nil && k.Node.Name != "":
		id.Node = k.Node.Name
	case a.o.ResolvePod == nil:
		return Identity{}, unauthenticated("token has no node claim and no pod resolver is configured")
	default:
		node, ok := a.o.ResolvePod(ns, k.Pod.Name, k.Pod.UID)
		if !ok {
			return Identity{}, unauthenticated("pod %s/%s with uid %s is not known", ns, k.Pod.Name, k.Pod.UID)
		}
		id.Node = node
	}
	return id, nil
}
