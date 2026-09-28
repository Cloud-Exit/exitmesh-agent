// Package tunnel implements the WebSocket tunnel binding (SPEC 9) and the enrollment client.
package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// Options configures the writer side of the tunnel.
type Options struct {
	// Endpoint is host[:port] or an https:// URL with an optional path prefix.
	Endpoint string
	// Credential returns the current bearer credential; it is read on every dial.
	Credential func() string
	// CAFile adds a PEM bundle to the system roots.
	CAFile string
	// Proxy selects a proxy per request; the default honors HTTPS_PROXY and NO_PROXY.
	Proxy func(*http.Request) (*url.URL, error)
	// DialContext overrides TCP dialing.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	Conn        ConnOptions
	UserAgent   string
}

// Transport dials tunnel sessions; it implements client.Transport.
type Transport struct {
	opts   Options
	base   *url.URL
	client *http.Client
}

var _ client.Transport = (*Transport)(nil)

// New validates options and builds the HTTP client.
func New(opts Options) (*Transport, error) {
	base, err := endpointURL(opts.Endpoint)
	if err != nil {
		return nil, err
	}
	hc, err := httpClient(opts)
	if err != nil {
		return nil, err
	}
	return &Transport{opts: opts, base: base, client: hc}, nil
}

func endpointURL(ep string) (*url.URL, error) {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return nil, errors.New("tunnel: endpoint required")
	}
	if !strings.Contains(ep, "://") {
		ep = "https://" + ep
	}
	u, err := url.Parse(ep)
	if err != nil {
		return nil, fmt.Errorf("tunnel: endpoint: %w", err)
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "https"
	default:
		return nil, fmt.Errorf("tunnel: endpoint scheme %q, TLS is required", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("tunnel: endpoint host required")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	return u, nil
}

func httpClient(opts Options) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tunnel: read CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tunnel: CA file %s contains no certificates", opts.CAFile)
		}
	}
	proxy := opts.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	dial := opts.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	tr := &http.Transport{
		Proxy:               proxy,
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{Transport: tr}, nil
}

func (t *Transport) endpoint(path string) string {
	u := *t.base
	u.Path += path
	return u.String()
}

func unauthorized(msg string) *protocol.RPCError {
	return &protocol.RPCError{Code: protocol.RPCUnauthorized, Message: msg, Data: &protocol.RPCErrorData{Code: protocol.CodeUnauthorized}}
}

// Dial opens a tunnel session with the current credential.
func (t *Transport) Dial(ctx context.Context) (client.Conn, error) {
	cred := ""
	if t.opts.Credential != nil {
		cred = t.opts.Credential()
	}
	if cred == "" {
		return nil, fmt.Errorf("tunnel: %w", unauthorized("no credential"))
	}
	h := http.Header{"Authorization": {"Bearer " + cred}}
	if t.opts.UserAgent != "" {
		h.Set("User-Agent", t.opts.UserAgent)
	}
	c := newConn(t.opts.Conn)
	ws, resp, err := websocket.Dial(ctx, t.endpoint(protocol.TunnelPath), &websocket.DialOptions{
		HTTPClient: t.client, HTTPHeader: h, Subprotocols: []string{protocol.TunnelSubprotocol}, OnPongReceived: c.pong,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		c.cancel()
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return nil, fmt.Errorf("tunnel: %w", unauthorized(resp.Status))
		}
		return nil, fmt.Errorf("tunnel: dial: %w", err)
	}
	if ws.Subprotocol() != protocol.TunnelSubprotocol {
		_ = ws.Close(websocket.StatusPolicyViolation, "subprotocol required")
		c.cancel()
		return nil, fmt.Errorf("tunnel: server did not negotiate %s", protocol.TunnelSubprotocol)
	}
	c.start(ws)
	return c, nil
}

// Enroll exchanges an enrollment token for a credential (SPEC 9.2).
func (t *Transport) Enroll(ctx context.Context, req protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint(protocol.EnrollPath), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	if t.opts.UserAgent != "" {
		hr.Header.Set("User-Agent", t.opts.UserAgent)
	}
	resp, err := t.client.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("tunnel: enroll: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("tunnel: enroll: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(b))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("tunnel: enroll: %w", unauthorized(msg))
		}
		return nil, fmt.Errorf("tunnel: enroll: %s: %s", resp.Status, msg)
	}
	var out protocol.EnrollResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("tunnel: enroll response: %w", err)
	}
	if out.TargetID == "" || out.Credential == "" {
		return nil, errors.New("tunnel: enroll response missing target_id or credential")
	}
	return &out, nil
}

// Enroll is a convenience wrapper that builds a Transport for one enrollment.
func Enroll(ctx context.Context, opts Options, req protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	t, err := New(opts)
	if err != nil {
		return nil, err
	}
	return t.Enroll(ctx, req)
}
