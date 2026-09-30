package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

type server struct {
	srv    *httptest.Server
	ca     string
	conns  chan *Conn
	bearer atomic.Value
	opts   ConnOptions
	setup  func(c *Conn)
	setup2 func(c *Conn)
}

func newServer(t *testing.T, opts ConnOptions, setup func(c *Conn)) *server {
	t.Helper()
	s := &server{conns: make(chan *Conn, 8), opts: opts, setup: setup}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case protocol.TunnelPath, "/prefix" + protocol.TunnelPath:
		default:
			http.NotFound(w, r)
			return
		}
		s.bearer.Store(r.Header.Get("Authorization"))
		c, err := Accept(w, r, s.opts)
		if err != nil {
			return
		}
		if s.setup != nil {
			s.setup(c)
		}
		s.conns <- c
		<-c.Done()
	}))
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	s.ca = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(s.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *server) endpoint() string { return strings.TrimPrefix(s.srv.URL, "https://") }

func (s *server) dial(t *testing.T, mod func(*Options)) (*Conn, *Conn) {
	t.Helper()
	opts := Options{Endpoint: s.endpoint(), CAFile: s.ca, Credential: func() string { return "secret" }}
	if mod != nil {
		mod(&opts)
	}
	tr, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tr.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.setup2 != nil {
		s.setup2(c.(*Conn))
	}
	t.Cleanup(func() { _ = c.Close() })
	select {
	case sc := <-s.conns:
		return c.(*Conn), sc
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept")
		return nil, nil
	}
}

// dialRaw dials a bare WebSocket past the Transport, as a misbehaving peer would.
func dialRaw(ctx context.Context, url string, opts *websocket.DialOptions) (*websocket.Conn, error) {
	ws, resp, err := websocket.Dial(ctx, url, opts)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	return ws, err
}

func echo(ctx context.Context, req *client.Request) (any, error) {
	switch req.Method {
	case "echo":
		return req.Params, nil
	case "fail":
		return nil, &protocol.RPCError{Code: protocol.RPCForbidden, Message: "nope", Data: &protocol.RPCErrorData{Code: protocol.CodeNotOwner}}
	case "boom":
		return nil, errors.New("internal")
	}
	return nil, &protocol.RPCError{Code: protocol.RPCMethodNotFound, Message: req.Method}
}

func TestRPCMux(t *testing.T) {
	var mu sync.Mutex
	var notes []string
	var frames [][]byte
	s := newServer(t, ConnOptions{}, func(c *Conn) {
		c.HandleBinary(func(_ context.Context, f []byte) {
			mu.Lock()
			frames = append(frames, f)
			mu.Unlock()
		})
		c.Handle(func(ctx context.Context, req *client.Request) (any, error) {
			if req.Notification {
				mu.Lock()
				notes = append(notes, string(req.Params))
				mu.Unlock()
				return nil, nil
			}
			return echo(ctx, req)
		})
	})
	c, sc := s.dial(t, nil)
	if got := s.bearer.Load(); got != "Bearer secret" {
		t.Fatalf("authorization %v", got)
	}
	c.Handle(echo)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out map[string]int
			if err := c.Call(ctx, "echo", map[string]int{"i": i}, &out); err != nil || out["i"] != i {
				t.Errorf("call %d: %v %v", i, out, err)
			}
		}(i)
	}
	wg.Wait()
	err := c.Call(ctx, "fail", nil, nil)
	var re *protocol.RPCError
	if !errors.As(err, &re) || re.Data.Code != protocol.CodeNotOwner || client.RPCErrorCode(err) != protocol.CodeNotOwner {
		t.Fatalf("error object %v", err)
	}
	if err := c.Call(ctx, "boom", nil, nil); !errors.As(err, &re) || re.Code != protocol.RPCInternalError {
		t.Fatalf("internal error %v", err)
	}
	if err := c.Call(ctx, "missing", nil, nil); !errors.As(err, &re) || re.Code != protocol.RPCMethodNotFound {
		t.Fatalf("missing method %v", err)
	}
	var back string
	if err := sc.Call(ctx, "echo", "from server", &back); err != nil || back != "from server" {
		t.Fatalf("reverse call %q %v", back, err)
	}
	for i := 0; i < 20; i++ {
		if err := c.Notify(ctx, "n", i); err != nil {
			t.Fatal(err)
		}
	}
	big := make([]byte, 2<<20)
	big[len(big)-1] = 7
	if err := c.SendBinary(ctx, big); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		done := len(notes) == 20 && len(frames) == 1
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("notifications or frame not delivered")
		}
		time.Sleep(2 * time.Millisecond)
	}
	for i, n := range notes {
		if n != fmt.Sprint(i) {
			t.Fatalf("notification order %v", notes)
		}
	}
	if len(frames[0]) != len(big) || frames[0][len(big)-1] != 7 {
		t.Fatal("binary frame corrupted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sc.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server side did not observe close")
	}
	if !errors.Is(c.Err(), ErrClosed) {
		t.Fatalf("err after close %v", c.Err())
	}
	if err := c.Call(ctx, "echo", 1, nil); err == nil {
		t.Fatal("call after close succeeded")
	}
}

func TestDispatchWaitsForHandler(t *testing.T) {
	s := newServer(t, ConnOptions{}, func(c *Conn) {
		c.Handle(echo)
		_ = c.Notify(context.Background(), "early", 1)
	})
	c, _ := s.dial(t, nil)
	time.Sleep(50 * time.Millisecond)
	got := make(chan string, 1)
	c.Handle(func(_ context.Context, req *client.Request) (any, error) {
		got <- req.Method
		return nil, nil
	})
	select {
	case m := <-got:
		if m != "early" {
			t.Fatalf("got %s", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued notification not dispatched")
	}
}

func TestNotificationsDrainBeforeDone(t *testing.T) {
	s := newServer(t, ConnOptions{}, func(c *Conn) {
		c.Handle(func(ctx context.Context, req *client.Request) (any, error) {
			go func() {
				_ = c.Notify(context.Background(), "first", 1)
				_ = c.Notify(context.Background(), "last", 2)
				_ = c.Close()
			}()
			return struct{}{}, nil
		})
	})
	var mu sync.Mutex
	var got []string
	s.setup2 = func(c *Conn) {
		c.Handle(func(_ context.Context, req *client.Request) (any, error) {
			if req.Method == "first" {
				time.Sleep(100 * time.Millisecond)
			}
			mu.Lock()
			got = append(got, req.Method)
			mu.Unlock()
			return nil, nil
		})
	}
	c, _ := s.dial(t, nil)
	_ = c.Call(context.Background(), "go", nil, nil)
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("not done")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != "first" || got[1] != "last" {
		t.Fatalf("dispatched before done: %v", got)
	}
}

func TestKeepalive(t *testing.T) {
	t.Run("idle session with a live peer stays open", func(t *testing.T) {
		opts := ConnOptions{PingInterval: 20 * time.Millisecond, DeadAfter: 100 * time.Millisecond}
		s := newServer(t, opts, func(c *Conn) { c.Handle(echo) })
		c, _ := s.dial(t, func(o *Options) { o.Conn = opts })
		c.Handle(echo)
		time.Sleep(400 * time.Millisecond)
		if c.Err() != nil {
			t.Fatalf("idle connection died: %v", c.Err())
		}
	})
	t.Run("silent peer is dead", func(t *testing.T) {
		stop := make(chan struct{})
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.TunnelSubprotocol}})
			if err != nil {
				return
			}
			<-stop
			_ = ws.CloseNow()
		}))
		defer srv.Close()
		defer close(stop)
		tr, err := New(Options{Endpoint: srv.URL, Credential: func() string { return "x" }, Conn: ConnOptions{PingInterval: 20 * time.Millisecond, DeadAfter: 100 * time.Millisecond}})
		if err != nil {
			t.Fatal(err)
		}
		tr.client = srv.Client()
		c, err := tr.Dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		c.Handle(echo)
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("dead peer not detected")
		}
		if !errors.Is(c.(*Conn).Err(), ErrDead) {
			t.Fatalf("err %v", c.(*Conn).Err())
		}
	})
}

func TestReadLimit(t *testing.T) {
	s := newServer(t, ConnOptions{ReadLimit: 1024}, func(c *Conn) { c.Handle(echo) })
	c, sc := s.dial(t, nil)
	c.Handle(echo)
	// The send may fail once the server has dropped the connection; the server side is what must reject it.
	_ = c.SendBinary(context.Background(), make([]byte, 4096))
	select {
	case <-sc.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("oversized message accepted")
	}
	if err := sc.Err(); err == nil || errors.Is(err, ErrClosed) {
		t.Fatalf("server ended with %v, want a read limit failure", err)
	}
	if DefaultReadLimit <= protocol.MaxFramePayload {
		t.Fatal("default read limit below the frame payload limit")
	}
}

func TestDialErrors(t *testing.T) {
	s := newServer(t, ConnOptions{}, func(c *Conn) { c.Handle(echo) })
	ctx := context.Background()
	tr, _ := New(Options{Endpoint: s.endpoint(), CAFile: s.ca, Credential: func() string { return "" }})
	if _, err := tr.Dial(ctx); client.RPCErrorCode(err) != protocol.CodeUnauthorized {
		t.Fatalf("empty credential: %v", err)
	}
	tr, _ = New(Options{Endpoint: s.endpoint(), Credential: func() string { return "x" }})
	if _, err := tr.Dial(ctx); err == nil || client.RPCErrorCode(err) != "" {
		t.Fatalf("untrusted certificate: %v", err)
	}
	denied := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "revoked", http.StatusUnauthorized)
	}))
	defer denied.Close()
	tr, _ = New(Options{Endpoint: denied.URL, Credential: func() string { return "x" }})
	tr.client = denied.Client()
	if _, err := tr.Dial(ctx); client.RPCErrorCode(err) != protocol.CodeUnauthorized {
		t.Fatalf("401: %v", err)
	}
	nosub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err == nil {
			_ = ws.CloseNow()
		}
	}))
	defer nosub.Close()
	tr, _ = New(Options{Endpoint: nosub.URL, Credential: func() string { return "x" }})
	tr.client = nosub.Client()
	if _, err := tr.Dial(ctx); err == nil {
		t.Fatal("server without the subprotocol accepted")
	}
	ws, err := dialRaw(ctx, s.srv.URL+protocol.TunnelPath, &websocket.DialOptions{HTTPClient: s.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ws.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("client without the subprotocol: %v", err)
	}
}

func TestEndpointAndCA(t *testing.T) {
	for ep, want := range map[string]string{
		"cp.example.com":                 "https://cp.example.com/agent/v1/tunnel",
		"https://cp.example.com:8443/x/": "https://cp.example.com:8443/x/agent/v1/tunnel",
		"wss://cp.example.com":           "https://cp.example.com/agent/v1/tunnel",
	} {
		tr, err := New(Options{Endpoint: ep})
		if err != nil || tr.endpoint(protocol.TunnelPath) != want {
			t.Fatalf("%s: %v %v", ep, tr, err)
		}
	}
	for _, ep := range []string{"", "http://cp.example.com", "https://"} {
		if _, err := New(Options{Endpoint: ep}); err == nil {
			t.Fatalf("endpoint %q accepted", ep)
		}
	}
	if _, err := New(Options{Endpoint: "cp", CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("missing CA file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := New(Options{Endpoint: "cp", CAFile: bad}); err == nil {
		t.Fatal("CA file without certificates accepted")
	}
	s := newServer(t, ConnOptions{}, func(c *Conn) { c.Handle(echo) })
	c, _ := s.dial(t, func(o *Options) { o.Endpoint = s.srv.URL + "/prefix" })
	c.Handle(echo)
}

func connectProxy(t *testing.T, target func(host string) string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		n.Add(1)
		up, err := net.Dial("tcp", target(r.Host))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		down, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		go func() {
			_, _ = io.Copy(up, buf)
			up.Close()
		}()
		_, _ = io.Copy(down, up)
		down.Close()
	}))
	t.Cleanup(p.Close)
	return p, &n
}

func TestProxy(t *testing.T) {
	s := newServer(t, ConnOptions{}, func(c *Conn) { c.Handle(echo) })
	addr := s.srv.Listener.Addr().String()
	p, n := connectProxy(t, func(string) string { return addr })
	c, _ := s.dial(t, func(o *Options) {
		o.Proxy = func(*http.Request) (*url.URL, error) { return url.Parse(p.URL) }
	})
	c.Handle(echo)
	if n.Load() != 1 {
		t.Fatalf("proxy connects %d", n.Load())
	}
}

// TestProxyFromEnvironment runs a child process so HTTPS_PROXY and NO_PROXY are read fresh.
func TestProxyFromEnvironment(t *testing.T) {
	s := newServer(t, ConnOptions{}, func(c *Conn) { c.Handle(echo) })
	_, port, _ := net.SplitHostPort(s.srv.Listener.Addr().String())
	addr := s.srv.Listener.Addr().String()
	p, n := connectProxy(t, func(string) string { return addr })
	for _, tc := range []struct {
		noProxy string
		via     int32
	}{{"", 1}, {"example.com", 0}} {
		before := n.Load()
		cmd := exec.Command(os.Args[0], "-test.run=^TestProxyEnvHelper$", "-test.v")
		cmd.Env = append(os.Environ(),
			"TUNNEL_PROXY_HELPER=1", "HTTPS_PROXY="+p.URL, "NO_PROXY="+tc.noProxy,
			"TUNNEL_HELPER_ENDPOINT=example.com:"+port, "TUNNEL_HELPER_ADDR="+addr, "TUNNEL_HELPER_CA="+s.ca)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "helper dialed") {
			t.Fatalf("NO_PROXY=%q: %v\n%s", tc.noProxy, err, out)
		}
		if got := n.Load() - before; got != tc.via {
			t.Fatalf("NO_PROXY=%q: %d proxy connects, want %d", tc.noProxy, got, tc.via)
		}
	}
}

func TestProxyEnvHelper(t *testing.T) {
	if os.Getenv("TUNNEL_PROXY_HELPER") != "1" {
		t.Skip("helper process for TestProxyFromEnvironment")
	}
	ep, addr := os.Getenv("TUNNEL_HELPER_ENDPOINT"), os.Getenv("TUNNEL_HELPER_ADDR")
	d := &net.Dialer{}
	tr, err := New(Options{
		Endpoint: ep, CAFile: os.Getenv("TUNNEL_HELPER_CA"), Credential: func() string { return "x" },
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			if a == ep {
				a = addr
			}
			return d.DialContext(ctx, network, a)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	fmt.Println("helper dialed")
}

func TestEnroll(t *testing.T) {
	var got protocol.EnrollRequest
	status := http.StatusOK
	body := `{"target_id":"t-1","credential":"cred","credential_id":"c-1"}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != protocol.EnrollPath || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad request line", http.StatusBadRequest)
			return
		}
		_ = json.NewDecoder(bufio.NewReader(r.Body)).Decode(&got)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	tr, _ := New(Options{Endpoint: srv.URL, UserAgent: "exitmesh-agent/0.1.0"})
	tr.client = srv.Client()
	req := protocol.EnrollRequest{Token: "emx1_h_t-1_0123456789abcdef", WriterID: protocol.WriterID{1}, TargetType: protocol.TargetHost, MachineID: "m", Hostname: "h"}
	res, err := tr.Enroll(context.Background(), req)
	if err != nil || res.TargetID != "t-1" || res.Credential != "cred" || got.MachineID != "m" || got.WriterID != req.WriterID {
		t.Fatalf("enroll %+v %v (sent %+v)", res, err, got)
	}
	status, body = http.StatusUnauthorized, "invalid token"
	if _, err := tr.Enroll(context.Background(), req); client.RPCErrorCode(err) != protocol.CodeUnauthorized {
		t.Fatalf("401: %v", err)
	}
	status, body = http.StatusInternalServerError, "oops"
	if _, err := tr.Enroll(context.Background(), req); err == nil || !strings.Contains(err.Error(), "oops") {
		t.Fatalf("500: %v", err)
	}
	status, body = http.StatusOK, "{"
	if _, err := tr.Enroll(context.Background(), req); err == nil {
		t.Fatal("malformed response accepted")
	}
	body = `{"target_id":"t-1"}`
	if _, err := tr.Enroll(context.Background(), req); err == nil {
		t.Fatal("response without credential accepted")
	}
	if _, err := Enroll(context.Background(), Options{Endpoint: "http://x"}, req); err == nil {
		t.Fatal("plain http endpoint accepted")
	}
}

func TestWritesAfterCloseAndInvalidJSON(t *testing.T) {
	s := newServer(t, ConnOptions{}, func(c *Conn) { c.Handle(echo) })
	c, _ := s.dial(t, nil)
	c.Handle(echo)
	_ = c.Close()
	ctx := context.Background()
	if err := c.SendBinary(ctx, []byte{1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("send after close: %v", err)
	}
	if err := c.Notify(ctx, "n", nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("notify after close: %v", err)
	}
	ws, err := dialRaw(ctx, s.srv.URL+protocol.TunnelPath, &websocket.DialOptions{HTTPClient: s.srv.Client(), Subprotocols: []string{protocol.TunnelSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageText, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	_, b, err := ws.Read(ctx)
	var m protocol.RPCMessage
	if err != nil || json.Unmarshal(b, &m) != nil || m.Error == nil || m.Error.Code != protocol.RPCParseError {
		t.Fatalf("parse error response %s %v", b, err)
	}
	if err := ws.Write(ctx, websocket.MessageText, []byte(`{"jsonrpc":"2.0","id":7,"method":"echo","params":[1]}`)); err != nil {
		t.Fatal(err)
	}
	if _, b, err = ws.Read(ctx); err != nil || json.Unmarshal(b, &m) != nil || string(m.Result) != "[1]" || idKey(m.ID) != "7" {
		t.Fatalf("response %s %v", b, err)
	}
	if idKey(nil) != "" {
		t.Fatal("nil id key")
	}
}
