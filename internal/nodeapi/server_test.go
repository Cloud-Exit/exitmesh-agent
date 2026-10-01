package nodeapi

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/metricfacts"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type fakeBackend struct {
	mu          sync.Mutex
	regs        []RegisterRequest
	regNodes    []string
	items       []Item
	queues      []string
	submitErr   error
	bundle      *BundlePayload
	bundleCh    chan struct{}
	kube        KubeUpdate
	kubeCh      chan struct{}
	tasks       []Task
	tasksCh     chan struct{}
	results     []TaskResult
	bundleCalls atomic.Int32
	kubeCalls   atomic.Int32
	taskCalls   atomic.Int32
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{bundleCh: make(chan struct{}), kubeCh: make(chan struct{}), tasksCh: make(chan struct{})}
}

func (b *fakeBackend) Register(_ context.Context, node string, req RegisterRequest) (RegisterResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.regs, b.regNodes = append(b.regs, req), append(b.regNodes, node)
	return RegisterResponse{TargetBundle: "b2", ServerTimeMs: 1}, nil
}

func (b *fakeBackend) Submit(_ context.Context, node, queue string, items []Item) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.submitErr != nil {
		return 0, b.submitErr
	}
	b.items = append(b.items, items...)
	b.queues = append(b.queues, queue)
	return items[len(items)-1].Seq, nil
}

func (b *fakeBackend) Bundle(_ context.Context, node, have string) (*BundlePayload, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer b.bundleCalls.Add(1)
	if b.bundle != nil && b.bundle.Version != have {
		p := *b.bundle
		return &p, b.bundleCh, nil
	}
	return nil, b.bundleCh, nil
}

func (b *fakeBackend) Kube(_ context.Context, node string, since uint64) (KubeUpdate, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer b.kubeCalls.Add(1)
	return b.kube, b.kubeCh, nil
}

func (b *fakeBackend) Tasks(_ context.Context, node string) ([]Task, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer b.taskCalls.Add(1)
	return append([]Task(nil), b.tasks...), b.tasksCh, nil
}

func (b *fakeBackend) TaskResult(_ context.Context, node string, res TaskResult) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, t := range b.tasks {
		if t.ID == res.ID {
			b.tasks = append(b.tasks[:i], b.tasks[i+1:]...)
			b.results = append(b.results, res)
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrUnknownTask, res.ID)
}

func (b *fakeBackend) locked(fn func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fn()
}

func (b *fakeBackend) change(fn func(*fakeBackend), ch *chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fn(b)
	close(*ch)
	*ch = make(chan struct{})
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), sub)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	api     *fakeAPI
	key     *testKey
	clock   *testClock
	backend *fakeBackend
	srv     *httptest.Server
	dir     string
	caFile  string
	logs    *syncBuffer
	auditMu sync.Mutex
	audits  []AuditEvent
}

func newEnv(t *testing.T, tune func(*Options)) *env {
	t.Helper()
	e := &env{key: newECKey(t, "k1"), clock: newClock(), backend: newFakeBackend(), dir: t.TempDir(), logs: &syncBuffer{}}
	e.api = newFakeAPI(t, e.key)
	o := Options{
		Auth: newAuth(t, e.api, e.clock, nil), Backend: e.backend, Clock: e.clock.Now,
		Audit: func(ev AuditEvent) {
			e.auditMu.Lock()
			e.audits = append(e.audits, ev)
			e.auditMu.Unlock()
		},
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)),
	}
	if tune != nil {
		tune(&o)
	}
	e.srv = httptest.NewTLSServer(NewServer(o))
	t.Cleanup(e.srv.Close)
	e.caFile = filepath.Join(e.dir, "ca.crt")
	if err := os.WriteFile(e.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) token(t *testing.T) string {
	return e.key.mint(t, claimsFor(e.clock.Now(), "node-1"))
}

func (e *env) client(t *testing.T, node, token string) *Client {
	t.Helper()
	tf := filepath.Join(e.dir, "token-"+node)
	if err := os.WriteFile(tf, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientOptions{BaseURL: e.srv.URL, CAFile: e.caFile, TokenFile: tf, Node: node, Timeout: 5 * time.Second, LongPollTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type rawResponse struct {
	StatusCode int
	Header     http.Header
}

func (e *env) raw(t *testing.T, method, path, ctype string, body io.Reader, token string) rawResponse {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	return rawResponse{StatusCode: resp.StatusCode, Header: resp.Header}
}

func (e *env) auditLog() []AuditEvent {
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	return append([]AuditEvent(nil), e.audits...)
}

func wantStatus(t *testing.T, err error, code int, retryable bool) {
	t.Helper()
	ae, ok := errors.AsType[*Error](err)
	if !ok || ae.StatusCode != code || ae.Retryable != retryable || IsRetryable(err) != retryable {
		t.Fatalf("err = %v, want HTTP %d retryable=%v", err, code, retryable)
	}
	if want := code == http.StatusBadRequest || code == http.StatusRequestEntityTooLarge; IsMalformed(err) != want {
		t.Fatalf("err = %v, malformed = %v, want %v", err, IsMalformed(err), want)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRegisterAndSubmit(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client(t, "node-1", e.token(t))
	ctx := context.Background()
	req := RegisterRequest{AgentVersion: "1.0.0", BundleVersion: "b1", Capabilities: []string{"metrics"}, Coverage: map[string]string{"logs": "covered"}, QueueUsage: QueueUsage{Items: 3},
		Process: &Process{UID: 65532, GID: 65532, Capabilities: []string{"CAP_DAC_READ_SEARCH"}}}
	resp, err := c.Register(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.TargetBundle != "b2" || resp.ServerTimeMs != e.clock.Now().UnixMilli() {
		t.Fatalf("register response = %+v", resp)
	}
	req.Node = "node-1"
	e.backend.locked(func() {
		if !reflect.DeepEqual(e.backend.regs, []RegisterRequest{req}) || e.backend.regNodes[0] != "node-1" {
			t.Fatalf("backend saw %+v from %v", e.backend.regs, e.backend.regNodes)
		}
	})
	items := testItems(t, "node-1")
	acked, err := c.Submit(ctx, "q1", items)
	if err != nil || acked != 5 {
		t.Fatalf("acked = %d, err = %v", acked, err)
	}
	e.backend.locked(func() {
		if !reflect.DeepEqual(e.backend.items, items) {
			t.Fatalf("backend items = %+v", e.backend.items)
		}
	})
	if len(e.auditLog()) != 0 {
		t.Fatalf("unexpected audits: %+v", e.auditLog())
	}
}

func TestRegisterRejectsInvalidProcess(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client(t, "node-1", e.token(t))
	many := make([]string, maxProcessCaps+1)
	for i := range many {
		many[i] = "CAP_X"
	}
	for _, p := range []*Process{{UID: -1}, {GID: -1}, {Capabilities: many}, {Capabilities: []string{""}}, {Capabilities: []string{strings.Repeat("C", maxCapName+1)}}} {
		if _, err := c.Register(context.Background(), RegisterRequest{Process: p}); !errors.Is(err, ErrInvalid) || IsRetryable(err) {
			t.Errorf("client sent process %+v: %v", p, err)
		}
		body, err := protocol.Marshal(RegisterRequest{Node: "node-1", Process: p})
		if err != nil {
			t.Fatal(err)
		}
		if r := e.raw(t, http.MethodPost, "/v1/node/register", ContentType, bytes.NewReader(body), e.token(t)); r.StatusCode != http.StatusBadRequest {
			t.Errorf("server accepted process %+v: %d", p, r.StatusCode)
		}
	}
}

func TestImpersonationRejected(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.token(t)
	other := e.client(t, "node-2", tok)
	_, err := other.Register(ctx, RegisterRequest{})
	wantStatus(t, err, http.StatusForbidden, false)
	_, err = other.Submit(ctx, "q1", testItems(t, "node-2"))
	wantStatus(t, err, http.StatusForbidden, false)

	own := e.client(t, "node-1", tok)
	finding := []Item{{Seq: 1, Kind: KindFinding, Finding: encodedFinding(t, "node-2")}}
	fact := []Item{{Seq: 1, Kind: KindMetricFacts, Facts: []metricfacts.Fact{{Node: "node-2", Fields: map[string]any{"x": 1.0}}}}}
	series := []Item{{Seq: 1, Kind: KindSeries, Part: &Part{RuleID: "r", Samples: []Sample{{Labels: map[string]string{engine.LabelNode: "node-2"}, Value: 1}}}}}
	for _, items := range [][]Item{finding, fact, series} {
		_, err := own.Submit(ctx, "q1", items)
		wantStatus(t, err, http.StatusForbidden, false)
	}
	audits := e.auditLog()
	if len(audits) != 5 {
		t.Fatalf("audits = %d, want 5", len(audits))
	}
	for _, a := range audits {
		if a.Kind != AuditImpersonation || a.AuthenticatedNode != "node-1" || a.ClaimedNode != "node-2" || a.Pod != "agent-abc" || a.PodUID != "pod-uid-1" || a.Namespace != testNS || !a.Time.Equal(e.clock.Now()) || a.Method != http.MethodPost || a.RemoteAddr == "" {
			t.Fatalf("audit = %+v", a)
		}
	}
	if audits[0].Path != "/v1/node/register" || audits[1].Path != "/v1/node/records" {
		t.Fatalf("audit paths = %s, %s", audits[0].Path, audits[1].Path)
	}
	e.backend.locked(func() {
		if len(e.backend.regs) != 0 || len(e.backend.items) != 0 {
			t.Fatal("backend must not see impersonating requests")
		}
	})
}

func TestUnauthenticated(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	bad := e.client(t, "node-1", "not-a-token")
	for range 3 {
		_, err := bad.Register(ctx, RegisterRequest{})
		wantStatus(t, err, http.StatusUnauthorized, false)
	}
	resp := e.raw(t, http.MethodGet, "/v1/node/tasks", "", nil, "")
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("no token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if n := e.logs.count("node api authentication failed"); n != 1 {
		t.Fatalf("auth failure log lines = %d, want 1 inside the window:\n%s", n, e.logs)
	}
	e.clock.Advance(DefaultAuthLogEvery)
	_, err := bad.Submit(ctx, "q1", testItems(t, "node-1"))
	wantStatus(t, err, http.StatusUnauthorized, false)
	if n := e.logs.count("node api authentication failed"); n != 2 || !strings.Contains(e.logs.String(), "suppressed=3") {
		t.Fatalf("auth failure log lines = %d, want 2 with suppressed=3:\n%s", n, e.logs)
	}
	if strings.Contains(e.logs.String(), "not-a-token") {
		t.Fatal("token leaked into logs")
	}
	expired := e.key.mint(t, claimsFor(e.clock.Now().Add(-time.Hour), "node-1"))
	_, err = e.client(t, "node-1", expired).WaitTasks(ctx)
	wantStatus(t, err, http.StatusUnauthorized, false)
	if n := e.backend.taskCalls.Load(); n != 0 {
		t.Fatalf("backend called %d times for unauthenticated requests", n)
	}
}

func TestAuthUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	e.api.set(func(f *fakeAPI) { f.discoveryStatus = http.StatusInternalServerError })
	_, err := e.client(t, "node-1", e.token(t)).Register(context.Background(), RegisterRequest{})
	wantStatus(t, err, http.StatusServiceUnavailable, true)
}

func TestLongPollBundle(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.LongPollMax = 150 * time.Millisecond })
	c := e.client(t, "node-1", e.token(t))
	ctx := context.Background()
	start := time.Now()
	p, err := c.WaitBundle(ctx, "b1")
	if err != nil || p != nil {
		t.Fatalf("idle poll: %+v %v", p, err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("idle poll returned after %s", d)
	}
	want := BundlePayload{Version: "b2", Archive: []byte("archive"), Signature: []byte("sig"), KeyManifest: []byte("km")}
	e.backend.change(func(b *fakeBackend) { b.bundle = &want }, &e.backend.bundleCh)
	if p, err = c.WaitBundle(ctx, "b1"); err != nil || !reflect.DeepEqual(*p, want) {
		t.Fatalf("immediate bundle = %+v, %v", p, err)
	}
	if p, err = c.WaitBundle(ctx, "b2"); err != nil || p != nil {
		t.Fatalf("current bundle must not be resent: %+v %v", p, err)
	}
}

func TestLongPollWake(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.LongPollMax = 10 * time.Second })
	c := e.client(t, "node-1", e.token(t))
	ctx := context.Background()

	got := make(chan *BundlePayload, 1)
	go func() {
		p, err := c.WaitBundle(ctx, "")
		if err != nil {
			t.Error(err)
		}
		got <- p
	}()
	waitFor(t, func() bool { return e.backend.bundleCalls.Load() == 1 })
	e.backend.change(func(*fakeBackend) {}, &e.backend.bundleCh)
	waitFor(t, func() bool { return e.backend.bundleCalls.Load() == 2 })
	e.backend.change(func(b *fakeBackend) { b.bundle = &BundlePayload{Version: "b3", Archive: []byte{1}} }, &e.backend.bundleCh)
	if p := <-got; p == nil || p.Version != "b3" || e.backend.bundleCalls.Load() != 3 {
		t.Fatalf("woken bundle = %+v after %d calls", p, e.backend.bundleCalls.Load())
	}

	kube := make(chan *KubeUpdate, 1)
	e.backend.change(func(b *fakeBackend) { b.kube = KubeUpdate{Revision: 4} }, &e.backend.kubeCh)
	go func() {
		u, err := c.WaitKube(ctx, 4)
		if err != nil {
			t.Error(err)
		}
		kube <- u
	}()
	waitFor(t, func() bool { return e.backend.kubeCalls.Load() == 1 })
	series := []KubeSeries{{Labels: map[string]string{"__name__": "kube_node_status_condition", "node": "node-1"}, Value: 1}}
	e.backend.change(func(b *fakeBackend) { b.kube = KubeUpdate{Revision: 5, Series: series} }, &e.backend.kubeCh)
	if u := <-kube; u == nil || u.Revision != 5 || !reflect.DeepEqual(u.Series, series) {
		t.Fatalf("woken kube update = %+v", u)
	}

	tasks := make(chan []Task, 1)
	go func() {
		ts, err := c.WaitTasks(ctx)
		if err != nil {
			t.Error(err)
		}
		tasks <- ts
	}()
	waitFor(t, func() bool { return e.backend.taskCalls.Load() == 1 })
	task := Task{ID: "q-1", Kind: TaskPromQLQuery, Payload: []byte("up"), DeadlineMs: 99}
	e.backend.change(func(b *fakeBackend) { b.tasks = []Task{task} }, &e.backend.tasksCh)
	if ts := <-tasks; !reflect.DeepEqual(ts, []Task{task}) {
		t.Fatalf("woken tasks = %+v", ts)
	}
}

func TestLongPollTimeouts(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.LongPollMax = 100 * time.Millisecond })
	c := e.client(t, "node-1", e.token(t))
	ctx := context.Background()
	e.backend.change(func(b *fakeBackend) { b.kube = KubeUpdate{Revision: 2} }, &e.backend.kubeCh)
	if u, err := c.WaitKube(ctx, 2); err != nil || u != nil {
		t.Fatalf("idle kube poll: %+v %v", u, err)
	}
	if u, err := c.WaitKube(ctx, 1); err != nil || u == nil || u.Revision != 2 {
		t.Fatalf("kube since 1: %+v %v", u, err)
	}
	if ts, err := c.WaitTasks(ctx); err != nil || ts != nil {
		t.Fatalf("idle task poll: %+v %v", ts, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		for e.backend.taskCalls.Load() < 2 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	if _, err := c.WaitTasks(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled poll: %v", err)
	}
}

func TestTaskResults(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client(t, "node-1", e.token(t))
	ctx := context.Background()
	e.backend.change(func(b *fakeBackend) { b.tasks = []Task{{ID: "q-1", Kind: TaskLogRead}} }, &e.backend.tasksCh)
	res := TaskResult{ID: "q-1", Payload: []byte("lines")}
	if err := c.PostResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	e.backend.locked(func() {
		if !reflect.DeepEqual(e.backend.results, []TaskResult{res}) {
			t.Fatalf("results = %+v", e.backend.results)
		}
	})
	wantStatus(t, c.PostResult(ctx, res), http.StatusNotFound, false)
	if err := c.PostResult(ctx, TaskResult{ID: "a/b"}); !errors.Is(err, ErrInvalid) || IsRetryable(err) {
		t.Fatalf("invalid id: %v", err)
	}
	body, _ := Marshal(TaskResult{ID: "q-2"})
	if r := e.raw(t, http.MethodPost, "/v1/node/tasks/q-1", ContentType, bytes.NewReader(body), e.token(t)); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("path and body id mismatch: %d", r.StatusCode)
	}
	if r := e.raw(t, http.MethodPost, "/v1/node/tasks/bad%20id", ContentType, bytes.NewReader(body), e.token(t)); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid path id: %d", r.StatusCode)
	}
}

func TestRequestValidation(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxBody = 2048 })
	c := e.client(t, "node-1", e.token(t))
	ctx := context.Background()
	tok := e.token(t)

	big := testFinding("node-1")
	big.Summary = strings.Repeat("x", 4096)
	b, err := protocol.EncodeFinding(big)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Submit(ctx, "q1", []Item{{Seq: 1, Kind: KindFinding, Finding: b}})
	wantStatus(t, err, http.StatusRequestEntityTooLarge, false)
	body, _ := Marshal(SubmitRequest{Node: "node-1", Items: []Item{{Seq: 1, Kind: KindFinding, Finding: b}}})
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/v1/node/records", io.MultiReader(bytes.NewReader(body)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversize body: %d", resp.StatusCode)
	}

	reg, _ := Marshal(RegisterRequest{Node: "node-1"})
	checks := []struct {
		name, method, path, ctype string
		body                      []byte
		want                      int
	}{
		{"wrong content type", http.MethodPost, "/v1/node/register", "application/json", reg, http.StatusUnsupportedMediaType},
		{"long agent version", http.MethodPost, "/v1/node/register", ContentType, mustRaw(t, RegisterRequest{Node: "node-1", AgentVersion: strings.Repeat("v", 300)}), http.StatusBadRequest},
		{"malformed cbor", http.MethodPost, "/v1/node/register", ContentType, []byte{0xff}, http.StatusBadRequest},
		{"descending seq", http.MethodPost, "/v1/node/records", ContentType, mustRaw(t, SubmitRequest{Node: "node-1", Items: []Item{{Seq: 2, Kind: KindSeries, Part: testPart("node-1")}, {Seq: 1, Kind: KindSeries, Part: testPart("node-1")}}}), http.StatusBadRequest},
		{"empty submit", http.MethodPost, "/v1/node/records", ContentType, mustRaw(t, SubmitRequest{Node: "node-1"}), http.StatusBadRequest},
		{"bad since", http.MethodGet, "/v1/node/kube?since=-1", "", nil, http.StatusBadRequest},
		{"long have", http.MethodGet, "/v1/node/bundle?have=" + strings.Repeat("v", 300), "", nil, http.StatusBadRequest},
		{"wrong method", http.MethodGet, "/v1/node/records", "", nil, http.StatusMethodNotAllowed},
	}
	for _, ch := range checks {
		if r := e.raw(t, ch.method, ch.path, ch.ctype, bytes.NewReader(ch.body), tok); r.StatusCode != ch.want {
			t.Errorf("%s: status %d, want %d", ch.name, r.StatusCode, ch.want)
		}
	}
	e.backend.locked(func() {
		if len(e.backend.items) != 0 || len(e.backend.regs) != 0 {
			t.Fatal("backend saw invalid requests")
		}
	})
}

func mustRaw(t *testing.T, v any) []byte {
	t.Helper()
	b, err := protocol.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBackendErrors(t *testing.T) {
	e := newEnv(t, nil)
	c := e.client(t, "node-1", e.token(t))
	ctx := context.Background()
	e.backend.locked(func() { e.backend.submitErr = errors.New("spool fsync failed") })
	_, err := c.Submit(ctx, "q1", testItems(t, "node-1"))
	wantStatus(t, err, http.StatusServiceUnavailable, true)
	if !strings.Contains(e.logs.String(), "spool fsync failed") {
		t.Fatalf("backend failure not logged:\n%s", e.logs)
	}
	e.backend.locked(func() { e.backend.submitErr = fmt.Errorf("%w: state not synchronized yet", ErrUnavailable) })
	before := e.logs.String()
	_, err = c.Submit(ctx, "q1", testItems(t, "node-1"))
	wantStatus(t, err, http.StatusServiceUnavailable, true)
	if !strings.Contains(err.Error(), "state not synchronized yet") {
		t.Fatalf("error text = %q", err)
	}
	if e.logs.String() != before {
		t.Fatalf("transient unavailability logged above debug:\n%s", e.logs)
	}
	resp := e.raw(t, http.MethodPost, "/v1/node/records", ContentType, bytes.NewReader(mustRaw(t, SubmitRequest{Node: "node-1", Queue: "q1", Items: testItems(t, "node-1")})), e.token(t))
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("status = %d, Retry-After = %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	e.backend.locked(func() { e.backend.submitErr = fmt.Errorf("%w: sequence regression", ErrInvalid) })
	_, err = c.Submit(ctx, "q1", testItems(t, "node-1"))
	wantStatus(t, err, http.StatusBadRequest, false)
	e.backend.change(func(b *fakeBackend) { b.bundle = &BundlePayload{Version: "no-archive"} }, &e.backend.bundleCh)
	_, err = c.WaitBundle(ctx, "")
	wantStatus(t, err, http.StatusInternalServerError, true)
	if !strings.Contains(err.Error(), "nodeapi: bundle: HTTP 500") {
		t.Fatalf("error text = %q", err)
	}
}

func TestClientErrors(t *testing.T) {
	e := newEnv(t, nil)
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]ClientOptions{
		"http scheme":    {BaseURL: "http://coordinator:8443", TokenFile: "t", Node: "n"},
		"no host":        {BaseURL: "https://", TokenFile: "t", Node: "n"},
		"no token file":  {BaseURL: e.srv.URL, Node: "n"},
		"no node":        {BaseURL: e.srv.URL, TokenFile: "t"},
		"missing CA":     {BaseURL: e.srv.URL, TokenFile: "t", Node: "n", CAFile: filepath.Join(dir, "absent")},
		"CA without PEM": {BaseURL: e.srv.URL, TokenFile: "t", Node: "n", CAFile: junk},
	} {
		if _, err := NewClient(o); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	ctx := context.Background()
	c := e.client(t, "node-1", e.token(t))
	if err := os.Remove(filepath.Join(e.dir, "token-node-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, RegisterRequest{}); !IsRetryable(err) || !strings.HasPrefix(err.Error(), "nodeapi: register: reading token") {
		t.Fatalf("missing token file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "token-node-1"), []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, RegisterRequest{}); !IsRetryable(err) {
		t.Fatalf("empty token file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "token-node-1"), []byte(e.token(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, RegisterRequest{}); err != nil {
		t.Fatalf("rotated token file is reread: %v", err)
	}
	if _, err := c.Submit(ctx, "q1", nil); !errors.Is(err, ErrInvalid) || IsRetryable(err) || !IsMalformed(err) {
		t.Fatalf("empty submit: %v", err)
	}
	untrusted, err := NewClient(ClientOptions{BaseURL: e.srv.URL, TokenFile: filepath.Join(e.dir, "token-node-1"), Node: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.Register(ctx, RegisterRequest{}); err == nil {
		t.Fatal("server certificate must be verified")
	}
	e.srv.Close()
	if _, err := c.Register(ctx, RegisterRequest{}); !IsRetryable(err) {
		t.Fatalf("closed server: %v", err)
	}
	for code, want := range map[int]bool{500: true, 503: true, 429: true, 408: true, 400: false, 401: false, 403: false, 404: false, 413: false} {
		if retryableStatus(code) != want {
			t.Errorf("status %d retryable = %v", code, !want)
		}
	}
}

func TestClientRejectsBadResponses(t *testing.T) {
	var mode atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 0:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
		case 1:
			w.Header().Set("Content-Type", ContentType)
			_, _ = w.Write([]byte{0xa1, 0x01, 0x60})
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	tf := filepath.Join(dir, "token")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	_ = os.WriteFile(tf, []byte("t"), 0o600)
	c, err := NewClient(ClientOptions{BaseURL: srv.URL + "/", CAFile: ca, TokenFile: tf, Node: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WaitTasks(context.Background()); err == nil || IsRetryable(err) {
		t.Fatalf("wrong content type: %v", err)
	}
	mode.Store(1)
	if _, err := c.WaitBundle(context.Background(), ""); !errors.Is(err, ErrInvalid) || IsRetryable(err) {
		t.Fatalf("invalid bundle: %v", err)
	}
}

func TestNewServerRequiresDependencies(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewServer without Auth must panic")
		}
	}()
	NewServer(Options{Backend: newFakeBackend()})
}
