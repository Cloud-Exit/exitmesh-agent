package coordinator

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rulesdefault"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// The published default bundle must activate on a coordinator that runs the default configuration.
func TestDefaultBundleRunsUnderDefaultPolicy(t *testing.T) {
	archive, err := rulesdefault.Archive(bundle.TargetKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(archive)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	sig, err := bundle.Sign(archive, e.trust.sign)
	if err != nil {
		t.Fatal(err)
	}
	r := e.start(e.config())
	if err := e.cp.PublishBundle(protocol.TargetKubernetes, b.Manifest.Version, archive, sig, e.trust.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "default bundle active", func() bool {
		if v := r.c.convergence(); v.Rejected != nil {
			t.Fatalf("default bundle rejected under the default policy: %s", v.Rejected.Reason)
		}
		return r.c.eng.BundleVersion() == b.Manifest.Version
	})
	for _, s := range r.c.eng.RuleStates() {
		if s.State == engine.StateFailed || s.State == engine.StateUnsupported {
			t.Errorf("default rule %s is %s under the default policy: %s", s.RuleID, s.State, s.Reason)
		}
	}
}

func TestNodeProcessIdentityInHealth(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	e.committed(r)
	n1 := e.nodeClient(t, r, "node-1", "node-1")
	ctx := context.Background()
	proc := &nodeapi.Process{UID: 0, GID: 0, Capabilities: []string{"CAP_DAC_READ_SEARCH"}}
	if _, err := n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test", Process: proc}); err != nil {
		t.Fatal(err)
	}
	nodeProcess := func() *nodeapi.Process {
		for _, n := range r.c.nodes.list() {
			if n.Name == "node-1" {
				return n.Process
			}
		}
		return nil
	}
	if p := nodeProcess(); p == nil || !reflect.DeepEqual(*p, *proc) {
		t.Fatalf("node process %+v", p)
	}
	eventually(t, "root node agent visible in the health report", func() bool {
		hs, _ := e.cp.HealthReports(e.targetID)
		return len(hs) > 0 && strings.Contains(string(hs[len(hs)-1]), `"process":{"uid":0,"gid":0,"capabilities":["CAP_DAC_READ_SEARCH"]}`)
	})
	if _, err := n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	if p := nodeProcess(); p != nil {
		t.Fatalf("stale process identity %+v after a registration without one", p)
	}
}

func TestNodeRegistrationLogsDistinguishHeartbeatsAndStatus(t *testing.T) {
	e := newEnv(t)
	logs := &syncBuffer{}
	e.logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	r := e.start(e.config())
	e.committed(r)
	n1 := e.nodeClient(t, r, "node-1", "node-1")
	req := nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "0.7.0", Warming: true, Coverage: map[string]string{"logs": "covered"},
		Process: &nodeapi.Process{UID: 65532, GID: 65532, Capabilities: []string{"CAP_DAC_READ_SEARCH"}}}
	r.c.nodes.touch("node-1", nil)
	step := func(what string, registered, changed, reconnected int) {
		t.Helper()
		if _, err := n1.Register(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		for msg, want := range map[string]int{"node agent registered": registered, "node agent status changed": changed, "node agent reconnected": reconnected, "node agent heartbeat": 0} {
			if n := strings.Count(logs.String(), msg); n != want {
				t.Fatalf("%s: %d %q lines, want %d", what, n, msg, want)
			}
		}
	}
	step("first registration", 1, 0, 0)
	step("heartbeat", 1, 0, 0)
	req.QueueUsage.Items = 10
	step("queue changed", 1, 0, 0)
	req.BundleVersion = "2026.09.1"
	step("bundle activated", 1, 1, 0)
	req.Warming = false
	step("warming finished", 1, 2, 0)
	step("heartbeat", 1, 2, 0)
	req.Coverage = map[string]string{"logs": "degraded"}
	step("coverage changed", 1, 3, 0)
	req.Process = &nodeapi.Process{UID: 0, GID: 0, Capabilities: []string{"CAP_DAC_READ_SEARCH"}}
	step("root fallback", 1, 4, 0)
	step("heartbeat", 1, 4, 0)
	e.clock.Advance(2 * time.Second)
	step("returning after the node timeout", 1, 4, 1)
	step("heartbeat after reconnect", 1, 4, 1)
}

// syncBuffer is a log sink safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A control plane that keeps failing bundle.fetch is retried with backoff and reported once, not once per retry.
func TestBundleFetchFailuresBackOffAndLogOnce(t *testing.T) {
	e := newEnv(t)
	logs := &syncBuffer{}
	e.logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	e.tune = func(tu *Tuning) { tu.HousekeepEvery, tu.BundleEvery = 10*time.Millisecond, 160*time.Millisecond }
	const unpublished = "No rule bundle is published for Kubernetes targets yet."
	e.cp.FailBundleFetch(unpublished)
	r := e.start(e.config())
	e.committed(r)
	eventually(t, "first failed fetch", func() bool { return e.cp.BundleFetches() >= 1 })
	start := e.cp.BundleFetches()
	time.Sleep(time.Second)
	// Constant 10ms retries would make about 100 attempts; doubling to the 160ms ceiling makes about 10.
	if n := e.cp.BundleFetches() - start; n > 20 || n < 2 {
		t.Fatalf("%d bundle.fetch attempts in 1s, want backoff between 10ms and 160ms", n)
	}
	if n := strings.Count(logs.String(), "bundle fetch failed"); n != 1 {
		t.Fatalf("the unchanged failure was logged %d times, want once:\n%s", n, logs.String())
	}

	e.cp.FailBundleFetch("")
	eventually(t, "fetch recovers with nothing published", func() bool { return strings.Contains(logs.String(), "bundle fetch recovered") })
	if r.c.eng.BundleVersion() != "" {
		t.Fatalf("a bundle became active without one being published")
	}
	eventually(t, "empty answer reported", func() bool { return strings.Contains(logs.String(), "no rule bundle is published") })
	settled := e.cp.BundleFetches()
	time.Sleep(400 * time.Millisecond)
	if n := e.cp.BundleFetches() - settled; n != 0 {
		t.Fatalf("%d fetches after an empty answer; the coordinator should wait for bundle.available", n)
	}
	archive, sig := e.trust.signed(t, "2026.09.1", badImageExpr)
	if err := e.cp.PublishBundle(protocol.TargetKubernetes, "2026.09.1", archive, sig, e.trust.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "published bundle active", func() bool { return r.c.eng.BundleVersion() == "2026.09.1" })
	if n := strings.Count(logs.String(), "no rule bundle is published"); n != 1 {
		t.Fatalf("the empty answer was logged %d times, want once:\n%s", n, logs.String())
	}
}

func TestRESTConfigRaisesClientRateLimit(t *testing.T) {
	rc := &rest.Config{Host: "https://10.0.0.1"}
	restConfig(rc)
	kc, err := kubernetes.NewForConfig(rc)
	if err != nil {
		t.Fatal(err)
	}
	if q := kc.CoreV1().RESTClient().GetRateLimiter().QPS(); q != 25 {
		t.Fatalf("client QPS = %v, want 25", q)
	}
	if rc.Burst != 50 || rc.UserAgent != "exitmesh-agent/"+Version {
		t.Fatalf("burst %d, user agent %q", rc.Burst, rc.UserAgent)
	}
}
