// Package coordinator wires the coordinator role: state collection, the spool and writer session,
// cluster rule evaluation, findings, the node agent API, and the local administration socket.
package coordinator

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/validators"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// Version is the agent version reported in hello, health, and enrollment.
var Version = "dev"

// Environment variables read by the coordinator.
const (
	EnvPodName        = "POD_NAME"
	EnvPodNamespace   = "POD_NAMESPACE"
	EnvNodeNamespace  = "EXITMESH_NODE_NAMESPACE"
	EnvNodeSA         = "EXITMESH_NODE_SERVICE_ACCOUNT"
	DefaultNodeNS     = "exitmesh-node"
	DefaultNodeSA     = "exitmesh-node"
	ClaimTemplateName = "data"
)

// Tuning holds intervals and thresholds; zero fields take the defaults.
type Tuning struct {
	EvalInterval   time.Duration // rule evaluation cycle, default 15s
	SnapshotEvery  time.Duration // recovery snapshot refresh throttle, default 5s
	AnchorDeltas   int           // deltas after which a periodic anchor is due, default 5000
	AnchorEvery    time.Duration // maximum time between anchors while connected, default 6h
	NodeTimeout    time.Duration // a node not seen for this long is uncovered, default 3m
	HousekeepEvery time.Duration // pressure, commit, and resync checks, default 5s
	PressureWarmup time.Duration // uptime before the projected window counts toward spool pressure, default 15m
	ExportEvery    time.Duration // air-gap export cadence, default 1m
	BundleEvery    time.Duration // bundle fetch retry and air-gap directory poll, default 1m
	RetryBase      time.Duration // enrollment retry base, default 2s
	BackoffBase    time.Duration // session reconnect backoff base, default 1s
	BackoffMax     time.Duration // default and maximum 5m
	HealthInterval time.Duration // agent.health cadence, default 60s
	LongPollMax    time.Duration // node API long-poll bound, default nodeapi.DefaultLongPollMax
	FlushInterval  time.Duration // collector event flush, default 30s
	CollectorRetry time.Duration // collector retry base after access failures; zero keeps the collector default
	// ReflectorBackoff overrides the collector's watch restart backoff.
	ReflectorBackoff *wait.Backoff
}

func (t *Tuning) defaults() {
	d := func(p *time.Duration, v time.Duration) {
		if *p <= 0 {
			*p = v
		}
	}
	d(&t.EvalInterval, 15*time.Second)
	d(&t.SnapshotEvery, 5*time.Second)
	if t.AnchorDeltas <= 0 {
		t.AnchorDeltas = 5000
	}
	d(&t.AnchorEvery, 6*time.Hour)
	d(&t.NodeTimeout, 3*time.Minute)
	d(&t.HousekeepEvery, 5*time.Second)
	d(&t.PressureWarmup, 15*time.Minute)
	d(&t.ExportEvery, time.Minute)
	d(&t.BundleEvery, time.Minute)
	d(&t.RetryBase, 2*time.Second)
	d(&t.BackoffBase, time.Second)
	d(&t.BackoffMax, 5*time.Minute)
	t.BackoffMax = min(t.BackoffMax, client.MaxBackoff)
	t.RetryBase = min(t.RetryBase, t.BackoffMax)
	t.BackoffBase = min(t.BackoffBase, t.BackoffMax)
	d(&t.HealthInterval, time.Minute)
	d(&t.LongPollMax, nodeapi.DefaultLongPollMax)
	d(&t.FlushInterval, 30*time.Second)
}

// Deps injects the external dependencies; Run builds the real ones.
type Deps struct {
	Dynamic   dynamic.Interface
	Metadata  metadata.Interface
	Discovery discovery.DiscoveryInterface
	Kube      kubernetes.Interface
	// Roots overrides the trust roots from cfg.Trust.
	Roots *bundle.Roots
	Clock func() time.Time
	// Tunnel is the base tunnel configuration; Endpoint and CAFile default to cfg, Credential is set here.
	Tunnel tunnel.Options
	// APIServer and JWKSClient reach issuer discovery and /openid/v1/jwks for node token validation.
	APIServer  string
	JWKSClient *http.Client
	Logger     *slog.Logger
	Getenv     func(string) string
	// LookbackClient reaches configured lookback sources; nil uses the default transport.
	LookbackClient *http.Client
	Tuning         Tuning
}

// Coordinator is one coordinator process.
type Coordinator struct {
	cfg  *config.Config
	d    Deps
	t    Tuning
	log  *slog.Logger
	now  func() time.Time
	red  *redact.Redactor
	caps []string

	podName, podNS, nodeNS, nodeSA string

	sp       *spool.Spool
	store    *commitStore
	cl       *client.Client
	col      *state.Collector
	tracker  *state.Tracker
	eng      *engine.Engine
	mem      *engine.MemSeries
	fnd      *findings.Tracker
	nfi      *nodeFindings
	bundles  *bundleState
	nodes    *registry
	tasks    *taskQueue
	kube     *kubeFeed
	inv      *investigate.Service
	targetID string
	airgap   bool

	sinkMu      sync.Mutex
	observed    *protocol.State
	resyncSince time.Time

	headMu   sync.Mutex
	head     *protocol.State
	headVer  uint64
	cache    *protocol.State
	cacheVer uint64
	podIdx   map[string]podRef
	podVer   uint64

	recovered        *protocol.State
	recoveredAt      time.Time
	rebaselineAtSync bool
	startedAt        time.Time

	evMu     sync.Mutex
	events   []engine.AlertEvent
	pendObs  []findings.Observation
	pressure bool

	statMu   sync.Mutex
	stats    chainStats
	place    placementReport
	audits   []nodeapi.AuditEvent
	auditN   int
	lastErrs map[string]string

	rebaseline  bool
	nodeAPIAddr string
	synced      chan struct{}
	ready       chan struct{}
	fatal       chan error
	kick        chan struct{}
	fatalOnce   sync.Once
	cancel      context.CancelFunc
	spoolFault  func() error
	// captured is the spool transaction of the session store's Do in progress, set and read under the sequence lock.
	captured *spool.Tx
}

type chainStats struct {
	LastCheckpoint    seqTime
	LastDelta         seqTime
	LastFinding       seqTime
	DeltasSinceAnchor int
	LastAnchor        time.Time
	Boundaries        []boundary
}

type seqTime struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
}

type boundary struct {
	Time   time.Time        `json:"time"`
	Epoch  protocol.EpochID `json:"epoch"`
	Reason string           `json:"reason"`
}

type placementReport struct {
	state.Placement
	Error string `json:"error,omitempty"`
}

var errNotReady = fmt.Errorf("%w: state not synchronized yet", nodeapi.ErrUnavailable)

// New validates the configuration and prepares a coordinator; Run opens the spool and starts it.
func New(cfg *config.Config, d Deps) (*Coordinator, error) {
	if cfg == nil {
		return nil, errors.New("coordinator: nil config")
	}
	if cfg.Role != config.RoleCoordinator {
		return nil, fmt.Errorf("coordinator: config role is %q", cfg.Role)
	}
	if d.Dynamic == nil || d.Metadata == nil || d.Discovery == nil {
		return nil, errors.New("coordinator: dynamic, metadata, and discovery clients are required")
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.Getenv == nil {
		d.Getenv = os.Getenv
	}
	red, err := redact.New(redact.Config{ExtraPatterns: cfg.Policy.RedactionPatterns})
	if err != nil {
		return nil, fmt.Errorf("coordinator: redaction patterns: %w", err)
	}
	log := d.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	log = slog.New(redact.NewHandler(log.Handler(), red)).With("role", config.RoleCoordinator)
	d.Tuning.defaults()
	c := &Coordinator{
		cfg: cfg, d: d, t: d.Tuning, log: log, now: d.Clock, red: red, airgap: cfg.AirGap.Enabled,
		synced: make(chan struct{}), ready: make(chan struct{}), fatal: make(chan error, 1), kick: make(chan struct{}, 1),
		lastErrs: map[string]string{},
	}
	c.caps = append([]string(nil), cfg.Capabilities...)
	sort.Strings(c.caps)
	c.caps = slices.Compact(c.caps)
	c.podName = firstNonEmpty(cfg.Coordinator.PodName, d.Getenv(EnvPodName))
	c.podNS = firstNonEmpty(cfg.Coordinator.Namespace, d.Getenv(EnvPodNamespace))
	c.nodeNS = firstNonEmpty(d.Getenv(EnvNodeNamespace), DefaultNodeNS)
	c.nodeSA = firstNonEmpty(d.Getenv(EnvNodeSA), DefaultNodeSA)
	if c.airgap && (cfg.AirGap.ExportDir == "" || cfg.AirGap.BundleDir == "") {
		return nil, errors.New("coordinator: the air-gap profile needs airgap.exportDir and airgap.bundleDir")
	}
	if c.airgap && cfg.EnrollmentTokenFile == "" {
		return nil, errors.New("coordinator: the air-gap profile needs enrollmentTokenFile to learn the target id")
	}
	if cfg.Coordinator.TLSCertFile == "" || cfg.Coordinator.TLSKeyFile == "" {
		return nil, errors.New("coordinator: coordinator.tlsCertFile and coordinator.tlsKeyFile are required for the node API")
	}
	return c, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Ready is closed once the state is synchronized and the node API listens.
func (c *Coordinator) Ready() <-chan struct{} { return c.ready }

// NodeAPIAddr returns the node API listen address once Ready is closed.
func (c *Coordinator) NodeAPIAddr() string {
	c.statMu.Lock()
	defer c.statMu.Unlock()
	return c.nodeAPIAddr
}

func (c *Coordinator) fail(err error) {
	c.fatalOnce.Do(func() {
		c.fatal <- err
		if c.cancel != nil {
			c.cancel()
		}
	})
}

func (c *Coordinator) setErr(key string, err error) {
	c.statMu.Lock()
	defer c.statMu.Unlock()
	if err == nil {
		delete(c.lastErrs, key)
		return
	}
	c.lastErrs[key] = err.Error()
}

func (c *Coordinator) poke() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Run starts the coordinator and blocks until ctx ends, a fatal error occurs, or the writer must stop.
func (c *Coordinator) Run(ctx context.Context) (err error) {
	c.startedAt = c.now()
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	defer cancel()
	sp, err := spool.Open(spool.Options{
		Dir: filepath.Join(c.cfg.StateDir, "spool"), CapacityBytes: int64(c.cfg.Spool.Capacity),
		WindowBytes: int64(c.cfg.Spool.Window), CoalesceAt: c.cfg.Spool.CoalesceAt, Clock: c.now, CommitFault: c.spoolFault,
	})
	if err != nil {
		if errors.Is(err, spool.ErrLocked) {
			return fmt.Errorf("coordinator: the spool at %s is locked by another coordinator process; refusing to run: %w", c.cfg.StateDir, err)
		}
		return fmt.Errorf("coordinator: open spool: %w", err)
	}
	c.sp = sp
	defer func() {
		if cerr := sp.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if h, ok := sp.Halted(); ok {
		return fmt.Errorf("coordinator: this writer was stopped (%s: %s at %s) and refuses to run; resolve the cause in ExitMesh, then clear the halt or reinstall with a new spool", h.Code, h.Message, h.At.Format(time.RFC3339))
	}
	c.log.Info("spool opened", "writer", sp.WriterID().String(), "incarnation", sp.Incarnation())
	if err := c.ensureIdentity(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if err := c.setup(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	go1 := func(fn func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); fn(ctx) }()
	}
	srv, err := c.listenNodeAPI()
	if err != nil {
		return err
	}
	go1(func(ctx context.Context) {
		<-ctx.Done()
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = srv.Shutdown(sctx)
	})
	go1(func(ctx context.Context) {
		if err := admin.Serve(ctx, c.cfg.StateDir, adminBackend{c}); err != nil && ctx.Err() == nil {
			c.log.Error("admin socket", "err", err)
			c.setErr("admin", err)
		}
	})
	colCtx, colCancel := context.WithCancel(ctx)
	colDone := make(chan struct{})
	go func() {
		defer close(colDone)
		if err := c.col.Run(colCtx); err != nil && colCtx.Err() == nil {
			c.fail(fmt.Errorf("coordinator: collector: %w", err))
		}
	}()
	select {
	case <-c.synced:
	case <-ctx.Done():
	}
	if ctx.Err() == nil {
		close(c.ready)
		if st := c.stateView(); st != nil {
			c.log.Info("state synchronized", "resources", len(st.Resources))
		}
		if c.cl != nil && !c.airgap {
			go1(c.runSession)
		}
		go1(c.evalLoop)
		go1(c.housekeepLoop)
		go1(c.bundleLoop)
		if c.airgap {
			go1(c.exportLoop)
		}
	}
	<-ctx.Done()
	colCancel()
	<-colDone
	wg.Wait()
	c.shutdown()
	select {
	case ferr := <-c.fatal:
		return ferr
	default:
	}
	return nil
}

func (c *Coordinator) runSession(ctx context.Context) {
	err := c.cl.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	var stop *client.StopError
	if errors.As(err, &stop) {
		c.log.Error("writer stopped by the control plane", "code", stop.Code)
		if stop.Code == client.HaltDeenrolled {
			c.fail(nil)
			return
		}
		c.fail(fmt.Errorf("coordinator: writer stopped: %s", stop.Code))
		return
	}
	c.fail(fmt.Errorf("coordinator: session: %w", err))
}

func (c *Coordinator) shutdown() {
	if c.stateView() != nil {
		c.flushFindings()
	}
	if err := c.store.saveNow(); err != nil && !errors.Is(err, errNotReady) {
		c.log.Warn("recovery snapshot at shutdown", "err", err)
	}
	c.store.flush(true)
}

func (c *Coordinator) agentInfo() protocol.AgentInfo {
	a := protocol.AgentInfo{Version: Version, Protocol: protocol.Version, Schema: protocol.SchemaVersion, Engine: bundle.EngineVersion, Role: config.RoleCoordinator, Platform: "kubernetes"}
	if c.d.Discovery != nil {
		if v, err := c.d.Discovery.ServerVersion(); err == nil && v != nil {
			a.KubernetesVersion = v.GitVersion
		}
	}
	return a
}

func (c *Coordinator) setup(ctx context.Context) error {
	sp := c.sp
	var err error
	if c.fnd, err = findings.NewTracker(findings.Options{
		TargetID: c.targetID, Store: sp.KV("findings"), LateThreshold: c.cfg.Policy.LateThreshold.D(),
		Redactor: c.red, Clock: c.now,
	}); err != nil {
		return fmt.Errorf("coordinator: findings: %w", err)
	}
	if c.nfi, err = loadNodeFindings(sp.KV("node-findings")); err != nil {
		return fmt.Errorf("coordinator: node findings: %w", err)
	}
	var roots bundle.Roots
	if c.d.Roots != nil {
		roots = *c.d.Roots
	} else if roots, err = bundle.LoadRoots(c.cfg.Trust.RootsFile, c.cfg.Trust.Roots, c.cfg.Trust.Threshold); err != nil {
		return fmt.Errorf("coordinator: trust roots: %w", err)
	}
	ver, err := bundle.NewVerifier(roots, sp.KV("trust"))
	if err != nil {
		return fmt.Errorf("coordinator: trust roots: %w", err)
	}
	ver.SetClock(c.now)
	c.bundles = newBundleState(bundle.NewStore(sp.KV("bundles"), ver, 0), ver, sp.KV("bundle-dist"), c.cfg.Policy.Bundle(bundle.TargetKubernetes), validators.For(bundle.TargetKubernetes))
	c.mem = engine.NewMemSeries(time.Hour, c.now)
	c.nodes = newRegistry(c.now, c.t.NodeTimeout)
	c.tasks = newTaskQueue()
	c.kube = newKubeFeed(c.now)
	if c.eng, err = engine.NewEngine(engine.Options{
		Role: engine.RoleCoordinator, Store: sp.KV("alerts"), Clock: c.now, Sink: c.onAlert,
		KubeSubset: state.PublishedSubset(), Queryable: c.mem, StateSource: c.stateView,
		ResolveResource: c.resolveResource, ClusterCoverage: c.clusterCoverage, Policy: c.enginePolicy(),
		DefaultInterval: c.t.EvalInterval,
	}); err != nil {
		return fmt.Errorf("coordinator: rule engine: %w", err)
	}
	c.loadBundle()
	if err := c.recover(); err != nil {
		return err
	}
	c.readPlacement(ctx)
	norm, err := state.NewNormalizer(state.OptionsFromConfig(c.cfg.Kubernetes, c.red))
	if err != nil {
		return fmt.Errorf("coordinator: normalizer: %w", err)
	}
	c.tracker = state.NewTracker(state.TrackerOptions{Normalizer: norm, Clock: c.now})
	co := state.CollectorOptions{
		Dynamic: c.d.Dynamic, Metadata: c.d.Metadata, Discovery: c.d.Discovery, Tracker: c.tracker,
		Sink: c.sink, OnSynced: c.onSynced, ExcludeNamespaces: c.cfg.Kubernetes.ExcludeNamespaces,
		Resources: c.cfg.Kubernetes.Resources, Logger: c.log, Clock: c.now, FlushInterval: c.t.FlushInterval,
		ReflectorBackoff: c.t.ReflectorBackoff, RetryBase: c.t.CollectorRetry, RetryMax: c.t.CollectorRetry,
	}
	if c.cfg.Kubernetes.Scope == "namespaces" {
		co.Namespaces = c.cfg.Kubernetes.Namespaces
	}
	if c.col, err = state.NewCollector(co); err != nil {
		return fmt.Errorf("coordinator: collector: %w", err)
	}
	c.store = &commitStore{ClientStore: spool.ClientStore{S: sp}, c: c}
	var tr client.Transport = offlineTransport{}
	if !c.airgap {
		opts := c.tunnelOptions()
		if tr, err = tunnel.New(opts); err != nil {
			return fmt.Errorf("coordinator: tunnel: %w", err)
		}
	}
	if c.cl, err = client.New(client.Options{
		Store: c.store, Transport: tr, Hooks: hooks{c}, Agent: c.agentInfo(), Logger: c.log,
		BackoffBase: c.t.BackoffBase, BackoffMax: c.t.BackoffMax, HealthInterval: c.t.HealthInterval,
	}); err != nil {
		return fmt.Errorf("coordinator: session client: %w", err)
	}
	if c.inv, err = investigate.NewService(investigate.Options{
		Role: investigate.RoleCoordinator, State: c.stateView, Nodes: router{c}, Coordinator: c.mem,
		Lookback: c.cfg.Lookback, HTTPClient: c.d.LookbackClient, Limits: c.cfg.Investigation, Audit: c.auditInvestigation,
		SaveFinding: c.saveQueryFinding, Clock: c.now, Redactor: c.red,
	}); err != nil {
		return fmt.Errorf("coordinator: investigation: %w", err)
	}
	return nil
}

func (c *Coordinator) tunnelOptions() tunnel.Options {
	opts := c.d.Tunnel
	if opts.Endpoint == "" {
		opts.Endpoint = c.cfg.Endpoint
	}
	if opts.CAFile == "" {
		opts.CAFile = c.cfg.EndpointCAFile
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "exitmesh-agent/" + Version
	}
	sp := c.sp
	opts.Credential = func() string { return sp.Identity().Credential }
	return opts
}

func (c *Coordinator) enginePolicy() engine.Policy {
	pol := c.cfg.Policy
	return engine.Policy{
		MaxEvalTime: pol.MaxRuleEvalTime.D(), MaxSamples: pol.MaxRuleSamples, MaxSeries: pol.MaxRuleSeries,
		MaxCounterBytes: int(pol.MaxCounterBytes), DisabledRules: pol.DisabledRules, Capabilities: c.caps,
	}
}

func (c *Coordinator) readPlacement(ctx context.Context) {
	rep := placementReport{}
	switch {
	case c.d.Kube == nil:
		rep.Error = "no Kubernetes client for placement detection"
	case c.podName == "" || c.podNS == "":
		rep.Error = "POD_NAME and POD_NAMESPACE are not set; storage placement is unknown"
	default:
		claim := ClaimTemplateName + "-" + c.podName
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		p, err := state.ReadPlacement(pctx, c.d.Kube, c.podNS, claim)
		cancel()
		rep.Placement = p
		if err != nil {
			rep.Error = err.Error()
			c.log.Warn("storage placement", "claim", claim, "err", err)
		} else if p.Pinned {
			c.log.Warn("coordinator volume is node-local; the coordinator is pinned to its node", "nodes", p.PinnedNodes)
		}
	}
	c.statMu.Lock()
	c.place = rep
	c.statMu.Unlock()
}

func (c *Coordinator) listenNodeAPI() (*http.Server, error) {
	certs := &certReloader{cert: c.cfg.Coordinator.TLSCertFile, key: c.cfg.Coordinator.TLSKeyFile}
	if _, err := certs.get(nil); err != nil {
		return nil, fmt.Errorf("coordinator: node API TLS: %w", err)
	}
	apiServer, httpc := c.d.APIServer, c.d.JWKSClient
	auth, err := nodeapi.NewAuthenticator(nodeapi.AuthOptions{
		APIServer: apiServer, HTTPClient: httpc, Audience: c.cfg.Coordinator.Audience,
		Namespace: c.nodeNS, ServiceAccount: c.nodeSA, ResolvePod: nodeapi.PodNodeResolver(c.lookupPod), Clock: c.now,
	})
	if err != nil {
		return nil, fmt.Errorf("coordinator: node authenticator: %w", err)
	}
	h := nodeapi.NewServer(nodeapi.Options{
		Auth: auth, Backend: nodeBackend{c}, Audit: c.auditNode, Clock: c.now, LongPollMax: c.t.LongPollMax, Logger: c.log,
	})
	ln, err := net.Listen("tcp", c.cfg.Coordinator.Listen)
	if err != nil {
		return nil, fmt.Errorf("coordinator: node API listen: %w", err)
	}
	srv := &http.Server{
		Handler: h, ReadHeaderTimeout: 10 * time.Second, WriteTimeout: c.t.LongPollMax + 30*time.Second,
		IdleTimeout: 2 * time.Minute, ErrorLog: slog.NewLogLogger(c.log.Handler(), slog.LevelWarn),
	}
	tl := tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.get})
	c.statMu.Lock()
	c.nodeAPIAddr = ln.Addr().String()
	c.statMu.Unlock()
	go func() {
		if err := srv.Serve(tl); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.fail(fmt.Errorf("coordinator: node API: %w", err))
		}
	}()
	return srv, nil
}

type certReloader struct {
	cert, key string
	mu        sync.Mutex
	mod       time.Time
	cur       *tls.Certificate
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := os.Stat(r.cert)
	if err != nil {
		if r.cur != nil {
			return r.cur, nil
		}
		return nil, err
	}
	if r.cur != nil && !st.ModTime().After(r.mod) {
		return r.cur, nil
	}
	kp, err := tls.LoadX509KeyPair(r.cert, r.key)
	if err != nil {
		if r.cur != nil {
			return r.cur, nil
		}
		return nil, err
	}
	r.cur, r.mod = &kp, st.ModTime()
	return r.cur, nil
}

func (c *Coordinator) auditNode(ev nodeapi.AuditEvent) {
	c.log.Warn("node agent submission rejected", "kind", ev.Kind, "authenticated_node", ev.AuthenticatedNode,
		"claimed_node", ev.ClaimedNode, "namespace", ev.Namespace, "pod", ev.Pod, "path", ev.Path, "remote", ev.RemoteAddr)
	c.statMu.Lock()
	defer c.statMu.Unlock()
	c.auditN++
	c.audits = append(c.audits, ev)
	if len(c.audits) > 20 {
		c.audits = c.audits[len(c.audits)-20:]
	}
}

type offlineTransport struct{}

func (offlineTransport) Dial(context.Context) (client.Conn, error) {
	return nil, errors.New("coordinator: the air-gap profile has no tunnel")
}
