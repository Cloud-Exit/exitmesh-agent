// Package node wires the node agent role: scrape, logs, rules, findings, and delivery to the coordinator.
package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	bolt "go.etcd.io/bbolt"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/privdrop"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/disk"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/scrape"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

// TaskExecutor runs coordinator investigation tasks against local telemetry.
type TaskExecutor interface {
	Execute(ctx context.Context, t nodeapi.Task) nodeapi.TaskResult
}

// Timing holds loop cadences; zero values take the defaults.
type Timing struct {
	EvalTick      time.Duration // how often due rules are checked (default 1s)
	Register      time.Duration // default 30s
	Facts         time.Duration // metric facts interval (default 60s)
	KubeRefresh   time.Duration // re-stamping of kube_* series (default 60s)
	DiskCheck     time.Duration // default 30s
	RetryMin      time.Duration // delivery backoff start (default 1s)
	RetryMax      time.Duration // delivery backoff ceiling (default 30s)
	TSDBBlock     time.Duration // TSDB block duration (default tsdb.DefaultBlockDuration)
	TSDBWALBytes  int           // TSDB WAL segment size (default tsdb.DefaultWALSegmentBytes)
	LogPoll       time.Duration // default logs.DefaultPollInterval
	LogCheckpoint time.Duration // default logs.DefaultCheckpointInterval
}

// Deps injects the external dependencies of an Agent.
type Deps struct {
	Kube kubernetes.Interface
	// Roots overrides the trust roots from cfg.Trust.
	Roots  *bundle.Roots
	Clock  func() time.Time
	NodeIP string
	// PodName is the agent's own pod, whose log streams are never tailed.
	PodName string
	// KubeletURL overrides https://NODE_IP:kubeletPort.
	KubeletURL       string
	KubeletTokenFile string
	KubeletCAFile    string
	// Coordinator fields left zero are filled from cfg.Coordinator.
	Coordinator  nodeapi.ClientOptions
	Executor     TaskExecutor
	AgentVersion string
	// Process overrides the identity read from /proc/self/status.
	Process *privdrop.Identity
	Logger  *slog.Logger
	Timing  Timing
}

// Run starts a node agent with in-cluster dependencies until ctx ends.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("node: in-cluster config: %w", err)
	}
	kc, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("node: kubernetes client: %w", err)
	}
	if cfg.Node.Name == "" {
		cfg.Node.Name = os.Getenv("NODE_NAME")
	}
	a, err := New(cfg, Deps{Kube: kc, NodeIP: os.Getenv("NODE_IP"), PodName: os.Getenv("POD_NAME"), Logger: log})
	if err != nil {
		return err
	}
	return a.Run(ctx)
}

// Agent is one node agent.
type Agent struct {
	cfg    *config.Config
	deps   Deps
	t      Timing
	log    *slog.Logger
	clock  func() time.Time
	node   string
	red    *redact.Redactor
	caps   map[string]bool
	vals   bundle.Validators
	bpol   bundle.Policy
	roots  bundle.Roots
	client *nodeapi.Client

	kubeletHost string
	kubeletPort int
	process     *nodeapi.Process

	startMu sync.Mutex
	started bool

	// Opened by Run.
	unlock   func() error
	meta     *bolt.DB
	stores   map[string]kv.Store
	queue    *spool.Queue
	db       *tsdb.DB
	gate     *gatedAppendable
	mem      *engine.MemSeries
	query    storage.Queryable
	prom     *promql.Engine
	scraper  *scrape.Manager
	tailer   *logs.Tailer
	ring     *evidence.Ring
	verifier *bundle.Verifier
	bstore   *bundle.Store
	eng      *engine.Engine
	tracker  *findings.Tracker
	budget   *disk.Budget
	exec     TaskExecutor
	pods     *podWatch
	norm     *state.Normalizer
	scope    nsScope

	startTime time.Time
	fresh     bool
	tailerRan bool

	rules   ruleState
	deliv   delivery
	kube    kubeState
	facts   factState
	cov     coverageState
	logsSet logState
	events  []engine.AlertEvent
	parts   []engine.Part
	// firing holds the latest firing event per LogQL instance so new matches refresh counts and evidence.
	firing map[string]engine.AlertEvent
}

const (
	bucketAlerts   = "alerts"
	bucketOffsets  = "offsets"
	bucketBundle   = "bundle"
	bucketTrust    = "trust"
	bucketFindings = "findings"
	bucketFacts    = "facts"
	metaFile       = "meta.db"
)

// New validates cfg and prepares an agent; Run opens the state directory.
func New(cfg *config.Config, d Deps) (*Agent, error) {
	if cfg == nil {
		return nil, errors.New("node: nil config")
	}
	if cfg.Node.Name == "" {
		return nil, errors.New("node: node name is required (node.name or NODE_NAME)")
	}
	if d.Kube == nil {
		return nil, errors.New("node: a Kubernetes client is required")
	}
	if cfg.StateDir == "" {
		return nil, errors.New("node: stateDir is required")
	}
	red, err := redact.New(redact.Config{ExtraPatterns: cfg.Policy.RedactionPatterns})
	if err != nil {
		return nil, fmt.Errorf("node: redaction policy: %w", err)
	}
	log := d.Logger
	if log == nil {
		log = slog.Default()
	}
	log = slog.New(redact.NewHandler(log.Handler(), red)).With("role", config.RoleNode, "node", cfg.Node.Name)
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.AgentVersion == "" {
		d.AgentVersion = buildVersion()
	}
	var roots bundle.Roots
	if d.Roots != nil {
		roots = *d.Roots
	} else if roots, err = bundle.LoadRoots(cfg.Trust.RootsFile, cfg.Trust.Roots, cfg.Trust.Threshold); err != nil {
		return nil, fmt.Errorf("node: trust roots: %w", err)
	}
	if len(roots.Keys) == 0 {
		return nil, bundle.ErrNoRoots
	}
	a := &Agent{cfg: cfg, deps: d, t: withDefaults(d.Timing), log: log, clock: d.Clock, node: cfg.Node.Name, red: red, roots: roots, caps: map[string]bool{},
		scope: newNSScope(cfg.Kubernetes)}
	for _, c := range cfg.Capabilities {
		a.caps[c] = true
	}
	if a.caps[config.CapMetrics] {
		if a.kubeletHost, a.kubeletPort, err = kubeletAddress(d, cfg); err != nil {
			return nil, err
		}
	}
	co := d.Coordinator
	if co.BaseURL == "" {
		co.BaseURL = cfg.Coordinator.ServiceURL
	}
	if co.CAFile == "" {
		co.CAFile = cfg.Coordinator.CAFile
	}
	if co.TokenFile == "" {
		co.TokenFile = cfg.Coordinator.TokenFile
	}
	if co.Node == "" {
		co.Node = a.node
	}
	if a.client, err = nodeapi.NewClient(co); err != nil {
		return nil, fmt.Errorf("node: coordinator client: %w", err)
	}
	a.vals = validators()
	a.bpol = cfg.Policy.Bundle(bundle.TargetKubernetes)
	id := d.Process
	if id == nil {
		cur, err := privdrop.Current()
		if err != nil {
			return nil, fmt.Errorf("node: process identity: %w", err)
		}
		id = &cur
	}
	a.process = &nodeapi.Process{UID: id.UID, GID: id.GID, Capabilities: slices.Clone(id.Capabilities)}
	if id.Root() {
		log.Warn("node agent runs as root (node.runAsRootFallback)", "capabilities", id.Capabilities)
	}
	return a, nil
}

func withDefaults(t Timing) Timing {
	def := func(p *time.Duration, v time.Duration) {
		if *p <= 0 {
			*p = v
		}
	}
	def(&t.EvalTick, time.Second)
	def(&t.Register, 30*time.Second)
	def(&t.Facts, time.Minute)
	def(&t.KubeRefresh, time.Minute)
	def(&t.DiskCheck, 30*time.Second)
	def(&t.RetryMin, time.Second)
	def(&t.RetryMax, 30*time.Second)
	def(&t.TSDBBlock, tsdb.DefaultBlockDuration)
	def(&t.LogPoll, logs.DefaultPollInterval)
	def(&t.LogCheckpoint, logs.DefaultCheckpointInterval)
	if t.TSDBWALBytes <= 0 {
		t.TSDBWALBytes = tsdb.DefaultWALSegmentBytes
	}
	return t
}

// Version is the agent release version, set by the binary from its build flags.
var Version string

func buildVersion() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "dev"
}

func kubeletAddress(d Deps, cfg *config.Config) (string, int, error) {
	if d.KubeletURL != "" {
		u, err := url.Parse(d.KubeletURL)
		if err != nil || u.Hostname() == "" {
			return "", 0, fmt.Errorf("node: kubelet URL %q is invalid", d.KubeletURL)
		}
		host, p, err := net.SplitHostPort(u.Host)
		if err != nil {
			return "", 0, fmt.Errorf("node: kubelet URL %q: %w", d.KubeletURL, err)
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, fmt.Errorf("node: kubelet URL port %q: %w", p, err)
		}
		return host, port, nil
	}
	if d.NodeIP == "" {
		return "", 0, errors.New("node: NODE_IP is required for the metrics capability")
	}
	return d.NodeIP, cfg.Node.KubeletPort, nil
}

// Run opens the state directory and runs every loop until ctx ends, then shuts down gracefully.
func (a *Agent) Run(ctx context.Context) error {
	a.startMu.Lock()
	if a.started {
		a.startMu.Unlock()
		return errors.New("node: agent already ran")
	}
	a.started = true
	a.startMu.Unlock()
	if err := a.open(); err != nil {
		return errors.Join(err, a.closeAll())
	}
	a.log.Info("node agent started", "version", a.deps.AgentVersion, "fresh_state", a.fresh, "capabilities", a.cfg.Capabilities)
	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	var tailWG sync.WaitGroup
	goLoop := func(g *sync.WaitGroup, fn func(context.Context)) {
		g.Add(1)
		go func() {
			defer g.Done()
			fn(runCtx)
		}()
	}
	goLoop(&wg, a.pods.run)
	goLoop(&wg, a.kubeLoop)
	goLoop(&wg, a.kubePoll)
	goLoop(&wg, a.bundleLoop)
	goLoop(&wg, a.evalLoop)
	goLoop(&wg, a.sendLoop)
	goLoop(&wg, a.registerLoop)
	goLoop(&wg, a.taskLoop)
	if a.db != nil {
		goLoop(&wg, a.factsLoop)
		goLoop(&wg, a.diskLoop)
	}
	if a.tailer != nil {
		a.tailerRan = true
		goLoop(&tailWG, func(c context.Context) {
			if err := a.tailer.Run(c); err != nil && !errors.Is(err, context.Canceled) {
				a.log.Warn("log tailer stopped", "err", err)
			}
		})
	}
	<-ctx.Done()
	cancel()
	wg.Wait()
	tailWG.Wait()
	return a.shutdown()
}

func (a *Agent) open() error {
	dir := a.cfg.StateDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("node: state dir: %w", err)
	}
	unlock, err := spool.LockDir(dir)
	if err != nil {
		return fmt.Errorf("node: state dir %s: %w", dir, err)
	}
	a.unlock = unlock
	metaPath := filepath.Join(dir, metaFile)
	if _, err := os.Stat(metaPath); errors.Is(err, os.ErrNotExist) {
		a.fresh = true
	}
	if a.meta, err = kv.OpenBolt(metaPath); err != nil {
		return fmt.Errorf("node: meta store: %w", err)
	}
	a.stores = map[string]kv.Store{}
	for _, b := range []string{bucketAlerts, bucketOffsets, bucketBundle, bucketTrust, bucketFindings, bucketFacts} {
		s, err := kv.NewBolt(a.meta, b)
		if err != nil {
			return fmt.Errorf("node: meta bucket %s: %w", b, err)
		}
		a.stores[b] = s
	}
	a.startTime = a.clock()
	capBytes := int64(a.cfg.Node.DiskCap)
	queueCap := capBytes / 4
	if a.queue, err = spool.OpenQueue(filepath.Join(dir, "queue"), queueCap); err != nil {
		return fmt.Errorf("node: queue: %w", err)
	}
	a.deliv.notify = make(chan struct{}, 1)
	a.mem = engine.NewMemSeries(tsdb.HardCeiling, a.clock)
	a.prom = promql.NewEngine(promql.EngineOpts{MaxSamples: 5_000_000, Timeout: 30 * time.Second, LookbackDelta: 5 * time.Minute})
	if a.caps[config.CapMetrics] {
		if a.db, err = tsdb.Open(filepath.Join(dir, "tsdb"), tsdb.Options{
			MaxBytes: capBytes / 2, BlockDuration: a.t.TSDBBlock, WALSegmentBytes: a.t.TSDBWALBytes, Logger: a.log.With("component", "tsdb"),
		}); err != nil {
			return fmt.Errorf("node: tsdb: %w", err)
		}
		a.gate = &gatedAppendable{next: a.db}
		a.scraper = scrape.NewManager(scrape.Options{
			Appendable: a.gate, DefaultInterval: a.cfg.Node.ScrapeInterval.D(), Logger: a.log.With("component", "scrape"),
			Budgets: scrape.Budgets{MaxTargets: a.cfg.Node.MaxTargets, MaxSeries: a.cfg.Node.MaxSeries, MaxSamplesPerSecond: a.cfg.Node.MaxSamplesRate},
		})
		a.budget = disk.DiskBudget(dir, capBytes, disk.Options{TSDB: a.db, TSDBDir: "tsdb", SpoolDir: "queue", SpoolReserve: queueCap})
	}
	a.query = mergedQueryable(a.db, a.mem)
	if a.norm, err = state.NewNormalizer(state.OptionsFromConfig(a.cfg.Kubernetes, a.red)); err != nil {
		return fmt.Errorf("node: normalizer: %w", err)
	}
	a.ring = evidence.New(int64(a.cfg.Node.EvidenceRing))
	a.pods = newPodWatch(a.deps.Kube, a.node, a.scope, a.onPods)
	if a.caps[config.CapLogs] {
		if a.tailer, err = logs.NewTailer(logs.Options{
			Root: a.cfg.Node.LogsPath, Node: a.node, Store: a.stores[bucketOffsets], Sink: a.onLine, OnEvent: a.onLogEvent,
			Enrich: a.pods.enrich, PollInterval: a.t.LogPoll, CheckpointInterval: a.t.LogCheckpoint, Clock: a.clock,
		}); err != nil {
			return fmt.Errorf("node: log tailer: %w", err)
		}
	}
	if a.verifier, err = bundle.NewVerifier(a.roots, a.stores[bucketTrust]); err != nil {
		return fmt.Errorf("node: trust store: %w", err)
	}
	a.verifier.SetClock(a.clock)
	a.bstore = bundle.NewStore(a.stores[bucketBundle], a.verifier, 0)
	if a.eng, err = engine.NewEngine(engine.Options{
		Role: engine.RoleNode, Store: a.stores[bucketAlerts], Clock: a.clock,
		Sink:       func(ev engine.AlertEvent) { a.events = append(a.events, ev) },
		Push:       func(p engine.Part) { a.parts = append(a.parts, p) },
		KubeSubset: state.PublishedSubset(), CompileLogQL: a.compileLogQL, Queryable: a.query,
		Coverage: a.engineCoverage, EvidenceLimited: a.ring.Limited, Policy: enginePolicy(a.cfg), ResolveResource: a.pods.resolve,
	}); err != nil {
		return fmt.Errorf("node: rule engine: %w", err)
	}
	if a.tracker, err = findings.NewTracker(findings.Options{
		TargetID: "node:" + a.node, Store: a.stores[bucketFindings], Redactor: a.red, Clock: a.clock,
		LateThreshold: a.cfg.Policy.LateThreshold.D(),
	}); err != nil {
		return fmt.Errorf("node: findings: %w", err)
	}
	if err := a.facts.load(a.stores[bucketFacts]); err != nil {
		return err
	}
	a.exec = a.deps.Executor
	if a.exec == nil {
		a.exec = a.defaultExecutor()
	}
	a.exec = scopedExecutor{next: a.exec, scope: a.scope}
	if err := a.loadLastKnownGood(); err != nil {
		return err
	}
	return nil
}

func (a *Agent) shutdown() error {
	var errs []error
	if a.scraper != nil {
		a.scraper.Stop()
	}
	if _, err := a.tracker.Flush(a.emitFinding); err != nil {
		errs = append(errs, fmt.Errorf("node: flush findings: %w", err))
	}
	errs = append(errs, a.closeAll())
	a.log.Info("node agent stopped")
	return errors.Join(errs...)
}

func (a *Agent) closeAll() error {
	var errs []error
	if a.tailer != nil && !a.tailerRan {
		if err := a.tailer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("node: log offsets: %w", err))
		}
	}
	if a.queue != nil {
		if err := a.queue.Close(); err != nil {
			errs = append(errs, fmt.Errorf("node: queue: %w", err))
		}
	}
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			errs = append(errs, fmt.Errorf("node: tsdb: %w", err))
		}
	}
	if a.meta != nil {
		if err := a.meta.Close(); err != nil {
			errs = append(errs, fmt.Errorf("node: meta store: %w", err))
		}
	}
	if a.unlock != nil {
		if err := a.unlock(); err != nil {
			errs = append(errs, fmt.Errorf("node: unlock: %w", err))
		}
	}
	return errors.Join(errs...)
}

func mergedQueryable(db *tsdb.DB, mem *engine.MemSeries) storage.Queryable {
	return storage.QueryableFunc(func(mint, maxt int64) (storage.Querier, error) {
		mq, err := mem.Querier(mint, maxt)
		if err != nil {
			return nil, err
		}
		if db == nil {
			return mq, nil
		}
		tq, err := db.Querier(mint, maxt)
		if err != nil {
			_ = mq.Close()
			return nil, err
		}
		return storage.NewMergeQuerier([]storage.Querier{tq, mq}, nil, storage.ChainedSeriesMerge), nil
	})
}

func (a *Agent) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
