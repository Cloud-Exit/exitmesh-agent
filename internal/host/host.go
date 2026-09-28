// Package host runs the host role: node agent and coordinator in one process on a Linux host without Kubernetes.
package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/journal"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts/nodemetrics"
	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/disk"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/scrape"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// Version is the agent version reported to the control plane; main sets it from its ldflags.
var Version = "dev"

// State directory layout.
const (
	SpoolDirName = "spool"
	TSDBDirName  = "tsdb"
	MetaFileName = "meta.db"
)

// Defaults.
const (
	DefaultCollectInterval = time.Minute
	DefaultTick            = 10 * time.Second
	DefaultDiskInterval    = time.Minute
)

var errLockHeld = errors.New("locked by another agent process")

// ErrKubernetesNode is returned when host mode is started on a Kubernetes node.
var ErrKubernetesNode = errors.New("host mode refuses to run on a Kubernetes node; install the Helm chart instead (docs/install-kubernetes.md)")

// Clock is the time source; After fires once the clock has passed now plus d.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Investigator serves investigation tools over the tunnel and the admin socket.
type Investigator interface {
	Tools() []client.Tool
	Call(ctx context.Context, name string, args json.RawMessage) (any, error)
}

// JournalReader is the subset of *journal.Reader the host uses.
type JournalReader interface {
	Refresh() error
	Next() (journal.Entry, bool)
	SaveCursor() error
	FileErrors() map[string]error
	Close() error
}

// Deps injects host sources and timing; zero values select the production defaults.
type Deps struct {
	Facts hostfacts.Options
	// FSRoot is the root filesystem for kubelet detection and node_exporter.
	FSRoot            string
	MetricsCollectors []string
	OpenJournal       func(journal.Options) (JournalReader, error)
	// Roots overrides cfg.Trust.
	Roots        *bundle.Roots
	Clock        Clock
	Tunnel       tunnel.Options
	Logger       *slog.Logger
	Investigator Investigator
	// CollectInterval is the host state collection period.
	CollectInterval time.Duration
	Tick            time.Duration
	// Ticks replaces the internal tick timer.
	Ticks          <-chan time.Time
	OnCycle        func(time.Time)
	HealthInterval time.Duration
	BackoffBase    time.Duration
	BackoffMax     time.Duration
}

// Host is one host agent.
type Host struct {
	cfg  *config.Config
	deps Deps
	log  *slog.Logger
	clk  Clock
	red  *redact.Redactor

	unlock   func() error
	meta     *bolt.DB
	sp       *spool.Spool
	store    client.Store
	cl       *client.Client
	verifier *bundle.Verifier
	bundles  *bundle.Store
	eng      *engine.Engine
	tracker  *findings.Tracker
	ring     *evidence.Ring
	db       *tsdb.DB
	exporter *nodemetrics.Exporter
	scraper  *scrape.Manager
	files    *logs.FileTailer
	jr       JournalReader
	budget   *disk.Budget
	facts    *hostfacts.Collector
	ht       *hostfacts.HostTracker
	idStore  kv.Store
	inv      Investigator

	head    head
	rules   ruleSet
	machine machineState

	sched           schedule
	runCtx          context.Context
	exp             *exportFile
	exportRecovered bool

	mu        sync.Mutex
	st        runtimeStatus
	bundleMu  sync.Mutex
	stopCause error
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// Run starts the host role and blocks until ctx ends or the writer must stop.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	h, err := New(cfg, Deps{Logger: log})
	if err != nil {
		return err
	}
	return h.Run(ctx)
}

// New validates the configuration and applies dependency defaults; nothing is opened until Run.
func New(cfg *config.Config, d Deps) (*Host, error) {
	if cfg == nil {
		return nil, errors.New("host: nil configuration")
	}
	if cfg.Role != config.RoleHost {
		return nil, fmt.Errorf("host: role is %q, not host", cfg.Role)
	}
	if d.Logger == nil {
		d.Logger = slog.New(redact.NewHandler(slog.DiscardHandler, redact.Default()))
	}
	if d.Clock == nil {
		d.Clock = realClock{}
	}
	def := hostfacts.DefaultOptions()
	if d.Facts.ProcRoot == "" {
		d.Facts.ProcRoot = def.ProcRoot
	}
	if d.Facts.SysRoot == "" {
		d.Facts.SysRoot = def.SysRoot
	}
	if d.Facts.EtcRoot == "" {
		d.Facts.EtcRoot = def.EtcRoot
	}
	if d.FSRoot == "" {
		d.FSRoot = "/"
	}
	if d.OpenJournal == nil {
		d.OpenJournal = func(o journal.Options) (JournalReader, error) { return journal.Open(o) }
	}
	if d.CollectInterval <= 0 {
		d.CollectInterval = DefaultCollectInterval
	}
	if d.Tick <= 0 {
		d.Tick = DefaultTick
	}
	red, err := redact.New(redact.Config{ExtraPatterns: cfg.Policy.RedactionPatterns})
	if err != nil {
		return nil, fmt.Errorf("host: policy.redactionPatterns: %w", err)
	}
	if d.Facts.Redactor == nil {
		d.Facts.Redactor = red
	}
	return &Host{cfg: cfg, deps: d, log: d.Logger, clk: d.Clock, red: red}, nil
}

// Run opens the state directory and runs every component until ctx ends.
func (h *Host) Run(ctx context.Context) (err error) {
	if k8s, why, kerr := hostfacts.IsKubernetesNode(h.deps.Facts.ProcRoot, h.deps.FSRoot); kerr != nil {
		return fmt.Errorf("host: kubelet detection: %w", kerr)
	} else if k8s {
		return fmt.Errorf("%w: %s", ErrKubernetesNode, why)
	}
	ctx, cancel := context.WithCancel(ctx)
	h.cancel, h.runCtx = cancel, ctx
	defer cancel()
	if err := h.open(); err != nil {
		h.close()
		return err
	}
	defer func() {
		cancel()
		h.wg.Wait()
		if cerr := h.close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	if code, halted := h.sp.Halted(); halted {
		if code.Code == client.HaltDeenrolled {
			h.log.Warn("this host was de-enrolled; purge /var/lib/exitmesh (exitmesh-agent purge-state) to enroll it again", "at", code.At)
			return nil
		}
		return fmt.Errorf("host: writer halted (%s): %s", code.Code, code.Message)
	}
	if err := h.ensureIdentity(ctx); err != nil {
		return err
	}
	if err := h.start(ctx); err != nil {
		return err
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		if err := admin.Serve(ctx, h.cfg.StateDir, h); err != nil && ctx.Err() == nil {
			h.log.Error("admin socket", "err", err)
		}
	}()
	if !h.cfg.AirGap.Enabled {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.session(ctx)
		}()
	}
	h.loop(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stopCause
}

func (h *Host) stop(cause error) {
	h.mu.Lock()
	if h.stopCause == nil {
		h.stopCause = cause
	}
	h.mu.Unlock()
	h.cancel()
}

func (h *Host) open() error {
	unlock, err := spool.LockDir(h.cfg.StateDir)
	if err != nil {
		if errors.Is(err, spool.ErrLocked) {
			return fmt.Errorf("host: state directory %s: %w", h.cfg.StateDir, errLockHeld)
		}
		return fmt.Errorf("host: state directory: %w", err)
	}
	h.unlock = unlock
	if h.meta, err = kv.OpenBolt(filepath.Join(h.cfg.StateDir, MetaFileName)); err != nil {
		return fmt.Errorf("host: %s: %w", MetaFileName, err)
	}
	if h.idStore, err = h.bucket("identity"); err != nil {
		return err
	}
	roots, err := h.roots()
	if err != nil {
		return err
	}
	trust, err := h.bucket("trust")
	if err != nil {
		return err
	}
	if h.verifier, err = bundle.NewVerifier(roots, trust); err != nil {
		return fmt.Errorf("host: trust roots: %w", err)
	}
	h.verifier.SetClock(h.clk.Now)
	bstore, err := h.bucket("bundles")
	if err != nil {
		return err
	}
	h.bundles = bundle.NewStore(bstore, h.verifier, 0)
	h.sp, err = spool.Open(spool.Options{
		Dir:           filepath.Join(h.cfg.StateDir, SpoolDirName),
		CapacityBytes: int64(h.cfg.Host.SpoolReserve),
		WindowBytes:   int64(h.cfg.Spool.Window),
		CoalesceAt:    h.cfg.Spool.CoalesceAt,
		Clock:         h.clk.Now,
	})
	if err != nil {
		if errors.Is(err, spool.ErrLocked) {
			return fmt.Errorf("host: spool: %w", errLockHeld)
		}
		return fmt.Errorf("host: spool: %w", err)
	}
	h.store = commitStore{Store: spool.ClientStore{S: h.sp}, h: h}
	return nil
}

func (h *Host) roots() (bundle.Roots, error) {
	if h.deps.Roots != nil {
		return *h.deps.Roots, nil
	}
	return bundle.LoadRoots(h.cfg.Trust.RootsFile, h.cfg.Trust.Roots, h.cfg.Trust.Threshold)
}

func (h *Host) bucket(name string) (kv.Store, error) {
	s, err := kv.NewBolt(h.meta, name)
	if err != nil {
		return nil, fmt.Errorf("host: %s bucket %s: %w", MetaFileName, name, err)
	}
	return s, nil
}

func (h *Host) close() error {
	var errs []error
	if h.scraper != nil {
		h.scraper.Stop()
	}
	if h.files != nil {
		errs = append(errs, h.files.Close())
	}
	if h.jr != nil {
		errs = append(errs, h.jr.SaveCursor(), h.jr.Close())
	}
	if h.facts != nil {
		errs = append(errs, h.facts.Close())
	}
	if h.db != nil {
		errs = append(errs, h.db.Close())
	}
	h.closeExport()
	if h.sp != nil {
		errs = append(errs, h.sp.Close())
	}
	if h.meta != nil {
		errs = append(errs, h.meta.Close())
	}
	if h.unlock != nil {
		errs = append(errs, h.unlock())
	}
	h.scraper, h.files, h.jr, h.facts, h.db, h.sp, h.meta, h.unlock = nil, nil, nil, nil, nil, nil, nil, nil
	return errors.Join(errs...)
}

func (h *Host) start(ctx context.Context) error {
	if err := h.recover(); err != nil {
		return err
	}
	if err := h.openTelemetry(); err != nil {
		return err
	}
	if err := h.openRules(); err != nil {
		return err
	}
	if err := h.openInvestigation(); err != nil {
		return err
	}
	src := h.deps.Facts
	h.facts = hostfacts.NewCollector(src)
	h.ht = hostfacts.NewHostTracker(h.facts, h.head.snapshot(), h.clk.Now)
	if err := h.collectState(ctx, true); err != nil {
		return err
	}
	h.sched.collect = h.clk.Now()
	var tr client.Transport = offlineTransport{}
	if !h.cfg.AirGap.Enabled {
		topts := h.deps.Tunnel
		topts.Endpoint = h.cfg.Endpoint
		topts.CAFile = h.cfg.EndpointCAFile
		topts.Credential = func() string { return h.sp.Identity().Credential }
		if topts.UserAgent == "" {
			topts.UserAgent = "exitmesh-agent/" + Version
		}
		t, err := tunnel.New(topts)
		if err != nil {
			return fmt.Errorf("host: tunnel: %w", err)
		}
		tr = t
	}
	cl, err := client.New(client.Options{
		Store: h.store, Transport: tr, Hooks: hooks{h}, Agent: h.agentInfo(), Logger: h.log,
		Clock: h.clk, HealthInterval: h.deps.HealthInterval, BackoffBase: h.deps.BackoffBase, BackoffMax: h.deps.BackoffMax,
	})
	if err != nil {
		return err
	}
	h.cl = cl
	if err := cl.Prepare(); err != nil {
		return fmt.Errorf("host: initial checkpoint: %w", err)
	}
	h.loadBundle()
	return nil
}

func (h *Host) agentInfo() protocol.AgentInfo {
	a := protocol.AgentInfo{Version: Version, Protocol: protocol.Version, Schema: protocol.SchemaVersion, Engine: bundle.EngineVersion, Role: config.RoleHost, Platform: "linux"}
	if b, err := os.ReadFile(filepath.Join(h.deps.Facts.EtcRoot, "os-release")); err == nil {
		a.OS = hostfacts.ParseOSRelease(b)["pretty_name"]
	}
	return a
}

type offlineTransport struct{}

func (offlineTransport) Dial(context.Context) (client.Conn, error) {
	return nil, errors.New("air-gap profile: records are delivered by export files")
}

type schedule struct{ collect, metrics, disk, bundle, checkpoint time.Time }

func (h *Host) loop(ctx context.Context) {
	for {
		now := h.clk.Now()
		h.cycle(ctx, now)
		if h.deps.OnCycle != nil {
			h.deps.OnCycle(now)
		}
		var wake <-chan time.Time
		if h.deps.Ticks != nil {
			wake = h.deps.Ticks
		} else {
			wake = h.clk.After(h.deps.Tick)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}
	}
}

func due(last *time.Time, now time.Time, every time.Duration) bool {
	if last.IsZero() || !now.Before(last.Add(every)) {
		*last = now
		return true
	}
	return false
}

func (h *Host) cycle(ctx context.Context, now time.Time) {
	s := &h.sched
	if h.exporter != nil && due(&s.metrics, now, h.cfg.Host.ScrapeInterval.D()) {
		h.gatherMetrics(now)
	}
	h.pollLogs(ctx, now)
	if due(&s.collect, now, h.deps.CollectInterval) {
		if err := h.collectState(ctx, false); err != nil {
			h.log.Warn("host state collection", "err", err)
		}
	}
	h.evaluate(ctx, now)
	if due(&s.checkpoint, now, logs.DefaultCheckpointInterval) {
		h.checkpointLogs()
	}
	if due(&s.disk, now, DefaultDiskInterval) {
		h.checkDisk(ctx)
	}
	if h.cfg.AirGap.Enabled && due(&s.bundle, now, time.Minute) {
		h.loadAirgapBundle()
	}
	if h.cfg.AirGap.Enabled {
		if err := h.exportPending(now); err != nil {
			h.log.Warn("air-gap export", "err", err)
		}
	} else {
		h.watchSession(ctx)
	}
}

func (h *Host) setErr(field *string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		*field = ""
		return
	}
	*field = h.red.String(err.Error())
}
