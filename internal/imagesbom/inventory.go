package imagesbom

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

// Options configures an Inventory.
type Options struct {
	Node         string
	ContentStore string
	// Dir holds the cache and the transient work directory; it lives under the agent state directory.
	Dir          string
	Limits       Limits
	CacheEntries int
	CacheBytes   int64
	// Settle delays background builds of newly observed digests.
	Settle time.Duration
	// Pause separates background builds so they stay low priority.
	Pause time.Duration
	// FailureRetry is how long a failed build is reported before it is tried again.
	FailureRetry time.Duration
	Arch         string
	Variant      string
	Redactor     *redact.Redactor
	Logger       *slog.Logger
	Clock        func() time.Time
}

type failure struct {
	reason string
	at     time.Time
}

// Inventory builds one image at a time, in the background for running digests and first for requested ones.
type Inventory struct {
	o     Options
	cache *cache
	build func(ctx context.Context, digest string) (Result, error)
	wake  chan struct{}

	mu        sync.Mutex
	observed  bool
	running   map[string]time.Time
	completed map[string]bool
	urgent    []string
	building  string
	failed    map[string]failure
}

// New opens the cache under o.Dir and prepares the builder.
func New(o Options) (*Inventory, error) {
	if o.Dir == "" {
		return nil, errors.New("imagesbom: a state directory is required")
	}
	if o.ContentStore == "" {
		o.ContentStore = DefaultContentStore
	}
	if o.CacheEntries <= 0 {
		o.CacheEntries = 256
	}
	if o.CacheBytes <= 0 {
		o.CacheBytes = 64 << 20
	}
	if o.Settle <= 0 {
		o.Settle = 30 * time.Second
	}
	if o.Pause <= 0 {
		o.Pause = 5 * time.Second
	}
	if o.FailureRetry <= 0 {
		o.FailureRetry = time.Hour
	}
	if o.Arch == "" {
		o.Arch, o.Variant = runtime.GOARCH, goVariant()
	}
	if o.Redactor == nil {
		o.Redactor = redact.Default()
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	routeScalibrLogs(o.Logger)
	c, err := openCache(filepath.Join(o.Dir, "cache"), o.CacheEntries, o.CacheBytes)
	if err != nil {
		return nil, err
	}
	b, err := newBuilder(contentStore{root: o.ContentStore, arch: o.Arch, variant: o.Variant}, filepath.Join(o.Dir, "work"), o.Limits)
	if err != nil {
		return nil, err
	}
	if err := removeAll(b.work); err != nil {
		return nil, err
	}
	return &Inventory{o: o, cache: c, build: b.build, wake: make(chan struct{}, 1), running: map[string]time.Time{}, completed: map[string]bool{}, failed: map[string]failure{}}, nil
}

func goVariant() string {
	if runtime.GOARCH == "arm" {
		return "v7"
	}
	return ""
}

func (i *Inventory) signal() {
	select {
	case i.wake <- struct{}{}:
	default:
	}
}

// Observe replaces the set of digests that run on this node; new ones are built in the background.
func (i *Inventory) Observe(digests []string) {
	now := i.o.Clock()
	i.mu.Lock()
	next := make(map[string]time.Time, len(digests))
	for _, d := range digests {
		if _, err := ParseDigest(d); err != nil {
			continue
		}
		if t, ok := i.running[d]; ok {
			next[d] = t
		} else {
			next[d] = now
		}
		if i.cache.has(d[len("sha256:"):]) {
			i.completed[d] = true
		}
	}
	for d := range i.completed {
		if _, ok := next[d]; !ok {
			delete(i.completed, d)
		}
	}
	i.running = next
	i.observed = true
	i.mu.Unlock()
	i.signal()
}

// Get returns the cached inventory, pending while it is queued or building, or unavailable with the reason.
func (i *Inventory) Get(digest string) Result {
	if _, err := ParseDigest(digest); err != nil {
		return Unavailable(digest, sentence(err.Error()))
	}
	now := i.o.Clock()
	if r, ok := i.cache.get(digest[len("sha256:"):], now); ok {
		return r
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.building == digest || slices.Contains(i.urgent, digest) {
		return Pending(digest)
	}
	if f, ok := i.failed[digest]; ok && now.Sub(f.at) < i.o.FailureRetry {
		return Unavailable(digest, f.reason)
	}
	if !i.observed {
		return Unavailable(digest, fmt.Sprintf("Node %s has not listed its pods yet; ask again shortly.", i.o.Node))
	}
	if _, ok := i.running[digest]; !ok {
		return Unavailable(digest, fmt.Sprintf("No running pod on node %s uses image %s.", i.o.Node, digest))
	}
	delete(i.failed, digest)
	i.urgent = append(i.urgent, digest)
	i.signal()
	return Pending(digest)
}

// Run builds queued digests one at a time until ctx ends.
func (i *Inventory) Run(ctx context.Context) {
	for ctx.Err() == nil {
		d, urgent := i.next()
		if d == "" {
			t := time.NewTimer(min(i.o.Settle, time.Minute))
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-i.wake:
			case <-t.C:
			}
			t.Stop()
			continue
		}
		i.runOne(ctx, d)
		if !urgent && !sleepCtx(ctx, i.o.Pause) {
			return
		}
	}
}

// next pops a requested digest, or picks the longest-running digest without an inventory once it settled.
func (i *Inventory) next() (string, bool) {
	now := i.o.Clock()
	i.mu.Lock()
	defer i.mu.Unlock()
	for len(i.urgent) > 0 {
		d := i.urgent[0]
		i.urgent = i.urgent[1:]
		if !i.cache.has(d[len("sha256:"):]) {
			i.building = d
			return d, true
		}
	}
	var pick string
	var first time.Time
	for d, seen := range i.running {
		if now.Sub(seen) < i.o.Settle || i.completed[d] || i.cache.has(d[len("sha256:"):]) {
			continue
		}
		if f, ok := i.failed[d]; ok && now.Sub(f.at) < i.o.FailureRetry {
			continue
		}
		if pick == "" || seen.Before(first) || (seen.Equal(first) && d < pick) {
			pick, first = d, seen
		}
	}
	i.building = pick
	return pick, false
}

func (i *Inventory) runOne(ctx context.Context, digest string) {
	begin := i.o.Clock()
	res, err := i.build(ctx, digest)
	now := i.o.Clock()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.building = ""
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		reason := i.o.Redactor.String(sentence(err.Error()))
		i.failed[digest] = failure{reason: reason, at: now}
		i.o.Logger.Info("image inventory unavailable", "digest", digest, "reason", reason)
		return
	}
	res = Redact(res, i.o.Redactor)
	if err := i.cache.put(res, now); err != nil {
		i.failed[digest] = failure{reason: i.o.Redactor.String(sentence(err.Error())), at: now}
		i.o.Logger.Warn("image inventory not cached", "digest", digest, "err", err)
		return
	}
	delete(i.failed, digest)
	if _, ok := i.running[digest]; ok {
		i.completed[digest] = true
	}
	i.o.Logger.Debug("image inventory built", "digest", digest, "packages", len(res.Packages), "truncated", res.Truncated, "duration", now.Sub(begin))
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
