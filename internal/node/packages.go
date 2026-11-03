package node

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const (
	bucketInventory = "inventory"
	invKeyLast      = "last"
	invKeySent      = "sent"
)

// inventoryState remembers the last queued inventory so only changes, and a periodic refresh, are sent.
type inventoryState struct {
	mu    sync.Mutex
	col   *hostfacts.Collector
	store kv.Store
	last  string
	sent  time.Time
	cov   string
}

// hostCollectorOptions maps the package databases and os-release below a host root mount.
func hostCollectorOptions(root string) hostfacts.Options {
	rpm := make([]string, len(hostfacts.DefaultRPMPaths))
	for i, p := range hostfacts.DefaultRPMPaths {
		rpm[i] = filepath.Join(root, p)
	}
	return hostfacts.Options{
		EtcRoot:      filepath.Join(root, "etc"),
		UsrLibRoot:   filepath.Join(root, "usr/lib"),
		DpkgDir:      filepath.Join(root, "var/lib/dpkg"),
		RPMPaths:     rpm,
		APKInstalled: filepath.Join(root, "lib/apk/db/installed"),
	}
}

func (s *inventoryState) load(store kv.Store, col *hostfacts.Collector) error {
	s.store, s.col = store, col
	b, _, err := store.Get(invKeyLast)
	if err != nil {
		return fmt.Errorf("node: inventory state: %w", err)
	}
	s.last = string(b)
	if b, _, err = store.Get(invKeySent); err != nil {
		return fmt.Errorf("node: inventory state: %w", err)
	}
	if ms, err := strconv.ParseInt(string(b), 10, 64); err == nil {
		s.sent = time.UnixMilli(ms)
	}
	return nil
}

func (s *inventoryState) coverage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cov == "" {
		return coverageWarming
	}
	return s.cov
}

func (a *Agent) packagesLoop(ctx context.Context) {
	for {
		if err := a.emitInventory(); err != nil && ctx.Err() == nil {
			a.log.Warn("package inventory", "err", err)
		}
		if !sleepCtx(ctx, a.t.Packages) {
			return
		}
	}
}

// emitInventory queues the host package inventory when it changed or the last one is older than the refresh period.
func (a *Agent) emitInventory() error {
	s := &a.inv
	inv := s.col.Inventory()
	key := inv.Digest() + "|" + strconv.FormatUint(uint64(inv.State), 10) + "|" + inv.Reason
	now := a.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch inv.State {
	case protocol.ScopeComplete:
		s.cov = coverageAvailable
	case protocol.ScopePartial:
		s.cov = "incomplete: " + inv.Reason
	default:
		s.cov = "unavailable: " + inv.Reason
	}
	if key == s.last && now.Sub(s.sent) < a.t.PackagesRefresh {
		return nil
	}
	w := nodeapi.InventoryFrom(inv)
	if err := a.enqueue(nodeapi.Item{Kind: nodeapi.KindPackages, Inventory: &w}); err != nil {
		return err
	}
	if err := s.store.Batch(map[string][]byte{invKeyLast: []byte(key), invKeySent: []byte(strconv.FormatInt(now.UnixMilli(), 10))}); err != nil {
		return fmt.Errorf("persist inventory state: %w", err)
	}
	s.last, s.sent = key, now
	return nil
}

func (a *Agent) packagesEnabled() bool { return a.caps[config.CapPackages] }
