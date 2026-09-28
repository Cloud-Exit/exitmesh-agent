package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/disk"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/metricfacts"
)

const maxFactsPerItem = 256

// factState remembers the last sent summary and pod UID per resource so only threshold changes and new pods are emitted.
type factState struct {
	mu      sync.Mutex
	store   kv.Store
	last    map[string]map[string]any
	lastUID map[string]string
	th      metricfacts.Thresholds
}

const factUIDPrefix = "uid/"

func (f *factState) load(s kv.Store) error {
	f.store, f.last, f.lastUID, f.th = s, map[string]map[string]any{}, map[string]string{}, metricfacts.DefaultThresholds()
	return s.ForEach("", func(k string, v []byte) error {
		if key, ok := strings.CutPrefix(k, factUIDPrefix); ok {
			f.lastUID[key] = string(v)
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal(v, &m); err != nil {
			return fmt.Errorf("node: metric facts state %s: %w", k, err)
		}
		f.last[k] = m
		return nil
	})
}

func (a *Agent) factsLoop(ctx context.Context) {
	for sleepCtx(ctx, a.t.Facts) {
		if err := a.emitFacts(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("metric facts", "err", err)
		}
	}
}

// emitFacts computes the interval's facts and queues those that moved past the thresholds.
func (a *Agent) emitFacts(ctx context.Context) error {
	facts, err := metricfacts.Compute(ctx, a.query, a.prom, a.clock(), a.t.Facts)
	if err != nil {
		return err
	}
	a.facts.mu.Lock()
	defer a.facts.mu.Unlock()
	var changed []metricfacts.Fact
	for _, f := range facts {
		if f.Pod != "" {
			uid, ok := a.pods.resolve(state.KindPod, f.Namespace, f.Pod)
			if !ok {
				continue
			}
			f.UID = uid
		}
		if f.UID != a.facts.lastUID[f.Key()] || a.facts.th.Changed(a.facts.last[f.Key()], f.Fields) {
			changed = append(changed, f)
		}
	}
	for len(changed) > 0 {
		n := min(len(changed), maxFactsPerItem)
		batch := changed[:n]
		changed = changed[n:]
		if err := a.enqueue(nodeapi.Item{Kind: nodeapi.KindMetricFacts, Facts: batch}); err != nil {
			return err
		}
		ops := map[string][]byte{}
		for _, f := range batch {
			b, err := json.Marshal(f.Fields)
			if err != nil {
				return err
			}
			ops[f.Key()] = b
			a.facts.last[f.Key()] = f.Fields
			if f.UID != "" {
				ops[factUIDPrefix+f.Key()] = []byte(f.UID)
				a.facts.lastUID[f.Key()] = f.UID
			}
		}
		if err := a.facts.store.Batch(ops); err != nil {
			return fmt.Errorf("persist metric facts state: %w", err)
		}
	}
	return nil
}

func (a *Agent) diskLoop(ctx context.Context) {
	pressured := false
	a.budget.Run(ctx, a.t.DiskCheck, func(r disk.Report, err error) {
		if err != nil && ctx.Err() == nil {
			a.log.Warn("disk budget check", "err", err)
		}
		a.gate.paused.Store(r.Pressure)
		if r.Pressure != pressured {
			pressured = r.Pressure
			lvl := slog.LevelInfo
			if r.Pressure {
				lvl = slog.LevelWarn
			}
			a.log.Log(ctx, lvl, "disk cap pressure changed", "pressure", r.Pressure, "used", r.Effective, "cap", r.Cap, "tsdb", r.TSDB, "freed", r.Freed)
		}
	})
}
