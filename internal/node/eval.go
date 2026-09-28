package node

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/logs"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const evidenceSource = "log"

func (a *Agent) evalLoop(ctx context.Context) {
	t := time.NewTicker(a.t.EvalTick)
	defer t.Stop()
	for {
		a.cycle(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// cycle switches a staged bundle, evaluates due rules, and turns results into queue items.
func (a *Agent) cycle(ctx context.Context) {
	a.applyPending()
	if a.caps[capLogs] {
		a.cov.checkLogsRoot(a.cfg.Node.LogsPath)
	}
	now := a.clock()
	a.events, a.parts = a.events[:0], a.parts[:0]
	if err := a.eng.Evaluate(ctx, now); err != nil && ctx.Err() == nil {
		a.log.Warn("rule evaluation", "err", err)
	}
	for _, p := range a.parts {
		a.enqueuePart(p)
	}
	a.events = append(a.events, a.steadyUpdates(now)...)
	a.handleEvents(now)
	a.trackFiring()
	if _, err := a.tracker.Flush(a.emitFinding); err != nil {
		a.log.Warn("finding updates not queued", "err", err)
	}
	a.cov.markEvaluated()
}

func (a *Agent) enqueuePart(p engine.Part) {
	wp, err := nodeapi.PartFromEngine(p)
	if err != nil {
		a.log.Warn("cluster rule part not pushed", "rule", p.RuleID, "err", err)
		return
	}
	_ = a.enqueue(nodeapi.Item{Kind: nodeapi.KindSeries, Part: &wp})
}

func (a *Agent) handleEvents(now time.Time) {
	byRule := map[string][]int{}
	for i, ev := range a.events {
		if ev.Class == bundle.ClassLogQL && (ev.Transition == engine.TransitionFiring || ev.Transition == engine.TransitionUpdate) {
			byRule[ev.RuleID] = append(byRule[ev.RuleID], i)
		}
	}
	ev := map[int][]protocol.Evidence{}
	lost := map[string]bool{}
	for rule, idx := range byRule {
		samples, l := a.ring.Take(rule, math.MaxInt32)
		lost[rule] = l
		maxN := a.evidenceCap(rule)
		var left []evidence.Sample
		for i := len(samples) - 1; i >= 0; i-- {
			s := samples[i]
			owner := -1
			for _, j := range idx {
				if consistent(a.events[j].Labels, s.Labels) {
					owner = j
					break
				}
			}
			switch {
			case owner < 0:
				left = append(left, s)
			case len(ev[owner]) < maxN:
				ev[owner] = append(ev[owner], protocol.Evidence{Source: evidenceSource, Time: uint64(s.Time.UnixMilli()), Text: s.Text, Count: 1, Labels: s.Labels})
			}
		}
		for i := len(left) - 1; i >= 0; i-- {
			a.ring.Add(rule, left[i])
		}
	}
	for i, e := range a.events {
		o, ok := a.observation(e, now)
		if !ok {
			continue
		}
		if e.Class == bundle.ClassLogQL {
			o.Evidence = ev[i]
			if lost[e.RuleID] || a.ring.Limited(e.RuleID) {
				o.Flags |= protocol.FindingEvidenceLimited
			}
		}
		if _, err := a.tracker.Observe(o, a.emitFinding); err != nil {
			a.log.Warn("finding not recorded", "rule", e.RuleID, "transition", e.Transition, "err", err)
		}
	}
}

// steadyUpdates re-observes firing LogQL instances that gained evidence since the last cycle, because the
// engine emits no event while an instance fires unchanged (PRD 5.3: repeated matches update counts and samples).
func (a *Agent) steadyUpdates(now time.Time) []engine.AlertEvent {
	seen := map[string]bool{}
	for _, e := range a.events {
		seen[e.RuleID+"\x00"+e.InstanceKey] = true
	}
	var out []engine.AlertEvent
	for k, e := range a.firing {
		if seen[k] || len(a.ring.Peek(e.RuleID, 1)) == 0 {
			continue
		}
		e.Transition, e.EvalTime = engine.TransitionUpdate, now
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID+out[i].InstanceKey < out[j].RuleID+out[j].InstanceKey })
	return out
}

func (a *Agent) trackFiring() {
	if a.firing == nil {
		a.firing = map[string]engine.AlertEvent{}
	}
	for _, e := range a.events {
		if e.Class != bundle.ClassLogQL {
			continue
		}
		k := e.RuleID + "\x00" + e.InstanceKey
		switch e.Transition {
		case engine.TransitionFiring, engine.TransitionUpdate:
			a.firing[k] = e
		default:
			delete(a.firing, k)
		}
	}
	for k, e := range a.firing {
		if _, ok := a.rules.meta[e.RuleID]; !ok {
			delete(a.firing, k)
		}
	}
}

// consistent reports whether a stream's labels agree with every label the alert shares with it.
func consistent(alert, stream map[string]string) bool {
	for k, v := range stream {
		if av, ok := alert[k]; ok && av != v {
			return false
		}
	}
	return true
}

func (a *Agent) evidenceCap(rule string) int {
	if m, ok := a.rules.meta[rule]; ok && m.Evidence.MaxSamples > 0 {
		return m.Evidence.MaxSamples
	}
	return findings.DefaultMaxSamples
}

func (a *Agent) observation(e engine.AlertEvent, now time.Time) (findings.Observation, bool) {
	o := findings.Observation{
		RuleID: e.RuleID, RuleVersion: uint64(max(e.RuleVersion, 0)), BundleVersion: e.BundleVersion,
		Labels: e.Labels, Category: e.Category, Severity: protocol.ParseSeverity(e.Severity), EvalTime: e.EvalTime,
		Resources: e.ResourceUIDs, Node: a.node, Summary: e.Summary,
	}
	if o.EvalTime.IsZero() {
		o.EvalTime = now
	}
	if m, ok := a.rules.meta[e.RuleID]; ok {
		o.DedupLabels = m.DedupLabels()
		o.MaxSamples, o.MaxBytes = m.Evidence.MaxSamples, m.Evidence.MaxBytes
	}
	if e.Incomplete {
		o.Flags |= protocol.FindingIncompleteCoverage
		o.Coverage = []string{"node " + a.node + ": " + a.engineCoverage().String()}
	}
	switch e.Transition {
	case engine.TransitionFiring, engine.TransitionUpdate:
		o.Kind = findings.Firing
	case engine.TransitionResolved:
		o.Kind = findings.Resolved
	case engine.TransitionStale:
		o.Kind = findings.Stale
	default:
		return o, false
	}
	return o, true
}

func (a *Agent) emitFinding(f protocol.Finding) (uint64, error) {
	b, err := protocol.EncodeFinding(&f)
	if err != nil {
		return 0, err
	}
	return a.enqueueErr(nodeapi.Item{Kind: nodeapi.KindFinding, Finding: b})
}

// onLine feeds one tailed line to every program selecting its stream; only matched lines are kept, redacted.
func (a *Agent) onLine(l logs.Line) {
	set := a.logsSet.cur.Load()
	if set == nil {
		return
	}
	var text string
	for _, lr := range set.rules {
		if len(lr.ids) == 0 || !lr.prog.Observe(l.Labels, l.Time, l.Text) {
			continue
		}
		if text == "" {
			text = a.red.String(l.Text)
		}
		for _, id := range lr.ids {
			a.ring.Add(id, evidence.Sample{Time: l.Time, Labels: l.Labels, Text: text})
		}
	}
}

func (a *Agent) onLogEvent(e logs.Event) {
	a.cov.logGap(e)
	a.log.Info("log input gap", "kind", string(e.Kind), "path", e.Path, "lost_bytes", e.LostBytes)
}

// engineCoverage is the local telemetry completeness node-local rules evaluate over.
func (a *Agent) engineCoverage() engine.Coverage {
	if a.warming() {
		return engine.CoverageWarming
	}
	if a.caps[capMetrics] && (a.kubeletDown() || a.gate.paused.Load()) {
		return engine.CoverageUncovered
	}
	if a.caps[capLogs] && a.cov.logsUnavailable() != "" {
		return engine.CoverageUncovered
	}
	return engine.CoverageCovered
}

// warming covers the first kubelet scrape and the rule windows after start: every window on fresh state, LogQL counter windows after a restart.
func (a *Agent) warming() bool {
	if a.caps[capMetrics] && !a.kubeletScraped() {
		return true
	}
	return a.clock().Sub(a.startTime) < a.warmupWindow()
}

func (a *Agent) warmupWindow() time.Duration {
	a.cov.mu.Lock()
	defer a.cov.mu.Unlock()
	if a.fresh {
		return a.cov.warmup
	}
	return a.cov.logWarmup
}

func (a *Agent) enqueue(it nodeapi.Item) error {
	_, err := a.enqueueErr(it)
	return err
}

// enqueueErr validates and appends an item; a full queue is counted and never blocks evaluation.
func (a *Agent) enqueueErr(it nodeapi.Item) (uint64, error) {
	a.deliv.appendMu.Lock()
	defer a.deliv.appendMu.Unlock()
	it.Seq = max(a.queue.Usage().Next, 1)
	b, err := nodeapi.Marshal(it)
	if err != nil {
		a.deliv.count(&a.deliv.invalid)
		a.log.Warn("queue item rejected before queueing", "kind", string(it.Kind), "err", err)
		return 0, err
	}
	seq, err := a.queue.Append(b)
	if err != nil {
		a.deliv.drop(it.Kind)
		if a.deliv.shouldLogDrop(a.clock()) {
			a.log.Warn("queue item dropped", "kind", string(it.Kind), "err", err, "usage", a.queue.Usage().Bytes)
		}
		return 0, err
	}
	a.signal(a.deliv.notify)
	return seq, nil
}
