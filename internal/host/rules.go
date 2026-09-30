package host

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"

	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/hostfacts"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/logql"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/validators"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/evidence"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

type logProgram struct {
	p     *logql.Program
	rules []string
}

type ruleSet struct {
	mu          sync.Mutex
	exprRules   map[string][]string
	pending     []*logProgram
	active      []*logProgram
	meta        map[string]bundle.RuleMeta
	version     string
	unsupported map[string]string
	events      []engine.AlertEvent
	airgapSig   string
}

func (rs *ruleSet) programs() []*logProgram {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.active
}

func (h *Host) openRules() error {
	alerts, err := h.bucket("alerts")
	if err != nil {
		return err
	}
	fstore, err := h.bucket("findings")
	if err != nil {
		return err
	}
	h.ring = evidence.New(int64(h.cfg.Host.EvidenceRing))
	var q storage.Queryable
	if h.db != nil {
		q = h.db
	}
	pol := h.cfg.Policy
	h.eng, err = engine.NewEngine(engine.Options{
		Role: engine.RoleHost, Store: alerts, Clock: h.clk.Now, Sink: h.sink,
		CompileLogQL: h.compileLogQL, Queryable: q, StateSource: h.head.snapshot,
		ScopeMatch: hostScopeMatch, ResolveResource: h.resolveResource, Coverage: h.coverage,
		EvidenceLimited: h.ring.Limited, DefaultInterval: time.Minute,
		Policy: engine.Policy{
			MaxEvalTime: pol.MaxRuleEvalTime.D(), MaxSamples: pol.MaxRuleSamples, MaxSeries: pol.MaxRuleSeries,
			MaxCounterBytes: int(pol.MaxCounterBytes), DisabledRules: pol.DisabledRules, Capabilities: h.cfg.Capabilities,
		},
	})
	if err != nil {
		return fmt.Errorf("host: rule engine: %w", err)
	}
	h.tracker, err = findings.NewTracker(findings.Options{
		TargetID: h.sp.Identity().TargetID, Store: fstore, LateThreshold: pol.LateThreshold.D(),
		MaxBytes: int(pol.MaxEvidenceBytes), Redactor: h.red, Clock: h.clk.Now,
	})
	if err != nil {
		return fmt.Errorf("host: findings: %w", err)
	}
	return nil
}

func (h *Host) compileLogQL(expr string, b bundle.Budget) (engine.LogProgram, error) {
	p, err := logql.CompileRule(expr, b)
	if err != nil {
		return nil, err
	}
	h.rules.mu.Lock()
	h.rules.pending = append(h.rules.pending, &logProgram{p: p, rules: h.rules.exprRules[expr]})
	h.rules.mu.Unlock()
	return p, nil
}

func (h *Host) sink(ev engine.AlertEvent) {
	h.rules.mu.Lock()
	h.rules.events = append(h.rules.events, ev)
	h.rules.mu.Unlock()
}

// activate stages a verified bundle in the engine and switches log programs, evidence shares, and retention.
func (h *Host) activate(a *bundle.Active) error {
	b := a.Bundle.Only(a.Result.Active)
	exprRules := map[string][]string{}
	weights := map[string]float64{}
	meta := map[string]bundle.RuleMeta{}
	for _, r := range b.LogQL {
		exprRules[r.Expr] = append(exprRules[r.Expr], r.Meta.ID)
		weights[r.Meta.ID] = 1
		meta[r.Meta.ID] = r.Meta
	}
	for _, r := range b.PromQL {
		meta[r.Meta.ID] = r.Meta
	}
	for _, r := range b.State {
		meta[r.Meta.ID] = r.Meta
	}
	h.rules.mu.Lock()
	h.rules.pending, h.rules.exprRules = nil, exprRules
	h.rules.mu.Unlock()
	if err := h.eng.SetBundle(b, engine.BundleResult{Unsupported: a.Result.Unsupported}); err != nil {
		return err
	}
	h.rules.mu.Lock()
	h.rules.active, h.rules.pending = h.rules.pending, nil
	h.rules.meta, h.rules.version, h.rules.unsupported = meta, b.Manifest.Version, a.Result.Unsupported
	h.rules.mu.Unlock()
	h.ring.SetRules(weights)
	if h.files != nil {
		h.files.SetFilter(h.streamFilter)
	}
	if h.db != nil {
		if _, err := h.db.SetRetention(promRetention(b.PromQL)); err != nil {
			h.log.Warn("tsdb retention", "err", err)
		}
	}
	h.setErr(&h.st.bundleError, nil)
	h.log.Info("rule bundle active", "bundle_version", b.Manifest.Version, "key_id", a.KeyID, "rules", len(a.Result.Active), "unsupported", len(a.Result.Unsupported))
	return nil
}

func (h *Host) loadBundle() {
	h.bundleMu.Lock()
	defer h.bundleMu.Unlock()
	a, ok, err := h.bundles.LoadLastKnownGood(validators.For(bundle.TargetHost), h.cfg.Policy.Bundle(bundle.TargetHost))
	switch {
	case err != nil:
		h.setErr(&h.st.bundleError, fmt.Errorf("last known good bundle: %w", err))
	case ok:
		if err := h.activate(a); err != nil {
			h.setErr(&h.st.bundleError, err)
		}
	}
	if h.cfg.AirGap.Enabled {
		h.loadAirgapBundleLocked()
	}
}

// fetchBundle asks the control plane for the assigned bundle; a rejected bundle keeps the last known good.
func (h *Host) fetchBundle(ctx context.Context) {
	h.bundleMu.Lock()
	defer h.bundleMu.Unlock()
	have, _, err := h.bundles.Current()
	if err != nil {
		h.setErr(&h.st.bundleError, err)
		return
	}
	fctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	res, err := h.cl.FetchBundle(fctx, have)
	if err != nil {
		h.setErr(&h.st.bundleError, fmt.Errorf("bundle fetch: %w", err))
		return
	}
	if len(res.Bundle) == 0 || res.Version == have {
		return
	}
	a, err := h.bundles.ActivateFetch(*res, validators.For(bundle.TargetHost), h.cfg.Policy.Bundle(bundle.TargetHost))
	if err != nil {
		h.setErr(&h.st.bundleError, fmt.Errorf("bundle %s rejected, keeping %q: %w", res.Version, have, err))
		h.log.Warn("rule bundle rejected; last known good stays active", "version", res.Version, "err", err)
		return
	}
	if err := h.activate(a); err != nil {
		h.setErr(&h.st.bundleError, err)
	}
}

func (h *Host) loadAirgapBundle() {
	h.bundleMu.Lock()
	defer h.bundleMu.Unlock()
	h.loadAirgapBundleLocked()
}

// loadAirgapBundleLocked verifies airgap.bundleDir when its files change, exactly like tunnel delivery.
func (h *Host) loadAirgapBundleLocked() {
	dir := h.cfg.AirGap.BundleDir
	if dir == "" {
		return
	}
	sig := dirSignature(dir, bundle.FileArchive, bundle.FileSignature, bundle.FileKeyManifest, "keymanifests")
	if sig == h.rules.airgapSig {
		return
	}
	h.rules.airgapSig = sig
	archive, signature, err := h.verifier.VerifyFiles(dir)
	if err != nil {
		h.setErr(&h.st.bundleError, fmt.Errorf("air-gap bundle in %s: %w", dir, err))
		return
	}
	a, err := h.bundles.Activate(archive, signature, validators.For(bundle.TargetHost), h.cfg.Policy.Bundle(bundle.TargetHost))
	if err != nil {
		h.setErr(&h.st.bundleError, fmt.Errorf("air-gap bundle rejected, keeping the last known good: %w", err))
		return
	}
	h.rules.mu.Lock()
	same := h.rules.version == a.Bundle.Manifest.Version
	h.rules.mu.Unlock()
	if same {
		return
	}
	if err := h.activate(a); err != nil {
		h.setErr(&h.st.bundleError, err)
	}
}

func dirSignature(dir string, names ...string) string {
	sum := sha256.New()
	for _, n := range names {
		p := filepath.Join(dir, n)
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(sum, "%s:absent;", n)
			continue
		}
		fmt.Fprintf(sum, "%s:%d:%d;", n, fi.Size(), fi.ModTime().UnixNano())
		if fi.IsDir() {
			ents, _ := os.ReadDir(p)
			for _, e := range ents {
				if i, err := e.Info(); err == nil {
					fmt.Fprintf(sum, "%s/%s:%d:%d;", n, e.Name(), i.Size(), i.ModTime().UnixNano())
				}
			}
		}
	}
	return fmt.Sprintf("%x", sum.Sum(nil))
}

// evaluate runs one engine cycle and turns its alert events into finding records.
func (h *Host) evaluate(ctx context.Context, now time.Time) {
	if err := h.eng.Evaluate(ctx, now); err != nil {
		h.setErr(&h.st.evalError, err)
	} else {
		h.setErr(&h.st.evalError, nil)
	}
	h.rules.mu.Lock()
	evs := h.rules.events
	h.rules.events = nil
	h.rules.mu.Unlock()
	err := h.do(func(tx *hostTx) error {
		for _, ev := range evs {
			if _, err := h.tracker.Observe(h.observation(ev), tx.finding); err != nil {
				return err
			}
		}
		_, err := h.tracker.Flush(tx.finding)
		return err
	})
	if err != nil {
		h.setErr(&h.st.findingsError, err)
		h.log.Warn("findings not spooled", "events", len(evs), "err", err)
		return
	}
	h.setErr(&h.st.findingsError, nil)
}

func (h *Host) observation(ev engine.AlertEvent) findings.Observation {
	h.rules.mu.Lock()
	meta := h.rules.meta[ev.RuleID]
	h.rules.mu.Unlock()
	o := findings.Observation{
		Kind: findings.Firing, RuleID: ev.RuleID, RuleVersion: uint64(max(ev.RuleVersion, 0)), BundleVersion: ev.BundleVersion,
		DedupLabels: meta.DedupLabels(), Labels: ev.Labels, Category: ev.Category, Severity: protocol.ParseSeverity(ev.Severity),
		EvalTime: ev.EvalTime, Resources: ev.ResourceUIDs, Summary: ev.Summary, Facts: map[string]any{"value": ev.Value},
		MaxSamples: meta.Evidence.MaxSamples, MaxBytes: meta.Evidence.MaxBytes,
	}
	switch ev.Transition {
	case engine.TransitionResolved:
		o.Kind, o.Facts = findings.Resolved, nil
	case engine.TransitionStale:
		o.Kind, o.Facts = findings.Stale, nil
	}
	if ev.Incomplete {
		o.Coverage = []string{"incomplete"}
	}
	if o.Kind == findings.Firing && meta.Class == bundle.ClassLogQL {
		n := meta.Evidence.MaxSamples
		if n <= 0 {
			n = findings.DefaultMaxSamples
		}
		samples, lost := h.ring.Take(ev.RuleID, n)
		for i, s := range samples {
			o.Evidence = append(o.Evidence, protocol.Evidence{
				Source: evidenceSource(s.Labels), Time: uint64(s.Time.UnixMilli()), Text: s.Text, Count: 1,
				Labels: s.Labels, Truncated: lost && i == 0,
			})
		}
	}
	return o
}

func evidenceSource(l map[string]string) string {
	switch {
	case l["filename"] != "":
		return "file:" + l["filename"]
	case l["unit"] != "":
		return "journal:" + l["unit"]
	case l["syslog_identifier"] != "":
		return "journal:" + l["syslog_identifier"]
	}
	return "journal"
}

func hostScopeMatch(key, kind, _ string) bool {
	for _, e := range hostfacts.Catalog {
		if e.EdgeType == "" && e.Kind == kind && hostfacts.ScopeKey(e.ID) == key {
			return true
		}
	}
	return false
}

func (h *Host) resolveResource(kind, namespace, name string) (string, bool) {
	h.head.mu.Lock()
	defer h.head.mu.Unlock()
	for uid, r := range h.head.state.Resources {
		if r.Kind == kind && r.Name == name && r.Namespace == namespace {
			return uid, true
		}
	}
	return "", false
}

func (h *Host) coverage() engine.Coverage {
	if h.exporter == nil {
		return engine.CoverageCovered
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.st.lastGather.IsZero() {
		return engine.CoverageWarming
	}
	return engine.CoverageCovered
}

// promRetention keeps the longest range plus for, keep_firing_for, and one interval (PRD R11).
func promRetention(rules []bundle.AlertRule) time.Duration {
	need := tsdb.DefaultBlockDuration
	p := parser.NewParser(parser.Options{})
	for _, r := range rules {
		e, err := p.ParseExpr(r.Expr)
		if err != nil {
			continue
		}
		iv := r.GroupInterval
		if iv <= 0 {
			iv = time.Minute
		}
		if d := lookback(e) + r.For + r.KeepFiringFor + iv; d > need {
			need = d
		}
	}
	return tsdb.ClampRetention(need)
}

func lookback(n parser.Node) time.Duration {
	switch e := n.(type) {
	case *parser.MatrixSelector:
		d := e.Range
		if vs, ok := e.VectorSelector.(*parser.VectorSelector); ok {
			d += vs.OriginalOffset
		}
		return d
	case *parser.VectorSelector:
		return e.OriginalOffset + 5*time.Minute
	case *parser.SubqueryExpr:
		return e.Range + e.OriginalOffset + lookback(e.Expr)
	}
	var max time.Duration
	for c := range parser.ChildrenIter(n) {
		if d := lookback(c); d > max {
			max = d
		}
	}
	return max
}
