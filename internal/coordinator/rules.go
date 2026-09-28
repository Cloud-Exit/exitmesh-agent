package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/findings"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Reserved rule identity of the coordinator's own findings.
const (
	RuleSpoolPressure  = "agent.spool_pressure"
	CategoryAgent      = "agent"
	NoBundle           = "none"
	pressureUsage      = 0.80
	pressureWindow     = 24 * time.Hour
	recoveredUsage     = 0.70
	recoveredWindow    = 30 * time.Hour
	kubeSource         = "kube"
	incompleteCoverage = "incomplete: not every contributing node agent was covered on the active bundle version"
)

func (c *Coordinator) onAlert(ev engine.AlertEvent) {
	c.evMu.Lock()
	c.events = append(c.events, ev)
	c.evMu.Unlock()
}

func (c *Coordinator) evalLoop(ctx context.Context) {
	tick := time.NewTicker(c.t.EvalInterval)
	defer tick.Stop()
	for {
		c.evaluate(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (c *Coordinator) evaluate(ctx context.Context) {
	now := c.now()
	c.refreshKube(now)
	if err := c.eng.Evaluate(ctx, now); err != nil {
		c.log.Warn("rule evaluation", "err", err)
		c.setErr("rules", err)
	} else {
		c.setErr("rules", nil)
	}
	c.recordEvents()
	c.flushFindings()
}

func (c *Coordinator) observation(ev engine.AlertEvent) (findings.Observation, bool) {
	o := findings.Observation{
		RuleID: ev.RuleID, RuleVersion: uint64(max(ev.RuleVersion, 0)), BundleVersion: ev.BundleVersion, Labels: ev.Labels,
		Category: ev.Category, Severity: protocol.ParseSeverity(ev.Severity), EvalTime: ev.EvalTime, Resources: ev.ResourceUIDs,
		Summary: ev.Summary,
	}
	switch ev.Transition {
	case engine.TransitionFiring, engine.TransitionUpdate:
		o.Kind = findings.Firing
	case engine.TransitionResolved:
		o.Kind = findings.Resolved
	case engine.TransitionStale:
		o.Kind = findings.Stale
	default:
		return o, false
	}
	if !math.IsNaN(ev.Value) && !math.IsInf(ev.Value, 0) {
		o.Facts = map[string]any{"value": ev.Value}
	}
	if m, ok := c.bundles.meta(ev.RuleID); ok {
		o.DedupLabels = m.DedupLabels()
		o.MaxSamples, o.MaxBytes = m.Evidence.MaxSamples, m.Evidence.MaxBytes
	}
	if ev.Incomplete {
		o.Coverage = []string{incompleteCoverage}
	}
	if o.Severity == 0 {
		o.Severity = protocol.SeverityMedium
	}
	return o, true
}

// recordEvents turns engine alert events into finding records; observations that could not be spooled are retried in order.
func (c *Coordinator) recordEvents() {
	c.evMu.Lock()
	evs := c.events
	c.events = nil
	obs := c.pendObs
	c.pendObs = nil
	c.evMu.Unlock()
	for _, ev := range evs {
		if o, ok := c.observation(ev); ok {
			obs = append(obs, o)
		}
	}
	if len(obs) == 0 {
		return
	}
	for i, o := range obs {
		err := c.do(func(t *txn) error {
			_, err := c.fnd.Observe(o, t.emitFinding)
			return err
		})
		if err != nil {
			c.appendFailed(err)
			c.evMu.Lock()
			c.pendObs = append(obs[i:len(obs):len(obs)], c.pendObs...)
			c.evMu.Unlock()
			return
		}
	}
	c.poke()
}

func (c *Coordinator) flushFindings() {
	if err := c.do(func(t *txn) error {
		_, err := c.fnd.Flush(t.emitFinding)
		return err
	}); err != nil && !errors.Is(err, errNotReady) {
		c.appendFailed(err)
	}
}

// checkPressure raises or resolves the spool pressure finding on the cluster itself (PRD S13).
func (c *Coordinator) checkPressure() {
	u := c.sp.Usage()
	ratio := 0.0
	if u.Capacity > 0 {
		ratio = float64(u.Bytes) / float64(u.Capacity)
	}
	// The rate estimate is noisy right after start, when the opening checkpoint dominates it.
	rated := c.now().Sub(c.startedAt) >= c.t.PressureWarmup
	c.evMu.Lock()
	was := c.pressure
	c.evMu.Unlock()
	pressured := ratio > pressureUsage || rated && u.ProjectedWindow < pressureWindow
	if was && !pressured {
		pressured = ratio >= recoveredUsage || rated && u.ProjectedWindow < recoveredWindow
	}
	if !pressured && !was {
		return
	}
	bv := c.bundles.version()
	if bv == "" {
		bv = NoBundle
	}
	window := u.ProjectedWindow.Seconds()
	if u.ProjectedWindow == time.Duration(math.MaxInt64) {
		window = -1
	}
	o := findings.Observation{
		Kind: findings.Firing, RuleID: RuleSpoolPressure, RuleVersion: 1, BundleVersion: bv, Category: CategoryAgent,
		Severity: protocol.SeverityHigh, EvalTime: c.now(),
		Facts:   map[string]any{"spool.bytes": u.Bytes, "spool.capacity": u.Capacity, "spool.usage_ratio": ratio, "spool.projected_window_seconds": window},
		Summary: fmt.Sprintf("Coordinator spool under pressure: %.0f%% of capacity used, projected outage window %s", ratio*100, windowText(u.ProjectedWindow)),
	}
	if !pressured {
		o.Kind, o.Summary = findings.Resolved, "Coordinator spool pressure recovered"
	}
	err := c.do(func(t *txn) error {
		_, err := c.fnd.Observe(o, t.emitFinding)
		return err
	})
	if err != nil {
		c.appendFailed(err)
		return
	}
	c.evMu.Lock()
	c.pressure = pressured
	c.evMu.Unlock()
}

func windowText(d time.Duration) string {
	if d == time.Duration(math.MaxInt64) {
		return "unbounded"
	}
	return d.Round(time.Minute).String()
}

func (c *Coordinator) housekeepLoop(ctx context.Context) {
	tick := time.NewTicker(c.t.HousekeepEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-c.kick:
		}
		c.housekeep()
	}
}

func (c *Coordinator) housekeep() {
	c.store.flush(false)
	c.resync()
	c.checkPressure()
	if c.airgap && c.rebaselineWanted() {
		if err := c.localRebaseline("spool capacity exceeded after full coalescing"); err != nil {
			c.log.Error("rebaseline", "err", err)
		}
	}
	c.maybeAnchor()
	if st := c.stateView(); st != nil {
		names := map[string]bool{}
		for _, r := range st.Resources {
			if r.Kind == state.KindNode {
				names[r.Name] = true
			}
		}
		c.nodes.prune(func(n string) bool { return names[n] })
		c.pruneNodeCursors(func(n string) bool { return names[n] })
	}
}

// findingResources resolves a node finding's affected resource from its labels; node agents only know their own pods.
func findingResources(labels map[string]string, ref *bundle.ResourceRef, resolve func(kind, ns, name string) (string, bool)) []string {
	if ref == nil || labels[ref.Name] == "" {
		return nil
	}
	ns := ""
	if ref.Namespace != "" {
		ns = labels[ref.Namespace]
	}
	if uid, ok := resolve(ref.Kind, ns, labels[ref.Name]); ok {
		return []string{uid}
	}
	return nil
}

// resolveResource maps alert labels to a resource UID in the chain head.
func (c *Coordinator) resolveResource(kind, namespace, name string) (string, bool) {
	st := c.stateView()
	if st == nil {
		return "", false
	}
	for uid, r := range st.Resources {
		if r.Name == name && r.Namespace == namespace && (r.Kind == kind || strings.HasSuffix(r.Kind, "/"+kind)) {
			return uid, true
		}
	}
	return "", false
}

type podRef struct{ node, uid string }

// lookupPod resolves a token's pod claim to its node from the chain head.
func (c *Coordinator) lookupPod(namespace, name string) (string, string, bool) {
	st := c.stateView()
	if st == nil {
		return "", "", false
	}
	c.headMu.Lock()
	idx, ver := c.podIdx, c.podVer
	c.headMu.Unlock()
	if idx == nil || ver != c.viewVersion() {
		idx = map[string]podRef{}
		for uid, r := range st.Resources {
			if r.Kind == state.KindPod {
				n, _ := r.Fields["nodeName"].(string)
				idx[r.Namespace+"/"+r.Name] = podRef{node: n, uid: uid}
			}
		}
		c.headMu.Lock()
		c.podIdx, c.podVer = idx, c.headVer
		c.headMu.Unlock()
	}
	p, ok := idx[namespace+"/"+name]
	return p.node, p.uid, ok
}

func (c *Coordinator) viewVersion() uint64 {
	c.headMu.Lock()
	defer c.headMu.Unlock()
	return c.headVer
}

// clusterCoverage reports whether every covered node contributes to cluster rules on the active version (PRD R5, M4).
func (c *Coordinator) clusterCoverage(ruleID string, _ int) engine.Coverage {
	active := c.eng.BundleVersion()
	cov := engine.CoverageCovered
	worse := func(v engine.Coverage) {
		if v > cov {
			cov = v
		}
	}
	for _, n := range c.nodes.list() {
		switch {
		case !n.Covered:
			worse(engine.CoverageUncovered)
		case n.BundleVersion != active || n.PartVersions[ruleID] != "" && n.PartVersions[ruleID] != active:
			worse(engine.CoverageConverging)
		case n.Warming:
			worse(engine.CoverageWarming)
		}
	}
	return cov
}

// kubeFeed synthesizes kube_* series from the chain head and tracks per-node revisions for node agents (PRD M7, M8).
type kubeFeed struct {
	now    func() time.Time
	mu     sync.Mutex
	stale  bool
	series []state.Series
	nodes  map[string]*nodeKube
}

type nodeKube struct {
	rev    uint64
	sum    [32]byte
	series []nodeapi.KubeSeries
	ch     chan struct{}
}

func newKubeFeed(now func() time.Time) *kubeFeed {
	return &kubeFeed{now: now, stale: true, nodes: map[string]*nodeKube{}}
}

func (k *kubeFeed) dirty() {
	k.mu.Lock()
	k.stale = true
	k.mu.Unlock()
}

// refreshKube restamps the kube_* series every cycle so lookback never ages them out, and recomputes them after state changes.
func (c *Coordinator) refreshKube(now time.Time) {
	k := c.kube
	k.mu.Lock()
	recompute := k.stale || k.series == nil
	k.stale = false
	k.mu.Unlock()
	st := c.stateView()
	if st == nil {
		return
	}
	series := state.KubeSeries(st, now.UnixMilli())
	c.mem.Replace(kubeSource, toEngineSeries(series))
	k.mu.Lock()
	defer k.mu.Unlock()
	k.series = series
	if recompute {
		for name, nk := range k.nodes {
			k.updateLocked(name, nk)
		}
	}
}

func toEngineSeries(in []state.Series) []engine.Series {
	out := make([]engine.Series, len(in))
	for i, s := range in {
		out[i] = engine.Series{Labels: s.Labels, Samples: []engine.Sample{{T: s.T, F: s.Value}}}
	}
	return out
}

func (k *kubeFeed) updateLocked(node string, nk *nodeKube) {
	sub := state.NodeScoped(k.series, node)
	ws := make([]nodeapi.KubeSeries, 0, len(sub))
	for _, s := range sub {
		ws = append(ws, nodeapi.KubeSeries{Labels: s.Labels.Map(), Value: s.Value})
	}
	sort.Slice(ws, func(i, j int) bool { return labelKey(ws[i].Labels) < labelKey(ws[j].Labels) })
	h := sha256.New()
	var buf [8]byte
	for _, s := range ws {
		h.Write([]byte(labelKey(s.Labels)))
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(s.Value))
		h.Write(buf[:])
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if nk.rev != 0 && sum == nk.sum {
		return
	}
	rev := uint64(k.now().UnixMilli())
	if rev <= nk.rev {
		rev = nk.rev + 1
	}
	nk.rev, nk.sum, nk.series = rev, sum, ws
	if nk.ch != nil {
		close(nk.ch)
	}
	nk.ch = make(chan struct{})
}

func labelKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte(0)
	}
	return b.String()
}

func (k *kubeFeed) get(node string) (nodeapi.KubeUpdate, <-chan struct{}) {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk := k.nodes[node]
	if nk == nil {
		nk = &nodeKube{}
		k.nodes[node] = nk
		if k.series != nil {
			k.updateLocked(node, nk)
		} else {
			nk.ch = make(chan struct{})
		}
	}
	return nodeapi.KubeUpdate{Revision: nk.rev, Series: nk.series}, nk.ch
}
