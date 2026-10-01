package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/metricfacts"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// NodeStatus is the coordinator's view of one node agent.
type NodeStatus struct {
	Name          string             `json:"name"`
	AgentVersion  string             `json:"agent_version"`
	BundleVersion string             `json:"bundle_version"`
	Capabilities  []string           `json:"capabilities,omitempty"`
	Coverage      map[string]string  `json:"coverage,omitempty"`
	Warming       bool               `json:"warming"`
	Queue         nodeapi.QueueUsage `json:"queue"`
	FirstSeen     time.Time          `json:"first_seen"`
	LastSeen      time.Time          `json:"last_seen"`
	LastSubmit    time.Time          `json:"last_submit,omitempty"`
	Covered       bool               `json:"covered"`
	// PartVersions is the bundle version of the latest part each cluster rule received from the node.
	PartVersions map[string]string `json:"part_versions,omitempty"`
	// FactsDropped counts pod metric facts not applied because the observed pod no longer exists on the node.
	FactsDropped uint64 `json:"facts_dropped,omitempty"`
	// Rules are the node's latest rule states other than plain active ones, most severe first, at most maxNodeRuleDetail.
	Rules []NodeRule `json:"rules,omitempty"`
	// RuleStates counts the node's rules per state.
	RuleStates map[string]int `json:"rule_states,omitempty"`
	// Process is the node agent's user and effective capabilities; UID 0 means the root fallback is in use.
	Process *nodeapi.Process `json:"process,omitempty"`

	rules []nodeapi.RuleStatus
}

// NodeRule is one node-local rule state as the node agent last registered it.
type NodeRule struct {
	ID              string    `json:"id"`
	Version         int       `json:"version"`
	State           string    `json:"state"`
	Reason          string    `json:"reason,omitempty"`
	LastEval        time.Time `json:"last_eval,omitempty"`
	BudgetLimited   bool      `json:"budget_limited,omitempty"`
	EvidenceLimited bool      `json:"evidence_limited,omitempty"`
}

// Health bounds for node rule states.
const (
	maxNodeRuleDetail = 64
	maxNodeRuleRollup = 2048
)

func (n *NodeStatus) setRules(rules []nodeapi.RuleStatus) {
	n.rules = append([]nodeapi.RuleStatus(nil), rules...)
	sort.SliceStable(n.rules, func(i, j int) bool {
		if ri, rj := nodeapi.RuleStateRank(n.rules[i].State), nodeapi.RuleStateRank(n.rules[j].State); ri != rj {
			return ri < rj
		}
		return n.rules[i].RuleID < n.rules[j].RuleID
	})
	n.Rules, n.RuleStates = nil, map[string]int{}
	for _, r := range n.rules {
		n.RuleStates[r.State]++
		if (r.State == engine.StateActive && !r.BudgetLimited && !r.EvidenceLimited) || len(n.Rules) >= maxNodeRuleDetail {
			continue
		}
		nr := NodeRule{ID: r.RuleID, Version: r.Version, State: r.State, Reason: r.Reason, BudgetLimited: r.BudgetLimited, EvidenceLimited: r.EvidenceLimited}
		if r.LastEvalMs > 0 {
			nr.LastEval = time.UnixMilli(r.LastEvalMs).UTC()
		}
		n.Rules = append(n.Rules, nr)
	}
}

// nodeRuleRollup counts the states one rule version has across covered node agents.
type nodeRuleRollup struct {
	ID              string         `json:"id"`
	Version         int            `json:"version"`
	Nodes           int            `json:"nodes"`
	States          map[string]int `json:"states"`
	BudgetLimited   int            `json:"budget_limited,omitempty"`
	EvidenceLimited int            `json:"evidence_limited,omitempty"`
}

func rollupNodeRules(nodes []NodeStatus) (out []nodeRuleRollup, truncated int) {
	type key struct {
		id      string
		version int
	}
	by := map[key]*nodeRuleRollup{}
	for _, n := range nodes {
		if !n.Covered {
			continue
		}
		for _, r := range n.rules {
			k := key{r.RuleID, r.Version}
			x := by[k]
			if x == nil {
				x = &nodeRuleRollup{ID: r.RuleID, Version: r.Version, States: map[string]int{}}
				by[k] = x
			}
			x.Nodes++
			x.States[r.State]++
			if r.BudgetLimited {
				x.BudgetLimited++
			}
			if r.EvidenceLimited {
				x.EvidenceLimited++
			}
		}
	}
	for _, x := range by {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Version < out[j].Version
	})
	if len(out) > maxNodeRuleRollup {
		truncated = len(out) - maxNodeRuleRollup
		out = out[:maxNodeRuleRollup]
	}
	return out, truncated
}

type registry struct {
	now     func() time.Time
	timeout time.Duration
	mu      sync.Mutex
	nodes   map[string]*NodeStatus
}

func newRegistry(now func() time.Time, timeout time.Duration) *registry {
	return &registry{now: now, timeout: timeout, nodes: map[string]*NodeStatus{}}
}

func (r *registry) touch(node string, fn func(n *NodeStatus)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.nodes[node]
	now := r.now()
	if n == nil {
		n = &NodeStatus{Name: node, FirstSeen: now, PartVersions: map[string]string{}}
		r.nodes[node] = n
	}
	if fn != nil {
		fn(n)
	}
	n.LastSeen = now
}

func (r *registry) list() []NodeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]NodeStatus, 0, len(r.nodes))
	for _, n := range r.nodes {
		cp := *n
		cp.Covered = now.Sub(n.LastSeen) <= r.timeout
		cp.PartVersions = make(map[string]string, len(n.PartVersions))
		for k, v := range n.PartVersions {
			cp.PartVersions[k] = v
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// prune forgets nodes that are uncovered and no longer exist in the cluster state.
func (r *registry) prune(exists func(string) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for name, n := range r.nodes {
		if now.Sub(n.LastSeen) > r.timeout && !exists(name) {
			delete(r.nodes, name)
		}
	}
}

type nodeBackend struct{ c *Coordinator }

func (b nodeBackend) Register(ctx context.Context, node string, req nodeapi.RegisterRequest) (nodeapi.RegisterResponse, error) {
	c := b.c
	level := slog.LevelDebug
	c.nodes.touch(node, func(n *NodeStatus) {
		if n.AgentVersion != req.AgentVersion || n.BundleVersion != req.BundleVersion || n.Warming != req.Warming ||
			!slices.Equal(n.Capabilities, req.Capabilities) || !maps.Equal(n.Coverage, req.Coverage) || !sameProcess(n.Process, req.Process) ||
			c.now().Sub(n.LastSeen) > c.nodes.timeout {
			level = slog.LevelInfo
		}
		n.AgentVersion, n.BundleVersion, n.Warming, n.Queue = req.AgentVersion, req.BundleVersion, req.Warming, req.QueueUsage
		n.Capabilities = append([]string(nil), req.Capabilities...)
		n.Coverage = map[string]string{}
		for k, v := range req.Coverage {
			n.Coverage[k] = v
		}
		n.setRules(req.Rules)
		n.Process = nil
		if p := req.Process; p != nil {
			n.Process = &nodeapi.Process{UID: p.UID, GID: p.GID, Capabilities: append([]string{}, p.Capabilities...)}
		}
	})
	// Nodes re-register as a heartbeat; only a new, returning, or changed node is worth an info line.
	c.log.Log(ctx, level, "node agent registered", "node", node, "version", req.AgentVersion, "bundle", req.BundleVersion, "warming", req.Warming)
	return nodeapi.RegisterResponse{TargetBundle: c.bundles.version()}, nil
}

func sameProcess(a, b *nodeapi.Process) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.UID == b.UID && a.GID == b.GID && slices.Equal(a.Capabilities, b.Capabilities)
}

// cursorKey names the idempotency cursor of one node queue; agents that predate queue identities share one per node.
func cursorKey(node, queue string) string {
	if queue == "" {
		return "node/" + node
	}
	return "node/" + node + "/" + queue
}

// staleCursors lists the cursors of the node's other queues, which a queue identity replaces for good.
func (c *Coordinator) staleCursors(node, queue string) []string {
	if queue == "" {
		return nil
	}
	var out []string
	for k := range c.sp.Cursors(cursorKey(node, "") + "/") {
		if k != cursorKey(node, queue) {
			out = append(out, k)
		}
	}
	if c.sp.Cursor(cursorKey(node, "")) != 0 {
		out = append(out, cursorKey(node, ""))
	}
	sort.Strings(out)
	return out
}

// pruneNodeCursors drops the cursors of nodes that stayed uncovered past the node timeout and left the cluster state.
func (c *Coordinator) pruneNodeCursors(exists func(string) bool) {
	if c.now().Sub(c.startedAt) <= c.t.NodeTimeout {
		return
	}
	covered := map[string]bool{}
	for _, n := range c.nodes.list() {
		covered[n.Name] = n.Covered
	}
	c.sinkMu.Lock()
	defer c.sinkMu.Unlock()
	var drop []string
	for k := range c.sp.Cursors("node/") {
		name, _, _ := strings.Cut(strings.TrimPrefix(k, "node/"), "/")
		if !covered[name] && !exists(name) {
			drop = append(drop, k)
		}
	}
	if len(drop) == 0 {
		return
	}
	err := c.do(func(t *txn) error {
		for _, k := range drop {
			t.tx.DeleteCursor(k)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errNotReady) {
		c.log.Warn("pruning cursors of removed nodes", "err", err)
	}
}

// Submit spools node findings and metric facts before acknowledging them; the cursor per node queue makes retries idempotent (PRD S12).
func (b nodeBackend) Submit(_ context.Context, node, queue string, items []nodeapi.Item) (uint64, error) {
	c := b.c
	c.nodes.touch(node, func(n *NodeStatus) { n.LastSubmit = c.now() })
	if c.headState() == nil {
		return 0, errNotReady
	}
	c.sinkMu.Lock()
	defer c.sinkMu.Unlock()
	if c.observed != nil {
		c.resyncLocked()
		if c.observed != nil {
			return 0, errors.New("coordinator: spool is not accepting records")
		}
	}
	key := cursorKey(node, queue)
	cur := c.sp.Cursor(key)
	stale := c.staleCursors(node, queue)
	var acked uint64
	var parts []nodeapi.Item
	err := c.do(func(t *txn) error {
		for _, k := range stale {
			t.tx.DeleteCursor(k)
		}
		for _, it := range items {
			acked = it.Seq
			if it.Seq <= cur {
				continue
			}
			switch it.Kind {
			case nodeapi.KindFinding:
				f, err := protocol.DecodeFinding(it.Finding)
				if err != nil {
					return fmt.Errorf("%w: finding %d: %w", nodeapi.ErrInvalid, it.Seq, err)
				}
				if f.Node == "" {
					f.Node = node
				}
				if len(f.Resources) == 0 && f.Provenance.Kind == protocol.ProvenanceRule {
					if m, ok := c.bundles.meta(f.Provenance.RuleID); ok {
						f.Resources = findingResources(f.Labels, m.ResourceLabels, c.resolveResource)
					}
				}
				seq, err := t.emit(*f, spool.WithCursor(key, it.Seq))
				if err != nil {
					return err
				}
				fc := *f
				t.after = append(t.after, func() { c.nfi.record(fc, seq) })
				cur = it.Seq
			case nodeapi.KindMetricFacts:
				ops := c.factOps(t, node, it.Facts)
				if len(ops) > 0 {
					if err := t.delta(ops, protocol.FlagMetricFacts, nil, spool.WithCursor(key, it.Seq)); err != nil {
						return err
					}
					t.noteView(ops)
					cur = it.Seq
				}
			case nodeapi.KindSeries:
				parts = append(parts, it)
			}
		}
		return nil
	})
	if err != nil {
		c.appendFailed(err)
		return 0, err
	}
	for _, it := range parts {
		c.storePart(node, it.Part.Engine())
	}
	c.poke()
	return acked, nil
}

// noteView records metric fact changes so later facts in the same batch compare against them.
func (t *txn) noteView(ops []protocol.Op) {
	if t.view == nil {
		t.view = map[string]map[string]any{}
	}
	for _, op := range ops {
		m := t.view[op.UID]
		if m == nil {
			m = map[string]any{}
			t.view[op.UID] = m
		}
		for k, v := range op.Fields {
			m[k] = v
		}
	}
}

func isMetricField(k string) bool {
	return strings.HasPrefix(k, "metric.") || strings.Contains(k, ".metric.")
}

// factOps turns metric facts into metric.* field updates on the node's pods and on the node itself when thresholds say changed.
func (c *Coordinator) factOps(t *txn, node string, facts []metricfacts.Fact) []protocol.Op {
	st := c.headState()
	pods, nodes := map[string][]string{}, map[string]string{}
	for uid, r := range st.Resources {
		switch r.Kind {
		case state.KindPod:
			if n, _ := r.Fields["nodeName"].(string); n == node {
				pods[r.Namespace+"/"+r.Name] = append(pods[r.Namespace+"/"+r.Name], uid)
			}
		case state.KindNode:
			nodes[r.Name] = uid
		}
	}
	var dropped uint64
	changes := map[string]map[string]any{}
	for _, f := range facts {
		var uid, prefix string
		switch {
		case f.Pod != "":
			uid = podFor(st, pods, node, f)
			if uid == "" {
				dropped++
				continue
			}
			if f.Container != "" {
				prefix = "containers." + f.Container + "."
			}
		case f.Node == node:
			uid = nodes[node]
		}
		if uid == "" {
			continue
		}
		fields, err := protocol.NormalizeFields(f.Fields, false)
		if err != nil {
			continue
		}
		prev, cur := map[string]any{}, map[string]any{}
		for k, v := range fields {
			if strings.HasPrefix(k, "metric.") {
				cur[prefix+k] = v
			}
		}
		res := st.Resources[uid]
		for k, v := range res.Fields {
			if isMetricField(k) && strings.HasPrefix(k, prefix+"metric.") && !strings.Contains(strings.TrimPrefix(k, prefix), ".metric.") {
				prev[k] = v
			}
		}
		if tv := t.view[uid]; tv != nil {
			for k, v := range tv {
				if strings.HasPrefix(k, prefix+"metric.") {
					if v == nil {
						delete(prev, k)
					} else {
						prev[k] = v
					}
				}
			}
		}
		if !metricfacts.DefaultThresholds().Changed(prev, cur) {
			continue
		}
		ch := protocol.FieldChanges(prev, cur)
		if len(ch) == 0 {
			continue
		}
		if changes[uid] == nil {
			changes[uid] = map[string]any{}
		}
		for k, v := range ch {
			changes[uid][k] = v
		}
	}
	if dropped > 0 {
		t.after = append(t.after, func() { c.nodes.touch(node, func(n *NodeStatus) { n.FactsDropped += dropped }) })
	}
	ops := make([]protocol.Op, 0, len(changes))
	for uid, ch := range changes {
		ops = append(ops, protocol.Update(uid, ch))
	}
	protocol.SortOps(ops)
	return ops
}

// podFor resolves a pod fact to the observed live pod of the node, by name only for agents without UIDs; "" when it is gone.
func podFor(st *protocol.State, pods map[string][]string, node string, f metricfacts.Fact) string {
	if f.UID == "" {
		if uids := pods[f.Namespace+"/"+f.Pod]; len(uids) == 1 {
			return uids[0]
		}
		return ""
	}
	r := st.Resources[f.UID]
	if r == nil || r.Kind != state.KindPod || r.Namespace != f.Namespace || r.Name != f.Pod {
		return ""
	}
	if n, _ := r.Fields["nodeName"].(string); n != node {
		return ""
	}
	return f.UID
}

// storePart keeps a node's part for a cluster rule only when it was evaluated under the active bundle (PRD R5).
func (c *Coordinator) storePart(node string, p engine.Part) {
	src := "part/" + node + "/" + p.RuleID
	c.nodes.touch(node, func(n *NodeStatus) { n.PartVersions[p.RuleID] = p.BundleVersion })
	if p.BundleVersion != c.eng.BundleVersion() {
		c.mem.Replace(src, nil)
		return
	}
	c.mem.Replace(src, engine.PartSeries(node, p))
}

func (b nodeBackend) Bundle(_ context.Context, node, have string) (*nodeapi.BundlePayload, <-chan struct{}, error) {
	b.c.nodes.touch(node, func(n *NodeStatus) {
		if have != "" {
			n.BundleVersion = have
		}
	})
	_, p, ch := b.c.bundles.current()
	if p == nil || p.Version == have {
		return nil, ch, nil
	}
	return p, ch, nil
}

func (b nodeBackend) Kube(_ context.Context, node string, since uint64) (nodeapi.KubeUpdate, <-chan struct{}, error) {
	b.c.nodes.touch(node, nil)
	u, ch := b.c.kube.get(node)
	if u.Revision <= since {
		return nodeapi.KubeUpdate{Revision: u.Revision}, ch, nil
	}
	return u, ch, nil
}

func (b nodeBackend) Tasks(_ context.Context, node string) ([]nodeapi.Task, <-chan struct{}, error) {
	b.c.nodes.touch(node, nil)
	ts, ch := b.c.tasks.take(node)
	return ts, ch, nil
}

func (b nodeBackend) TaskResult(_ context.Context, node string, res nodeapi.TaskResult) error {
	b.c.nodes.touch(node, nil)
	return b.c.tasks.deliver(node, res)
}

// taskQueue hands investigation tasks to node agents and waits for their results.
type taskQueue struct {
	mu      sync.Mutex
	pending map[string][]nodeapi.Task
	wake    map[string]chan struct{}
	waiters map[string]*taskWaiter
}

type taskWaiter struct {
	node string
	ch   chan nodeapi.TaskResult
}

func newTaskQueue() *taskQueue {
	return &taskQueue{pending: map[string][]nodeapi.Task{}, wake: map[string]chan struct{}{}, waiters: map[string]*taskWaiter{}}
}

func (q *taskQueue) wakeLocked(node string) chan struct{} {
	ch := q.wake[node]
	if ch == nil {
		ch = make(chan struct{})
		q.wake[node] = ch
	}
	return ch
}

func (q *taskQueue) take(node string) ([]nodeapi.Task, <-chan struct{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	ts := q.pending[node]
	delete(q.pending, node)
	return ts, q.wakeLocked(node)
}

func (q *taskQueue) deliver(node string, res nodeapi.TaskResult) error {
	q.mu.Lock()
	w := q.waiters[res.ID]
	if w == nil || w.node != node {
		q.mu.Unlock()
		return nodeapi.ErrUnknownTask
	}
	delete(q.waiters, res.ID)
	q.mu.Unlock()
	w.ch <- res
	return nil
}

func (q *taskQueue) run(ctx context.Context, node string, t nodeapi.Task) (nodeapi.TaskResult, error) {
	if t.ID == "" {
		var b [12]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nodeapi.TaskResult{}, err
		}
		t.ID = hex.EncodeToString(b[:])
	}
	if dl, ok := ctx.Deadline(); ok && t.DeadlineMs == 0 {
		t.DeadlineMs = dl.UnixMilli()
	}
	w := &taskWaiter{node: node, ch: make(chan nodeapi.TaskResult, 1)}
	q.mu.Lock()
	q.waiters[t.ID] = w
	q.pending[node] = append(q.pending[node], t)
	ch := q.wakeLocked(node)
	close(ch)
	q.wake[node] = make(chan struct{})
	q.mu.Unlock()
	select {
	case res := <-w.ch:
		return res, nil
	case <-ctx.Done():
		q.mu.Lock()
		delete(q.waiters, t.ID)
		ts := q.pending[node]
		for i := range ts {
			if ts[i].ID == t.ID {
				q.pending[node] = append(ts[:i:i], ts[i+1:]...)
				break
			}
		}
		q.mu.Unlock()
		return nodeapi.TaskResult{}, fmt.Errorf("node %s: task %s: %w", node, t.ID, ctx.Err())
	}
}

// router fans investigation tasks out to covered node agents over the node API task queue.
type router struct{ c *Coordinator }

var _ investigate.NodeRouter = router{}

func (r router) Nodes() []string {
	var out []string
	for _, n := range r.c.nodes.list() {
		if n.Covered {
			out = append(out, n.Name)
		}
	}
	return out
}

func (r router) Run(ctx context.Context, node string, t nodeapi.Task) (nodeapi.TaskResult, error) {
	for _, n := range r.c.nodes.list() {
		if n.Name == node && n.Covered {
			return r.c.tasks.run(ctx, node, t)
		}
	}
	return nodeapi.TaskResult{}, fmt.Errorf("node %s is not covered by a connected node agent", node)
}

// nodeFindings indexes finding records submitted by node agents so lifecycle summaries include them (PRD 7.7).
type nodeFindings struct {
	store kv.Store
	mu    sync.Mutex
	byID  map[string]*nodeEpisode
}

type nodeEpisode struct {
	DedupKey    string           `json:"dedup_key"`
	FirstSeen   uint64           `json:"first_seen"`
	RuleID      string           `json:"rule_id,omitempty"`
	Transitions []nodeTransition `json:"transitions"`
}

type nodeTransition struct {
	Seq      uint64              `json:"seq"`
	T        protocol.Transition `json:"t"`
	Eval     uint64              `json:"eval"`
	Bundle   string              `json:"bundle,omitempty"`
	Severity protocol.Severity   `json:"severity"`
}

const nodeFindingPrefix = "f/"

func loadNodeFindings(s kv.Store) (*nodeFindings, error) {
	n := &nodeFindings{store: s, byID: map[string]*nodeEpisode{}}
	err := s.ForEach(nodeFindingPrefix, func(k string, v []byte) error {
		var e nodeEpisode
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		n.byID[strings.TrimPrefix(k, nodeFindingPrefix)] = &e
		return nil
	})
	return n, err
}

// record runs under the spool lock right after the finding record is appended.
func (n *nodeFindings) record(f protocol.Finding, seq uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	e := n.byID[f.ID]
	if e == nil {
		e = &nodeEpisode{DedupKey: f.DedupKey, FirstSeen: f.FirstSeen}
		n.byID[f.ID] = e
	}
	if f.Provenance.Kind == protocol.ProvenanceRule {
		e.RuleID = f.Provenance.RuleID
	}
	e.Transitions = append(e.Transitions, nodeTransition{Seq: seq, T: f.Transition, Eval: f.EvalTime, Bundle: f.Provenance.BundleVersion, Severity: f.Severity})
	if b, err := json.Marshal(e); err == nil {
		_ = n.store.Put(nodeFindingPrefix+f.ID, b)
	}
}

func lifecycle(t protocol.Transition) string {
	switch t {
	case protocol.TransitionResolved:
		return protocol.LifecycleResolved
	case protocol.TransitionStale:
		return protocol.LifecycleStale
	}
	return protocol.LifecycleFiring
}

func (n *nodeFindings) Summary(from, watermark uint64) []protocol.SummaryEntry {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []protocol.SummaryEntry
	for id, e := range n.byID {
		var last *nodeTransition
		touched := false
		for i := range e.Transitions {
			tr := &e.Transitions[i]
			if tr.Seq > watermark {
				break
			}
			last, touched = tr, touched || tr.Seq > from
		}
		if !touched {
			continue
		}
		out = append(out, protocol.SummaryEntry{
			FindingID: id, DedupKey: e.DedupKey, State: lifecycle(last.T), FirstSeen: e.FirstSeen, LastTransition: last.Seq,
			EvalTime: last.Eval, RuleID: e.RuleID, BundleVersion: last.Bundle, Severity: last.Severity.String(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	return out
}

// Commit prunes resolved episodes and transitions at or below the committed sequence.
func (n *nodeFindings) Commit(seq uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	ops := map[string][]byte{}
	for id, e := range n.byID {
		lastT := e.Transitions[len(e.Transitions)-1]
		if lastT.T == protocol.TransitionResolved && lastT.Seq <= seq {
			delete(n.byID, id)
			ops[nodeFindingPrefix+id] = nil
			continue
		}
		keep := 0
		for i, tr := range e.Transitions {
			if tr.Seq <= seq {
				keep = i
			}
		}
		if keep == 0 {
			continue
		}
		e.Transitions = append([]nodeTransition(nil), e.Transitions[keep:]...)
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		ops[nodeFindingPrefix+id] = b
	}
	if len(ops) == 0 {
		return nil
	}
	return n.store.Batch(ops)
}
