package node

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
)

const maxBatchBytes = 4 << 20

type delivery struct {
	appendMu sync.Mutex
	notify   chan struct{}

	mu        sync.Mutex
	dropped   map[nodeapi.ItemKind]uint64
	invalid   uint64
	rejected  uint64
	lastDrop  time.Time
	acked     uint64
	lastError string
	target    string
}

func (d *delivery) count(p *uint64) {
	d.mu.Lock()
	*p++
	d.mu.Unlock()
}

func (d *delivery) drop(k nodeapi.ItemKind) {
	d.mu.Lock()
	if d.dropped == nil {
		d.dropped = map[nodeapi.ItemKind]uint64{}
	}
	d.dropped[k]++
	d.mu.Unlock()
}

func (d *delivery) shouldLogDrop(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.lastDrop) < time.Minute && !d.lastDrop.IsZero() {
		return false
	}
	d.lastDrop = now
	return true
}

func (d *delivery) droppedSummary() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var parts []string
	for k, n := range d.dropped {
		parts = append(parts, fmt.Sprintf("%s=%d", k, n))
	}
	if d.rejected > 0 {
		parts = append(parts, fmt.Sprintf("rejected=%d", d.rejected))
	}
	if d.invalid > 0 {
		parts = append(parts, fmt.Sprintf("invalid=%d", d.invalid))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (d *delivery) setError(err error) {
	d.mu.Lock()
	if err == nil {
		d.lastError = ""
	} else {
		d.lastError = err.Error()
	}
	d.mu.Unlock()
}

// sendLoop drains the queue to the coordinator and acknowledges locally only after the coordinator's durable ack.
func (a *Agent) sendLoop(ctx context.Context) {
	back := a.t.RetryMin
	var next uint64
	for ctx.Err() == nil {
		items := a.queue.Peek(next, maxBatchBytes)
		if len(items) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-a.deliv.notify:
			case <-time.After(a.t.Register):
			}
			continue
		}
		acked, err := a.submit(ctx, items)
		a.deliv.setError(err)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Debug("queue delivery failed", "err", err, "items", len(items))
			if !sleepCtx(ctx, back) {
				return
			}
			back = min(2*back, a.t.RetryMax)
			continue
		}
		if acked < items[0].Seq {
			if !sleepCtx(ctx, back) {
				return
			}
			back = min(2*back, a.t.RetryMax)
			continue
		}
		back = a.t.RetryMin
		a.ack(acked)
		next = acked + 1
	}
}

func (a *Agent) ack(seq uint64) {
	if err := a.queue.Ack(seq); err != nil {
		a.log.Warn("queue ack failed", "seq", seq, "err", err)
		return
	}
	if err := a.tracker.Commit(seq); err != nil {
		a.log.Warn("finding commit failed", "seq", seq, "err", err)
	}
	a.deliv.mu.Lock()
	a.deliv.acked = max(a.deliv.acked, seq)
	a.deliv.mu.Unlock()
}

// submit sends a batch; only items the coordinator refuses as malformed are dropped, every other failure keeps the queue.
func (a *Agent) submit(ctx context.Context, q []spool.QueueItem) (uint64, error) {
	items := make([]nodeapi.Item, 0, len(q))
	for _, qi := range q {
		var it nodeapi.Item
		if err := nodeapi.Unmarshal(qi.Data, &it); err != nil {
			a.deliv.count(&a.deliv.invalid)
			a.log.Warn("undecodable queue item dropped", "seq", qi.Seq, "err", err)
			if len(items) > 0 {
				break
			}
			return qi.Seq, nil
		}
		it.Seq = qi.Seq
		items = append(items, it)
	}
	acked, err := a.client.Submit(ctx, a.queue.ID(), items)
	if err == nil || !nodeapi.IsMalformed(err) || ctx.Err() != nil {
		return acked, err
	}
	if len(items) == 1 {
		a.deliv.count(&a.deliv.rejected)
		a.log.Warn("coordinator rejected a queue item; dropping it", "seq", items[0].Seq, "kind", string(items[0].Kind), "err", err)
		return items[0].Seq, nil
	}
	var last uint64
	for _, it := range items {
		n, err := a.client.Submit(ctx, a.queue.ID(), []nodeapi.Item{it})
		switch {
		case err == nil:
			last = max(last, n)
		case !nodeapi.IsMalformed(err) || ctx.Err() != nil:
			return last, err
		default:
			a.deliv.count(&a.deliv.rejected)
			a.log.Warn("coordinator rejected a queue item; dropping it", "seq", it.Seq, "kind", string(it.Kind), "err", err)
			last = it.Seq
		}
	}
	return last, nil
}

func (a *Agent) registerLoop(ctx context.Context) {
	for {
		req := nodeapi.RegisterRequest{
			Node: a.node, AgentVersion: a.deps.AgentVersion, BundleVersion: a.eng.BundleVersion(),
			Capabilities: capList(a.cfg.Capabilities), Coverage: a.coverageReport(), Warming: a.warming(),
			QueueUsage: queueUsage(a.queue.Usage()), Rules: a.ruleStatuses(), Process: a.process,
		}
		rctx, cancel := context.WithTimeout(ctx, a.t.Register)
		resp, err := a.client.Register(rctx, req)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Debug("register failed", "err", err)
		} else {
			a.deliv.mu.Lock()
			a.deliv.target = resp.TargetBundle
			a.deliv.mu.Unlock()
		}
		if !sleepCtx(ctx, a.t.Register) {
			return
		}
	}
}

// ruleStatuses reports the local rule states for coordinator health, redacted, most severe first, within the wire bounds.
func (a *Agent) ruleStatuses() []nodeapi.RuleStatus {
	now := a.clock()
	limited := map[string]bool{}
	if set := a.logsSet.cur.Load(); set != nil {
		for _, lr := range set.rules {
			if lr.prog.Status().BudgetLimited {
				for _, id := range lr.ids {
					limited[id] = true
				}
			}
		}
	}
	states := a.eng.RuleStates()
	out := make([]nodeapi.RuleStatus, 0, len(states))
	for _, r := range states {
		rs := nodeapi.RuleStatus{
			RuleID: r.RuleID, Version: r.Version, State: r.State, Reason: truncateUTF8(a.red.String(r.Reason), nodeapi.MaxRuleReason),
			BudgetLimited:   r.State == engine.StateBudgetLimited || now.Before(r.BackoffUntil) || limited[r.RuleID],
			EvidenceLimited: a.ring.Limited(r.RuleID),
		}
		if !r.LastEval.IsZero() {
			rs.LastEvalMs = r.LastEval.UnixMilli()
		}
		out = append(out, rs)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := nodeapi.RuleStateRank(out[i].State), nodeapi.RuleStateRank(out[j].State); ri != rj {
			return ri < rj
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out[:min(len(out), nodeapi.MaxRuleStatuses)]
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func capList(c []string) []string {
	out := append([]string(nil), c...)
	sort.Strings(out)
	return out
}

func queueUsage(u spool.QueueUsage) nodeapi.QueueUsage {
	return nodeapi.QueueUsage{Bytes: u.Bytes, Capacity: u.Capacity, Items: u.Items, Acked: u.Acked, Next: u.Next}
}
