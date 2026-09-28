package node

import (
	"context"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

func (a *Agent) defaultExecutor() TaskExecutor {
	root := ""
	if a.caps[capLogs] {
		root = a.cfg.Node.LogsPath
	}
	o := investigate.ExecOptions{
		Node: a.node, Queryable: a.query, PodLogRoot: root, Enrich: a.pods.enrich, Evidence: a.ring,
		Limits: a.cfg.Investigation, Redactor: a.red, Clock: a.clock,
	}
	if a.db != nil {
		o.Retention = a.db.Retention
	}
	return investigate.NewExecutor(o)
}

// taskLoop long-polls investigation tasks and runs them with bounded concurrency, apart from evaluation.
func (a *Agent) taskLoop(ctx context.Context) {
	sem := make(chan struct{}, max(a.cfg.Investigation.MaxConcurrency, 1))
	var mu sync.Mutex
	inflight := map[string]bool{}
	var wg sync.WaitGroup
	defer wg.Wait()
	back := a.t.RetryMin
	for ctx.Err() == nil {
		tasks, err := a.client.WaitTasks(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Debug("task poll failed", "err", err)
			if !sleepCtx(ctx, back) {
				return
			}
			back = min(2*back, a.t.RetryMax)
			continue
		}
		back = a.t.RetryMin
		for _, t := range tasks {
			mu.Lock()
			dup := inflight[t.ID]
			inflight[t.ID] = true
			mu.Unlock()
			if dup {
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			wg.Add(1)
			go func(t nodeapi.Task) {
				defer wg.Done()
				defer func() {
					<-sem
					mu.Lock()
					delete(inflight, t.ID)
					mu.Unlock()
				}()
				a.runTask(ctx, t)
			}(t)
		}
	}
}

func (a *Agent) runTask(ctx context.Context, t nodeapi.Task) {
	timeout := a.cfg.Investigation.Timeout.D()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	if t.DeadlineMs > 0 {
		var c2 context.CancelFunc
		tctx, c2 = context.WithDeadline(tctx, time.UnixMilli(t.DeadlineMs))
		defer c2()
	}
	res := a.exec.Execute(tctx, t)
	cancel()
	res.ID = t.ID
	back := a.t.RetryMin
	for attempt := 0; attempt < 5 && ctx.Err() == nil; attempt++ {
		err := a.client.PostResult(ctx, res)
		if err == nil || !nodeapi.IsRetryable(err) {
			if err != nil {
				a.log.Warn("task result refused", "task", t.ID, "err", err)
			}
			return
		}
		if !sleepCtx(ctx, back) {
			return
		}
		back = min(2*back, a.t.RetryMax)
	}
}
