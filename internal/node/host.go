package node

import (
	"context"
	"time"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/nodehost"
)

// hostSeriesReserve is the TSDB head headroom for node CPU, memory, filesystem, and per-device network series.
const hostSeriesReserve = 8 + 2 + 4 + 3*nodehost.DefaultMaxDevices

// hostLoop gathers node memory and network series every scrape interval.
func (a *Agent) hostLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.Node.ScrapeInterval.D())
	defer t.Stop()
	var lastErr, lastNetErr string
	for {
		errText, netErr := a.gatherHost()
		if errText != lastErr && errText != "" {
			a.log.Warn("node host metrics not gathered", "err", errText)
		}
		if netErr != lastNetErr && netErr != "" {
			a.log.Warn("node network devices unavailable", "path", a.cfg.Node.SysPath, "reason", netErr)
		}
		lastErr, lastNetErr = errText, netErr
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// gatherHost appends one gather unless disk pressure paused ingestion; it returns the gather error and the network reason as text.
func (a *Agent) gatherHost() (string, string) {
	if a.gate.paused.Load() {
		return "", ""
	}
	ts := a.clock().UnixMilli()
	app := a.gate.Appender(context.Background())
	var appendErr error
	st, err := a.hostm.Gather(func(l labels.Labels, v float64) {
		if _, err := app.Append(0, l, ts, v); err != nil && appendErr == nil {
			appendErr = err
		}
	})
	if err == nil {
		err = appendErr
	}
	if err != nil {
		_ = app.Rollback()
		return err.Error(), st.NetworkError
	}
	if err := app.Commit(); err != nil {
		return err.Error(), st.NetworkError
	}
	return "", st.NetworkError
}
