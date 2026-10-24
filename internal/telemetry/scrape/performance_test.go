package scrape

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

func benchmarkBody(n, generation int) []byte {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "container_memory_working_set_bytes{namespace=\"production\",pod=\"worker-%d\",container=\"worker\",id=\"/kubepods.slice/kubepods-burstable.slice/pod-%d-%d\",image=\"registry.example.invalid/workload:2026-10\",name=\"worker\",cpu=\"total\"} %d\n", i, generation, i, 1000000+i)
	}
	return []byte(b.String())
}

func BenchmarkMetricsBudget(b *testing.B) {
	for _, maxSeries := range []int{10000, 1} {
		b.Run(fmt.Sprintf("max_series_%d", maxSeries), func(b *testing.B) {
			db, err := tsdb.Open(b.TempDir(), tsdb.Options{})
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			m := newTestManager(db, Budgets{MaxSeries: maxSeries})
			l := testLoop(m, Target{URL: "http://example.invalid/metrics", Labels: map[string]string{"node": "node-a", "job": "kubelet", "metrics_path": "/metrics/cadvisor"}})
			body := benchmarkBody(10000, 0)
			now := time.Now().UnixMilli()
			run := func(ts int64) {
				l.iter++
				app := db.Appender(context.Background())
				if _, err := l.appendBody(app, body, "text/plain", ts); err != nil {
					b.Fatal(err)
				}
				l.staleUnseen(app, ts)
				if err := app.Commit(); err != nil {
					b.Fatal(err)
				}
			}
			run(now)
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				run(now + int64(i) + 1)
			}
		})
	}
}
