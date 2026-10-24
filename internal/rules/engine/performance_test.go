package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
)

func BenchmarkMemSeriesRetentionCopy(b *testing.B) {
	now := time.Unix(1800000000, 0)
	m := NewMemSeries(6*time.Hour, func() time.Time { return now })
	const seriesCount = 10
	const historySamples = 21601
	seed := make([]Series, seriesCount)
	for i := range seed {
		seed[i] = Series{Labels: labels.FromStrings("__name__", "kube_pod_info", "pod", fmt.Sprintf("pod-%d", i)), Samples: make([]Sample, historySamples)}
		for j := range seed[i].Samples {
			seed[i].Samples[j] = Sample{T: now.Add(time.Duration(j) * time.Second).UnixMilli(), F: 1}
		}
	}
	m.Replace("pods", seed)
	now = now.Add(6 * time.Hour)
	for i := range seed {
		seed[i].Samples = []Sample{{F: 1}}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		now = now.Add(time.Second)
		for i := range seed {
			seed[i].Samples[0].T = now.UnixMilli()
		}
		m.Replace("pods", seed)
	}
	benchmarkRetainedSeries = m
}

var benchmarkRetainedSeries *MemSeries
