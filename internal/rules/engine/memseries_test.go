package engine

import (
	"context"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
)

func instant(t *testing.T, q storage.Queryable, expr string, ts time.Time) promql.Vector {
	t.Helper()
	eng := promql.NewEngine(promql.EngineOpts{MaxSamples: 1e6, Timeout: time.Minute, LookbackDelta: 5 * time.Minute})
	qry, err := eng.NewInstantQuery(context.Background(), q, nil, expr, ts)
	if err != nil {
		t.Fatal(err)
	}
	defer qry.Close()
	res := qry.Exec(context.Background())
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	v, err := res.Vector()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func ms(ts time.Time) int64 { return timestamp.FromTime(ts) }

func TestMemSeriesReplaceMarksMissingSeriesStale(t *testing.T) {
	now := at(0)
	m := NewMemSeries(time.Hour, func() time.Time { return now })
	a, b := labels.FromStrings("__name__", "kube_pod_info", "pod", "a"), labels.FromStrings("__name__", "kube_pod_info", "pod", "b")
	m.Replace("kube", []Series{{Labels: a, Samples: []Sample{{T: ms(at(0)), F: 1}}}, {Labels: b, Samples: []Sample{{T: ms(at(0)), F: 1}}}})
	if v := instant(t, m, "kube_pod_info", at(time.Minute)); len(v) != 2 {
		t.Fatalf("got %v", v)
	}
	m.Replace("kube", []Series{{Labels: a, Samples: []Sample{{T: ms(at(2 * time.Minute)), F: 1}}}})
	v := instant(t, m, "kube_pod_info", at(2*time.Minute))
	if len(v) != 1 || v[0].Metric.Get("pod") != "a" {
		t.Fatalf("stale series still visible: %v", v)
	}
	now = at(3 * time.Minute)
	m.Replace("kube", nil)
	if v := instant(t, m, "kube_pod_info", at(3*time.Minute)); len(v) != 0 {
		t.Fatalf("empty replace kept series: %v", v)
	}
	if v := instant(t, m, "kube_pod_info", at(time.Minute)); len(v) != 2 {
		t.Fatalf("history lost: %v", v)
	}
}

func TestMemSeriesSourcesAreIndependentAndMerge(t *testing.T) {
	m := NewMemSeries(time.Hour, nil)
	x := labels.FromStrings("__name__", "x", "k", "v")
	m.Replace("s1", []Series{{Labels: x, Samples: []Sample{{T: ms(at(0)), F: 1}, {T: ms(at(time.Minute)), F: 2}}}})
	m.Replace("s2", []Series{{Labels: x, Samples: []Sample{{T: ms(at(time.Minute)), F: 9}, {T: ms(at(2 * time.Minute)), F: 3}}}})
	m.Replace("s3", []Series{{Labels: labels.FromStrings("__name__", "y", "k", "w"), Samples: []Sample{{T: ms(at(0)), F: 5}}}})
	if got := m.Sources(); !slices.Equal(got, []string{"s1", "s2", "s3"}) {
		t.Fatalf("sources %v", got)
	}
	q, _ := m.Querier(ms(at(0)), ms(at(10*time.Minute)))
	set := q.Select(context.Background(), true, nil, labels.MustNewMatcher(labels.MatchEqual, "__name__", "x"))
	var ts []int64
	for set.Next() {
		it := set.At().Iterator(nil)
		for it.Next() != 0 {
			tt, _ := it.At()
			ts = append(ts, tt)
		}
	}
	if !slices.Equal(ts, []int64{ms(at(0)), ms(at(time.Minute)), ms(at(2 * time.Minute))}) {
		t.Fatalf("merged timestamps %v", ts)
	}
	names, _, _ := q.LabelNames(context.Background(), nil)
	if !slices.Equal(names, []string{"__name__", "k"}) {
		t.Fatalf("names %v", names)
	}
	vals, _, _ := q.LabelValues(context.Background(), "k", nil)
	if !slices.Equal(vals, []string{"v", "w"}) {
		t.Fatalf("values %v", vals)
	}
	vals, _, _ = q.LabelValues(context.Background(), "k", nil, labels.MustNewMatcher(labels.MatchEqual, "__name__", "y"))
	if !slices.Equal(vals, []string{"w"}) {
		t.Fatalf("matched values %v", vals)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMemSeriesRetentionAndOrdering(t *testing.T) {
	now := at(0)
	m := NewMemSeries(10*time.Minute, func() time.Time { return now })
	x := labels.FromStrings("__name__", "x")
	m.Replace("s", []Series{{Labels: x, Samples: []Sample{{T: ms(at(time.Minute)), F: 2}, {T: ms(at(0)), F: 1}}}})
	m.Replace("s", []Series{{Labels: x, Samples: []Sample{{T: ms(at(0)), F: 7}}}})
	q, _ := m.Querier(0, math.MaxInt64)
	set := q.Select(context.Background(), false, nil, labels.MustNewMatcher(labels.MatchEqual, "__name__", "x"))
	set.Next()
	var got []float64
	it := set.At().Iterator(nil)
	for it.Next() != 0 {
		_, f := it.At()
		got = append(got, f)
	}
	if !slices.Equal(got, []float64{1, 2}) {
		t.Fatalf("out-of-order sample accepted: %v", got)
	}
	m.Replace("s", []Series{{Labels: x, Samples: []Sample{{T: ms(at(30 * time.Minute)), F: 3}}}})
	set = q.Select(context.Background(), false, &storage.SelectHints{Start: 0, End: math.MaxInt64}, labels.MustNewMatcher(labels.MatchEqual, "__name__", "x"))
	set.Next()
	n := 0
	it = set.At().Iterator(nil)
	for it.Next() != 0 {
		n++
	}
	if n != 1 {
		t.Fatalf("retention kept %d samples", n)
	}
	now = at(40 * time.Minute)
	m.Replace("s", nil)
	if got := m.Sources(); !slices.Equal(got, []string{"s"}) {
		t.Fatalf("sources %v", got)
	}
	now = at(2 * time.Hour)
	m.Replace("s", nil)
	if got := m.Sources(); len(got) != 0 {
		t.Fatalf("expired source kept: %v", got)
	}
}
