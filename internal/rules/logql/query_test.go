package logql

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/promql"
)

func fixtureLines() Lines {
	var ls Lines
	for i := 0; i < 20; i++ {
		pod := fmt.Sprintf("p%d", i%2)
		level := "info"
		if i%4 == 0 {
			level = "error"
		}
		ls = append(ls, Line{
			Labels: map[string]string{"namespace": "shop", "pod": pod},
			Time:   t0.Add(time.Duration(i) * time.Second),
			Text:   fmt.Sprintf("level=%s n=%d", level, i),
		})
	}
	ls = append(ls, Line{Labels: map[string]string{"namespace": "other", "pod": "x"}, Time: t0, Text: "level=error n=99"})
	return ls
}

func TestRunLogQuery(t *testing.T) {
	src := fixtureLines()
	lim := Limits{Start: t0, End: t0.Add(time.Minute)}
	res, err := RunQuery(context.Background(), `{namespace="shop"} | logfmt | level="error"`, src, lim)
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != ResultStreams || len(res.Lines) != 5 || res.Truncated {
		t.Fatalf("got %+v", res)
	}
	if res.Lines[0].Text != "level=error n=16" || res.Lines[4].Text != "level=error n=0" {
		t.Fatalf("backward order: %v", res.Lines)
	}
	if got := res.Lines[0].Labels.String(); got != `{level="error", n="16", namespace="shop", pod="p0"}` {
		t.Fatalf("labels %s", got)
	}
	if res.ScannedLines != 20 {
		t.Fatalf("source must receive the stream matchers: scanned %d", res.ScannedLines)
	}
	lim.Direction = Forward
	lim.MaxLines = 2
	res, err = RunQuery(context.Background(), `{namespace="shop"} |= "error"`, src, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 2 || res.Lines[0].Text != "level=error n=0" || res.Lines[1].Text != "level=error n=4" ||
		!res.Truncated || !reflect.DeepEqual(res.Limited, []string{LimitLines}) {
		t.Fatalf("forward limit: %+v", res)
	}
	lim = Limits{Start: t0, End: t0.Add(time.Minute), MaxBytes: 35}
	res, err = RunQuery(context.Background(), `{namespace="shop"} |= "error"`, src, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 2 || res.Lines[0].Text != "level=error n=16" || res.ResultBytes > 35 || !reflect.DeepEqual(res.Limited, []string{LimitBytes}) {
		t.Fatalf("byte limit: %+v", res)
	}
	lim = Limits{Start: t0.Add(5 * time.Second), End: t0.Add(12 * time.Second)}
	res, err = RunQuery(context.Background(), `{namespace="shop"} |= "error"`, src, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 1 || res.Lines[0].Text != "level=error n=8" {
		t.Fatalf("window [start, end): %+v", res.Lines)
	}
}

func TestRunMetricInstant(t *testing.T) {
	src := fixtureLines()
	lim := Limits{Start: t0, End: t0.Add(19 * time.Second)}
	cases := []struct {
		q    string
		want map[string]float64
	}{
		{`sum by (pod) (count_over_time({namespace="shop"} | logfmt | level="error" [10s]))`, map[string]float64{`{pod="p0"}`: 2}},
		{`count_over_time({namespace="shop"}[1m])`, map[string]float64{`{namespace="shop", pod="p0"}`: 10, `{namespace="shop", pod="p1"}`: 10}},
		{`sum(rate({namespace="shop"}[20s]))`, map[string]float64{`{}`: 1}},
		{`sum(bytes_over_time({namespace="shop"} |= "error" [1m]))`, map[string]float64{`{}`: float64(len("level=error n=0")*3 + len("level=error n=12")*2)}},
		{`sum(count_over_time({namespace="shop"}[1m])) > 100`, map[string]float64{}},
		{`topk(1, sum by (pod) (count_over_time({namespace="shop"} |~ "n=1[0-9]" [1m])))`, map[string]float64{`{pod="p0"}`: 5}},
	}
	for _, tc := range cases {
		res, err := RunQuery(context.Background(), tc.q, src, lim)
		if err != nil {
			t.Fatalf("%s: %v", tc.q, err)
		}
		if res.Type != ResultVector {
			t.Fatalf("type %s", res.Type)
		}
		if got := vectorMap(res.Vector); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.q, got, tc.want)
		}
	}
}

func TestRunMetricRange(t *testing.T) {
	src := fixtureLines()
	lim := Limits{Start: t0.Add(4 * time.Second), End: t0.Add(12 * time.Second), Step: 4 * time.Second}
	res, err := RunQuery(context.Background(), `sum(count_over_time({namespace="shop"} |= "error" [5s]))`, src, lim)
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != ResultMatrix || len(res.Matrix) != 1 {
		t.Fatalf("got %+v", res)
	}
	want := []promql.FPoint{
		{T: t0.Add(4 * time.Second).UnixMilli(), F: 2},
		{T: t0.Add(8 * time.Second).UnixMilli(), F: 2},
		{T: t0.Add(12 * time.Second).UnixMilli(), F: 2},
	}
	if !reflect.DeepEqual(res.Matrix[0].Floats, want) {
		t.Fatalf("got %v", res.Matrix[0].Floats)
	}
	res, err = RunQuery(context.Background(), `count_over_time({namespace="shop"} |= "error" [1s])`, src, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matrix) != 1 || len(res.Matrix[0].Floats) != 3 {
		t.Fatalf("window (t-1s, t] must include lines exactly at t: %+v", res.Matrix)
	}
}

func TestRunMetricLimits(t *testing.T) {
	src := fixtureLines()
	lim := Limits{Start: t0, End: t0.Add(20 * time.Second), MaxSeries: 1}
	res, err := RunQuery(context.Background(), `count_over_time({namespace="shop"}[1m])`, src, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vector) != 1 || !reflect.DeepEqual(res.Limited, []string{LimitSeries}) {
		t.Fatalf("got %+v", res)
	}
	lim = Limits{Start: t0, End: t0.Add(20 * time.Second), Step: time.Second, MaxSamples: 10}
	if _, err := RunQuery(context.Background(), `count_over_time({namespace="shop"}[1m])`, src, lim); err == nil || !strings.Contains(err.Error(), "exceed the sample limit") {
		t.Fatalf("got %v", err)
	}
	lim.MaxSamples = 30
	res, err = RunQuery(context.Background(), `count_over_time({namespace="shop"}[1m])`, src, lim)
	if err != nil || len(res.Matrix) != 1 || !reflect.DeepEqual(res.Limited, []string{LimitSamples}) {
		t.Fatalf("got %+v %v", res, err)
	}
	bad := Lines{{Labels: map[string]string{"namespace": "shop"}, Time: t0, Text: "not json"}}
	_, err = RunQuery(context.Background(), `sum(count_over_time({namespace="shop"} | json [1m]))`, bad, Limits{Start: t0, End: t0.Add(time.Second)})
	var pe *PipelineError
	if !errors.As(err, &pe) {
		t.Fatalf("got %v", err)
	}
	if _, err := RunQuery(context.Background(), `{namespace="shop"}`, src, Limits{}); err == nil {
		t.Fatal("a query window is required")
	}
	if _, err := RunQuery(context.Background(), `{namespace="shop"} | line_format "x"`, src, Limits{Start: t0, End: t0}); err == nil {
		t.Fatal("unsupported queries must be rejected")
	}
}

func TestRunQueryTimeout(t *testing.T) {
	slow := LineSourceFunc(func(ctx context.Context, req SourceRequest, yield func(Line) bool) error {
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
			if !yield(Line{Labels: map[string]string{"app": "x"}, Time: t0, Text: "x"}) {
				return nil
			}
		}
	})
	lim := Limits{Start: t0, End: t0.Add(time.Second), Timeout: 30 * time.Millisecond}
	res, err := RunQuery(context.Background(), `{app="x"}`, slow, lim)
	if err != nil || !res.Truncated || !reflect.DeepEqual(res.Limited, []string{LimitTimeout}) || len(res.Lines) == 0 {
		t.Fatalf("got %+v %v", res, err)
	}
	res, err = RunQuery(context.Background(), `count_over_time({app="x"}[2s])`, slow, lim)
	if err != nil || !reflect.DeepEqual(res.Limited, []string{LimitTimeout}) || len(res.Vector) != 1 {
		t.Fatalf("got %+v %v", res, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunQuery(ctx, `{app="x"}`, slow, lim); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation must be an error, got %v", err)
	}
}

func TestSourceRequestWindow(t *testing.T) {
	var got SourceRequest
	src := LineSourceFunc(func(_ context.Context, req SourceRequest, _ func(Line) bool) error {
		got = req
		return nil
	})
	lim := Limits{Start: t0, End: t0.Add(time.Minute), Step: 30 * time.Second}
	if _, err := RunQuery(context.Background(), `rate({app="x", env!="dev"}[5m])`, src, lim); err != nil {
		t.Fatal(err)
	}
	if !got.Start.Equal(t0.Add(-5*time.Minute+time.Nanosecond)) || !got.End.Equal(t0.Add(time.Minute)) || len(got.Matchers) != 2 {
		t.Fatalf("got %+v", got)
	}
	if !got.Match(map[string]string{"app": "x", "env": "prod"}) || got.Match(map[string]string{"app": "x", "env": "dev"}) {
		t.Fatal("Match must apply matchers")
	}
}
