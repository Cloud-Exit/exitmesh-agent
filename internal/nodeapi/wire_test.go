package nodeapi

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/metricfacts"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func testFinding(node string) *protocol.Finding {
	return &protocol.Finding{
		ID: "f1", DedupKey: "d1", Transition: protocol.TransitionFiring,
		Provenance: protocol.Provenance{Kind: protocol.ProvenanceRule, RuleID: "r1", RuleVersion: 2, BundleVersion: "b1"},
		Category:   "availability", Severity: protocol.SeverityHigh, EvalTime: 1000, FirstSeen: 900, LastSeen: 1000, Count: 2,
		Resources: []string{"pod/a"}, Facts: map[string]any{"restarts": int64(3)}, Node: node,
		Labels: map[string]string{"namespace": "default"}, Summary: "crash looping",
	}
}

func encodedFinding(t *testing.T, node string) []byte {
	t.Helper()
	b, err := protocol.EncodeFinding(testFinding(node))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testPart(node string) *Part {
	return &Part{
		RuleID: "cluster-errors", RuleVersion: 3, BundleVersion: "b1", EvalTimeMs: 1_700_000_000_000,
		Samples: []Sample{
			{Labels: map[string]string{"__name__": engine.SplitMetric, engine.LabelNode: node, "job": "api"}, Value: 12.5, TimestampMs: 1_700_000_000_000},
			{Labels: map[string]string{"job": "db"}, Value: 0, TimestampMs: 1_700_000_000_000},
		},
	}
}

func testItems(t *testing.T, node string) []Item {
	return []Item{
		{Seq: 1, Kind: KindFinding, Finding: encodedFinding(t, node)},
		{Seq: 2, Kind: KindMetricFacts, Facts: []metricfacts.Fact{
			{Namespace: "default", Pod: "a", Container: "c", Node: node, Fields: map[string]any{metricfacts.CPUP95: 0.25, metricfacts.CPUSaturated: false}},
			{Node: node, Fields: map[string]any{metricfacts.NodeMemPressure: true}},
		}},
		{Seq: 5, Kind: KindSeries, Part: testPart(node)},
	}
}

func roundTrip[T any](t *testing.T, in T) T {
	t.Helper()
	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal %T: %v", in, err)
	}
	again, err := Marshal(in)
	if err != nil || !bytes.Equal(b, again) {
		t.Fatalf("encoding of %T is not deterministic", in)
	}
	var out T
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal %T: %v", in, err)
	}
	return out
}

func check[T any](t *testing.T, in T) {
	t.Helper()
	if out := roundTrip(t, in); !reflect.DeepEqual(in, out) {
		t.Fatalf("%T round trip:\n got %#v\nwant %#v", in, out, in)
	}
}

func TestCBORRoundTrip(t *testing.T) {
	check(t, RegisterRequest{
		Node: "node-1", AgentVersion: "1.2.3", BundleVersion: "b1", Capabilities: []string{"inventory", "metrics"},
		Coverage: map[string]string{"logs": "covered", "metrics": "warming"}, Warming: true,
		QueueUsage: QueueUsage{Bytes: 4096, Capacity: 1 << 30, Items: 7, Acked: 3, Next: 11},
	})
	check(t, RegisterRequest{Node: "node-1"})
	check(t, RegisterResponse{TargetBundle: "b2", ServerTimeMs: 1_700_000_000_123})
	check(t, SubmitRequest{Node: "node-1", Items: testItems(t, "node-1")})
	check(t, SubmitResponse{AckedThrough: 42})
	check(t, BundlePayload{Version: "b2", Archive: []byte{1, 2, 3}, Signature: []byte{4}, KeyManifest: []byte{5, 6}})
	check(t, KubeUpdate{Revision: 9, Series: []KubeSeries{{Labels: map[string]string{"__name__": "kube_node_info", "node": "node-1"}, Value: 1}}})
	check(t, KubeUpdate{Revision: 1})
	check(t, Task{ID: "t-1", Kind: TaskPromQLQuery, Payload: []byte("up"), DeadlineMs: 1_700_000_000_000})
	check(t, TaskList{Tasks: []Task{{ID: "a", Kind: TaskLogQLQuery}, {ID: "b", Kind: TaskLogRead, Payload: []byte{0}}}})
	check(t, TaskResult{ID: "t-1", Payload: []byte("result")})
	check(t, TaskResult{ID: "t-2", Error: "deadline exceeded"})
	check(t, *testPart("node-1"))

	items := roundTrip(t, SubmitRequest{Node: "node-1", Items: testItems(t, "node-1")}).Items
	f, err := protocol.DecodeFinding(items[0].Finding)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := protocol.EncodeFinding(f); !bytes.Equal(b, encodedFinding(t, "node-1")) || f.Node != "node-1" || f.Summary != "crash looping" {
		t.Fatalf("finding did not survive the round trip: %+v", f)
	}
}

func TestFactFieldsNormalized(t *testing.T) {
	in := SubmitRequest{Node: "n", Items: []Item{{Seq: 1, Kind: KindMetricFacts, Facts: []metricfacts.Fact{{Node: "n", Fields: map[string]any{"count": 3, "neg": -2}}}}}}
	out := roundTrip(t, in)
	if got := out.Items[0].Facts[0].Fields; got["count"] != int64(3) || got["neg"] != int64(-2) {
		t.Fatalf("fields = %#v", got)
	}
}

func TestPartEngineConversion(t *testing.T) {
	ts := time.UnixMilli(1_700_000_000_000)
	ep := engine.Part{RuleID: "r", RuleVersion: 4, BundleVersion: "b", EvalTime: ts, Vector: promql.Vector{
		{Metric: labels.FromStrings("job", "api", engine.LabelNode, "n1"), F: 3.5, T: ts.UnixMilli()},
		{Metric: labels.FromStrings("job", "db"), F: -1, T: ts.UnixMilli() - 1000},
	}}
	wp, err := PartFromEngine(ep)
	if err != nil {
		t.Fatal(err)
	}
	back := roundTrip(t, wp).Engine()
	if back.RuleID != "r" || back.RuleVersion != 4 || back.BundleVersion != "b" || !back.EvalTime.Equal(ts) || len(back.Vector) != 2 {
		t.Fatalf("engine part = %+v", back)
	}
	for i, s := range back.Vector {
		if want := ep.Vector[i]; !labels.Equal(s.Metric, want.Metric) || s.F != want.F || s.T != want.T {
			t.Fatalf("sample %d = %v, want %v", i, s, want)
		}
	}
	if (Part{RuleID: "r"}).Engine().Vector != nil {
		t.Fatal("empty part should have a nil vector")
	}
	nan := ep
	nan.Vector = promql.Vector{{Metric: labels.FromStrings("a", "b"), F: math.NaN()}}
	if _, err := PartFromEngine(nan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NaN sample: %v", err)
	}
	hist := ep
	hist.Vector = promql.Vector{{Metric: labels.FromStrings("a", "b"), H: &histogram.FloatHistogram{}}}
	if _, err := PartFromEngine(hist); !errors.Is(err, ErrInvalid) {
		t.Fatalf("histogram sample: %v", err)
	}
}

func TestMarshalValidates(t *testing.T) {
	node := "node-1"
	fact := metricfacts.Fact{Node: node, Fields: map[string]any{"x": 1.0}}
	cases := map[string]any{
		"register without node":   RegisterRequest{},
		"register long version":   RegisterRequest{Node: node, AgentVersion: strings.Repeat("v", 300)},
		"submit without items":    SubmitRequest{Node: node},
		"submit zero seq":         SubmitRequest{Node: node, Items: []Item{{Kind: KindMetricFacts, Facts: []metricfacts.Fact{fact}}}},
		"submit descending":       SubmitRequest{Node: node, Items: []Item{{Seq: 2, Kind: KindMetricFacts, Facts: []metricfacts.Fact{fact}}, {Seq: 1, Kind: KindMetricFacts, Facts: []metricfacts.Fact{fact}}}},
		"submit duplicate seq":    SubmitRequest{Node: node, Items: []Item{{Seq: 1, Kind: KindMetricFacts, Facts: []metricfacts.Fact{fact}}, {Seq: 1, Kind: KindMetricFacts, Facts: []metricfacts.Fact{fact}}}},
		"unknown kind":            Item{Seq: 1, Kind: "other"},
		"finding garbage":         Item{Seq: 1, Kind: KindFinding, Finding: []byte{0xff}},
		"finding with facts":      Item{Seq: 1, Kind: KindFinding, Finding: encodedFinding(t, node), Facts: []metricfacts.Fact{fact}},
		"facts empty":             Item{Seq: 1, Kind: KindMetricFacts},
		"fact without resource":   Item{Seq: 1, Kind: KindMetricFacts, Facts: []metricfacts.Fact{{Fields: map[string]any{"x": 1.0}}}},
		"fact NaN":                Item{Seq: 1, Kind: KindMetricFacts, Facts: []metricfacts.Fact{{Node: node, Fields: map[string]any{"x": math.NaN()}}}},
		"series without part":     Item{Seq: 1, Kind: KindSeries},
		"series with finding":     Item{Seq: 1, Kind: KindSeries, Part: testPart(node), Finding: []byte{1}},
		"part without rule":       Part{},
		"part infinite":           Part{RuleID: "r", Samples: []Sample{{Value: math.Inf(1)}}},
		"part empty label":        Part{RuleID: "r", Samples: []Sample{{Labels: map[string]string{"": "x"}}}},
		"bundle without version":  BundlePayload{Archive: []byte{1}},
		"bundle without archive":  BundlePayload{Version: "b"},
		"kube NaN":                KubeUpdate{Series: []KubeSeries{{Value: math.NaN()}}},
		"task bad id":             Task{ID: "a/b", Kind: TaskLogRead},
		"task without kind":       Task{ID: "a"},
		"task list with bad task": TaskList{Tasks: []Task{{ID: ""}}},
		"result bad id":           TaskResult{ID: strings.Repeat("x", 129)},
	}
	for name, v := range cases {
		if _, err := Marshal(v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestUnmarshalStrict(t *testing.T) {
	valid, err := Marshal(TaskResult{ID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	var big bytes.Buffer
	big.Write([]byte{0xa1, 0x01, 0x5a})
	n := MaxResponseBytes
	big.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	big.Write(make([]byte, n))
	cases := map[string]struct {
		b []byte
		v any
	}{
		"duplicate key":     {[]byte{0xa2, 0x01, 0x61, 'a', 0x01, 0x61, 'b'}, &TaskResult{}},
		"trailing bytes":    {append(append([]byte{}, valid...), 0x00), &TaskResult{}},
		"indefinite length": {[]byte{0xbf, 0x01, 0x61, 'a', 0xff}, &TaskResult{}},
		"tag":               {[]byte{0xa1, 0x01, 0xc0, 0x61, 'a'}, &TaskResult{}},
		"invalid utf-8":     {[]byte{0xa1, 0x01, 0x61, 0xff}, &TaskResult{}},
		"NaN":               {[]byte{0xa2, 0x01, 0x01, 0x02, 0x81, 0xa1, 0x02, 0xf9, 0x7e, 0x00}, &KubeUpdate{}},
		"infinity":          {[]byte{0xa2, 0x01, 0x01, 0x02, 0x81, 0xa1, 0x02, 0xf9, 0x7c, 0x00}, &KubeUpdate{}},
		"wrong type":        {[]byte{0xa1, 0x01, 0x01}, &TaskResult{}},
		"invalid content":   {[]byte{0xa1, 0x01, 0x60}, &TaskResult{}},
		"oversize":          {big.Bytes(), &TaskResult{}},
		"truncated":         {valid[:len(valid)-1], &TaskResult{}},
	}
	for name, c := range cases {
		if err := Unmarshal(c.b, c.v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	var withUnknown TaskResult
	if err := Unmarshal([]byte{0xa2, 0x01, 0x61, 't', 0x18, 0x63, 0x61, 'x'}, &withUnknown); err != nil || withUnknown.ID != "t" {
		t.Fatalf("unknown key should be ignored: %v %+v", err, withUnknown)
	}
}
