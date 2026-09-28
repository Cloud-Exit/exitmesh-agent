package logql

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

// lokiAutoLabels are labels a Loki server may add on ingestion or on error; they are not compared.
var lokiAutoLabels = map[string]bool{"service_name": true, "detected_level": true, "__error_details__": true}

type lokiClient struct {
	base   string
	tenant string
	http   *http.Client
}

func (c *lokiClient) do(t *testing.T, method, path string, q url.Values, body []byte) (int, []byte) {
	t.Helper()
	u := strings.TrimRight(c.base, "/") + path
	if q != nil {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.tenant != "" {
		req.Header.Set("X-Scope-OrgID", c.tenant)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("loki %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

func (c *lokiClient) push(t *testing.T, lines Lines) {
	t.Helper()
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	byKey := map[string]*stream{}
	var order []string
	for _, l := range lines {
		k := labels.FromMap(l.Labels).String()
		s := byKey[k]
		if s == nil {
			s = &stream{Stream: l.Labels}
			byKey[k] = s
			order = append(order, k)
		}
		s.Values = append(s.Values, [2]string{strconv.FormatInt(l.Time.UnixNano(), 10), l.Text})
	}
	var payload struct {
		Streams []*stream `json:"streams"`
	}
	for _, k := range order {
		payload.Streams = append(payload.Streams, byKey[k])
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if code, b := c.do(t, http.MethodPost, "/loki/api/v1/push", nil, body); code/100 != 2 {
		t.Fatalf("loki push: %d %s", code, b)
	}
}

type lokiResult struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

func (c *lokiClient) logQuery(t *testing.T, q string, start, end time.Time) (map[string]map[string]string, error) {
	t.Helper()
	v := url.Values{"query": {q}, "start": {strconv.FormatInt(start.UnixNano(), 10)},
		"end": {strconv.FormatInt(end.UnixNano(), 10)}, "limit": {"5000"}, "direction": {"backward"}}
	code, b := c.do(t, http.MethodGet, "/loki/api/v1/query_range", v, nil)
	if code != http.StatusOK {
		return nil, fmt.Errorf("loki %d: %s", code, b)
	}
	var res lokiResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	var streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	if err := json.Unmarshal(res.Data.Result, &streams); err != nil {
		t.Fatalf("loki streams: %v: %s", err, b)
	}
	out := map[string]map[string]string{}
	for _, s := range streams {
		for _, v := range s.Values {
			out[v[1]] = s.Stream
		}
	}
	return out, nil
}

func (c *lokiClient) instant(t *testing.T, q string, ts time.Time) (map[string]float64, error) {
	t.Helper()
	v := url.Values{"query": {q}, "time": {strconv.FormatInt(ts.UnixNano(), 10)}}
	code, b := c.do(t, http.MethodGet, "/loki/api/v1/query", v, nil)
	if code != http.StatusOK {
		return nil, fmt.Errorf("loki %d: %s", code, b)
	}
	var res lokiResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	var vec []struct {
		Metric map[string]string `json:"metric"`
		Value  [2]any            `json:"value"`
	}
	if err := json.Unmarshal(res.Data.Result, &vec); err != nil {
		t.Fatalf("loki vector: %v: %s", err, b)
	}
	out := map[string]float64{}
	for _, s := range vec {
		f, err := strconv.ParseFloat(fmt.Sprint(s.Value[1]), 64)
		if err != nil {
			t.Fatal(err)
		}
		out[comparableLabels(s.Metric)] = f
	}
	return out, nil
}

func comparableLabels(m map[string]string) string {
	c := map[string]string{}
	for k, v := range m {
		if !lokiAutoLabels[k] && k != "run" {
			c[k] = v
		}
	}
	return labelsString(c)
}

// TestLokiAcceptsCanonicalForms checks that every canonical form the printer emits is valid LogQL for Loki.
func TestLokiAcceptsCanonicalForms(t *testing.T) {
	base := os.Getenv("LOKI_URL")
	if base == "" {
		t.Skip("LOKI_URL is not set; skipping the canonical form check against a real Loki")
	}
	c := &lokiClient{base: base, tenant: os.Getenv("LOKI_TENANT"), http: &http.Client{Timeout: 30 * time.Second}}
	for _, tc := range validQueries {
		code, b := c.do(t, http.MethodGet, "/loki/api/v1/format_query", url.Values{"query": {tc.want}}, nil)
		var res struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(b, &res); err != nil || code != http.StatusOK || res.Status != "success" {
			t.Errorf("Loki rejects canonical form %q: %d %s", tc.want, code, b)
		}
	}
}

// TestLokiDifferential compares RunQuery with a real Loki; it runs only when LOKI_URL is set.
func TestLokiDifferential(t *testing.T) {
	base := os.Getenv("LOKI_URL")
	if base == "" {
		t.Skip("LOKI_URL is not set; skipping the differential test against a real Loki")
	}
	c := &lokiClient{base: base, tenant: os.Getenv("LOKI_TENANT"), http: &http.Client{Timeout: 30 * time.Second}}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	start := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	var lines Lines
	for _, l := range engineFixture(start) {
		ls := map[string]string{"run": run, "service_name": "exitmesh-diff"}
		for k, v := range l.Labels {
			ls[k] = v
		}
		lines = append(lines, Line{Labels: ls, Time: l.Time, Text: l.Text})
	}
	c.push(t, lines)
	end := start.Add(time.Minute)
	scope := []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "run", run)}
	scoped := func(q string) string {
		s, err := InjectScope(q, scope)
		if err != nil {
			t.Fatalf("InjectScope(%q): %v", q, err)
		}
		return s
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		got, err := c.logQuery(t, scoped(`{app=~".+"}`), start.Add(-time.Minute), end)
		if err == nil && len(got) == len(lines) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("loki did not ingest the fixture: %d of %d lines, %v", len(got), len(lines), err)
		}
		time.Sleep(time.Second)
	}
	logQueries := []string{
		`{app="api"} |= "error"`,
		`{app="api"} != "error" !~ "(?i)debug"`,
		`{app="api"} |~ "err(or)?s\\b"`,
		`{app="api"} |~ "one.line"`,
		`{app="api"} | logfmt | level="error"`,
		`{app="api"} | logfmt | status >= 300 | __error__=""`,
		`{app="api"} | logfmt | status >= 300`,
		`{app="api"} | logfmt | dur > 1s`,
		`{app="api"} | json`,
		`{app="api"} | json | __error__=""`,
		`{app="api"} | json | level=~"w.*|e.*" or status=404`,
		`{app="api"} | json lvl="level", uid="user.id"`,
		`{app="web"} | pattern "<ip> - <_> \"<method> <path> <_>\" <status>"`,
		`{app="web"} | pattern "GET <path>"`,
		`{app="web"} | regexp "(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) - (?P<user>\\S+)"`,
		`{app="web"} | regexp "(?P<method>GET|POST) (?P<path>/\\S*)( (?P<proto>HTTP/\\S+))?"`,
		`{app="web"} | pattern "<a> - <b> <c>"`,
		`{app="api"} | logfmt`,
		`{app="api"} | logfmt | size > 1KB, latency >= 250ms level="warn"`,
		`{app="api"} | logfmt | level="error" or (status=~"2.." and level!="info")`,
		`{app="api"} |= "" != "zzz"`,
		`{app="api"} != ""`,
		`{app="api"} | json | pod="p0"`,
		`{app="api"} | json | level=""`,
	}
	for _, q := range logQueries {
		sq := scoped(q)
		want, lerr := c.logQuery(t, sq, start.Add(-time.Minute), end)
		res, err := RunQuery(context.Background(), sq, lines, Limits{Start: start.Add(-time.Minute), End: end, MaxLines: 5000})
		if (lerr != nil) != (err != nil) {
			t.Fatalf("%s: loki error %v, ours %v", sq, lerr, err)
		}
		if err != nil {
			continue
		}
		if len(res.Lines) != len(want) {
			t.Fatalf("%s: ours %d lines, loki %d: %v", sq, len(res.Lines), len(want), want)
		}
		for _, l := range res.Lines {
			ll, ok := want[l.Text]
			if !ok {
				t.Fatalf("%s: loki lacks %q", sq, l.Text)
			}
			if a, b := comparableLabels(l.Labels.Map()), comparableLabels(ll); a != b {
				t.Fatalf("%s: %q labels ours %s, loki %s", sq, l.Text, a, b)
			}
		}
	}
	metricQueries := []string{
		`sum by (pod) (count_over_time({app="api"} |= "error" [1h]))`,
		`sum by (level) (count_over_time({app="api"} | logfmt [1h]))`,
		`sum by (level) (count_over_time({app="api"} | json [1h]))`,
		`sum by (level) (count_over_time({app="api"} | json | __error__="" [1h]))`,
		`sum by (__error__) (count_over_time({app="api"} | json [1h]))`,
		`sum by (pod) (bytes_over_time({app="api"}[1h]))`,
		`sum by (pod) (rate({app="api"}[1h])) * 3600 > 2`,
		`max by (app) (count_over_time({app=~"api|web"}[1h]))`,
		`avg(count_over_time({app=~"api|web"}[1h]))`,
		`count(count_over_time({app=~"api|web"}[1h]))`,
		`topk(1, sum by (pod) (count_over_time({app=~"api|web"}[1h])))`,
		`sum by (method) (count_over_time({app="web"} | pattern "<ip> - <_> \"<method> <path> <_>\" <status>" [1h]))`,
		`sum(count_over_time({app="api"} | logfmt | status >= 300 | __error__="" [1h])) > bool 1`,
		`sum by (lvl) (count_over_time({app="api"} | json lvl="level" | __error__="" [1h]))`,
		`sum by (level) (count_over_time({app="api"} | json | __error__="" [1h]))`,
		`sum without (pod) (count_over_time({app="api"} | logfmt | __error__="" [1h]))`,
		`min by (app) (count_over_time({app=~"api|web"}[1h]))`,
		`count by (app) (rate({app=~"api|web"}[1h]))`,
		`count_over_time({app="web"} | regexp "(?P<method>GET|POST) " [1h])`,
		`sum(count_over_time({app="api"}[1h])) / 2 - 1`,
		`2 ^ 2 * sum(count_over_time({app="api"}[1h]))`,
	}
	for _, q := range metricQueries {
		sq := scoped(q)
		want, lerr := c.instant(t, sq, end)
		res, err := RunQuery(context.Background(), sq, lines, Limits{Start: end, End: end})
		var pe *PipelineError
		if lerr != nil || err != nil {
			if lerr == nil || !errors.As(err, &pe) || !strings.Contains(lerr.Error(), "pipeline error") {
				t.Fatalf("%s: loki error %v, ours %v", sq, lerr, err)
			}
			continue
		}
		got := map[string]float64{}
		for _, s := range res.Vector {
			got[comparableLabels(s.Metric.Map())] = s.F
		}
		if len(got) != len(want) {
			t.Fatalf("%s: ours %v, loki %v", sq, got, want)
		}
		prog, err := CompileRule(sq, bundle.Budget{})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines {
			prog.Observe(l.Labels, l.Time, l.Text)
		}
		vec, err := prog.Eval(end)
		if err != nil {
			t.Fatalf("%s: rule evaluation: %v", sq, err)
		}
		if len(vec) != len(want) {
			t.Fatalf("%s: rule %v, loki %v", sq, vec, want)
		}
		for _, smp := range vec {
			if w, ok := want[comparableLabels(smp.Metric.Map())]; !ok || math.Abs(w-smp.F) > 1e-9 {
				t.Fatalf("%s: rule %v, loki %v", sq, vec, want)
			}
		}
		keys := make([]string, 0, len(want))
		for k := range want {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if g, ok := got[k]; !ok || math.Abs(g-want[k]) > 1e-9 {
				t.Fatalf("%s: ours %v, loki %v", sq, got, want)
			}
		}
	}
	for _, q := range []string{
		`sum(count_over_time({app="api"}[20s]))`,
		`sum by (pod) (rate({app=~"api|web"} |= "e" [7s]))`,
	} {
		sq := scoped(q)
		step := 5 * time.Second
		rs, re := start.Truncate(step), end.Truncate(step)
		want := c.rangeQuery(t, sq, rs, re, step)
		res, err := RunQuery(context.Background(), sq, lines, Limits{Start: rs, End: re, Step: step})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, sr := range res.Matrix {
			got[comparableLabels(sr.Metric.Map())] = fmt.Sprint(sr.Floats)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s:\nours %v\nloki %v", sq, got, want)
		}
	}
}

func (c *lokiClient) rangeQuery(t *testing.T, q string, start, end time.Time, step time.Duration) map[string]string {
	t.Helper()
	v := url.Values{"query": {q}, "start": {strconv.FormatInt(start.UnixNano(), 10)}, "end": {strconv.FormatInt(end.UnixNano(), 10)},
		"step": {strconv.FormatFloat(step.Seconds(), 'f', -1, 64)}}
	code, b := c.do(t, http.MethodGet, "/loki/api/v1/query_range", v, nil)
	if code != http.StatusOK {
		t.Fatalf("loki %d: %s", code, b)
	}
	var res lokiResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	var mat []struct {
		Metric map[string]string `json:"metric"`
		Values [][2]any          `json:"values"`
	}
	if err := json.Unmarshal(res.Data.Result, &mat); err != nil {
		t.Fatalf("loki matrix: %v: %s", err, b)
	}
	out := map[string]string{}
	for _, s := range mat {
		var pts []promqlPoint
		for _, v := range s.Values {
			ts, _ := v[0].(float64)
			f, err := strconv.ParseFloat(fmt.Sprint(v[1]), 64)
			if err != nil {
				t.Fatal(err)
			}
			pts = append(pts, promqlPoint{T: int64(math.Round(ts * 1000)), F: f})
		}
		out[comparableLabels(s.Metric)] = fmt.Sprint(pts)
	}
	return out
}

// promqlPoint prints like promql.FPoint so both sides compare as strings.
type promqlPoint struct {
	T int64
	F float64
}

func (p promqlPoint) String() string { return promql.FPoint{T: p.T, F: p.F}.String() }
