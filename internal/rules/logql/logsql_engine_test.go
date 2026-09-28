package logql

import (
	"context"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/logstorage"
)

// engineFixture exercises substring versus word matching, parsers, quoting and missing pattern literals.
func engineFixture(base time.Time) Lines {
	api0 := map[string]string{"app": "api", "pod": "p0"}
	api1 := map[string]string{"app": "api", "pod": "p1"}
	web := map[string]string{"app": "web", "pod": "w0"}
	texts := []struct {
		stream map[string]string
		text   string
	}{
		{api0, `level=error msg="connection error" status=500 dur=1.5s`},
		{api1, `level=info msg="errors happened" status=200`},
		{api0, `ERROR upper case`},
		{api1, `a terror attack`},
		{api0, `{"level":"warn","status":404,"user":{"id":"u1"}}`},
		{api1, `{"level":"error","status":503,"tags":["x"]}`},
		{api0, `not json level=debug`},
		{api1, "line one\nline two error"},
		{web, `10.0.0.1 - frank "GET /index.html HTTP/1.1" 200`},
		{web, `10.0.0.2 - - "POST /api" 500`},
		{web, `10.0.0.3 - bob "GET /x`},
		{web, `"quoted start" - x "A B C" 1`},
		{web, `GET /health`},
		{web, `POST GET /x`},
		{api0, `{"level":null,"tags":["x"],"n":1.50,"b":true,"s":"[x"}`},
		{api1, `k="a \"q\" b" e= bare w=1 x=y=z u="unterminated`},
		{api0, `  {"level":"error","lead":"space"}`},
		{api0, `{"pod":"x","a-b":1,"nested":{"k":"v","deep":{"z":true}},"level":""}`},
		{api1, `size=2KB latency=250ms level=warn`},
	}
	var ls Lines
	for i, tx := range texts {
		ls = append(ls, Line{Labels: tx.stream, Time: base.Add(time.Duration(i) * time.Second), Text: tx.text})
	}
	return ls
}

type vlEngine struct {
	s *logstorage.Storage
}

func openEngine(t *testing.T, lines Lines) *vlEngine {
	t.Helper()
	s := logstorage.MustOpenStorage(t.TempDir(), &logstorage.StorageConfig{Retention: 7 * 24 * time.Hour, FutureRetention: 24 * time.Hour})
	t.Cleanup(s.MustClose)
	for _, l := range lines {
		lr := logstorage.GetLogRows(nil, nil, nil, nil, "")
		var fields []logstorage.Field
		names := make([]string, 0, len(l.Labels))
		for k := range l.Labels {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fields = append(fields, logstorage.Field{Name: k, Value: l.Labels[k]})
		}
		fields = append(fields, logstorage.Field{Name: "_msg", Value: l.Text})
		lr.MustAdd(logstorage.TenantID{}, l.Time.UnixNano(), fields, len(names))
		s.MustAddRows(lr)
		logstorage.PutLogRows(lr)
	}
	s.DebugFlush()
	return &vlEngine{s: s}
}

func (e *vlEngine) query(t *testing.T, q string, ts time.Time) []map[string]string {
	t.Helper()
	pq, err := logstorage.ParseQueryAtTimestamp(q, ts.UnixNano())
	if err != nil {
		t.Fatalf("LogsQL %q does not parse: %v", q, err)
	}
	var mu sync.Mutex
	var rows []map[string]string
	qctx := logstorage.NewQueryContext(context.Background(), &logstorage.QueryStats{}, []logstorage.TenantID{{}}, pq, false, nil)
	err = e.s.RunQuery(qctx, func(_ uint, db *logstorage.DataBlock) {
		mu.Lock()
		defer mu.Unlock()
		for i := 0; i < db.RowsCount(); i++ {
			row := map[string]string{}
			for _, c := range db.Columns {
				if v := c.Values[i]; v != "" {
					row[strings.Clone(c.Name)] = strings.Clone(v)
				}
			}
			rows = append(rows, row)
		}
	})
	if err != nil {
		t.Fatalf("LogsQL %q failed: %v", q, err)
	}
	return rows
}

func streamLabels(t *testing.T, s string) map[string]string {
	t.Helper()
	e, err := ParseExpr(s)
	if err != nil {
		t.Fatalf("stream %q: %v", s, err)
	}
	m := map[string]string{}
	for _, mt := range e.(*LogExpr).Matchers {
		m[mt.Name] = mt.Value
	}
	return m
}

func TestLogsQLEngineLogQueries(t *testing.T) {
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	lines := engineFixture(base)
	vl := openEngine(t, lines)
	end := base.Add(time.Minute)
	const accessPattern = `<ip> - <_> \"<method> <path> <_>\" <status>`
	cases := []struct {
		logql  string
		fields []string
	}{
		{`{app="api"} |= "error"`, nil},
		{`{app="api"} |= "rror at"`, nil},
		{`{app="api"} != "error"`, nil},
		{`{app="api"} |= "error" != "connection"`, nil},
		{`{app="api"} |~ "err(or)?s\\b"`, nil},
		{`{app="api"} |~ "one.line"`, nil},
		{`{app="api"} !~ "(?i)error"`, nil},
		{`{app="api"} |~ ".+"`, nil},
		{`{app="api"} != ""`, nil},
		{`{pod=~"p.*", app!="web"} |= "error"`, nil},
		{`{app="api", app="web"}`, nil},
		{`{app="api"} | pod="p1"`, nil},
		{`{app="api"} | json | pod="p0"`, []string{"pod", "level"}},
		{`{app=~"api|web"} | regexp "(?P<pod>\\S+) - " | pod=~"p.*|10.*"`, []string{"pod"}},
		{`{app="api"} | logfmt | level="error"`, []string{"level", "status", "dur"}},
		{`{app="api"} | logfmt | level=~"err.*|warn" or status="200"`, []string{"level", "status"}},
		{`{app="api"} | logfmt | level!="info"`, []string{"level"}},
		{`{app="api"} | json | level="error"`, []string{"level", "status"}},
		{`{app="api"} | json | level!="error"`, []string{"level"}},
		{`{app="api"} | json | level=~"w.*"`, []string{"level", "status"}},
		{`{app="api"} | json | level!=""`, []string{"level", "n", "b", "s"}},
		{`{app="api"} | logfmt | k!=""`, []string{"k", "e", "bare", "w"}},
		{`{app="api"} | json | n="1.50" b="true" s="[x"`, []string{"n", "b", "s"}},
		{`{app="api"} | json | lead="space"`, []string{"lead"}},
		{`{app="api"} |~ "^line two"`, nil},
		{`{app="api"} | logfmt | level=~"err"`, nil},
		{`{app="api"} | json | user!=""`, nil},
		{`{app="web"} | pattern "` + accessPattern + `"`, []string{"ip", "method", "path", "status"}},
		{`{app="web"} | pattern "` + accessPattern + `" | status="200" or method="GET"`, []string{"ip", "method", "path", "status"}},
		{`{app="web"} | pattern "GET <path>"`, []string{"path"}},
		{`{app="web"} | pattern "<ip> - <user> \"<rest>"`, []string{"ip", "user", "rest"}},
		{`{app="web"} | regexp "(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) - (?P<user>\\S+)"`, []string{"ip", "user"}},
		{`{app="web"} | regexp "(?P<method>GET|POST) (?P<path>/\\S*)" | path=~"/(x|api.*)"`, []string{"method", "path"}},
	}
	for _, tc := range cases {
		t.Run(tc.logql, func(t *testing.T) {
			logsql, err := ToLogsQL(tc.logql)
			if err != nil {
				t.Fatalf("ToLogsQL: %v", err)
			}
			res, err := RunQuery(context.Background(), tc.logql, lines, Limits{Start: base.Add(-time.Minute), End: end})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]map[string]string{}
			for _, l := range res.Lines {
				f := map[string]string{}
				for _, n := range tc.fields {
					if v := l.Labels.Get(n); v != "" {
						f[n] = v
					}
				}
				want[l.Text] = f
			}
			got := map[string]map[string]string{}
			for _, row := range vl.query(t, logsql, end) {
				f := map[string]string{}
				for _, n := range tc.fields {
					if v := row[n]; v != "" {
						f[n] = v
					}
				}
				got[row["_msg"]] = f
			}
			if len(got) != len(want) {
				t.Fatalf("LogsQL %s\nmatched %d lines %v\nLogQL matched %d lines %v", logsql, len(got), got, len(want), want)
			}
			for msg, wf := range want {
				gf, ok := got[msg]
				if !ok {
					t.Fatalf("LogsQL %s misses %q", logsql, msg)
				}
				for _, n := range tc.fields {
					if gf[n] != wf[n] {
						t.Fatalf("LogsQL %s: %q field %s = %q, LogQL label = %q", logsql, msg, n, gf[n], wf[n])
					}
				}
			}
		})
	}
}

func TestLogsQLEngineMetricQueries(t *testing.T) {
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	lines := engineFixture(base)
	vl := openEngine(t, lines)
	end := base.Add(time.Minute)
	for _, q := range []string{
		`sum by (pod) (count_over_time({app="api"} |= "error" [1h]))`,
		`sum(count_over_time({app="api"} |= "nomatch" [1h]))`,
		`sum(count_over_time({app="api"} |= "error" [1h])) > 2`,
		`sum by (level) (count_over_time({app="api"} | logfmt [1h]))`,
		`sum by (pod) (bytes_over_time({app="api"}[1h]))`,
		`sum by (pod) (rate({app="api"}[1h])) * 3600`,
		`max by (app) (count_over_time({app=~"api|web"}[1h]))`,
		`avg(count_over_time({app=~"api|web"}[1h]))`,
		`count(count_over_time({app=~"api|web"}[1h]))`,
		`sum by (method) (count_over_time({app="web"} | pattern "<ip> - <_> \"<method> <path> <_>\" <status>" [1h])) > 0`,
		`count_over_time({app="api"} |= "error" [1h])`,
		`count_over_time({app="web"}[20s])`,
		`sum(sum by (pod) (count_over_time({app=~"api|web"}[1h]))) - 1`,
	} {
		t.Run(q, func(t *testing.T) {
			logsql, err := ToLogsQL(q)
			if err != nil {
				t.Fatalf("ToLogsQL: %v", err)
			}
			res, err := RunQuery(context.Background(), q, lines, Limits{Start: end, End: end})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]float64{}
			for _, s := range res.Vector {
				want[s.Metric.String()] = s.F
			}
			got := map[string]float64{}
			for _, row := range vl.query(t, logsql, end) {
				ls := map[string]string{}
				for k, v := range row {
					switch k {
					case LogsQLValueField:
					case "_stream":
						for sk, sv := range streamLabels(t, v) {
							ls[sk] = sv
						}
					default:
						ls[k] = v
					}
				}
				v, err := strconv.ParseFloat(row[LogsQLValueField], 64)
				if err != nil {
					t.Fatalf("value %q: %v", row[LogsQLValueField], err)
				}
				got[labelsString(ls)] = v
			}
			if len(got) != len(want) {
				t.Fatalf("LogsQL %s = %v, LogQL = %v", logsql, got, want)
			}
			for k, w := range want {
				if g, ok := got[k]; !ok || math.Abs(g-w) > 1e-9 {
					t.Fatalf("LogsQL %s = %v, LogQL = %v", logsql, got, want)
				}
			}
		})
	}
}

func labelsString(m map[string]string) string {
	var ls []string
	for k := range m {
		ls = append(ls, k)
	}
	sort.Strings(ls)
	parts := make([]string, len(ls))
	for i, k := range ls {
		parts[i] = k + "=" + strconv.Quote(m[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// TestLogsQLDocumentedDifferences pins the data-dependent differences listed in docs/logql-subset.md.
func TestLogsQLDocumentedDifferences(t *testing.T) {
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	stream := map[string]string{"app": "api"}
	lines := Lines{
		{Labels: stream, Time: base, Text: `{"tags":["x"]}`},
		{Labels: stream, Time: base.Add(time.Second), Text: `x=y=z`},
		{Labels: stream, Time: base.Add(2 * time.Second), Text: `u="unterminated`},
	}
	vl := openEngine(t, lines)
	end := base.Add(time.Minute)
	for _, tc := range []struct{ logql, field, vlValue string }{
		{`{app="api"} | json | tags!=""`, "tags", `["x"]`},
		{`{app="api"} | logfmt | x!=""`, "x", "y=z"},
		{`{app="api"} | logfmt | u!=""`, "u", `"unterminated`},
	} {
		res, err := RunQuery(context.Background(), tc.logql, lines, Limits{Start: base, End: end})
		if err != nil || len(res.Lines) != 0 {
			t.Fatalf("%s: LogQL must extract nothing, got %+v %v", tc.logql, res, err)
		}
		logsql, err := ToLogsQL(tc.logql)
		if err != nil {
			t.Fatal(err)
		}
		rows := vl.query(t, logsql, end)
		if len(rows) != 1 || rows[0][tc.field] != tc.vlValue {
			t.Fatalf("%s: documented LogsQL behavior changed: %v", logsql, rows)
		}
	}
	metric := `sum(count_over_time({app="api"} | json [1h]))`
	_, err := RunQuery(context.Background(), metric, lines, Limits{Start: end, End: end})
	var pe *PipelineError
	if !errors.As(err, &pe) {
		t.Fatalf("LogQL must fail on JSON parser errors, got %v", err)
	}
	logsql, err := ToLogsQL(metric)
	if err != nil {
		t.Fatal(err)
	}
	if rows := vl.query(t, logsql, end); len(rows) != 1 || rows[0][LogsQLValueField] != "3" {
		t.Fatalf("documented LogsQL behavior changed: %v", rows)
	}
}
