package logql

import (
	"errors"
	"strings"
	"testing"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/logstorage"
)

var translations = []struct {
	name, logql, logsql string
	// parsed lists fragments the VictoriaLogs parser's canonical form must contain.
	parsed []string
}{
	{"stream selector to stream filter", `{app="api", env!="dev", ns=~"prod-.*", pod!~"canary.*"}`,
		`_stream:{"app"="api","env"!="dev","ns"=~"prod-.*","pod"!~"canary.*"}`,
		[]string{`{app="api",env!="dev",ns=~"prod-.*",pod!~"canary.*"}`}},
	{"substring not word", `{app="api"} |= "rror"`,
		`_stream:{"app"="api"} *"rror"*`,
		[]string{`*rror*`}},
	{"substring phrase with spaces", `{app="api"} |= "connection reset by"`,
		`_stream:{"app"="api"} *"connection reset by"*`,
		[]string{`*"connection reset by"*`}},
	{"negated substring", `{app="api"} != "healthz"`,
		`_stream:{"app"="api"} !*"healthz"*`,
		[]string{`!*healthz*`}},
	{"empty substring is dropped", `{app="api"} |= ""`,
		`_stream:{"app"="api"}`, nil},
	{"negated empty substring matches nothing", `{app="api"} != ""`,
		`_stream:{"app"="api"} !~".*"`, nil},
	{"regexp", `{app="api"} |~ "code=5\\d\\d" !~ "(?i)debug"`,
		`_stream:{"app"="api"} ~"(?-s:code=5\\d\\d)" !~"(?-s:(?i)debug)"`,
		[]string{`~"(?-s:code=5\\d\\d)"`, `!~"(?-s:(?i)debug)"`}},
	{"regexp dot does not match newline", `{app="api"} |~ ".+"`,
		`_stream:{"app"="api"} ~"(?-s:.+)"`, []string{`~"(?-s:.+)"`}},
	{"json", `{app="api"} | json`,
		`_stream:{"app"="api"} | copy _msg as "exitmesh.json" | replace_regexp ("^[ \\t\\r\\n]+", "") at "exitmesh.json" | unpack_json from "exitmesh.json" keep_original_fields | delete "exitmesh.json"`,
		[]string{"unpack_json from exitmesh.json keep_original_fields"}},
	{"logfmt with extracted label field filter", `{app="api"} |= "x" | logfmt | level="error" |= "y"`,
		`_stream:{"app"="api"} *"x"* | unpack_logfmt keep_original_fields | filter "level":="error" *"y"*`,
		[]string{"unpack_logfmt keep_original_fields", `level:=error`, `*y*`}},
	{"label filter operators", `{app="api"} | logfmt | a="1" or b!="2", c=~"x.*" d!~"y"`,
		`_stream:{"app"="api"} | unpack_logfmt keep_original_fields | filter "a":="1" or ((!"b":="2" "c":~"^(?s:x.*)$") !"d":~"^(?s:y)$")`,
		[]string{`a:=1 or !b:=2 c:~"^(?s:x.*)$" !d:~"^(?s:y)$"`}},
	{"stream label filter before a parser", `{app="api"} | pod_name="p1"`,
		`_stream:{"app"="api"} "pod_name":="p1"`, []string{`pod_name:=p1`}},
	{"underscore label guaranteed by selector", `{app="api", k8s_app="web"} | json | k8s_app="web"`,
		`_stream:{"app"="api","k8s_app"="web"} | copy _msg as "exitmesh.json" | replace_regexp ("^[ \\t\\r\\n]+", "") at "exitmesh.json" | unpack_json from "exitmesh.json" keep_original_fields | delete "exitmesh.json" | filter "k8s_app":="web"`, nil},
	{"pattern", `{app="api"} | pattern "<ip> - <_> \"<method> <path>\" <status>"`,
		`_stream:{"app"="api"} | extract "<plain:ip> - <plain:exitmesh.skip.0> &#34;<plain:method> <plain:path>&#34; <plain:status>" keep_original_fields` +
			` | extract if (!_msg:~"^(?s:.*) - ") "<plain:ip>" keep_original_fields` +
			` | extract if (_msg:~"^(?s:.*) - (?s:.*) \"" !_msg:~"^(?s:.*) - (?s:.*) \"(?s:.*) ") "<plain:ip> - <plain:exitmesh.skip.0> &#34;<plain:method>" keep_original_fields` +
			` | extract if (_msg:~"^(?s:.*) - (?s:.*) \"(?s:.*) " !_msg:~"^(?s:.*) - (?s:.*) \"(?s:.*) (?s:.*)\" ") "<plain:ip> - <plain:exitmesh.skip.0> &#34;<plain:method> <plain:path>" keep_original_fields` +
			` | delete "exitmesh.skip.0"`, nil},
	{"pattern leading literal is anchored", `{app="api"} | pattern "GET <path>"`,
		`_stream:{"app"="api"} | extract if (_msg:="GET "*) "GET <plain:path>" keep_original_fields`,
		[]string{`extract if (="GET "*)`}},
	{"regexp parser", `{app="api"} | regexp "(?P<method>\\w+) (?P<path>\\S+)"`,
		`_stream:{"app"="api"} | extract_regexp "(?-s:(?P<method>\\w+) (?P<path>\\S+))" keep_original_fields`, nil},
	{"count_over_time by stream", `count_over_time({app="api"} |= "error" [5m])`,
		`_time:(now-5m,now] _stream:{"app"="api"} *"error"* | stats by (_stream) count() as value`,
		[]string{`_time:(now-5m,now]`, `stats by (_stream) count(*) as value`}},
	{"sum by extracted label", `sum by (level) (count_over_time({app="api"} | logfmt [1h]))`,
		`_time:(now-1h,now] _stream:{"app"="api"} | unpack_logfmt keep_original_fields | stats by ("level") count() as value`, nil},
	{"global sum drops empty row", `sum(count_over_time({app="api"}[5m])) > 10`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats count() as "exitmesh.rows", count() as value | filter "exitmesh.rows":>0 | delete "exitmesh.rows" | filter value:>10`, nil},
	{"rate", `sum by (pod) (rate({app="api"}[2m])) * 60`,
		`_time:(now-2m,now] _stream:{"app"="api"} | stats by ("pod") count() as value | math (value / 120) as value | math (value * 60) as value`, nil},
	{"bytes_over_time", `bytes_over_time({app="api"}[30s])`,
		`_time:(now-30s,now] _stream:{"app"="api"} | stats by (_stream) sum_len(_msg) as value`, nil},
	{"max over series", `max by (ns) (count_over_time({app="api"}[5m]))`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats by (_stream, "ns") count() as value | stats by ("ns") max(value) as value`, nil},
	{"count of series", `count(rate({app="api"}[5m]))`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats by (_stream) count() as value | math (value / 300) as value | stats count() as "exitmesh.rows", count() as value | filter "exitmesh.rows":>0 | delete "exitmesh.rows"`, nil},
	{"nested aggregation", `sum(sum by (pod) (count_over_time({app="api"}[5m])))`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats by ("pod") count() as value | stats count() as "exitmesh.rows", sum(value) as value | filter "exitmesh.rows":>0 | delete "exitmesh.rows"`, nil},
	{"scalar on the left", `100 <= sum by (pod) (count_over_time({app="api"}[5m]))`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats by ("pod") count() as value | filter value:>=100`, nil},
	{"equality comparison", `sum by (pod) (count_over_time({app="api"}[5m])) == 3`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats by ("pod") count() as value | filter value:>=3 value:<=3`, nil},
	{"inequality comparison", `sum by (pod) (count_over_time({app="api"}[5m])) != 3`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats by ("pod") count() as value | filter !(value:>=3 value:<=3)`, nil},
	{"folded scalar arithmetic", `2 * 3 - sum by (pod) (count_over_time({app="api"}[5m]))`,
		`_time:(now-5m,now] _stream:{"app"="api"} | stats by ("pod") count() as value | math (6 - value) as value`, nil},
}

func TestToLogsQL(t *testing.T) {
	for _, tc := range translations {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToLogsQL(tc.logql)
			if err != nil {
				t.Fatalf("ToLogsQL(%q): %v", tc.logql, err)
			}
			if got != tc.logsql {
				t.Fatalf("ToLogsQL(%q)\n got %s\nwant %s", tc.logql, got, tc.logsql)
			}
			q, err := logstorage.ParseQueryAtTimestamp(got, 1e18)
			if err != nil {
				t.Fatalf("LogsQL %q does not parse: %v", got, err)
			}
			canon := q.String()
			for _, frag := range tc.parsed {
				if !strings.Contains(canon, frag) {
					t.Fatalf("parsed form %q lacks %q", canon, frag)
				}
			}
		})
	}
}

func TestToLogsQLSubstringNotWord(t *testing.T) {
	got, err := ToLogsQL(`{app="api"} |= "error"`)
	if err != nil {
		t.Fatal(err)
	}
	q, err := logstorage.ParseQuery(got)
	if err != nil {
		t.Fatal(err)
	}
	word, err := logstorage.ParseQuery(`_stream:{"app"="api"} "error"`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(q.String(), " *error*") || strings.HasSuffix(word.String(), "*error*") {
		t.Fatalf("substring %q must differ from the LogsQL word filter %q", q.String(), word.String())
	}
}

func TestToLogsQLTimeWindow(t *testing.T) {
	got, err := ToLogsQL(`count_over_time({app="api"}[5m])`)
	if err != nil {
		t.Fatal(err)
	}
	const now = int64(1_700_000_000_000_000_000)
	q, err := logstorage.ParseQueryAtTimestamp(got, now)
	if err != nil {
		t.Fatal(err)
	}
	if lo, hi := q.GetFilterTimeRange(); lo != now-300e9+1 || hi != now {
		t.Fatalf("window [%d, %d] is not LogQL's (now-5m, now]", lo, hi)
	}
}

func TestToLogsQLRejections(t *testing.T) {
	cases := []struct{ logql, construct, reason string }{
		{`{app="api"} | json code="resp.code"`, "json extraction parameters", "no JSON path extraction"},
		{`{app="api"} | json | logfmt`, "a second parser stage", "overwrite"},
		{`{app="api"} | json | status_code="500"`, `extracted label "status_code"`, "sanitizes keys"},
		{`{app="api"} | logfmt | status >= 500`, `number label filter "status >= 500"`, "__error__"},
		{`{app="api"} | logfmt | latency > 1s`, `duration label filter "latency > 1s"`, "__error__"},
		{`{app="api"} | json | __error__=""`, "label filter on __error__", "records no parser errors"},
		{`{app="api"} | _msg="x"`, `label "_msg"`, "reserves field names"},
		{`{app="api"} | pattern "<_ip> x"`, `pattern capture "_ip"`, "reserves field names"},
		{`{app="api"} | regexp "(?P<_ip>\\S+)"`, `regexp capture "_ip"`, "reserves field names"},
		{`count_over_time({app="api"} | logfmt [5m])`, "count_over_time with a parser and no enclosing sum by", "every extracted label"},
		{`max(count_over_time({app="api"} | logfmt [5m]))`, "max over a range aggregation with a parser", "series identity"},
		{`topk(3, count_over_time({app="api"}[5m]))`, "topk", "tie semantics"},
		{`sum without (pod) (count_over_time({app="api"}[5m]))`, "without grouping", "all fields except"},
		{`sum by (value) (count_over_time({app="api"}[5m]))`, `label "value"`, "reserved for the translated sample value"},
		{`sum(count_over_time({app="api"}[5m])) > bool 1`, "bool modifier", "no boolean"},
		{`sum(count_over_time({app="api"}[5m])) % 2`, `operator "%"`, "no verified"},
		{`1 / sum(count_over_time({app="api"}[5m]))`, "division by a sample value", "infinities"},
		{`sum(count_over_time({app="api"}[5m])) / 0`, "division by zero", "infinities"},
	}
	for _, tc := range cases {
		_, err := ToLogsQL(tc.logql)
		var te *TranslationError
		if !errors.As(err, &te) {
			t.Errorf("ToLogsQL(%q) = %v, want a TranslationError", tc.logql, err)
			continue
		}
		if te.Construct != tc.construct || !strings.Contains(te.Reason, tc.reason) {
			t.Errorf("ToLogsQL(%q) = %q / %q, want %q / %q", tc.logql, te.Construct, te.Reason, tc.construct, tc.reason)
		}
	}
	var ue *UnsupportedError
	if _, err := ToLogsQL(`{app="api"} | line_format "x"`); !errors.As(err, &ue) {
		t.Fatalf("queries outside the subset must fail parsing, got %v", err)
	}
}
