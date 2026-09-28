package logql

import (
	"testing"
)

func runPipeline(t *testing.T, query string, stream map[string]string, line string) (map[string]string, bool) {
	t.Helper()
	e, err := ParseExpr(query)
	if err != nil {
		t.Fatalf("ParseExpr(%q): %v", query, err)
	}
	p, err := newPipeline(e.(*LogExpr))
	if err != nil {
		t.Fatal(err)
	}
	if !p.matchStream(stream) {
		return nil, false
	}
	st, ok := p.process(stream, line)
	if !ok {
		return nil, false
	}
	return st.labels().Map(), true
}

func TestPipelineStages(t *testing.T) {
	stream := map[string]string{"app": "api", "level": "info"}
	cases := []struct {
		name  string
		query string
		line  string
		ok    bool
		want  map[string]string
	}{
		{"selector mismatch", `{app="web"}`, "x", false, nil},
		{"substring not word", `{app="api"} |= "rror"`, "an error occurred", true, map[string]string{"app": "api", "level": "info"}},
		{"substring case sensitive", `{app="api"} |= "Error"`, "an error occurred", false, nil},
		{"negated substring", `{app="api"} != "health"`, "GET /healthz", false, nil},
		{"empty substring matches all", `{app="api"} |= ""`, "", true, map[string]string{"app": "api", "level": "info"}},
		{"negated empty substring matches none", `{app="api"} != ""`, "x", false, nil},
		{"regex unanchored", `{app="api"} |~ "code=5\\d\\d"`, "status code=503 path=/", true, map[string]string{"app": "api", "level": "info"}},
		{"negated regex", `{app="api"} !~ "(?i)DEBUG"`, "debug: x", false, nil},
		{"chain", `{app="api"} |= "a" |= "b" != "c"`, "a b", true, map[string]string{"app": "api", "level": "info"}},
		{"json flattens and renames conflicts", `{app="api"} | json`,
			`{"level":"error","resp":{"code":503,"ok":false},"tags":["a"],"n":null,"my-key":"v","1st":"x","msg":"a\"b"}`, true,
			map[string]string{"app": "api", "level": "info", "level_extracted": "error", "resp_code": "503", "resp_ok": "false", "my_key": "v", "_1st": "x", "msg": `a"b`}},
		{"json error", `{app="api"} | json`, `not json`, true, map[string]string{"app": "api", "level": "info", "__error__": "JSONParserErr"}},
		{"json array is an error", `{app="api"} | json`, `[1,2]`, true, map[string]string{"app": "api", "level": "info", "__error__": "JSONParserErr"}},
		{"json error filtered", `{app="api"} | json | __error__=""`, `{"a":`, false, nil},
		{"json error kept by explicit filter", `{app="api"} | json | __error__="JSONParserErr"`, `{"a":`, true, map[string]string{"app": "api", "level": "info", "__error__": "JSONParserErr"}},
		{"json params", `{app="api"} | json code="resp.code", first="servers[0]", ua="headers[\"User-Agent\"]", obj="resp", missing="nope"`,
			`{"resp":{"code":503},"servers":["s1","s2"],"headers":{"User-Agent":"curl"}}`, true,
			map[string]string{"app": "api", "level": "info", "code": "503", "first": "s1", "ua": "curl", "obj": `{"code":503}`, "missing": ""}},
		{"json params escapes and leading byte", `{app="api"} | json a="a", n="n", arr="arr"`, `{"a":"x\u00e9\"y","n":null,"arr":["q\"r"]}`, true,
			map[string]string{"app": "api", "level": "info", "a": `xé"y`, "n": "", "arr": `["q"r"]`}},
		{"json params require a JSON start", `{app="api"} | json a="a"`, ` {"a":1}`, true,
			map[string]string{"app": "api", "level": "info", "__error__": "JSONParserErr"}},
		{"json empty string is kept", `{app="api"} | json`, `{"a":""}`, true, map[string]string{"app": "api", "level": "info", "a": ""}},
		{"numeric on empty value is an error", `{app="api"} | json | a > 1`, `{"a":""}`, true,
			map[string]string{"app": "api", "level": "info", "a": "", "__error__": "LabelFilterErr"}},
		{"logfmt", `{app="api"} | logfmt`, `level=error msg="a \"quoted\" value" dur=1.5s empty= bare a-b=1`, true,
			map[string]string{"app": "api", "level": "info", "level_extracted": "error", "msg": `a "quoted" value`, "dur": "1.5s", "a_b": "1"}},
		{"logfmt skips malformed pairs", `{app="api"} | logfmt`, `a=1 c=x=y "q x"=1 d=4 g="v"h=8 i="\\q" k="\q" j=9 e="unterminated f=6`, true,
			map[string]string{"app": "api", "level": "info", "a": "1", "d": "4", "g": "v", "h": "8", "i": `\q`, "j": "9"}},
		{"pattern", `{app="api"} | pattern "<ip> - <_> \"<method> <path> <_>\" <status>"`,
			`10.0.0.1 - frank "GET /index.html HTTP/1.1" 200`, true,
			map[string]string{"app": "api", "level": "info", "ip": "10.0.0.1", "method": "GET", "path": "/index.html", "status": "200"}},
		{"pattern leading literal anchors", `{app="api"} | pattern "GET <path>"`, `POST GET /x`, true, map[string]string{"app": "api", "level": "info"}},
		{"pattern missing literal takes rest", `{app="api"} | pattern "<a> x <b> y <c>"`, `1 x 2 z`, true,
			map[string]string{"app": "api", "level": "info", "a": "1", "b": "2 z"}},
		{"pattern missing literal after skip stops", `{app="api"} | pattern "<a> x <_> y <c>"`, `1 x 2 z`, true,
			map[string]string{"app": "api", "level": "info", "a": "1"}},
		{"regexp", `{app="api"} | regexp "(?P<method>[A-Z]+) (?P<path>\\S+)( (?P<extra>\\d+))?"`, `GET /x`, true,
			map[string]string{"app": "api", "level": "info", "method": "GET", "path": "/x", "extra": ""}},
		{"regexp no match", `{app="api"} | regexp "(?P<n>\\d+)"`, `none`, true, map[string]string{"app": "api", "level": "info"}},
		{"label filter string", `{app="api"} | logfmt | status=~"5.."`, `status=503`, true, map[string]string{"app": "api", "level": "info", "status": "503"}},
		{"label filter regex anchored", `{app="api"} | logfmt | status=~"5."`, `status=503`, false, nil},
		{"label filter absent is empty", `{app="api"} | logfmt | missing=""`, `a=1`, true, map[string]string{"app": "api", "level": "info", "a": "1"}},
		{"numeric", `{app="api"} | logfmt | status >= 500`, `status=503`, true, map[string]string{"app": "api", "level": "info", "status": "503"}},
		{"numeric false", `{app="api"} | logfmt | status >= 500`, `status=404`, false, nil},
		{"numeric missing label drops", `{app="api"} | logfmt | status >= 500`, `a=1`, false, nil},
		{"numeric parse error keeps line", `{app="api"} | logfmt | status >= 500`, `status=abc`, true,
			map[string]string{"app": "api", "level": "info", "status": "abc", "__error__": "LabelFilterErr"}},
		{"numeric parse error filtered", `{app="api"} | logfmt | status >= 500 | __error__=""`, `status=abc`, false, nil},
		{"numeric missing label after error drops", `{app="api"} | json | status >= 500`, `bad`, false, nil},
		{"first error wins", `{app="api"} | logfmt | a > 1 | b > 1`, `a=x b=y`, true,
			map[string]string{"app": "api", "level": "info", "a": "x", "b": "y", "__error__": "LabelFilterErr"}},
		{"duration", `{app="api"} | logfmt | dur > 1s`, `dur=1.5s`, true, map[string]string{"app": "api", "level": "info", "dur": "1.5s"}},
		{"duration false", `{app="api"} | logfmt | dur > 1s`, `dur=900ms`, false, nil},
		{"bytes", `{app="api"} | logfmt | size >= 1KiB`, `size=2KB`, true, map[string]string{"app": "api", "level": "info", "size": "2KB"}},
		{"bytes false", `{app="api"} | logfmt | size >= 1KiB`, `size=1000`, false, nil},
		{"or", `{app="api"} | logfmt | a="1" or b="2"`, `b=2`, true, map[string]string{"app": "api", "level": "info", "b": "2"}},
		{"and", `{app="api"} | logfmt | a="1", b="2"`, `b=2`, false, nil},
		{"stream label filter", `{app="api"} | level="info"`, `x`, true, map[string]string{"app": "api", "level": "info"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := runPipeline(t, tc.query, stream, tc.line)
			if ok != tc.ok {
				t.Fatalf("matched=%v want %v (labels %v)", ok, tc.ok, got)
			}
			if !ok {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("labels %v want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("labels %v want %v", got, tc.want)
				}
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	cases := map[string]uint64{"100": 100, "1KB": 1000, "1kib": 1024, "1.5 MB": 1500000, "2,000B": 2000, "1G": 1e9}
	for in, want := range cases {
		if got, err := parseBytes(in); err != nil || got != want {
			t.Errorf("parseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"abc", "1XB", ""} {
		if _, err := parseBytes(in); err == nil {
			t.Errorf("parseBytes(%q) succeeded", in)
		}
	}
}

func FuzzPipelineLine(f *testing.F) {
	for _, s := range []string{`{"a":{"b":[1,{"c":"d"}]},"e":"fé","g":null}`, ` {"x" : -1.5e3 , "y":true}`, `a=1 b="x \"y\"" c=`, `x=y=z "q"=1`, `10.0.0.1 - frank "GET / HTTP/1.1" 200`, "", `{`, `["a"]`} {
		f.Add(s)
	}
	var pipes []*pipeline
	for _, q := range []string{
		`{a="b"} | json`,
		`{a="b"} | json x="a.b[1].c", y="e", z="[\"g\"]"`,
		`{a="b"} | logfmt | c > 1 or b=~".+"`,
		`{a="b"} | pattern "<ip> - <_> \"<m> <p> <_>\" <s>"`,
		`{a="b"} | regexp "(?P<k>\\w+)=(?P<v>\\S*)"`,
	} {
		e, err := ParseExpr(q)
		if err != nil {
			f.Fatal(err)
		}
		p, err := newPipeline(e.(*LogExpr))
		if err != nil {
			f.Fatal(err)
		}
		pipes = append(pipes, p)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, p := range pipes {
			if st, ok := p.process(map[string]string{"a": "b"}, line); ok {
				_ = st.labels()
			}
		}
	})
}
