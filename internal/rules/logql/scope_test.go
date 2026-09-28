package logql

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
)

func TestInjectScope(t *testing.T) {
	scope := []*labels.Matcher{
		labels.MustNewMatcher(labels.MatchEqual, "namespace", "shop"),
		labels.MustNewMatcher(labels.MatchEqual, "node", "n1"),
	}
	cases := []struct{ in, want string }{
		{`{app="api"}`, `{app="api", namespace="shop", node="n1"}`},
		{`{namespace="other"} |= "x"`, `{namespace="other", namespace="shop", node="n1"} |= "x"`},
		{`{namespace=~".+"}`, `{namespace=~".+", namespace="shop", node="n1"}`},
		{`sum by (pod) (rate({app="api"} | json | namespace="other" [5m])) > 1`,
			`sum by (pod) (rate({app="api", namespace="shop", node="n1"} | json | namespace="other" [5m])) > 1`},
		{`topk(3, count_over_time({app="api"}[1m]))`, `topk(3, count_over_time({app="api", namespace="shop", node="n1"} [1m]))`},
	}
	for _, tc := range cases {
		got, err := InjectScope(tc.in, scope)
		if err != nil {
			t.Fatalf("InjectScope(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("InjectScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
		e, err := ParseExpr(got)
		if err != nil {
			t.Fatal(err)
		}
		for _, log := range logExprs(e) {
			for _, sm := range scope {
				found := false
				for _, m := range log.Matchers {
					found = found || (m.Name == sm.Name && m.Type == sm.Type && m.Value == sm.Value)
				}
				if !found {
					t.Fatalf("scope matcher %s missing from %q", sm, got)
				}
			}
		}
	}
}

func TestInjectScopeCannotWiden(t *testing.T) {
	src := Lines{
		{Labels: map[string]string{"namespace": "shop", "app": "api"}, Time: t0, Text: "in scope"},
		{Labels: map[string]string{"namespace": "other", "app": "api"}, Time: t0, Text: "out of scope"},
	}
	scope := []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "namespace", "shop")}
	lim := Limits{Start: t0, End: t0.Add(time.Second)}
	for _, q := range []string{
		`{app="api"}`,
		`{namespace=~".+"}`,
		`{namespace="other"}`,
		`{namespace!="shop", app="api"}`,
		`{app="api"} | json | namespace="other"`,
	} {
		scoped, err := InjectScope(q, scope)
		if err != nil {
			t.Fatal(err)
		}
		res, err := RunQuery(context.Background(), scoped, src, lim)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range res.Lines {
			if l.Labels.Get("namespace") != "shop" {
				t.Fatalf("%q escaped its scope: %v", scoped, l)
			}
		}
	}
}

func TestInjectScopeRejects(t *testing.T) {
	scope := []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "namespace", "shop")}
	if _, err := InjectScope(`{app="api"} | line_format "x"`, scope); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("got %v", err)
	}
	if _, err := InjectScope(`{app="api"} |= "x" or "y"`, scope); err == nil {
		t.Fatal("a query the parser rejects must be rejected")
	}
	if _, err := InjectScope(`{app="api"}`, []*labels.Matcher{{Type: labels.MatchEqual, Name: "bad-name", Value: "x"}}); err == nil {
		t.Fatal("invalid scope label names must be rejected")
	}
	if _, err := InjectScope(`{app="api"}`, []*labels.Matcher{nil}); err == nil {
		t.Fatal("nil scope matchers must be rejected")
	}
	if _, err := InjectScope(`{app="api"}`, []*labels.Matcher{{Type: labels.MatchRegexp, Name: "a", Value: "("}}); err == nil {
		t.Fatal("invalid scope regexps must be rejected")
	}
}
