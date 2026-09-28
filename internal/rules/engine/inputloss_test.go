package engine

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
)

type pt struct {
	l labels.Labels
	v float64
}

// scrapeAt replaces the store with one sample per point at ts, stale-marking series left out.
func scrapeAt(m *MemSeries, ts time.Time, pts ...pt) {
	ss := make([]Series, len(pts))
	for i, p := range pts {
		ss[i] = Series{Labels: p.l, Samples: []Sample{{T: timestamp.FromTime(ts), F: p.v}}}
	}
	m.Replace("tsdb", ss)
}

type lossStep struct {
	at   time.Duration
	pts  []pt
	want []string
}

func TestPartialInputLossIsStaleNotResolved(t *testing.T) {
	x := func(inst, job string) labels.Labels {
		return labels.FromStrings("__name__", "x", "instance", inst, "job", job, "host", inst)
	}
	fs := func(name, inst string) labels.Labels {
		return labels.FromStrings("__name__", name, "instance", inst, "job", "node", "mountpoint", "/")
	}
	uname := func(inst string) labels.Labels {
		return labels.FromStrings("__name__", "node_uname_info", "instance", inst, "job", "node", "nodename", "host-"+inst)
	}
	disk := func(inst string, avail float64) []pt {
		return []pt{{fs("node_filesystem_avail_bytes", inst), avail}, {fs("node_filesystem_size_bytes", inst), 100}, {uname(inst), 1}}
	}
	cases := []struct {
		name   string
		expr   string
		labels map[string]string
		steps  []lossStep
	}{
		{
			name: "target A disappears while B still exports the metric",
			expr: `x > 1`,
			steps: []lossStep{
				{0, []pt{{x("a", "node"), 5}, {x("b", "node"), 0}}, []string{TransitionFiring}},
				{time.Minute, []pt{{x("b", "node"), 0}}, []string{TransitionStale}},
				{10 * time.Minute, []pt{{x("b", "node"), 0}}, []string{}},
				{11 * time.Minute, []pt{{x("a", "node"), 0}, {x("b", "node"), 0}}, []string{TransitionResolved}},
			},
		},
		{
			name: "series stays present and drops below the threshold",
			expr: `x > 1`,
			steps: []lossStep{
				{0, []pt{{x("a", "node"), 5}, {x("b", "node"), 0}}, []string{TransitionFiring}},
				{time.Minute, []pt{{x("a", "node"), 0}, {x("b", "node"), 0}}, []string{TransitionResolved}},
			},
		},
		{
			name: "aggregation group loses every member",
			expr: `sum by (job) (x) > 10`,
			steps: []lossStep{
				{0, []pt{{x("a1", "j1"), 6}, {x("a2", "j1"), 6}, {x("b", "j2"), 1}}, []string{TransitionFiring}},
				{time.Minute, []pt{{x("b", "j2"), 1}}, []string{TransitionStale}},
				{2 * time.Minute, []pt{{x("a1", "j1"), 1}, {x("a2", "j1"), 1}, {x("b", "j2"), 1}}, []string{TransitionResolved}},
			},
		},
		{
			name:   "join target disappears; a rule label overrides an input label",
			expr:   `(1 - node_filesystem_avail_bytes / node_filesystem_size_bytes) * on(instance) group_left(nodename) node_uname_info > 0.9`,
			labels: map[string]string{"job": "infra"},
			steps: []lossStep{
				{0, append(disk("a", 5), disk("b", 50)...), []string{TransitionFiring}},
				{time.Minute, disk("b", 50), []string{TransitionStale}},
				{2 * time.Minute, append(disk("a", 50), disk("b", 50)...), []string{TransitionResolved}},
			},
		},
		{
			name: "label_replace rewrites an input label",
			expr: `label_replace(x, "instance", "$1:9100", "host", "(.+)") > 1`,
			steps: []lossStep{
				{0, []pt{{x("a", "node"), 5}, {x("b", "node"), 0}}, []string{TransitionFiring}},
				{time.Minute, []pt{{x("b", "node"), 0}}, []string{TransitionStale}},
				{2 * time.Minute, []pt{{x("a", "node"), 0}, {x("b", "node"), 0}}, []string{TransitionResolved}},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := NewMemSeries(time.Hour, func() time.Time { return t0 })
			r := promRule("r", c.expr, 0, 0)
			r.Labels = c.labels
			e, s := newTestEngine(t, Options{Role: RoleHost, Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
			for _, st := range c.steps {
				scrapeAt(m, at(st.at), st.pts...)
				eval(t, e, at(st.at))
				evs := only(s.take(), "r")
				if got := transitions(evs); !slices.Equal(got, st.want) {
					t.Fatalf("at %s: transitions %v, want %v", st.at, got, st.want)
				}
				for _, ev := range evs {
					if ev.Transition == TransitionStale && !ev.Incomplete {
						t.Fatalf("stale event is not incomplete: %+v", ev)
					}
					if ev.Transition == TransitionResolved && ev.Incomplete {
						t.Fatalf("resolution from incomplete evaluation: %+v", ev)
					}
				}
				if slices.Equal(st.want, []string{TransitionStale}) {
					if rs := stateOf(e, "r"); rs.State != StateStale || !strings.Contains(rs.Reason, "input series") || rs.Firing != 1 {
						t.Fatalf("rule state %+v", rs)
					}
				}
			}
		})
	}
}

func TestInstanceInputChecksAreBounded(t *testing.T) {
	x := func(inst string, v float64) pt { return pt{labels.FromStrings("__name__", "x", "instance", inst), v} }
	m := NewMemSeries(time.Hour, func() time.Time { return t0 })
	r := promRule("r", `x > 1`, 0, 0)
	r.Meta.Budget.MaxSeries = 2
	e, s := newTestEngine(t, Options{Role: RoleHost, Queryable: m}, mkBundle("v1", nil, []bundle.AlertRule{r}, nil))
	all := func(v float64) []pt { return []pt{x("a", v), x("b", v), x("c", v), x("d", v)} }
	for _, st := range []lossStep{
		{0, []pt{x("a", 5), x("b", 5)}, []string{TransitionFiring, TransitionFiring}},
		{time.Minute, []pt{x("c", 5), x("d", 5)}, []string{TransitionStale, TransitionStale, TransitionFiring, TransitionFiring}},
		{2 * time.Minute, all(0), []string{TransitionResolved, TransitionResolved, TransitionStale, TransitionStale}},
		{3 * time.Minute, all(0), []string{TransitionResolved, TransitionResolved}},
	} {
		scrapeAt(m, at(st.at), st.pts...)
		eval(t, e, at(st.at))
		if got := transitions(only(s.take(), "r")); !slices.Equal(got, st.want) {
			t.Fatalf("at %s: transitions %v, want %v", st.at, got, st.want)
		}
	}
}
