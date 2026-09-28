package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const oomGroup = `      - alert: OOMLogged
        expr: sum by (namespace, pod) (count_over_time({namespace="prod", container="app"} |= "OutOfMemory" [1m])) > 0
`

const sidecarGroup = `      - alert: SidecarOOM
        expr: sum by (namespace, pod) (count_over_time({namespace="prod", container="sidecar"} |= "OutOfMemory" [1m])) > 0
`

var oomRule = ruleSpec{id: "oom-logs", class: "logql", scope: "node", file: "loki/app.yaml", group: "app", alert: "OOMLogged", caps: "logs", extra: "    budget:\n      max_series: 100\n    evidence:\n      max_samples: 5\n"}

func logBundle(version string, rules []ruleSpec, groups ...string) map[string]string {
	return bundleFiles(version, rules, map[string]string{"loki/app.yaml": "groups:\n  - name: app\n    interval: 10s\n    rules:\n" + strings.Join(groups, "")})
}

// startLogs starts an agent on a log bundle and waits until the warm-up window is over.
func (h *harness) startLogs(version string) *Agent {
	h.t.Helper()
	a := h.start()
	h.waitBundle(version)
	h.step(time.Minute)
	return a
}

func (h *harness) itemBytes() []byte {
	var all []byte
	for _, k := range []nodeapi.ItemKind{nodeapi.KindFinding, nodeapi.KindMetricFacts, nodeapi.KindSeries} {
		for _, it := range h.coord.received(k) {
			b, err := nodeapi.Marshal(it)
			if err != nil {
				h.t.Fatal(err)
			}
			all = append(all, b...)
		}
	}
	return all
}

func TestLogQLRuleRedactedEvidenceAndNoUnmatchedRetention(t *testing.T) {
	h := newHarness(t, options{caps: "logs"})
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory from before the agent started")
	h.coord.setBundle(h.trust.payload(t, logBundle("l1", []ruleSpec{oomRule}, oomGroup)))
	a := h.startLogs("l1")
	h.waitFor("existing stream opened at its end", func() bool { return a.tailer.Stats().Files >= 1 })
	h.writeLog("prod", "web-1", "uid-web-1", "app",
		"GET /healthz 200 UNMATCHED-MARKER-app", "GET /ready 200 UNMATCHED-MARKER-app", "GET /x 404 UNMATCHED-MARKER-app",
		"OutOfMemory: worker killed password=hunter2secret", "OutOfMemory: worker killed password=hunter2secret",
		"Authorization: Bearer abcdefghijklmnopqrst OutOfMemory again")
	h.writeLog("prod", "web-1", "uid-web-1", "sidecar", "OutOfMemory UNMATCHED-MARKER-sidecar")
	h.writeLog("other", "chatty-1", "uid-chatty-1", "main", "hello UNMATCHED-MARKER-chatty")
	h.waitFor("matched stream read", func() bool { return a.tailer.Stats().Lines >= 6 })
	h.step(10 * time.Second)
	if r := h.rule("oom-logs"); r.Firing != 1 {
		t.Fatalf("oom-logs %+v", r)
	}
	h.waitDelivered()
	if n := a.tailer.Stats().Lines; n != 6 {
		t.Fatalf("tailer delivered %d lines, want only the 6 new lines of the selected stream", n)
	}
	fs := h.coord.findings(t)
	if got := transitions(fs, "oom-logs"); !slices.Equal(got, []string{"firing"}) {
		t.Fatalf("transitions %v", got)
	}
	f := fs[0]
	if f.Labels["namespace"] != "prod" || f.Labels["pod"] != "web-1" || f.Flags&protocol.FindingIncompleteCoverage != 0 {
		t.Fatalf("finding %+v", f)
	}
	var total uint64
	for _, ev := range f.Evidence {
		total += ev.Count
		if !strings.Contains(ev.Text, "<redacted>") || strings.Contains(ev.Text, "UNMATCHED") {
			t.Fatalf("evidence %q is not a redacted matching line", ev.Text)
		}
		if ev.Labels["container"] != "app" || ev.Labels["workload"] != "web" || ev.Labels["workload_kind"] != "Deployment" {
			t.Fatalf("evidence labels %v", ev.Labels)
		}
	}
	if total != 3 {
		t.Fatalf("evidence counts %d, want 3 matched lines", total)
	}
	check := func(stage string) {
		for _, needle := range []string{"UNMATCHED-MARKER", "hunter2secret", "abcdefghijklmnopqrst", "before the agent started"} {
			if hits := scanState(t, h.dir, needle); len(hits) > 0 {
				t.Fatalf("%s: %q retained in %v", stage, needle, hits)
			}
			if bytes.Contains(h.itemBytes(), []byte(needle)) {
				t.Fatalf("%s: %q delivered to the coordinator", stage, needle)
			}
			if strings.Contains(h.logb.String(), needle) {
				t.Fatalf("%s: %q written to diagnostics", stage, needle)
			}
		}
	}
	check("running")
	if err := h.shutdown(); err != nil {
		t.Fatal(err)
	}
	check("stopped")
}

func TestEvidenceOverflowMarksEvidenceLimitedAndKeepsFiring(t *testing.T) {
	h := newHarness(t, options{caps: "logs", ring: "2Ki"})
	h.coord.setBundle(h.trust.payload(t, logBundle("l1", []ruleSpec{oomRule}, oomGroup)))
	a := h.startLogs("l1")
	var lines []string
	for i := range 60 {
		lines = append(lines, fmt.Sprintf("OutOfMemory worker %02d %s", i, strings.Repeat("x", 80)))
	}
	h.writeLog("prod", "web-1", "uid-web-1", "app", lines...)
	h.waitFor("lines read", func() bool { return a.tailer.Stats().Lines >= 60 })
	h.step(10 * time.Second)
	r := h.rule("oom-logs")
	if r.Firing != 1 || r.State != engine.StateEvidenceLimited {
		t.Fatalf("rule %+v, want firing and evidence-limited", r)
	}
	if st := a.ring.Stats(); st.Bytes > st.Ceiling {
		t.Fatalf("ring %d bytes over ceiling %d", st.Bytes, st.Ceiling)
	}
	h.waitDelivered()
	fs := h.coord.findings(t)
	if len(fs) != 1 || fs[0].Flags&protocol.FindingEvidenceLimited == 0 || len(fs[0].Evidence) == 0 || len(fs[0].Evidence) > 5 {
		t.Fatalf("findings %+v", fs)
	}
	if st := a.Status(); st.Coverage["logs.evidence_limited"] != "oom-logs" {
		t.Fatalf("coverage %v", st.Coverage)
	}
	h.writeLog("prod", "web-1", "uid-web-1", "app", lines[:30]...)
	h.waitFor("more lines read", func() bool { return a.tailer.Stats().Lines >= 90 })
	h.step(10 * time.Second)
	if r := h.rule("oom-logs"); r.Firing != 1 {
		t.Fatalf("rule stopped firing after overflow: %+v", r)
	}
	h.waitDelivered()
	if got := transitions(h.coord.findings(t), "oom-logs"); slices.Contains(got, "resolved") {
		t.Fatalf("transitions %v", got)
	}
}

func TestMatchAllRuleRespectsBudgets(t *testing.T) {
	h := newHarness(t, options{caps: "logs", ring: "8Ki"})
	rule := ruleSpec{id: "any-line", class: "logql", scope: "node", file: "loki/app.yaml", group: "app", alert: "AnyLine", caps: "logs",
		extra: "    budget:\n      max_series: 2\n    evidence:\n      max_samples: 3\n"}
	h.coord.setBundle(h.trust.payload(t, logBundle("m1", []ruleSpec{rule}, "      - alert: AnyLine\n        expr: count_over_time({namespace=~\".+\"}[1m]) > 0\n")))
	a := h.start()
	h.waitBundle("m1")
	h.step(time.Minute)
	for i := range 20 {
		line := fmt.Sprintf("line %02d %s", i, strings.Repeat("y", 100))
		h.writeLog("prod", "web-1", "uid-web-1", "app", line)
		h.writeLog("prod", "web-1", "uid-web-1", "sidecar", line)
		h.writeLog("other", "chatty-1", "uid-chatty-1", "main", line)
		h.writeLog(testNS, selfPod, "self-uid", "agent", "self "+line)
	}
	h.waitFor("streams read", func() bool { return a.tailer.Stats().Lines >= 60 })
	h.step(10 * time.Second)
	if n := a.tailer.Stats().Lines; n != 60 {
		t.Fatalf("tailer delivered %d lines; the agent's own pod must never be tailed", n)
	}
	r := h.rule("any-line")
	if r.Firing == 0 || r.Firing > 2 {
		t.Fatalf("rule %+v, want at most max_series instances", r)
	}
	if st := a.ring.Stats(); st.Bytes > st.Ceiling {
		t.Fatalf("ring %d bytes over ceiling %d", st.Bytes, st.Ceiling)
	}
	cov := a.Status().Coverage
	if cov["logs.budget_limited"] != "any-line" || cov["logs.evidence_limited"] != "any-line" {
		t.Fatalf("suppression not reported: %v", cov)
	}
	h.waitDelivered()
	ids := map[string]bool{}
	for _, f := range h.coord.findings(t) {
		ids[f.ID] = true
		if len(f.Evidence) > 3 || f.Flags&protocol.FindingEvidenceLimited == 0 {
			t.Fatalf("finding evidence %d flags %b", len(f.Evidence), f.Flags)
		}
		for _, ev := range f.Evidence {
			if ev.Labels["pod"] == selfPod {
				t.Fatal("agent's own log line became evidence")
			}
		}
	}
	if len(ids) == 0 || len(ids) > 2 {
		t.Fatalf("%d findings, want at most 2", len(ids))
	}
}

func TestRestartResumesOffsetsAndAlertState(t *testing.T) {
	h := newHarness(t, options{caps: "logs"})
	h.coord.setBundle(h.trust.payload(t, logBundle("l1", []ruleSpec{oomRule}, oomGroup)))
	a := h.start()
	h.waitBundle("l1")
	if !a.fresh {
		t.Fatal("empty state dir not detected as fresh")
	}
	h.waitFor("reimaged warm-up disclosed", func() bool {
		reg, ok := h.coord.lastRegister()
		return ok && reg.Warming && reg.Coverage["logs"] == "warming: reimaged"
	})
	h.step(time.Minute)
	if reg := a.coverageReport(); reg["logs"] != coverageAvailable || a.warming() {
		t.Fatalf("coverage after warm-up %v", reg)
	}
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory one", "OutOfMemory two")
	h.waitFor("lines read", func() bool { return a.tailer.Stats().Lines >= 2 })
	h.step(10 * time.Second)
	h.waitDelivered()
	if got := transitions(h.coord.findings(t), "oom-logs"); !slices.Equal(got, []string{"firing"}) {
		t.Fatalf("transitions %v", got)
	}

	dup, err := New(h.config(), h.deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := dup.Run(context.Background()); !errors.Is(err, spool.ErrLocked) {
		t.Fatalf("second agent on a held state dir: %v", err)
	}
	if err := h.shutdown(); err != nil {
		t.Fatal(err)
	}

	b := h.start()
	if b.fresh {
		t.Fatal("restart treated as fresh state")
	}
	h.waitBundle("l1")
	if cov := b.coverageReport(); cov["logs"] != coverageWarming {
		t.Fatalf("restart must warm LogQL counters without the reimaged reason: %v", cov)
	}
	if r := h.rule("oom-logs"); r.Firing != 1 {
		t.Fatalf("alert state not resumed: %+v", r)
	}
	h.waitFor("app stream reopened", func() bool { return b.tailer.Stats().Files >= 1 })
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory three")
	h.waitFor("new line read", func() bool { return b.tailer.Stats().Lines >= 1 })
	h.step(10 * time.Second)
	h.waitDelivered()
	if n := b.tailer.Stats().Lines; n != 1 {
		t.Fatalf("restart re-read %d lines, want only the new one", n)
	}
	if r := h.rule("oom-logs"); r.Firing != 1 {
		t.Fatalf("rule after restart %+v", r)
	}
	got := transitions(h.coord.findings(t), "oom-logs")
	firing := 0
	for _, tr := range got {
		if tr == "firing" {
			firing++
		}
		if tr == "resolved" {
			t.Fatalf("restart resolved the finding: %v", got)
		}
	}
	if firing != 1 {
		t.Fatalf("duplicate findings across restart: %v", got)
	}
	ids := map[string]bool{}
	for _, f := range h.coord.findings(t) {
		ids[f.ID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("finding ids %v", ids)
	}
}

func TestBundleSwitchAndLastKnownGood(t *testing.T) {
	h := newHarness(t, options{caps: "logs"})
	sidecarRule := ruleSpec{id: "oom-sidecar", class: "logql", scope: "node", file: "loki/app.yaml", group: "app", alert: "SidecarOOM", caps: "logs", extra: "    budget:\n      max_series: 100\n"}
	h.coord.setBundle(h.trust.payload(t, logBundle("l1", []ruleSpec{oomRule}, oomGroup)))
	a := h.startLogs("l1")
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory one")
	h.waitFor("line read", func() bool { return a.tailer.Stats().Lines >= 1 })
	h.step(10 * time.Second)
	if r := h.rule("oom-logs"); r.Firing != 1 {
		t.Fatalf("v1 rule %+v", r)
	}

	h.coord.setBundle(h.trust.payload(t, logBundle("l2", []ruleSpec{oomRule, sidecarRule}, oomGroup, sidecarGroup)))
	h.waitBundle("l2")
	h.writeLog("prod", "web-1", "uid-web-1", "sidecar", "OutOfMemory in sidecar")
	h.waitFor("sidecar line read", func() bool { return a.tailer.Stats().Lines >= 2 })
	h.step(10 * time.Second)
	if r := h.rule("oom-logs"); r.Firing != 1 {
		t.Fatalf("rule lost its counters across the switch: %+v", r)
	}
	h.waitDelivered()
	fs := h.coord.findings(t)
	for _, f := range fs {
		if f.Provenance.RuleID == "oom-sidecar" && f.Provenance.BundleVersion != "l2" {
			t.Fatalf("finding evaluated under %s", f.Provenance.BundleVersion)
		}
	}
	if got := transitions(fs, "oom-sidecar"); !slices.Equal(got, []string{"firing"}) {
		t.Fatalf("new rule transitions %v", got)
	}
	if got := transitions(fs, "oom-logs"); !slices.Equal(got, []string{"firing"}) {
		t.Fatalf("switch changed the running rule: %v", got)
	}

	rogue, err := bundle.GenerateKey("rogue")
	if err != nil {
		t.Fatal(err)
	}
	bad := h.trust.payload(t, logBundle("l3", []ruleSpec{oomRule}, oomGroup))
	if bad.Signature, err = bundle.Sign(bad.Archive, rogue); err != nil {
		t.Fatal(err)
	}
	h.coord.setBundle(bad)
	h.waitFor("untrusted bundle rejected", func() bool { return strings.Contains(a.Status().BundleError, "untrusted") })
	invalid := h.trust.payload(t, logBundle("l4", []ruleSpec{oomRule}, "      - alert: OOMLogged\n        expr: sum(count_over_time({namespace=\"prod\"} |= [1m]))\n"))
	h.coord.setBundle(invalid)
	h.waitFor("invalid bundle rejected", func() bool { return strings.HasPrefix(a.Status().Coverage["bundle"], "rejected l4") })
	h.step(10 * time.Second)
	if v := a.eng.BundleVersion(); v != "l2" {
		t.Fatalf("active bundle %s, want last known good l2", v)
	}
	if r := h.rule("oom-sidecar"); !r.Found {
		t.Fatal("last known good rules replaced")
	}
	if err := h.shutdown(); err != nil {
		t.Fatal(err)
	}
	b := h.start()
	h.waitBundle("l2")
	h.waitFor("invalid bundle rejected after restart", func() bool { return strings.HasPrefix(b.Status().Coverage["bundle"], "rejected l4") })
	if v := b.eng.BundleVersion(); v != "l2" {
		t.Fatalf("after restart %s", v)
	}
}

func TestSteadyFiringLogQLRefreshesCountsAndEvidence(t *testing.T) {
	h := newHarness(t, options{caps: "logs"})
	h.writeLog("prod", "web-1", "uid-web-1", "app", "starting")
	group := strings.Replace(oomGroup, "[1m]", "[5m]", 1)
	h.coord.setBundle(h.trust.payload(t, logBundle("l1", []ruleSpec{oomRule}, group)))
	a := h.startLogs("l1")
	h.waitFor("stream opened", func() bool { return a.tailer.Stats().Files >= 1 })
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory: first")
	h.waitFor("first line", func() bool { return a.tailer.Stats().Lines >= 1 })
	h.step(10 * time.Second)
	h.waitDelivered()
	if got := transitions(h.coord.findings(t), "oom-logs"); !slices.Equal(got, []string{"firing"}) {
		t.Fatalf("transitions %v", got)
	}
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory: second", "OutOfMemory: third")
	h.waitFor("later lines", func() bool { return a.tailer.Stats().Lines >= 3 })
	h.step(10 * time.Second)
	h.step(55 * time.Second)
	h.waitDelivered()
	fs := h.coord.findings(t)
	if got := transitions(fs, "oom-logs"); !slices.Equal(got, []string{"firing", "update"}) {
		t.Fatalf("steady firing must refresh with an update: %v", got)
	}
	up := fs[len(fs)-1]
	var texts []string
	for _, ev := range up.Evidence {
		texts = append(texts, ev.Text)
	}
	if up.Count <= fs[0].Count || !slices.ContainsFunc(texts, func(s string) bool { return strings.Contains(s, "third") }) {
		t.Fatalf("update count %d (first %d), evidence %v", up.Count, fs[0].Count, texts)
	}
}
