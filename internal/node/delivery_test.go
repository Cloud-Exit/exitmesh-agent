package node

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
)

func TestAuthFailuresKeepQueueAndRetry(t *testing.T) {
	h := newHarness(t, options{caps: "logs"})
	a := h.start()
	var submits atomic.Int64
	deny := atomic.Int64{}
	intercept := func(r *http.Request) int {
		if r.URL.Path != "/v1/node/records" {
			return 0
		}
		submits.Add(1)
		if deny.Load() != 0 {
			return int(deny.Load())
		}
		return 0
	}
	h.intercept.Store(&intercept)
	if err := os.WriteFile(h.tokenFile, []byte("not-a-valid-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	part := nodeapi.Part{RuleID: "r", EvalTimeMs: 1, Samples: []nodeapi.Sample{{Labels: map[string]string{"a": "b"}, Value: 1, TimestampMs: 1}}}
	for range 3 {
		if err := a.enqueue(nodeapi.Item{Kind: nodeapi.KindSeries, Part: &part}); err != nil {
			t.Fatal(err)
		}
	}
	h.waitFor("unauthorized submissions", func() bool { return submits.Load() >= 3 })
	if u := a.queue.Usage(); u.Items != 3 || a.Status().Dropped != "" {
		t.Fatalf("401 dropped queued items: queue %+v dropped %q", u, a.Status().Dropped)
	}
	deny.Store(http.StatusForbidden)
	if err := os.WriteFile(h.tokenFile, []byte(h.api.mint(t, testNode)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := submits.Load()
	h.waitFor("forbidden submissions", func() bool { return submits.Load() >= n+3 })
	if u := a.queue.Usage(); u.Items != 3 || a.Status().Dropped != "" {
		t.Fatalf("403 dropped queued items: queue %+v dropped %q", u, a.Status().Dropped)
	}
	deny.Store(0)
	h.waitDelivered()
	h.coord.set(func(c *fakeCoord) {
		for seq := uint64(1); seq <= 3; seq++ {
			if c.accepted[seq] != 1 {
				t.Errorf("item %d accepted %d times", seq, c.accepted[seq])
			}
		}
		if len(c.accepted) != 3 {
			t.Errorf("coordinator accepted %v", c.accepted)
		}
	})
	if d := a.Status().Dropped; d != "" {
		t.Fatalf("items dropped: %q", d)
	}
}

func TestQueueIdentitySentAndRenewedWhenStateIsLost(t *testing.T) {
	h := newHarness(t, options{caps: "logs"})
	part := nodeapi.Part{RuleID: "r", EvalTimeMs: 1}
	run := func(n int) string {
		a := h.start()
		for range n {
			if err := a.enqueue(nodeapi.Item{Kind: nodeapi.KindSeries, Part: &part}); err != nil {
				t.Fatal(err)
			}
		}
		h.waitDelivered()
		id := a.queue.ID()
		if err := h.shutdown(); err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := run(2)
	if again := run(1); again != first {
		t.Fatalf("queue identity changed across a restart: %s then %s", first, again)
	}
	if err := os.RemoveAll(h.dir); err != nil {
		t.Fatal(err)
	}
	fresh := run(1)
	if fresh == first || len(fresh) != 32 {
		t.Fatalf("queue identity after losing the state directory: %q, before %q", fresh, first)
	}
	var got []string
	h.coord.set(func(c *fakeCoord) { got = append(got, c.queueSeqs...) })
	want := []string{first + "/1", first + "/2", first + "/3", fresh + "/1"}
	if !slices.Equal(got, want) {
		t.Fatalf("submissions %v, want %v", got, want)
	}
}

func TestRegistrationReportsRuleStates(t *testing.T) {
	h := newHarness(t, options{caps: "logs", ring: "8Ki"})
	rule := ruleSpec{id: "any-line", class: "logql", scope: "node", file: "loki/app.yaml", group: "app", alert: "AnyLine", caps: "logs",
		extra: "    budget:\n      max_series: 2\n    evidence:\n      max_samples: 3\n"}
	h.coord.setBundle(h.trust.payload(t, logBundle("m1", []ruleSpec{rule, oomRule}, "      - alert: AnyLine\n        expr: count_over_time({namespace=~\".+\"}[1m]) > 0\n", oomGroup)))
	h.preopenStreams()
	a := h.start()
	h.waitBundle("m1")
	h.step(time.Minute)
	h.waitFor("streams opened", func() bool { return a.tailer.Stats().Files >= 3 })
	for i := range 20 {
		line := fmt.Sprintf("line %02d %s", i, strings.Repeat("y", 100))
		h.writeLog("prod", "web-1", "uid-web-1", "app", line)
		h.writeLog("prod", "web-1", "uid-web-1", "sidecar", line)
		h.writeLog("other", "chatty-1", "uid-chatty-1", "main", line)
	}
	h.waitFor("streams read", func() bool { return a.tailer.Stats().Lines >= 60 })
	h.step(10 * time.Second)
	var got []nodeapi.RuleStatus
	h.waitFor("rule states registered", func() bool {
		reg, ok := h.coord.lastRegister()
		got = reg.Rules
		return ok && len(got) == 2 && got[0].RuleID == "any-line" && got[0].EvidenceLimited && got[0].BudgetLimited
	})
	if got[0].State != engine.StateEvidenceLimited || got[0].Version != 1 || got[0].LastEvalMs == 0 || got[0].Reason == "" {
		t.Fatalf("limited rule status %+v", got[0])
	}
	if got[1].RuleID != "oom-logs" || got[1].State != engine.StateActive || got[1].BudgetLimited || got[1].EvidenceLimited {
		t.Fatalf("healthy rule status %+v", got[1])
	}
}
