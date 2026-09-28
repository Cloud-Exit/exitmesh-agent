package node

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	clienttesting "k8s.io/client-go/testing"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

const anyOOMGroup = `      - alert: AnyOOM
        expr: sum by (namespace, pod) (count_over_time({namespace=~".+"} |= "OutOfMemory" [1m])) > 0
`

var anyOOMRule = ruleSpec{id: "any-oom", class: "logql", scope: "node", file: "loki/app.yaml", group: "app", alert: "AnyOOM", caps: "logs",
	extra: "    budget:\n      max_series: 100\n    evidence:\n      max_samples: 5\n"}

// checkLogScope drives a broad rule and broad investigation reads; nothing from namespace "other" may come back.
func checkLogScope(t *testing.T, h *harness) {
	t.Helper()
	h.coord.setBundle(h.trust.payload(t, logBundle("s1", []ruleSpec{anyOOMRule}, anyOOMGroup)))
	a := h.startLogs("s1")
	h.writeLog("other", "chatty-1", "uid-chatty-1", "main", "OutOfMemory in an excluded namespace", "hello from other")
	h.writeLog("prod", "web-1", "uid-web-1", "app", "OutOfMemory in prod", "hello from prod")
	h.waitFor("in-scope stream tailed", func() bool { return a.tailer.Stats().Lines >= 2 })
	h.step(10 * time.Second)
	h.step(10 * time.Second)
	if n := a.tailer.Stats().Lines; n != 2 {
		t.Fatalf("tailer read %d lines; out-of-scope streams must never be read", n)
	}
	h.waitDelivered()
	fs := h.coord.findings(t)
	if len(fs) == 0 {
		t.Fatal("in-scope stream produced no finding")
	}
	for _, f := range fs {
		if f.Labels["namespace"] != "prod" {
			t.Fatalf("finding for namespace %q", f.Labels["namespace"])
		}
		for _, ev := range f.Evidence {
			if ev.Labels["namespace"] != "prod" || strings.Contains(ev.Text, "excluded") {
				t.Fatalf("out-of-scope evidence %+v", ev)
			}
		}
	}
	now := h.clock.Now()
	run := func(id string, kind nodeapi.TaskKind, query string) investigate.TaskResponse {
		b, err := json.Marshal(investigate.TaskQuery{Query: query, StartMs: now.Add(-time.Hour).UnixMilli(), EndMs: now.UnixMilli()})
		if err != nil {
			t.Fatal(err)
		}
		h.coord.addTask(nodeapi.Task{ID: id, Kind: kind, Payload: b, DeadlineMs: now.Add(time.Minute).UnixMilli()})
		var res nodeapi.TaskResult
		h.waitFor("task "+id, func() bool {
			var ok bool
			res, ok = h.coord.result(id)
			return ok
		})
		if res.Error != "" {
			t.Fatalf("task %s: %s", id, res.Error)
		}
		var out investigate.TaskResponse
		if err := json.Unmarshal(res.Payload, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for id, kind := range map[string]nodeapi.TaskKind{"q-logql": nodeapi.TaskLogQLQuery, "q-read": nodeapi.TaskLogRead} {
		q := `{namespace=~".+"} |= "hello"`
		if kind == nodeapi.TaskLogRead {
			q = `{namespace=~".+"}`
		}
		out := run(id, kind, q)
		if len(out.Data.Lines) == 0 {
			t.Fatalf("%s returned nothing from the in-scope stream", id)
		}
		for _, l := range out.Data.Lines {
			if l.Labels["namespace"] != "prod" {
				t.Fatalf("%s returned an out-of-scope line %+v", id, l)
			}
		}
	}
	count := run("q-count", nodeapi.TaskLogQLQuery, `sum(count_over_time({namespace=~".+"}[1h]))`)
	if len(count.Data.Series) != 1 || len(count.Data.Series[0].Points) == 0 || count.Data.Series[0].Points[0].V != 2 {
		t.Fatalf("aggregate over every namespace counted out-of-scope lines: %+v", count.Data)
	}
	ev := run("q-evidence", nodeapi.TaskEvidence, "any-oom")
	for _, l := range ev.Data.Lines {
		if l.Labels["namespace"] != "prod" {
			t.Fatalf("evidence read returned %+v", l)
		}
	}
}

func TestExcludedNamespacesNeverRead(t *testing.T) {
	h := newHarness(t, options{caps: "logs", extraTop: "kubernetes:\n  excludeNamespaces: [other]\n"})
	checkLogScope(t, h)
	if _, ok := h.agent.pods.resolve("Pod", "other", "chatty-1"); ok {
		t.Fatal("pod of an excluded namespace tracked by the pod watch")
	}
}

func TestNamespaceProfileWatchesPodsPerNamespace(t *testing.T) {
	h := newHarness(t, options{caps: "logs", extraTop: "kubernetes:\n  scope: namespaces\n  namespaces: [prod, staging]\n"})
	forbidden := func(a clienttesting.Action) error {
		if a.GetNamespace() == "" {
			return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("pods is forbidden at the cluster scope"))
		}
		if a.GetNamespace() != "prod" && a.GetNamespace() != "staging" {
			return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("namespace not granted"))
		}
		return nil
	}
	var namespaces sync.Map
	h.kube.PrependReactor("list", "pods", func(a clienttesting.Action) (bool, runtime.Object, error) {
		namespaces.Store(a.GetNamespace(), true)
		if err := forbidden(a); err != nil {
			return true, nil, err
		}
		return false, nil, nil
	})
	h.kube.PrependWatchReactor("pods", func(a clienttesting.Action) (bool, watch.Interface, error) {
		if err := forbidden(a); err != nil {
			return true, nil, err
		}
		return false, nil, nil
	})
	checkLogScope(t, h)
	a := h.agent
	h.waitFor("pods synchronized per namespace", a.pods.synced)
	if uid, ok := a.pods.resolve("Pod", "prod", "web-1"); !ok || uid != "uid-web-1" {
		t.Fatalf("pod in a granted namespace: %q %v", uid, ok)
	}
	if _, ok := a.pods.resolve("Pod", "prod", "db-1"); ok {
		t.Fatal("pod of another node tracked")
	}
	for _, ns := range []string{"", "other"} {
		if _, ok := namespaces.Load(ns); ok {
			t.Fatalf("pods listed in namespace %q outside the profile", ns)
		}
	}
	if a.Status().Coverage["pods"] != coverageAvailable {
		t.Fatalf("pod coverage %q", a.Status().Coverage["pods"])
	}
}

func TestNamespaceScope(t *testing.T) {
	for _, c := range []struct {
		name    string
		k       config.Kubernetes
		allowed []string
		denied  []string
		watched []string
		query   string
	}{
		{"cluster", config.Kubernetes{Scope: "cluster"}, []string{"a", "kube-system"}, nil, nil, `{app="x"}`},
		{"excluded", config.Kubernetes{Scope: "cluster", ExcludeNamespaces: []string{"kube-system", "kube-system"}}, []string{"a"}, []string{"kube-system"}, nil,
			`{app="x", namespace!~"kube-system"}`},
		{"allowlist", config.Kubernetes{Scope: "namespaces", Namespaces: []string{"b", "a"}, ExcludeNamespaces: []string{"b"}}, []string{"a"}, []string{"b", "c"},
			[]string{"a"}, `{app="x", namespace=~"a", namespace!~"b"}`},
		{"emptied", config.Kubernetes{Scope: "namespaces", Namespaces: []string{"a"}, ExcludeNamespaces: []string{"a"}}, nil, []string{"a", ""}, []string{},
			`{app="x", namespace=~"\x00", namespace!~"a"}`},
	} {
		s := newNSScope(c.k)
		for _, ns := range c.allowed {
			if !s.allows(ns) {
				t.Errorf("%s: %q denied", c.name, ns)
			}
		}
		for _, ns := range c.denied {
			if s.allows(ns) {
				t.Errorf("%s: %q allowed", c.name, ns)
			}
		}
		if w := s.watched(); !slices.Equal(w, c.watched) || (w == nil) != (c.watched == nil) {
			t.Errorf("%s: watched %#v, want %#v", c.name, w, c.watched)
		}
		b, _ := json.Marshal(investigate.TaskQuery{Query: `{app="x"}`})
		res := scopedExecutor{next: echoExecutor{}, scope: s}.Execute(context.Background(), nodeapi.Task{ID: "t", Kind: nodeapi.TaskLogRead, Payload: b})
		var q investigate.TaskQuery
		if err := json.Unmarshal(res.Payload, &q); err != nil || q.Query != c.query {
			t.Errorf("%s: scoped query %q (%v), want %q", c.name, q.Query, err, c.query)
		}
	}
}

type echoExecutor struct{}

func (echoExecutor) Execute(_ context.Context, t nodeapi.Task) nodeapi.TaskResult {
	return nodeapi.TaskResult{ID: t.ID, Payload: t.Payload}
}
