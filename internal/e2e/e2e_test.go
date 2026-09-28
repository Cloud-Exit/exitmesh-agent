package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/coordinator"
	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/internal/state"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func (e *env) nodeClient(t *testing.T, tokenNode, claimed string) *nodeapi.Client {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "token")
	writeFile(t, tok, []byte(e.api.mint(t, e.clk.Now(), tokenNode)))
	c, err := nodeapi.NewClient(nodeapi.ClientOptions{BaseURL: "https://" + e.listen, CAFile: e.cert, TokenFile: tok, Node: claimed})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStartupEnrollCheckpointAndBundleDistribution(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if !strings.HasPrefix(e.token, "emx1_c_") {
		t.Fatalf("enrollment token %q is not a cluster token", e.token)
	}
	enrolled := false
	for _, a := range e.cp.Audit(e.target) {
		enrolled = enrolled || a.Event == "enrolled"
	}
	if !enrolled {
		t.Fatal("no enrollment audited at the control plane")
	}
	rs := e.records()
	if rs[0].Checkpoint.Reason != protocol.ReasonInitial || rs[0].Seq != 1 {
		t.Fatalf("first record %+v is not the initial checkpoint", rs[0].Envelope)
	}
	st, _, _ := e.state()
	want := map[string]int{state.KindNode: 2, state.KindPod: 2, state.KindDeployment: 1, state.KindReplicaSet: 1, state.KindService: 1}
	got := map[string]int{}
	for _, r := range st.Resources {
		got[r.Kind]++
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("head state has %d %s, want %d (all %v)", got[k], k, n, got)
		}
	}
	if len(st.Resources) != 7 {
		t.Fatalf("head state has %d resources, want 7: %v", len(st.Resources), got)
	}
	norm, err := state.NewNormalizer(state.OptionsFromConfig(e.coordConfig().Kubernetes, redact.Default()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range e.cl.objs {
		res, _, err := norm.Normalize(toUnstructured(t, o))
		if err != nil {
			t.Fatal(err)
		}
		head := st.Resources[res.UID]
		if head == nil || head.Kind != res.Kind || head.Name != res.Name || head.Namespace != res.Namespace {
			t.Fatalf("head state %+v, fake cluster normalizes to %+v", head, res)
		}
		for k, v := range res.Fields {
			if !protocol.ValueEqual(head.Fields[k], v) {
				t.Fatalf("%s field %s: head %v, fake cluster %v", res.UID, k, head.Fields[k], v)
			}
		}
	}
	for uid, f := range map[string]map[string]any{
		"pod-1":   {"nodeName": nodeA, "containers.app.image": "nginx:1.27"},
		"pod-2":   {"nodeName": nodeB},
		"dep-web": {"replicas": int64(2), "containers.app.image": "nginx:1.27"},
	} {
		for k, v := range f {
			if !protocol.ValueEqual(st.Resources[uid].Fields[k], v) {
				t.Fatalf("%s %s = %v, want %v", uid, k, st.Resources[uid].Fields[k], v)
			}
		}
	}

	h, _ := e.health()
	if h.TargetID != e.target || !h.Session.Registered {
		t.Fatalf("coordinator identity %q registered %v, enrolled target %q", h.TargetID, h.Session.Registered, e.target)
	}
	if h.Bundle.State != "converged" || h.Bundle.Target != version || h.Bundle.Coordinator != version || h.Bundle.Versions[version] != 2 || h.Bundle.KeySequence != 2 {
		t.Fatalf("bundle convergence %+v", h.Bundle)
	}
	for _, a := range e.nodes {
		if st := a.a.Status(); st.BundleVersion != version || st.BundleError != "" {
			t.Fatalf("%s bundle %q error %q", a.name, st.BundleVersion, st.BundleError)
		}
	}
	p, err := e.nodeClient(t, nodeA, nodeA).WaitBundle(context.Background(), "")
	if err != nil || p == nil {
		t.Fatalf("bundle poll %v %v", p, err)
	}
	if p.Version != version || !bytes.Equal(p.Archive, e.archive) || !bytes.Equal(p.Signature, e.sig) || !bytes.Equal(p.KeyManifest, e.tr.m2) ||
		len(p.KeyManifestChain) != 1 || !bytes.Equal(p.KeyManifestChain[0], e.tr.m1) {
		t.Fatalf("distributed bundle differs from the published one: version %q chain %d", p.Version, len(p.KeyManifestChain))
	}
}

func TestNodeLocalJoinFindingAndRecovery(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.nodes[nodeA]
	n := a.kubelet.count()
	a.kubelet.setMem(0.95 * memLimit)
	e.waitFor("high memory scraped", func() bool { return a.kubelet.count() >= n+2 })
	e.until("join finding at refcp", 5, func() bool {
		fs := e.findingState("mem-near-limit")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleFiring
	})
	fr := e.findingRecords("mem-near-limit")
	f := fr[0]
	if f.Transition != protocol.TransitionFiring || f.Node != nodeA || f.Provenance.Kind != protocol.ProvenanceRule ||
		f.Provenance.RuleVersion != 1 || f.Provenance.BundleVersion != version || f.Labels["pod"] != "web-1" || f.Labels["container"] != "app" {
		t.Fatalf("join finding %+v", f)
	}
	if !slices.Equal(f.Resources, []string{"pod-1"}) {
		t.Fatalf("join finding resources %v, want the affected pod's UID", f.Resources)
	}
	if f.Flags&protocol.FindingIncompleteCoverage != 0 || len(f.Coverage) != 0 {
		t.Fatalf("join finding flagged incomplete: %v", f.Coverage)
	}
	for _, r := range e.findingRecords("mem-near-limit") {
		if r.Node != nodeA {
			t.Fatalf("finding from %s, only node A is over its limit", r.Node)
		}
	}
	n = a.kubelet.count()
	a.kubelet.setMem(0.5 * memLimit)
	e.waitFor("recovered memory scraped", func() bool { return a.kubelet.count() >= n+2 })
	e.until("join finding resolved", 5, func() bool {
		fs := e.findingState("mem-near-limit")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleResolved
	})
	var ts []protocol.Transition
	for _, r := range e.findingRecords("mem-near-limit") {
		if r.ID != f.ID {
			t.Fatalf("second finding episode %s", r.ID)
		}
		ts = append(ts, r.Transition)
	}
	if !slices.Equal(ts, []protocol.Transition{protocol.TransitionFiring, protocol.TransitionResolved}) {
		t.Fatalf("transitions %v", ts)
	}
}

func TestLogQLFindingRedactedEvidenceAndNoUnmatchedRetention(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.nodes[nodeB]
	const unmatched, secret, token = "UNMATCHED-MARKER", "hunter2secret", "abcdefghijklmnopqrst"
	lines := b.a.Status().Logs.Lines
	b.writeLog(t, e.clk.Now(), "app",
		"GET /healthz 200 "+unmatched+"-1", "ERROR payment failed password="+secret, "GET /ready 200 "+unmatched+"-2",
		"ERROR payment failed password="+secret, "ERROR upstream Authorization: Bearer "+token)
	b.writeLog(t, e.clk.Now(), "sidecar", "ERROR "+unmatched+"-sidecar")
	e.nodes[nodeA].writeLog(t, e.clk.Now(), "app", "INFO "+unmatched+"-node-a")
	e.waitFor("matched stream read", func() bool { return b.a.Status().Logs.Lines >= lines+5 })
	e.until("LogQL finding at refcp", 5, func() bool {
		fs := e.findingState("app-errors")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleFiring
	})
	fr := e.findingRecords("app-errors")
	f := fr[0]
	if f.Node != nodeB || f.Provenance.BundleVersion != version || f.Labels["pod"] != "web-2" || f.Labels["container"] != "app" ||
		!slices.Equal(f.Resources, []string{"pod-2"}) || f.Count < 1 {
		t.Fatalf("LogQL finding %+v", f)
	}
	var total uint64
	for _, r := range fr {
		for _, ev := range r.Evidence {
			total += ev.Count
			if ev.Source != "log" || !strings.Contains(ev.Text, redact.Placeholder) || !strings.Contains(ev.Text, "ERROR") {
				t.Fatalf("evidence %+v is not a redacted matching line", ev)
			}
			if ev.Labels["pod"] != "web-2" || ev.Labels["container"] != "app" || ev.Labels["workload"] != "web" {
				t.Fatalf("evidence labels %v", ev.Labels)
			}
		}
	}
	if total != 3 {
		t.Fatalf("evidence counts %d, want the 3 matched lines", total)
	}
	var sent []byte
	for _, r := range e.records() {
		sent = append(sent, r.Bytes()...)
	}
	for _, needle := range []string{unmatched, secret, token} {
		if bytes.Contains(sent, []byte(needle)) {
			t.Fatalf("%q reached refcp records", needle)
		}
		for _, dir := range []string{e.coordDir, e.nodes[nodeA].dir, b.dir} {
			if hits := scanDir(t, dir, needle); len(hits) > 0 {
				t.Fatalf("%q retained in %v", needle, hits)
			}
		}
	}
}

func (e *env) ruleHealth(id string) (lastEval time.Time, firing int, state string) {
	h, _ := e.health()
	for _, r := range h.Rules {
		if r.ID == id {
			return r.LastEval, r.Firing, r.State
		}
	}
	return time.Time{}, 0, ""
}

func TestClusterRuleFromBothNodesIncompleteWhenOneStops(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for i := 0; i < 2; i++ {
		e.advance(step)
	}
	h, _ := e.health()
	for _, n := range h.Nodes {
		if n.PartVersions["cluster-cpu"] != version || !n.Covered {
			t.Fatalf("node %s part versions %v covered %v", n.Name, n.PartVersions, n.Covered)
		}
	}
	if last, firing, _ := e.ruleHealth("cluster-cpu"); last.IsZero() || firing != 0 || len(e.findingRecords("cluster-cpu")) != 0 {
		t.Fatalf("cluster rule fired on node A's contribution alone: last eval %v firing %d", last, firing)
	}
	b := e.nodes[nodeB]
	n := b.kubelet.count()
	b.kubelet.startCPU()
	e.waitFor("node B CPU scraped", func() bool { return b.kubelet.count() >= n+2 })
	e.until("cluster finding at refcp", 5, func() bool {
		fs := e.findingState("cluster-cpu")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleFiring
	})
	f := e.findingRecords("cluster-cpu")[0]
	v, _ := f.Facts["value"].(float64)
	if f.Transition != protocol.TransitionFiring || f.Labels["namespace"] != ns || f.Node != "" || v < 1.1 || v > 2 ||
		f.Flags&protocol.FindingIncompleteCoverage != 0 || len(f.Coverage) != 0 || f.Provenance.BundleVersion != version {
		t.Fatalf("cluster finding %+v (value %v)", f, v)
	}

	e.stopNode(nodeB)
	e.advance(2 * step)
	// Finding updates are throttled to one per minute, so the incomplete update follows within six intervals.
	e.until("cluster finding flagged incomplete", 8, func() bool {
		for _, r := range e.findingRecords("cluster-cpu") {
			if r.Transition == protocol.TransitionUpdate && r.Flags&protocol.FindingIncompleteCoverage != 0 && strings.Contains(strings.Join(r.Coverage, ","), "incomplete") {
				return true
			}
		}
		return false
	})
	if fs := e.findingState("cluster-cpu"); len(fs) != 1 || fs[0].State != protocol.LifecycleFiring {
		t.Fatalf("cluster finding after node B stopped %+v", fs)
	}
	e.advance(6 * time.Minute)
	e.until("cluster finding stale once every contribution aged out", 3, func() bool {
		fs := e.findingState("cluster-cpu")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleStale
	})
	for i := 0; i < 2; i++ {
		e.advance(step)
	}
	for _, r := range e.findingRecords("cluster-cpu") {
		if r.Transition == protocol.TransitionResolved {
			t.Fatalf("cluster finding resolved while node B was uncovered: %+v", r)
		}
	}
	h = e.freshHealth(e.clk.Now(), "node B uncovered", nil)
	if !slices.Contains(h.Bundle.Uncovered, nodeB) {
		t.Fatalf("node B not reported uncovered: %+v", h.Bundle)
	}
}

func TestDeploymentImageUpdateDeltaAndStateFinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, _, before := e.state()
	e.cl.setDeploymentImage(t, "nginx:bad")
	var delta *protocol.Record
	e.waitFor("image delta at refcp", func() bool {
		for _, r := range e.records() {
			if r.Seq <= before || r.Delta == nil {
				continue
			}
			for _, op := range r.Delta.Ops {
				if op.UID == "dep-web" && op.Kind == protocol.OpUpdate && protocol.ValueEqual(op.Fields["containers.app.image"], "nginx:bad") {
					delta = r
					return true
				}
			}
		}
		return false
	})
	if delta.Delta.Flags&protocol.FlagSynthetic != 0 {
		t.Fatalf("watch update committed as a synthetic delta")
	}
	e.until("state rule finding at refcp", 3, func() bool {
		fs := e.findingState("deploy-bad-image")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleFiring
	})
	f := e.findingRecords("deploy-bad-image")[0]
	if !slices.Equal(f.Resources, []string{"dep-web"}) || f.Provenance.BundleVersion != version || f.Labels["name"] != "web" || f.Labels["kind"] != "apps/Deployment" {
		t.Fatalf("state finding %+v", f)
	}
	st, _, _ := e.state()
	if got := st.Resources["dep-web"].Fields["containers.app.image"]; !protocol.ValueEqual(got, "nginx:bad") {
		t.Fatalf("reconstructed deployment image %v", got)
	}
	e.cl.setDeploymentImage(t, "nginx:1.28")
	e.until("state rule finding resolved", 3, func() bool {
		fs := e.findingState("deploy-bad-image")
		return len(fs) == 1 && fs[0].State == protocol.LifecycleResolved
	})
}

func sources(t *testing.T, res map[string]any, list string) map[string]int {
	t.Helper()
	data, _ := res["data"].(map[string]any)
	out := map[string]int{}
	items, _ := data[list].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		src, _ := m["source"].(string)
		out[src]++
	}
	return out
}

func checkEnvelope(t *testing.T, tool string, res map[string]any, source string, start, end int64, query string) {
	t.Helper()
	w, _ := res["window"].(map[string]any)
	lim, _ := res["limits"].(map[string]any)
	if res["source"] != source || w == nil || int64(w["start"].(float64)) != start || int64(w["end"].(float64)) != end || lim == nil || lim["max_lines"] == nil {
		t.Fatalf("%s envelope %v", tool, res)
	}
	if q, _ := res["query"].(string); query != "" && !strings.Contains(q, query) {
		t.Fatalf("%s query %q does not carry %q", tool, q, query)
	}
}

func TestInvestigationToolsThroughRefcp(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.nodes[nodeA], e.nodes[nodeB]
	la, lb := a.a.Status().Logs.Lines, b.a.Status().Logs.Lines
	now := e.clk.Now()
	a.writeLog(t, now, "sidecar", "hello from the sidecar SIDECAR-LINE")
	b.writeLog(t, now, "app", "ERROR checkout failed password=hunter2secret")
	e.waitFor("node B matched line held as evidence", func() bool { return b.a.Status().Logs.Lines >= lb+1 })
	if st := a.a.Status().Logs; st.Streams != 1 || st.Lines != la {
		t.Fatalf("node A tails %d streams and read %d new lines; no rule selects the sidecar stream", st.Streams, st.Lines-la)
	}
	start, end := now.Add(-time.Minute).UnixMilli(), now.Add(time.Second).UnixMilli()
	args := func(extra map[string]any) map[string]any {
		m := map[string]any{"requester": "user:e2e", "purpose": "end-to-end investigation", "scope": map[string]any{"namespaces": []string{ns}},
			"window": map[string]any{"start": start, "end": end}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	res := e.callTool("promql.query", args(map[string]any{"query": `container_memory_working_set_bytes{container="app"}`}))
	checkEnvelope(t, "promql.query", res, "live", start, end, `namespace="shop"`)
	if got := sources(t, res, "series"); got["node/"+nodeA] != 1 || got["node/"+nodeB] != 1 {
		t.Fatalf("promql.query series by source %v, want one from each node", got)
	}
	nodes := map[string]string{}
	for _, n := range res["data"].(map[string]any)["nodes"].([]any) {
		m := n.(map[string]any)
		nodes[m["node"].(string)] = m["status"].(string)
	}
	if nodes[nodeA] != "ok" || nodes[nodeB] != "ok" {
		t.Fatalf("promql.query fan-out %v", nodes)
	}

	res = e.callTool("logql.query", args(map[string]any{"query": `{container="sidecar"} |= "hello"`}))
	checkEnvelope(t, "logql.query", res, "live", start, end, `namespace="shop"`)
	if got := sources(t, res, "lines"); got["node/"+nodeA] != 1 || len(got) != 1 {
		t.Fatalf("logql.query lines by source %v", got)
	}
	if line := res["data"].(map[string]any)["lines"].([]any)[0].(map[string]any); !strings.Contains(line["text"].(string), "SIDECAR-LINE") {
		t.Fatalf("logql.query line %v", line)
	}

	res = e.callTool("evidence.query", args(map[string]any{"rule_id": "app-errors"}))
	checkEnvelope(t, "evidence.query", res, "live", start, end, "app-errors")
	if got := sources(t, res, "lines"); got["node/"+nodeB] != 1 || len(got) != 1 {
		t.Fatalf("evidence.query lines by source %v", got)
	}
	if text := res["data"].(map[string]any)["lines"].([]any)[0].(map[string]any)["text"].(string); !strings.Contains(text, redact.Placeholder) || strings.Contains(text, "hunter2secret") {
		t.Fatalf("evidence line %q is not redacted", text)
	}

	res = e.callTool("state.query", args(map[string]any{"kind": "Pod"}))
	checkEnvelope(t, "state.query", res, "state", start, end, "")
	var pods []string
	for _, r := range res["data"].(map[string]any)["resources"].([]any) {
		pods = append(pods, r.(map[string]any)["uid"].(string))
	}
	if !slices.Equal(pods, []string{"pod-1", "pod-2"}) {
		t.Fatalf("state.query pods %v", pods)
	}
	// Audits are tunnel notifications handled apart from the tool response, so they can land after it.
	e.waitFor("every investigation audited at refcp", func() bool {
		audited := map[string]bool{}
		for _, au := range e.cp.Audit(e.target) {
			if au.Event == "investigation" {
				for _, tool := range []string{"promql.query", "logql.query", "evidence.query", "state.query"} {
					audited[tool] = audited[tool] || strings.Contains(au.Detail, tool)
				}
			}
		}
		return len(audited) == 4 && audited["promql.query"] && audited["logql.query"] && audited["evidence.query"] && audited["state.query"]
	})
}

type findingKey struct {
	id    string
	tr    protocol.Transition
	eval  uint64
	count uint64
}

// Not parallel: the restarted coordinator rebinds the node API port the node agents know.
func TestCoordinatorRestartKeepsEpochAndDeliversSpooledFindingsOnce(t *testing.T) {
	e := newEnv(t)
	epoch := e.epochs()[0].ID
	a, b := e.nodes[nodeA], e.nodes[nodeB]
	e.stopCoordinator()

	n := a.kubelet.count()
	a.kubelet.setMem(0.95 * memLimit)
	lb := b.a.Status().Logs.Lines
	b.writeLog(t, e.clk.Now(), "app", "ERROR one", "ERROR two", "ERROR three")
	e.waitFor("inputs observed while the coordinator is down", func() bool {
		return a.kubelet.count() >= n+2 && b.a.Status().Logs.Lines >= lb+3
	})
	e.advance(step)
	e.waitFor("findings spooled in the node queues", func() bool {
		sa, sb := a.a.Status(), b.a.Status()
		return sa.OpenFindings == 1 && sb.OpenFindings == 1 && sa.Queue.Items > 0 && sb.Queue.Items > 0 && sa.DeliveryError != "" && sb.DeliveryError != ""
	})
	if len(e.findingRecords("mem-near-limit"))+len(e.findingRecords("app-errors")) != 0 {
		t.Fatal("findings reached refcp while the coordinator was down")
	}

	e.startCoordinator()
	e.waitFor("node queues drained into the restarted coordinator", func() bool {
		return a.a.Status().Queue.Items == 0 && b.a.Status().Queue.Items == 0
	})
	e.waitFor("spooled findings committed at refcp", func() bool {
		return len(e.findingRecords("mem-near-limit")) >= 1 && len(e.findingRecords("app-errors")) >= 1
	})
	e.advance(step)
	h := e.freshHealth(e.clk.Now(), "restarted coordinator committed", func(h coordinator.Health) bool {
		return h.Session.CommittedHead == h.Chain.Head
	})
	if es := e.epochs(); len(es) != 1 || es[0].ID != epoch || h.Session.Epoch != epoch.String() || h.Incarnation != 2 {
		t.Fatalf("epochs after restart %+v, session epoch %s incarnation %d", es, h.Session.Epoch, h.Incarnation)
	}
	seen := map[findingKey]int{}
	for _, r := range e.records() {
		if f := r.Finding; f != nil {
			seen[findingKey{f.ID, f.Transition, f.EvalTime, f.Count}]++
		}
	}
	for k, c := range seen {
		if c != 1 {
			t.Fatalf("finding record %+v committed %d times", k, c)
		}
	}
	for _, rule := range []string{"mem-near-limit", "app-errors"} {
		fr := e.findingRecords(rule)
		if len(fr) != 1 || fr[0].Transition != protocol.TransitionFiring {
			t.Fatalf("%s records after restart %+v, want exactly one firing", rule, fr)
		}
	}
	st, _, head := e.state()
	if head != h.Chain.Head {
		t.Fatalf("refcp head %d, coordinator head %d", head, h.Chain.Head)
	}
	res := e.callTool("state.query", map[string]any{"requester": "user:e2e", "purpose": "reconstruction check", "scope": map[string]any{"cluster": true}})
	got := map[string]any{}
	for _, r := range res["data"].(map[string]any)["resources"].([]any) {
		m := r.(map[string]any)
		got[m["uid"].(string)] = m
	}
	for uid, r := range st.Resources {
		want := map[string]any{}
		raw, _ := json.Marshal(investigate.StateResource{UID: r.UID, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name, Fields: r.Fields})
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got[uid], want) {
			t.Fatalf("resource %s: coordinator %v, refcp reconstruction %v", uid, got[uid], want)
		}
	}
	if len(got) != len(st.Resources) {
		t.Fatalf("coordinator has %d resources, refcp reconstruction %d", len(got), len(st.Resources))
	}
}

func TestNodeImpersonationRejectedAndAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := context.Background()
	now := uint64(e.clk.Now().UnixMilli())
	f := protocol.Finding{
		ID: protocol.FindingID("node:"+nodeB, "forged|node-b", now), DedupKey: "forged|node-b", Transition: protocol.TransitionFiring,
		Provenance: protocol.Provenance{Kind: protocol.ProvenanceRule, RuleID: "forged", RuleVersion: 1, BundleVersion: version},
		Category:   "errors", Severity: protocol.SeverityCritical, EvalTime: now, FirstSeen: now, LastSeen: now, Count: 1, Node: nodeB,
	}
	fb, err := protocol.EncodeFinding(&f)
	if err != nil {
		t.Fatal(err)
	}
	items := []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindFinding, Finding: fb}}
	claimsB := e.nodeClient(t, nodeA, nodeB)
	if _, err := claimsB.Submit(ctx, "", items); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("node A token submitting as node B: %v", err)
	}
	asA := e.nodeClient(t, nodeA, nodeA)
	if _, err := asA.Submit(ctx, "", items); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("node A token submitting a finding naming node B: %v", err)
	}
	h := e.freshHealth(e.clk.Now(), "impersonation audited in health", func(h coordinator.Health) bool {
		return h.Security.ImpersonationRejected == 2 && len(h.Security.Recent) == 2
	})
	for _, ev := range h.Security.Recent {
		if ev.Kind != nodeapi.AuditImpersonation || ev.AuthenticatedNode != nodeA || ev.ClaimedNode != nodeB || ev.Pod != "exitmesh-node-"+nodeA || ev.Path != "/v1/node/records" {
			t.Fatalf("audit event %+v", ev)
		}
	}
	if !strings.Contains(e.coordLog.String(), "node agent submission rejected") {
		t.Fatal("impersonation not logged by the coordinator")
	}
	e.advance(step)
	if fr := e.findingRecords("forged"); len(fr) != 0 {
		t.Fatalf("forged finding committed: %+v", fr)
	}
	for _, n := range []string{nodeA, nodeB} {
		if st := e.nodes[n].a.Status(); st.DeliveryError != "" || st.Dropped != "" {
			t.Fatalf("%s delivery disturbed: %q %q", n, st.DeliveryError, st.Dropped)
		}
	}
}

func TestNodeRuleStatesReachCoordinatorHealth(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.stopNode(nodeB)
	b := e.startNode(nodeB, "policy:\n  maxRuleSamples: 1\n")
	e.waitFor("node B scrapes", func() bool { return b.kubelet.count() > 0 })
	e.waitFor("node B evaluates on the budget", func() bool {
		for _, r := range b.a.Status().Rules {
			if r.RuleID == "mem-near-limit" && r.State == "budget_limited" {
				return true
			}
		}
		return false
	})
	h := e.freshHealth(e.clk.Now(), "budget-limited node rule in coordinator health", func(h coordinator.Health) bool {
		for _, n := range h.Nodes {
			if n.Name != nodeB {
				continue
			}
			for _, r := range n.Rules {
				if r.ID == "mem-near-limit" && r.State == "budget_limited" && r.BudgetLimited && r.Reason != "" {
					return true
				}
			}
		}
		return false
	})
	for _, n := range h.Nodes {
		if n.Name == nodeA {
			for _, r := range n.Rules {
				if r.ID == "mem-near-limit" {
					t.Fatalf("node A reports %+v without a budget cap", r)
				}
			}
		}
	}
	for _, x := range h.NodeRules {
		if x.ID == "mem-near-limit" && x.States["budget_limited"] == 1 && x.BudgetLimited == 1 && x.Nodes == 2 {
			return
		}
	}
	t.Fatalf("node rule rollup %+v", h.NodeRules)
}
