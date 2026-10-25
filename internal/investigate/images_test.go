package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/imagesbom"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

func imgDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// imageNodes answers image_sbom tasks per node and digest.
type imageNodes struct {
	mu      sync.Mutex
	answers map[string]map[string]imagesbom.Result
	errs    map[string]string
	down    map[string]bool
	runs    []string
}

func (f *imageNodes) Nodes() []string {
	var out []string
	for n := range f.answers {
		out = append(out, n)
	}
	for n := range f.errs {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func (f *imageNodes) Run(_ context.Context, node string, t nodeapi.Task) (nodeapi.TaskResult, error) {
	f.mu.Lock()
	f.runs = append(f.runs, node)
	f.mu.Unlock()
	if t.Kind != nodeapi.TaskImageSBOM {
		return nodeapi.TaskResult{}, errors.New("unexpected task kind")
	}
	if f.down[node] {
		return nodeapi.TaskResult{}, errors.New("node api: connection reset token=abcdefgh123")
	}
	if msg, ok := f.errs[node]; ok {
		return nodeapi.TaskResult{ID: t.ID, Error: msg}, nil
	}
	var req imagesbom.TaskRequest
	if err := json.Unmarshal(t.Payload, &req); err != nil {
		return nodeapi.TaskResult{}, err
	}
	res, ok := f.answers[node][req.Digest]
	if !ok {
		res = imagesbom.Unavailable(req.Digest, "No running pod on node "+node+" uses image "+req.Digest+".")
	}
	b, _ := json.Marshal(res)
	return nodeapi.TaskResult{ID: t.ID, Payload: b}, nil
}

func (f *imageNodes) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.runs)
	f.runs = nil
	slices.Sort(out)
	return out
}

func imageState() *protocol.State {
	st := protocol.NewState()
	for _, r := range []protocol.Resource{
		{UID: "p1", Kind: "Pod", Namespace: "shop", Name: "api-1", Fields: map[string]any{"nodeName": "n1", "containers.app.imageID": "registry.example/app@" + imgDigest('a')}},
		{UID: "p2", Kind: "Pod", Namespace: "other", Name: "db-1", Fields: map[string]any{"nodeName": "n2", "initContainers.init.imageID": "docker-pullable://registry.example/db@" + imgDigest('b')}},
		{UID: "p3", Kind: "Pod", Namespace: "shop", Name: "batch-1", Fields: map[string]any{"nodeName": "n3", "containers.job.imageID": imgDigest('c')}},
		{UID: "p4", Kind: "Pod", Namespace: "shop", Name: "edge-1", Fields: map[string]any{"nodeName": "n5", "containers.proxy.imageID": imgDigest('e')}},
		{UID: "d1", Kind: "apps/Deployment", Namespace: "shop", Name: "api", Fields: map[string]any{"containers.app.image": "registry.example/app@" + imgDigest('f')}},
	} {
		st.Resources[r.UID] = &r
	}
	return st
}

func readyResult(d string, truncated bool) imagesbom.Result {
	return imagesbom.Result{Status: imagesbom.StatusReady, Digest: d, Labels: imagesbom.Labels{Source: "https://ci:hunter2pw@github.com/acme/app", Revision: "abc"},
		Packages:  []imagesbom.Package{{Ecosystem: "Debian:12", Name: "libc6", Version: "2.36-9", PURL: "pkg:deb/debian/libc6@2.36-9", Location: "/var/lib/dpkg/status"}},
		Truncated: truncated, Scanner: imagesbom.Scanner}
}

func newImageService(t *testing.T, nodes *imageNodes) (*Service, *[]AuditRecord) {
	t.Helper()
	var audit []AuditRecord
	st := imageState()
	svc, err := NewService(Options{
		Role: RoleCoordinator, State: func() *protocol.State { return st }, Nodes: nodes, ImageInventory: true,
		Audit: func(r AuditRecord) { audit = append(audit, r) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, &audit
}

func callImage(t *testing.T, svc *Service, a map[string]any) (imagesbom.Result, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(a)
	v, err := svc.Call(context.Background(), ToolImageSBOM, raw)
	if err != nil {
		t.Fatalf("%v: %v", a, err)
	}
	res := v.(imagesbom.Result)
	b, _ := json.Marshal(res)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return res, m
}

func TestImageSBOMTool(t *testing.T) {
	nodes := &imageNodes{
		answers: map[string]map[string]imagesbom.Result{
			"n1": {imgDigest('a'): readyResult(imgDigest('a'), false)},
			"n2": {imgDigest('b'): imagesbom.Pending(imgDigest('b'))},
			"n4": {imgDigest('d'): readyResult(imgDigest('d'), true)},
		},
		errs: map[string]string{"n5": `unknown task kind "image_sbom"`},
	}
	svc, audit := newImageService(t, nodes)
	if !slices.ContainsFunc(svc.Tools(), func(tl client.Tool) bool { return tl.Name == ToolImageSBOM }) {
		t.Fatal("image.sbom.get not advertised")
	}

	res, m := callImage(t, svc, map[string]any{"digest": imgDigest('a')})
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"digest", "labels", "packages", "scanner", "status", "truncated"}) {
		t.Fatalf("result keys %v", keys)
	}
	if res.Status != imagesbom.StatusReady || len(res.Packages) != 1 || res.Labels.Source != "https://ci:"+redact.Placeholder+"@github.com/acme/app" {
		t.Fatalf("ready %+v", res)
	}
	if got := nodes.ran(); !slices.Equal(got, []string{"n1"}) {
		t.Fatalf("asked %v, want only the node running the digest", got)
	}
	if a := (*audit)[len(*audit)-1]; a.Tool != ToolImageSBOM || a.Outcome != OutcomeOK || a.Truncated {
		t.Fatalf("audit %+v", a)
	}

	if res, _ = callImage(t, svc, map[string]any{"digest": imgDigest('b')}); res.Status != imagesbom.StatusPending || len(res.Packages) != 0 || res.Reason != "" {
		t.Fatalf("pending %+v", res)
	}
	if got := nodes.ran(); !slices.Equal(got, []string{"n2"}) {
		t.Fatalf("asked %v", got)
	}

	if res, _ = callImage(t, svc, map[string]any{"digest": imgDigest('c')}); res.Status != imagesbom.StatusUnavailable || res.Reason != "No node agent is connected on node n3, which runs image "+imgDigest('c')+"." {
		t.Fatalf("disconnected %+v", res)
	}
	if got := nodes.ran(); len(got) != 0 {
		t.Fatalf("asked %v", got)
	}

	res, _ = callImage(t, svc, map[string]any{"digest": imgDigest('d')})
	if res.Status != imagesbom.StatusReady || !res.Truncated {
		t.Fatalf("cached elsewhere %+v", res)
	}
	if got := nodes.ran(); !slices.Equal(got, []string{"n1", "n2", "n4", "n5"}) {
		t.Fatalf("digest outside state asked %v, want every connected node", got)
	}
	if a := (*audit)[len(*audit)-1]; a.Outcome != OutcomeLimited || !a.Truncated {
		t.Fatalf("truncated audit %+v", a)
	}

	if res, _ = callImage(t, svc, map[string]any{"digest": imgDigest('9')}); res.Status != imagesbom.StatusUnavailable || res.Reason != "No running pod in the cluster uses image "+imgDigest('9')+", and no node agent holds its inventory." {
		t.Fatalf("unknown %+v", res)
	}
	nodes.ran()

	if res, _ = callImage(t, svc, map[string]any{"digest": imgDigest('e')}); res.Status != imagesbom.StatusUnavailable || res.Reason != `The node agent on n5 cannot read images: unknown task kind "image_sbom".` {
		t.Fatalf("old node agent %+v", res)
	}

	scoped := map[string]any{"requester": "user:alice", "purpose": "vulnerability triage", "scope": map[string]any{"namespaces": []string{"shop"}}}
	scoped["digest"] = imgDigest('b')
	if res, _ = callImage(t, svc, scoped); res.Status != imagesbom.StatusUnavailable || res.Reason != "No pod inside the request scope runs image "+imgDigest('b')+"." {
		t.Fatalf("out of scope %+v", res)
	}
	nodes.ran()
	scoped["digest"] = imgDigest('d')
	if res, _ = callImage(t, svc, scoped); res.Status != imagesbom.StatusUnavailable || !strings.Contains(res.Reason, "inside the request scope") {
		t.Fatalf("scoped digest outside state %+v", res)
	}
	if got := nodes.ran(); len(got) != 0 {
		t.Fatalf("scoped call fanned out to %v", got)
	}
	scoped["digest"] = imgDigest('a')
	if res, _ = callImage(t, svc, scoped); res.Status != imagesbom.StatusReady {
		t.Fatalf("in scope %+v", res)
	}
	if a := (*audit)[len(*audit)-1]; a.Requester != "user:alice" || a.Purpose != "vulnerability triage" {
		t.Fatalf("audit %+v", a)
	}

	for name, a := range map[string]map[string]any{
		"no digest":     {},
		"bad digest":    {"digest": "sha256:ABC"},
		"unknown field": {"digest": imgDigest('a'), "path": "/etc"},
		"bad scope":     {"digest": imgDigest('a'), "scope": map[string]any{"namespaces": []string{"Bad_NS"}}},
	} {
		raw, _ := json.Marshal(a)
		if _, err := svc.Call(context.Background(), ToolImageSBOM, raw); errClass(err) != ClassInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestImageSBOMToolNodeFailures(t *testing.T) {
	nodes := &imageNodes{
		answers: map[string]map[string]imagesbom.Result{
			"n1": {imgDigest('a'): imagesbom.Unavailable(imgDigest('a'), "Image "+imgDigest('a')+" is not in the containerd content store of this node.")},
			"n3": {imgDigest('c'): {Status: "bogus", Digest: imgDigest('c')}},
		},
		down: map[string]bool{"n2": true},
	}
	nodes.answers["n2"] = nil
	svc, _ := newImageService(t, nodes)
	if res, _ := callImage(t, svc, map[string]any{"digest": imgDigest('a')}); res.Status != imagesbom.StatusUnavailable || res.Reason != "Image "+imgDigest('a')+" is not in the containerd content store of this node." {
		t.Fatalf("node reason not passed on %+v", res)
	}
	res, _ := callImage(t, svc, map[string]any{"digest": imgDigest('b')})
	if res.Status != imagesbom.StatusUnavailable || !strings.HasPrefix(res.Reason, "The node agent on n2 did not answer: ") || strings.Contains(res.Reason, "abcdefgh123") {
		t.Fatalf("down node %+v", res)
	}
	if res, _ := callImage(t, svc, map[string]any{"digest": imgDigest('c')}); res.Status != imagesbom.StatusUnavailable || res.Reason != "The node agent on n3 returned an invalid image inventory." {
		t.Fatalf("invalid answer %+v", res)
	}
}

func TestImageSBOMToolNotAdvertised(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.svc.Call(context.Background(), ToolImageSBOM, json.RawMessage(`{"digest":"`+imgDigest('a')+`"}`)); errClass(err) != ClassInvalid {
		t.Fatalf("got %v", err)
	}
	if _, err := NewService(Options{Role: RoleHost, Local: NewExecutor(ExecOptions{Node: "h"}), ImageInventory: true}); err == nil {
		t.Fatal("host role accepted image inventory")
	}
}
