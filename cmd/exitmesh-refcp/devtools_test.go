package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func TestTrustBundlesAndStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trustDir := t.TempDir()
	rules := filepath.Join(repoRoot(t), "rules")
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-create-host", "-cert-dir", t.TempDir(), "-trust-dir", trustDir,
			"-bundle-host", filepath.Join(rules, "host"), "-bundle-kubernetes", filepath.Join(rules, "kubernetes"), "-status"}, pw, io.Discard)
		pw.Close()
	}()
	lines := map[string][]string{}
	sc := bufio.NewScanner(pr)
	for len(lines["bundle"]) < 2 && sc.Scan() {
		f := strings.Fields(sc.Text())
		lines[f[0]] = append(lines[f[0]], strings.Join(f[1:], " "))
	}
	go func() { _, _ = io.Copy(io.Discard, pr) }()
	if len(lines["roots"]) != 1 || len(lines["bundle"]) != 2 || len(lines["target"]) != 1 {
		t.Fatalf("output %v", lines)
	}
	entry, err := os.ReadFile(filepath.Join(trustDir, "roots.txt"))
	if err != nil {
		t.Fatal(err)
	}
	roots, err := bundle.LoadRoots(filepath.Join(trustDir, "roots.json"), []string{strings.TrimSpace(string(entry))}, 0)
	if err == nil {
		t.Fatal("the same root in roots.json and roots.txt must be a duplicate")
	}
	if roots, err = bundle.LoadRoots("", []string{strings.TrimSpace(string(entry))}, 0); err != nil || len(roots.Keys) != 1 {
		t.Fatalf("roots.txt: %v", err)
	}
	f := strings.Fields(lines["target"][0])
	endpoint, caFile := lines["endpoint"][0], lines["ca"][0]
	opts := tunnel.Options{Endpoint: endpoint, CAFile: caFile}
	wid, _ := protocol.NewWriterID()
	res, err := tunnel.Enroll(ctx, opts, protocol.EnrollRequest{Token: f[3], WriterID: wid, TargetType: protocol.TargetHost, MachineID: "0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	opts.Credential = func() string { return res.Credential }
	tr, err := tunnel.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tr.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Handle(func(context.Context, *client.Request) (any, error) { return nil, nil })
	ep, _ := protocol.NewEpoch(time.Now())
	var hr protocol.HelloResult
	if err := c.Call(ctx, protocol.MethodHello, protocol.HelloParams{
		TargetID: res.TargetID, TargetType: protocol.TargetHost, WriterID: wid, Incarnation: 1, Epoch: ep, MachineID: "0123456789abcdef0123456789abcdef",
		EpochOpen: &protocol.EpochOpen{Reason: protocol.OpenInitial}, Agent: protocol.AgentInfo{Protocol: 1},
	}, &hr); err != nil {
		t.Fatal(err)
	}
	var fetched protocol.BundleFetchResult
	if err := c.Call(ctx, protocol.MethodBundleFetch, protocol.BundleFetchParams{TargetType: protocol.TargetHost}, &fetched); err != nil {
		t.Fatal(err)
	}
	v, err := bundle.NewVerifier(roots, kv.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.AcceptManifest(fetched.KeyManifest); err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyBundle(fetched.Bundle, fetched.Signature); err != nil {
		t.Fatalf("published bundle does not verify against the generated roots: %v", err)
	}
	pem, _ := os.ReadFile(caFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 10 * time.Second}
	resp, err := hc.Get("https://" + endpoint + StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st struct {
		Targets []targetStatus `json:"targets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if len(st.Targets) != 1 || st.Targets[0].ID != res.TargetID || st.Targets[0].Type != protocol.TargetHost || st.Targets[0].Error != "" {
		t.Fatalf("status %+v", st)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBundleNeedsTrust(t *testing.T) {
	if err := run(context.Background(), []string{"-listen", "127.0.0.1:0", "-bundle-host", "x"}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "-trust-dir") {
		t.Fatalf("got %v", err)
	}
}
