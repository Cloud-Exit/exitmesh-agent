package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/imagesbom"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

func TestImageSBOMTaskFitsNodeAPI(t *testing.T) {
	dir := t.TempDir()
	hex := strings.Repeat("a", 64)
	original := imagesbom.Result{Status: imagesbom.StatusReady, Digest: "sha256:" + hex, Scanner: imagesbom.Scanner, Packages: []imagesbom.Package{
		{Ecosystem: "npm", Name: "small", Version: "1.2.3"},
		{Ecosystem: "npm", Name: "large", Version: "1.2.3", Location: strings.Repeat("x", nodeapi.MaxRequestBytes)},
	}}
	cache := filepath.Join(dir, "cache")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, hex+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := imagesbom.New(imagesbom.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	executor := imageExecutor{images: inv, node: "n1"}
	payload, _ := json.Marshal(imagesbom.TaskRequest{Digest: original.Digest})
	res := executor.Execute(context.Background(), nodeapi.Task{ID: "image-task", Kind: nodeapi.TaskImageSBOM, Payload: payload})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	wire, err := nodeapi.Marshal(res)
	if err != nil || len(wire) > nodeapi.MaxRequestBytes {
		t.Fatalf("image task cannot be posted: bytes=%d err=%v", len(wire), err)
	}
	var bounded imagesbom.Result
	if err := json.Unmarshal(res.Payload, &bounded); err != nil {
		t.Fatal(err)
	}
	if !bounded.Truncated || bounded.Reason == "" || len(bounded.Packages) != 1 || bounded.Packages[0].Name != "small" {
		t.Fatalf("wrong bounded task result: packages=%d truncated=%v reason=%q", len(bounded.Packages), bounded.Truncated, bounded.Reason)
	}
	if cached := inv.Get(original.Digest); cached.Truncated || len(cached.Packages) != 2 {
		t.Fatal("transmission limit changed the cached inventory")
	}
}
