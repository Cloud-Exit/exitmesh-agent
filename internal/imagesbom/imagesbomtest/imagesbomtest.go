// Package imagesbomtest writes synthetic containerd content stores for tests of image inventory callers.
package imagesbomtest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Alpine names the package an AlpineImage holds.
const (
	AlpinePackage   = "musl"
	AlpineVersion   = "1.2.5-r0"
	AlpineEcosystem = "Alpine:v3.20"
	AlpineSource    = "https://github.com/acme/app"
)

// ContentStore creates an empty content store layout under dir and returns its root.
func ContentStore(t testing.TB, dir string) string {
	t.Helper()
	root := filepath.Join(dir, "io.containerd.content.v1.content")
	if err := os.MkdirAll(filepath.Join(root, "blobs", "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func put(t testing.TB, root string, b []byte) map[string]any {
	t.Helper()
	sum := sha256.Sum256(b)
	d := "sha256:" + hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(d, "sha256:")), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"digest": d, "size": len(b)}
}

func putJSON(t testing.TB, root, mediaType string, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d := put(t, root, b)
	d["mediaType"] = mediaType
	return d
}

// AlpineImage writes a one-layer Alpine image for the running architecture and returns its index digest.
func AlpineImage(t testing.TB, root string) string {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for name, body := range map[string]string{
		"etc/os-release":       "ID=alpine\nVERSION_ID=3.20.3\n",
		"lib/apk/db/installed": "P:" + AlpinePackage + "\nV:" + AlpineVersion + "\nA:x86_64\no:musl\n\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(tb.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	layer := put(t, root, gz.Bytes())
	layer["mediaType"] = "application/vnd.oci.image.layer.v1.tar+gzip"
	cfg := putJSON(t, root, "application/vnd.oci.image.config.v1+json", map[string]any{
		"architecture": runtime.GOARCH, "os": "linux",
		"config": map[string]any{"Labels": map[string]string{"org.opencontainers.image.source": AlpineSource, "org.opencontainers.image.revision": "abc123"}},
	})
	man := putJSON(t, root, "application/vnd.oci.image.manifest.v1+json", map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": cfg, "layers": []any{layer},
	})
	man["platform"] = map[string]string{"architecture": runtime.GOARCH, "os": "linux"}
	idx := putJSON(t, root, "application/vnd.oci.image.index.v1+json", map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{man},
	})
	return idx["digest"].(string)
}
