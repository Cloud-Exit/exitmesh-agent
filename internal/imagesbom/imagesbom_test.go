package imagesbom

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

type tarFile struct {
	name string
	body []byte
	mode int64
	typ  byte
	link string
}

func tarball(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.body)), Typeflag: f.typ, Linkname: f.link, ModTime: time.Unix(1700000000, 0)}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(f.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type store struct {
	t    *testing.T
	root string
}

func newStore(t *testing.T) *store {
	root := filepath.Join(t.TempDir(), "io.containerd.content.v1.content")
	if err := os.MkdirAll(filepath.Join(root, "blobs", "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &store{t: t, root: root}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *store) put(mediaType string, b []byte) descriptor {
	d := descriptor{MediaType: mediaType, Digest: digestOf(b), Size: int64(len(b))}
	if err := os.WriteFile(filepath.Join(s.root, "blobs", "sha256", strings.TrimPrefix(d.Digest, "sha256:")), b, 0o444); err != nil {
		s.t.Fatal(err)
	}
	return d
}

func (s *store) putJSON(mediaType string, v any) descriptor {
	b, err := json.Marshal(v)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.put(mediaType, b)
}

// unstored describes a blob that is referenced but absent, like other platforms of a pulled index.
func unstored(mediaType string, seed string) descriptor {
	return descriptor{MediaType: mediaType, Digest: digestOf([]byte(seed)), Size: int64(len(seed))}
}

var (
	goBinOnce sync.Once
	goBin     []byte
	goBinErr  error
)

// goBinary builds a tiny static Go program so the gobinary extractor reads real build information.
func goBinary(t *testing.T) []byte {
	t.Helper()
	goBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "imagesbom-gobin")
		if err != nil {
			goBinErr = err
			return
		}
		defer os.RemoveAll(dir)
		for name, body := range map[string]string{
			"go.mod":  "module example.com/hello\n\ngo 1.22\n",
			"main.go": "package main\n\nfunc main() { println(\"hello\") }\n",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				goBinErr = err
				return
			}
		}
		goTool, err := exec.LookPath("go")
		if err != nil {
			goBinErr = err
			return
		}
		cmd := exec.Command(goTool, "build", "-trimpath", "-o", filepath.Join(dir, "hello"), ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod", "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			goBinErr = errors.New(string(out))
			return
		}
		goBin, goBinErr = os.ReadFile(filepath.Join(dir, "hello"))
	})
	if goBinErr != nil {
		t.Skipf("cannot build a Go test binary: %v", goBinErr)
	}
	return goBin
}

const (
	debianRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nID=debian\n"
	dpkgStatus    = "Package: libc6\nStatus: install ok installed\nPriority: optional\nSection: libs\nInstalled-Size: 12000\nMaintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>\nArchitecture: amd64\nMulti-Arch: same\nSource: glibc\nVersion: 2.36-9+deb12u4\nDescription: GNU C Library: Shared libraries\n"
	alpineRelease = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"
	apkInstalled  = "C:Q1abcdefghijklmnopqrstuvwxyz0123=\nP:musl\nV:1.2.5-r0\nA:x86_64\nS:383152\nI:622592\nT:the musl c library (libc) implementation\nU:https://musl.libc.org/\nL:MIT\no:musl\nm:Natanael Copa <ncopa@alpinelinux.org>\nt:1700000000\nc:0123456789abcdef0123456789abcdef01234567\n\n"
	secretBody    = "password=hunter2\n"
)

const (
	ociIndex    = "application/vnd.oci.image.index.v1+json"
	ociManifest = "application/vnd.oci.image.manifest.v1+json"
	ociConfig   = "application/vnd.oci.image.config.v1+json"
	ociGzip     = "application/vnd.oci.image.layer.v1.tar+gzip"
	ociTar      = "application/vnd.oci.image.layer.v1.tar"
	dockerList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerMan   = "application/vnd.docker.distribution.manifest.v2+json"
	dockerCfg   = "application/vnd.docker.container.image.v1+json"
	dockerGzip  = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

type testImage struct {
	index, manifest, config string
}

func manifestFor(cfg descriptor, mediaType string, layers ...descriptor) map[string]any {
	return map[string]any{"schemaVersion": 2, "mediaType": mediaType, "config": cfg, "layers": layers}
}

func configJSON(labels map[string]string) map[string]any {
	return map[string]any{"architecture": "amd64", "os": "linux", "config": map[string]any{"Labels": labels}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{}}}
}

// debianImage is a multi-arch OCI image whose amd64 manifest has a gzip layer and an uncompressed layer with whiteouts.
func (s *store) debianImage(t *testing.T) testImage {
	l1 := s.put(ociGzip, gzipped(t, tarball(t, []tarFile{
		{name: "etc/", typ: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", body: []byte(debianRelease)},
		{name: "etc/secret.conf", body: []byte(secretBody)},
		{name: "var/lib/dpkg/status", body: []byte(dpkgStatus)},
		{name: "usr/local/bin/hello", body: goBinary(t), mode: 0o755},
		{name: "usr/bin/script", body: []byte("#!/bin/sh\necho " + secretBody), mode: 0o755},
		{name: "app/node_modules/x/package.json", body: []byte(`{"name":"x","version":"1.2.3"}`)},
		{name: "opt/vendor/node_modules/gone/package.json", body: []byte(`{"name":"gone","version":"0.1.0"}`)},
		{name: "usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA", body: []byte("Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n")},
		{name: "usr/lib/python3/dist-packages/old-1.0.dist-info/METADATA", body: []byte("Metadata-Version: 2.1\nName: old\nVersion: 1.0\n")},
	})))
	l2 := s.put(ociTar, tarball(t, []tarFile{
		{name: "usr/lib/python3/dist-packages/.wh.old-1.0.dist-info"},
		{name: "opt/vendor/node_modules/kept/package.json", body: []byte(`{"name":"kept","version":"2.0.0"}`)},
		{name: "opt/vendor/.wh..wh..opq"},
	}))
	cfg := s.putJSON(ociConfig, configJSON(map[string]string{
		LabelSource:   "https://ci:s3cr3tpass@github.com/acme/app",
		LabelRevision: "0123456789abcdef",
	}))
	man := s.putJSON(ociManifest, manifestFor(cfg, ociManifest, l1, l2))
	man.Platform = &platform{Architecture: "amd64", OS: "linux"}
	arm := unstored(ociManifest, "arm64 manifest")
	arm.Platform = &platform{Architecture: "arm64", OS: "linux", Variant: "v8"}
	idx := s.putJSON(ociIndex, map[string]any{"schemaVersion": 2, "mediaType": ociIndex, "manifests": []descriptor{arm, man}})
	return testImage{index: idx.Digest, manifest: man.Digest, config: cfg.Digest}
}

// alpineImage is a Docker manifest list whose os-release is a relative symlink.
func (s *store) alpineImage(t *testing.T) testImage {
	l := s.put(dockerGzip, gzipped(t, tarball(t, []tarFile{
		{name: "usr/lib/os-release", body: []byte(alpineRelease)},
		{name: "etc/os-release", typ: tar.TypeSymlink, link: "../usr/lib/os-release"},
		{name: "lib/apk/db/installed", body: []byte(apkInstalled)},
	})))
	cfg := s.putJSON(dockerCfg, configJSON(nil))
	man := s.putJSON(dockerMan, manifestFor(cfg, dockerMan, l))
	man.Platform = &platform{Architecture: "amd64", OS: "linux"}
	idx := s.putJSON(dockerList, map[string]any{"schemaVersion": 2, "mediaType": dockerList, "manifests": []descriptor{man}})
	return testImage{index: idx.Digest, manifest: man.Digest, config: cfg.Digest}
}

func (s *store) builder(t *testing.T, lim Limits) *builder {
	t.Helper()
	b, err := newBuilder(contentStore{root: s.root, arch: "amd64"}, filepath.Join(t.TempDir(), "work"), lim)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func find(res Result, eco, name string) *Package {
	for i, p := range res.Packages {
		if p.Ecosystem == eco && p.Name == name {
			return &res.Packages[i]
		}
	}
	return nil
}

func names(res Result) []string {
	var out []string
	for _, p := range res.Packages {
		out = append(out, p.Ecosystem+"/"+p.Name+"@"+p.Version)
	}
	return out
}

func TestBuildDebianImage(t *testing.T) {
	s := newStore(t)
	img := s.debianImage(t)
	b := s.builder(t, Limits{})
	res, err := b.build(context.Background(), img.index)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusReady || res.Digest != img.index || res.Truncated || res.Reason != "" || res.Scanner != "osv-scalibr 0.5.3" {
		t.Fatalf("result %+v", res)
	}
	if res.Labels.Source != "https://ci:s3cr3tpass@github.com/acme/app" || res.Labels.Revision != "0123456789abcdef" {
		t.Fatalf("labels %+v", res.Labels)
	}
	libc := find(res, "Debian:12", "libc6")
	if libc == nil || libc.Version != "2.36-9+deb12u4" || libc.Location != "/var/lib/dpkg/status" || !strings.HasPrefix(libc.PURL, "pkg:deb/debian/libc6@2.36-9") {
		t.Fatalf("dpkg package %+v in %v", libc, names(res))
	}
	if p := find(res, "npm", "x"); p == nil || p.Version != "1.2.3" || p.Location != "/app/node_modules/x/package.json" || !strings.HasPrefix(p.PURL, "pkg:npm/x@1.2.3") {
		t.Fatalf("npm package %+v", p)
	}
	if p := find(res, "PyPI", "requests"); p == nil || p.Version != "2.31.0" || p.PURL != "pkg:pypi/requests@2.31.0" {
		t.Fatalf("python package %+v", p)
	}
	if p := find(res, "Go", "go"); p == nil || p.Location != "/usr/local/bin/hello" || p.Version != strings.TrimPrefix(runtime.Version(), "go") {
		t.Fatalf("go stdlib %+v in %v", p, names(res))
	}
	if find(res, "npm", "kept") == nil || find(res, "npm", "gone") != nil || find(res, "PyPI", "old") != nil {
		t.Fatalf("whiteouts not applied: %v", names(res))
	}
	raw, _ := json.Marshal(res)
	if bytes.Contains(raw, []byte("hunter2")) || bytes.Contains(raw, []byte("secret.conf")) || bytes.Contains(raw, []byte("usr/bin/script")) {
		t.Fatalf("result carries file contents or unrelated files: %s", raw)
	}
	if _, err := os.Stat(b.work); !os.IsNotExist(err) {
		t.Fatalf("work directory left behind: %v", err)
	}
	byManifest, err := b.build(context.Background(), img.manifest)
	if err != nil || len(byManifest.Packages) != len(res.Packages) {
		t.Fatalf("by manifest digest: %v %v", err, names(byManifest))
	}
	byConfig, err := b.build(context.Background(), img.config)
	if err != nil || len(byConfig.Packages) != len(res.Packages) {
		t.Fatalf("by image config digest: %v %v", err, names(byConfig))
	}
}

func TestBuildAlpineImage(t *testing.T) {
	s := newStore(t)
	img := s.alpineImage(t)
	res, err := s.builder(t, Limits{}).build(context.Background(), img.index)
	if err != nil {
		t.Fatal(err)
	}
	p := find(res, "Alpine:v3.20", "musl")
	if p == nil || p.Version != "1.2.5-r0" || p.Location != "/lib/apk/db/installed" || !strings.HasPrefix(p.PURL, "pkg:apk/alpine/musl@1.2.5-r0") {
		t.Fatalf("apk package %+v in %v", p, names(res))
	}
	if res.Labels != (Labels{}) || res.Truncated {
		t.Fatalf("result %+v", res)
	}
}

func TestBuildTruncation(t *testing.T) {
	s := newStore(t)
	img := s.debianImage(t)
	for name, tc := range map[string]struct {
		lim  Limits
		want string
	}{
		"layer bytes":  {Limits{MaxLayerBytes: 4096}, "byte uncompressed bound"},
		"file count":   {Limits{MaxFiles: 3}, "more than 3 files"},
		"staged bytes": {Limits{MaxStagedBytes: 64 << 10}, "hold package metadata exceed the 65536 byte bound"},
		"packages":     {Limits{MaxPackages: 2}, "more than 2 packages"},
		"wall time":    {Limits{Timeout: time.Nanosecond}, "time bound"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := s.builder(t, tc.lim).build(context.Background(), img.index)
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != StatusReady || !res.Truncated || !strings.Contains(res.Reason, tc.want) || !strings.HasSuffix(res.Reason, "so the package list is incomplete.") {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

func TestBuildUnavailable(t *testing.T) {
	s := newStore(t)
	img := s.debianImage(t)
	ctx := context.Background()
	if _, err := s.builder(t, Limits{}).build(ctx, digestOf([]byte("absent"))); err == nil || !strings.Contains(err.Error(), "not in the containerd content store") {
		t.Fatalf("absent image: %v", err)
	}
	b, err := newBuilder(contentStore{root: s.root, arch: "s390x"}, filepath.Join(t.TempDir(), "w"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.build(ctx, img.index); err == nil || !strings.Contains(err.Error(), "no linux/s390x manifest") {
		t.Fatalf("platform: %v", err)
	}
	b.store = contentStore{root: filepath.Join(t.TempDir(), "missing"), arch: "amd64"}
	if _, err := b.build(ctx, img.index); err == nil || !strings.Contains(err.Error(), "imageInventory.contentStore") {
		t.Fatalf("missing store: %v", err)
	}
	if _, err := s.builder(t, Limits{}).build(ctx, "sha256:nothex"); err == nil {
		t.Fatal("malformed digest accepted")
	}
	var m document
	raw, _ := os.ReadFile(filepath.Join(s.root, "blobs", "sha256", strings.TrimPrefix(img.manifest, "sha256:")))
	_ = json.Unmarshal(raw, &m)
	tampered := filepath.Join(s.root, "blobs", "sha256", strings.TrimPrefix(m.Layers[1].Digest, "sha256:"))
	if err := os.Chmod(tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tampered, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.builder(t, Limits{}).build(ctx, img.index); err == nil || !strings.Contains(err.Error(), "layer 2") {
		t.Fatalf("tampered layer: %v", err)
	}
	for _, l := range m.Layers {
		_ = os.Remove(filepath.Join(s.root, "blobs", "sha256", strings.TrimPrefix(l.Digest, "sha256:")))
	}
	if _, err := s.builder(t, Limits{}).build(ctx, img.index); err == nil || !strings.Contains(err.Error(), "layers of image") {
		t.Fatalf("discarded layers: %v", err)
	}
}

func TestDigestFromImageID(t *testing.T) {
	d := digestOf([]byte("x"))
	for id, want := range map[string]string{
		"docker.io/library/nginx@" + d: d,
		"docker-pullable://nginx@" + d: d,
		d:                              d,
		"docker://" + d:                d,
		"nginx:1.27":                   "",
		"":                             "",
		"sha256:ABC":                   "",
	} {
		if got, ok := DigestFromImageID(id); got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", id, got, ok)
		}
	}
}

func newInventory(t *testing.T, s *store, dir string, mod func(*Options)) *Inventory {
	t.Helper()
	o := Options{Node: "n1", ContentStore: s.root, Dir: dir, Arch: "amd64", Settle: 10 * time.Millisecond, Pause: time.Millisecond, Logger: slog.New(slog.DiscardHandler)}
	if mod != nil {
		mod(&o)
	}
	inv, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func runInventory(t *testing.T, inv *Inventory) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); inv.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

func waitStatus(t *testing.T, inv *Inventory, digest, status string) Result {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		r := inv.Get(digest)
		if r.Status == status {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s stayed %+v, want %s", digest, r, status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestInventoryPendingReadyAndCache(t *testing.T) {
	s := newStore(t)
	img, alp := s.debianImage(t), s.alpineImage(t)
	dir := filepath.Join(t.TempDir(), "sbom")
	inv := newInventory(t, s, dir, nil)
	missing := digestOf([]byte("not pulled"))
	if r := inv.Get(img.index); r.Status != StatusUnavailable || r.Reason != "Node n1 has not listed its pods yet; ask again shortly." {
		t.Fatalf("before the first pod listing %+v", r)
	}
	inv.Observe([]string{img.index, missing, "not-a-digest"})
	if r := inv.Get(img.index); r.Status != StatusPending || len(r.Packages) != 0 || r.Scanner != Scanner {
		t.Fatalf("before build %+v", r)
	}
	if r := inv.Get(alp.index); r.Status != StatusUnavailable || r.Reason != "No running pod on node n1 uses image "+alp.index+"." {
		t.Fatalf("not running %+v", r)
	}
	runInventory(t, inv)
	ready := waitStatus(t, inv, img.index, StatusReady)
	if ready.Labels.Source != "https://ci:"+redact.Placeholder+"@github.com/acme/app" {
		t.Fatalf("labels not redacted before caching: %+v", ready.Labels)
	}
	if find(ready, "Debian:12", "libc6") == nil {
		t.Fatalf("packages %v", names(ready))
	}
	failed := waitStatus(t, inv, missing, StatusUnavailable)
	if !strings.Contains(failed.Reason, "is not in the containerd content store") || !strings.HasPrefix(failed.Reason, "Image ") {
		t.Fatalf("failure %+v", failed)
	}

	if err := os.RemoveAll(s.root); err != nil {
		t.Fatal(err)
	}
	if r := inv.Get(img.index); r.Status != StatusReady {
		t.Fatalf("cache miss after the content store went away: %+v", r)
	}
	reopened := newInventory(t, s, dir, nil)
	if r := reopened.Get(img.index); r.Status != StatusReady || len(r.Packages) != len(ready.Packages) {
		t.Fatalf("cache not persisted: %+v", r)
	}
}

func TestInventoryBackgroundAndLRU(t *testing.T) {
	s := newStore(t)
	img, alp := s.debianImage(t), s.alpineImage(t)
	inv := newInventory(t, s, filepath.Join(t.TempDir(), "sbom"), func(o *Options) { o.CacheEntries = 1 })
	runInventory(t, inv)
	inv.Observe([]string{img.index})
	deadline := time.Now().Add(30 * time.Second)
	for !inv.cache.has(img.index[7:]) {
		if time.Now().After(deadline) {
			t.Fatal("running digest never built in the background")
		}
		time.Sleep(5 * time.Millisecond)
	}
	inv.Observe([]string{alp.index})
	waitStatus(t, inv, alp.index, StatusReady)
	if inv.cache.has(img.index[7:]) {
		t.Fatal("least recently used entry not evicted")
	}
	if r := inv.Get(img.index); r.Status != StatusUnavailable {
		t.Fatalf("evicted digest that no longer runs: %+v", r)
	}
}

func TestInventoryBuildsOneAtATime(t *testing.T) {
	s := newStore(t)
	inv := newInventory(t, s, filepath.Join(t.TempDir(), "sbom"), func(o *Options) { o.Settle = time.Hour })
	var active, peak, builds atomic.Int32
	inv.build = func(ctx context.Context, d string) (Result, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		builds.Add(1)
		time.Sleep(5 * time.Millisecond)
		return Result{Status: StatusReady, Digest: d, Packages: []Package{}, Scanner: Scanner}, nil
	}
	var ds []string
	for i := range 6 {
		ds = append(ds, digestOf([]byte{byte(i)}))
	}
	inv.Observe(ds)
	runInventory(t, inv)
	var wg sync.WaitGroup
	for _, d := range ds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			waitStatus(t, inv, d, StatusReady)
		}()
	}
	wg.Wait()
	if peak.Load() != 1 || builds.Load() != int32(len(ds)) {
		t.Fatalf("peak concurrent builds %d, builds %d", peak.Load(), builds.Load())
	}
}

func zipped(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBuildJavaArchive(t *testing.T) {
	inner := zipped(t, map[string][]byte{
		"META-INF/maven/org.example/inner/pom.properties": []byte("groupId=org.example\nartifactId=inner\nversion=2.0.0\n"),
		"padding.bin": bytes.Repeat([]byte{0x5a}, 8192),
	})
	outer := zipped(t, map[string][]byte{
		"META-INF/maven/org.example/app/pom.properties": []byte("groupId=org.example\nartifactId=app\nversion=1.4.2\n"),
		"BOOT-INF/lib/inner-2.0.0.jar":                  inner,
	})
	s := newStore(t)
	l := s.put(ociGzip, gzipped(t, tarball(t, []tarFile{{name: "opt/app/app.jar", body: outer}})))
	cfg := s.putJSON(ociConfig, configJSON(nil))
	man := s.putJSON(ociManifest, manifestFor(cfg, ociManifest, l))
	res, err := s.builder(t, Limits{}).build(context.Background(), man.Digest)
	if err != nil {
		t.Fatal(err)
	}
	app, nested := find(res, "Maven", "org.example:app"), find(res, "Maven", "org.example:inner")
	if app == nil || app.Version != "1.4.2" || app.Location != "/opt/app/app.jar" || nested == nil || nested.Version != "2.0.0" || res.Truncated {
		t.Fatalf("java packages %v (%+v)", names(res), res)
	}
	b := s.builder(t, Limits{})
	if b.ex, err = newExtractors(1024); err != nil {
		t.Fatal(err)
	}
	if res, err = b.build(context.Background(), man.Digest); err != nil || !res.Truncated || !strings.Contains(res.Reason, "Java archive") {
		t.Fatalf("nested archive bound %+v %v", res, err)
	}
}
