package imagesbom

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func buildTestLayers(t *testing.T, lim Limits, layers ...[]tarFile) Result {
	t.Helper()
	s := newStore(t)
	var ds []descriptor
	for _, files := range layers {
		ds = append(ds, s.put(ociTar, tarball(t, files)))
	}
	cfg := s.putJSON(ociConfig, configJSON(nil))
	man := s.putJSON(ociManifest, manifestFor(cfg, ociManifest, ds...))
	res, err := s.builder(t, lim).build(context.Background(), man.Digest)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestBuildLayerPaddingBound(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "tar", true: "gzip"}[compressed], func(t *testing.T) {
			s := newStore(t)
			raw := append(tarball(t, nil), bytes.Repeat([]byte{0}, 1<<20)...)
			media := ociTar
			if compressed {
				raw, media = gzipped(t, raw), ociGzip
			}
			layer := s.put(media, raw)
			cfg := s.putJSON(ociConfig, configJSON(nil))
			man := s.putJSON(ociManifest, manifestFor(cfg, ociManifest, layer))
			res, err := s.builder(t, Limits{MaxLayerBytes: 4096}).build(context.Background(), man.Digest)
			if err != nil || !res.Truncated || !strings.Contains(res.Reason, "uncompressed bound") {
				t.Fatalf("padding escaped the layer limit: truncated=%v reason=%q err=%v", res.Truncated, res.Reason, err)
			}
		})
	}
}

type cancelReader struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (r cancelReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.cancel()
	return n, err
}

func TestLayerVerificationHonorsCancellation(t *testing.T) {
	s := newStore(t)
	raw := append(tarball(t, nil), bytes.Repeat([]byte{0}, 1<<20)...)
	layer := s.put(ociGzip, gzipped(t, raw))
	b := s.builder(t, Limits{})
	lr, err := b.store.openLayer(layer)
	if err != nil {
		t.Fatal(err)
	}
	defer lr.Close()
	fsys := newRootfs(t.TempDir(), b.ex, b.lim)
	if err := fsys.apply(context.Background(), 0, lr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = lr.verify(ctx, fsys.reader(ctx, cancelReader{r: lr, cancel: cancel}))
	var stop *errStop
	if !errors.As(err, &stop) || !strings.Contains(stop.reason, "time bound") || fsys.readBytes >= int64(len(raw)) {
		t.Fatalf("verification ignored cancellation: bytes=%d err=%v", fsys.readBytes, err)
	}
}

func TestBuildParserFailureMarksIncomplete(t *testing.T) {
	res := buildTestLayers(t, Limits{}, []tarFile{
		{name: "app/node_modules/broken/package.json", body: []byte(`{"name":"broken","version":`)},
		{name: "app/node_modules/valid/package.json", body: []byte(`{"name":"valid","version":"1.2.3"}`)},
	})
	if !res.Truncated || res.Reason == "" || find(res, "npm", "valid") == nil {
		t.Fatalf("parser failure lost coverage or valid packages: truncated=%v reason=%q packages=%v", res.Truncated, res.Reason, names(res))
	}
}

func TestBuildUnstagedHardlinkMarksIncomplete(t *testing.T) {
	res := buildTestLayers(t, Limits{}, []tarFile{
		{name: "store/abcdef", body: []byte(`{"name":"linked","version":"1.2.3"}`)},
		{name: "app/node_modules/linked/package.json", typ: tar.TypeLink, link: "store/abcdef"},
	})
	if !res.Truncated || !strings.Contains(res.Reason, "hardlink") {
		t.Fatalf("missing hardlink metadata reported complete: truncated=%v reason=%q", res.Truncated, res.Reason)
	}
}

func TestBuildHardlinksRetainStagingBudget(t *testing.T) {
	metadata := append([]byte(`{"name":"linked","version":"1.2.3"}`), bytes.Repeat([]byte{' '}, 800)...)
	base := []tarFile{
		{name: "original/package.json", body: metadata},
		{name: "retained/package.json", typ: tar.TypeLink, link: "original/package.json"},
	}
	for name, overwrite := range map[string]tarFile{
		"whiteout": {name: "original/.wh.package.json"},
		"opaque":   {name: "original/.wh..wh..opq"},
		"replace":  {name: "original/package.json", body: []byte(`{"name":"replacement","version":"2.0.0"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			res := buildTestLayers(t, Limits{MaxStagedBytes: 1000}, base, []tarFile{
				overwrite,
				{name: "extra/package.json", body: metadata},
			})
			if !res.Truncated || !strings.Contains(res.Reason, "1000 byte bound") || find(res, "npm", "linked") == nil {
				t.Fatalf("retained hardlink escaped staging budget: truncated=%v reason=%q packages=%v", res.Truncated, res.Reason, names(res))
			}
		})
	}
	res := buildTestLayers(t, Limits{MaxStagedBytes: 1000}, base, []tarFile{
		{name: "original/.wh.package.json"},
		{name: "retained/.wh.package.json"},
		{name: "extra/package.json", body: metadata},
	})
	if res.Truncated || len(res.Packages) != 1 || res.Packages[0].Location != "/extra/package.json" {
		t.Fatalf("last hardlink did not release staging budget: truncated=%v reason=%q packages=%v", res.Truncated, res.Reason, names(res))
	}
}

func TestInventoryCachePressureDoesNotRepeatBuilds(t *testing.T) {
	for _, bound := range []string{"entries", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			now := time.Unix(1700000000, 0)
			inv := newInventory(t, newStore(t), t.TempDir(), func(o *Options) {
				o.Clock = func() time.Time { return now }
				if bound == "entries" {
					o.CacheEntries = 1
				} else {
					o.CacheBytes = 256
				}
			})
			ds := []string{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("c", 64)}
			counts := map[string]int{}
			inv.build = func(_ context.Context, d string) (Result, error) {
				counts[d]++
				return Result{Status: StatusReady, Digest: d, Packages: []Package{}, Scanner: Scanner}, nil
			}
			inv.Observe(ds)
			now = now.Add(time.Minute)
			for range 8 {
				d, _ := inv.next()
				if d == "" {
					break
				}
				inv.runOne(context.Background(), d)
				now = now.Add(time.Second)
				inv.Observe(ds)
			}
			for _, d := range ds {
				if counts[d] != 1 {
					t.Fatalf("cache pressure repeated or starved builds: %v", counts)
				}
			}
			if res := inv.Get(ds[0]); res.Status != StatusPending {
				t.Fatalf("evicted digest cannot be requested again: %s", res.Status)
			}
			d, urgent := inv.next()
			if d != ds[0] || !urgent {
				t.Fatalf("evicted request not prioritized: digest=%s urgent=%v", d, urgent)
			}
			inv.runOne(context.Background(), d)
			if res := inv.Get(d); res.Status != StatusReady {
				t.Fatalf("requested rebuild not cached: %s", res.Status)
			}
			if d, _ := inv.next(); d != "" {
				t.Fatalf("requested rebuild restarted background churn: %s", d)
			}
			inv.Observe(nil)
			inv.Observe(ds[1:2])
			now = now.Add(time.Minute)
			if d, urgent := inv.next(); d != ds[1] || urgent {
				t.Fatalf("newly observed digest was not scheduled: digest=%s urgent=%v", d, urgent)
			}
		})
	}
}

func resultBytes(t *testing.T, r Result) int64 {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return int64(len(b))
}
