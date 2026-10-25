package imagesbom

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// DefaultContentStore is containerd's default content store; k3s and RKE2 use their own paths (docs/install-kubernetes.md).
const DefaultContentStore = "/var/lib/containerd/io.containerd.content.v1.content"

const (
	maxManifestBytes = 4 << 20
	maxConfigBytes   = 8 << 20
	// maxScannedBlobs bounds the search for a manifest when a pod reports only an image config digest.
	maxScannedBlobs = 20000
)

var errBlobMissing = errors.New("blob not in the content store")

type descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *platform `json:"platform,omitempty"`
}

type platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

// document holds the fields of an OCI or Docker index, manifest, or image config.
type document struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Config    *descriptor  `json:"config"`
	Layers    []descriptor `json:"layers"`
	RootFS    *struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type imageConfig struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

// image is a resolved platform manifest.
type image struct {
	config descriptor
	layers []descriptor
	labels map[string]string
}

// contentStore reads containerd's content store read-only by blobs/sha256/<hex>.
type contentStore struct {
	root    string
	arch    string
	variant string
}

func (c contentStore) blobPath(digest string) (string, error) {
	if _, err := ParseDigest(digest); err != nil {
		return "", err
	}
	return filepath.Join(c.root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), nil
}

func (c contentStore) check() error {
	st, err := os.Stat(filepath.Join(c.root, "blobs", "sha256"))
	if err != nil || !st.IsDir() {
		return fmt.Errorf("the containerd content store at %s cannot be read; set imageInventory.contentStore to the node's content store (k3s and RKE2 use their own paths)", c.root)
	}
	return nil
}

// readBlob reads a small blob in full and verifies its digest.
func (c contentStore) readBlob(digest string, limit int64) ([]byte, error) {
	p, err := c.blobPath(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errBlobMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("blob %s exceeds %d bytes", digest, limit)
	}
	if sum := sha256.Sum256(b); "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("blob %s does not match its digest", digest)
	}
	return b, nil
}

func (c contentStore) readDocument(digest string, limit int64) (*document, error) {
	b, err := c.readBlob(digest, limit)
	if err != nil {
		return nil, err
	}
	var d document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("blob %s is not an image document: %w", digest, err)
	}
	return &d, nil
}

func isIndex(d *document) bool {
	return len(d.Manifests) > 0 || strings.HasSuffix(d.MediaType, "image.index.v1+json") || strings.HasSuffix(d.MediaType, "manifest.list.v2+json")
}

func isManifest(d *document) bool { return d.Config != nil && d.Config.Digest != "" }

// resolve walks an index to the manifest for the node's platform and reads its config labels.
func (c contentStore) resolve(digest string) (*image, error) {
	d, err := c.readDocument(digest, maxManifestBytes)
	if errors.Is(err, errBlobMissing) {
		return nil, fmt.Errorf("image %s is not in the containerd content store of this node", digest)
	}
	if err != nil {
		return nil, err
	}
	for depth := 0; isIndex(d); depth++ {
		if depth > 2 {
			return nil, fmt.Errorf("image index %s nests too deeply", digest)
		}
		child, err := c.pick(d.Manifests)
		if err != nil {
			return nil, err
		}
		if d, err = c.readDocument(child.Digest, maxManifestBytes); errors.Is(err, errBlobMissing) {
			return nil, fmt.Errorf("the linux/%s manifest of image %s is not in the containerd content store of this node", c.platformName(), digest)
		} else if err != nil {
			return nil, err
		}
	}
	if !isManifest(d) {
		if d.RootFS == nil {
			return nil, fmt.Errorf("blob %s is neither an image index, a manifest, nor an image config", digest)
		}
		if d, err = c.manifestForConfig(digest); err != nil {
			return nil, err
		}
	}
	img := &image{config: *d.Config, layers: d.Layers}
	b, err := c.readBlob(d.Config.Digest, maxConfigBytes)
	if errors.Is(err, errBlobMissing) {
		return nil, fmt.Errorf("the config of image %s is not in the containerd content store of this node", digest)
	}
	if err != nil {
		return nil, err
	}
	var cfg imageConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("the config of image %s is not valid JSON", digest)
	}
	img.labels = cfg.Config.Labels
	return img, nil
}

func (c contentStore) platformName() string {
	if c.variant != "" {
		return c.arch + "/" + c.variant
	}
	return c.arch
}

// pick chooses the linux manifest for the node architecture, preferring an exact variant.
func (c contentStore) pick(ms []descriptor) (descriptor, error) {
	var loose *descriptor
	for i, m := range ms {
		p := m.Platform
		if p == nil || p.Architecture != c.arch || (p.OS != "" && p.OS != "linux") {
			continue
		}
		if p.Variant == c.variant {
			return m, nil
		}
		if loose == nil {
			loose = &ms[i]
		}
	}
	if loose != nil {
		return *loose, nil
	}
	return descriptor{}, fmt.Errorf("the image index has no linux/%s manifest", c.platformName())
}

// manifestForConfig finds the manifest that references a config digest, for pods that report an image ID instead of a repository digest.
func (c contentStore) manifestForConfig(configDigest string) (*document, error) {
	dir := filepath.Join(c.root, "blobs", "sha256")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for i, e := range entries {
		if i >= maxScannedBlobs {
			break
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxManifestBytes || len(e.Name()) != 64 {
			continue
		}
		d, err := c.readDocument("sha256:"+e.Name(), maxManifestBytes)
		if err != nil || !isManifest(d) || d.Config.Digest != configDigest {
			continue
		}
		return d, nil
	}
	return nil, fmt.Errorf("no manifest in the containerd content store of this node references image config %s", configDigest)
}

// layerReader opens a layer blob, decompresses it by its magic bytes, and verifies its digest when fully read.
type layerReader struct {
	f    *os.File
	h    hash.Hash
	want string
	raw  *bufio.Reader
	r    io.Reader
	zr   *zstd.Decoder
}

func (c contentStore) openLayer(l descriptor) (*layerReader, error) {
	p, err := c.blobPath(l.Digest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errBlobMissing
	}
	if err != nil {
		return nil, err
	}
	lr := &layerReader{f: f, h: sha256.New(), want: l.Digest}
	br := bufio.NewReader(io.TeeReader(f, lr.h))
	lr.raw = br
	magic, _ := br.Peek(4)
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		lr.r = gz
	case bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		zr, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		lr.zr, lr.r = zr, zr
	default:
		lr.r = br
	}
	return lr, nil
}

func (l *layerReader) Read(p []byte) (int, error) { return l.r.Read(p) }

// verify drains the compressed stream and checks the layer digest.
func (l *layerReader) verify() error {
	if _, err := io.Copy(io.Discard, l.r); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, l.raw); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(l.h.Sum(nil)); got != l.want {
		return fmt.Errorf("layer %s does not match its digest", l.want)
	}
	return nil
}

func (l *layerReader) Close() error {
	if l.zr != nil {
		l.zr.Close()
	}
	return l.f.Close()
}
