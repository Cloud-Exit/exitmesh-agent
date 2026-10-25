package imagesbom

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits bound one build; reaching any of them marks the result truncated with the reason.
type Limits struct {
	// MaxLayerBytes bounds the uncompressed layer bytes read.
	MaxLayerBytes int64
	// MaxFiles bounds the layer entries read.
	MaxFiles int
	// MaxStagedBytes bounds the package metadata files staged on disk for the extractors.
	MaxStagedBytes int64
	MaxPackages    int
	Timeout        time.Duration
}

// DefaultLimits are the build bounds used when a limit is zero.
func DefaultLimits() Limits {
	return Limits{MaxLayerBytes: 4 << 30, MaxFiles: 500_000, MaxStagedBytes: 128 << 20, MaxPackages: 20_000, Timeout: 10 * time.Minute}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxLayerBytes <= 0 {
		l.MaxLayerBytes = d.MaxLayerBytes
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxStagedBytes <= 0 {
		l.MaxStagedBytes = d.MaxStagedBytes
	}
	if l.MaxPackages <= 0 {
		l.MaxPackages = d.MaxPackages
	}
	if l.Timeout <= 0 {
		l.Timeout = d.Timeout
	}
	return l
}

// builder turns one image digest into a package inventory.
type builder struct {
	store contentStore
	work  string
	lim   Limits
	ex    *extractorSet
}

func newBuilder(store contentStore, work string, lim Limits) (*builder, error) {
	lim = lim.withDefaults()
	ex, err := newExtractors(maxNestedArchiveBytes)
	if err != nil {
		return nil, err
	}
	return &builder{store: store, work: work, lim: lim, ex: ex}, nil
}

// build returns a ready result, truncated with a reason when a bound was reached; an error is a sentence saying why no inventory exists.
func (b *builder) build(ctx context.Context, digest string) (Result, error) {
	if _, err := ParseDigest(digest); err != nil {
		return Result{}, err
	}
	if err := b.store.check(); err != nil {
		return Result{}, err
	}
	img, err := b.store.resolve(digest)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, b.lim.Timeout)
	defer cancel()
	if err := removeAll(b.work); err != nil {
		return Result{}, err
	}
	root := filepath.Join(b.work, "rootfs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Result{}, fmt.Errorf("the image inventory work directory cannot be created: %w", err)
	}
	defer func() { _ = removeAll(b.work) }()
	fsys := newRootfs(root, b.ex, b.lim)
	missing := 0
	for i, l := range img.layers {
		lr, err := b.store.openLayer(l)
		if errors.Is(err, errBlobMissing) {
			missing++
			fsys.note("some image layers are not kept in the containerd content store")
			continue
		}
		if err != nil {
			return Result{}, fmt.Errorf("layer %d of image %s cannot be read: %w", i+1, digest, err)
		}
		err = fsys.apply(ctx, i, lr)
		if err == nil {
			err = lr.verify()
		}
		_ = lr.Close()
		var stop *errStop
		if errors.As(err, &stop) {
			fsys.note(stop.reason)
			break
		}
		if err != nil {
			return Result{}, fmt.Errorf("layer %d of image %s cannot be read: %w", i+1, digest, err)
		}
	}
	if len(img.layers) > 0 && missing == len(img.layers) {
		return Result{}, fmt.Errorf("the layers of image %s are not kept in the containerd content store of this node, so its packages cannot be read", digest)
	}
	fsys.resolveLinks()
	pkgs, reason := b.ex.extract(ctx, root, fsys.kept(), b.lim.MaxPackages)
	if reason != "" {
		fsys.note(reason)
	}
	res := Result{
		Status:    StatusReady,
		Digest:    digest,
		Labels:    Labels{Source: img.labels[LabelSource], Revision: img.labels[LabelRevision]},
		Packages:  pkgs,
		Truncated: len(fsys.truncated) > 0,
		Scanner:   Scanner,
	}
	if res.Packages == nil {
		res.Packages = []Package{}
	}
	if res.Truncated {
		res.Reason = sentence(strings.Join(fsys.truncated, "; ") + ", so the package list is incomplete")
	}
	return res, nil
}

// sentence capitalizes s and ends it with a period.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	r, n := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[n:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
