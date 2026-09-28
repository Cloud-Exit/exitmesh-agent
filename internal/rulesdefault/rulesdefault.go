// Package rulesdefault serves the default ExitMesh rule bundle sources embedded from rules/ and builds their archives.
package rulesdefault

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/rules"
)

// Targets returns the target types that have a default bundle.
func Targets() []string { return []string{bundle.TargetKubernetes, bundle.TargetHost} }

// Sources returns the default bundle sources of targetType keyed by archive member path.
func Sources(targetType string) (map[string][]byte, error) {
	if targetType != bundle.TargetKubernetes && targetType != bundle.TargetHost {
		return nil, fmt.Errorf("rulesdefault: no default bundle for target type %q", targetType)
	}
	sub, err := fs.Sub(rules.FS, targetType)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	err = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		out[p] = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Archive builds the default bundle.tar.gz of targetType in memory, byte-identical to bundle.Build over rules/<targetType>.
func Archive(targetType string) ([]byte, error) {
	src, err := Sources(targetType)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(src))
	for n := range src {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	for _, n := range names {
		body := src[n]
		h := &tar.Header{Name: n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if _, err := bundle.Parse(buf.Bytes()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
