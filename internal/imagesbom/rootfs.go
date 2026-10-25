package imagesbom

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

// errStop ends layer processing at a bound; the reason is reported as truncation.
type errStop struct{ reason string }

func (e *errStop) Error() string { return e.reason }

var goBuildInfoMagic = []byte("\xff Go buildinf:")

type keptFile struct {
	path       string
	layer      int
	size       int64
	extractors []filesystem.Extractor
}

type symlink struct {
	target string
	layer  int
}

// rootfs materializes only the files extractors need from the layers, bottom to top, under dir; it never creates symlinks on disk.
type rootfs struct {
	dir   string
	ex    *extractorSet
	lim   Limits
	files map[string]*keptFile
	links map[string]symlink

	entries     int
	readBytes   int64
	stagedBytes int64
	truncated   []string
}

func newRootfs(dir string, ex *extractorSet, lim Limits) *rootfs {
	return &rootfs{dir: dir, ex: ex, lim: lim, files: map[string]*keptFile{}, links: map[string]symlink{}}
}

func (r *rootfs) disk(p string) string { return filepath.Join(r.dir, filepath.FromSlash(p)) }

func (r *rootfs) note(reason string) {
	for _, t := range r.truncated {
		if t == reason {
			return
		}
	}
	r.truncated = append(r.truncated, reason)
}

// countingReader enforces the uncompressed byte bound across all layers.
type countingReader struct {
	r *rootfs
	n io.Reader
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.n.Read(p)
	c.r.readBytes += int64(n)
	if c.r.readBytes > c.r.lim.MaxLayerBytes {
		return n, &errStop{fmt.Sprintf("the image layers exceed the %d byte uncompressed bound", c.r.lim.MaxLayerBytes)}
	}
	return n, err
}

func cleanName(name string) string {
	if strings.ContainsRune(name, 0) {
		return ""
	}
	p := path.Clean("/" + name)
	return strings.TrimPrefix(p, "/")
}

// apply reads one layer; an *errStop means a bound was reached and later layers are not applied.
func (r *rootfs) apply(ctx context.Context, layer int, src io.Reader) error {
	tr := tar.NewReader(countingReader{r: r, n: src})
	for {
		if ctx.Err() != nil {
			return &errStop{"the build reached its time bound before every layer was read"}
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			var stop *errStop
			if errors.As(err, &stop) {
				return stop
			}
			return fmt.Errorf("layer %d is not a valid tar stream: %w", layer, err)
		}
		r.entries++
		if r.entries > r.lim.MaxFiles {
			return &errStop{fmt.Sprintf("the image holds more than %d files", r.lim.MaxFiles)}
		}
		name := cleanName(hdr.Name)
		if name == "" {
			continue
		}
		dir, base := path.Split(name)
		if base == ".wh..wh..opq" {
			r.opaque(strings.TrimSuffix(dir, "/"), layer)
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			r.remove(dir + strings.TrimPrefix(base, ".wh."))
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			r.replace(name)
			if err := r.regular(ctx, layer, name, hdr, tr); err != nil {
				return err
			}
		case tar.TypeSymlink:
			r.replace(name)
			if osReleasePaths[name] {
				r.links[name] = symlink{target: hdr.Linkname, layer: layer}
			}
		case tar.TypeLink:
			r.replace(name)
			r.hardlink(layer, name, cleanName(hdr.Linkname), hdr)
		case tar.TypeDir:
			if r.files[name] != nil {
				r.replace(name)
			}
		}
	}
}

// replace drops what a lower layer staged at p before a new entry takes its place; only a staged directory needs a subtree scan.
func (r *rootfs) replace(p string) {
	if f := r.files[p]; f != nil {
		r.stagedBytes -= f.size
		delete(r.files, p)
		_ = os.Remove(r.disk(p))
	}
	delete(r.links, p)
	if st, err := os.Lstat(r.disk(p)); err == nil && st.IsDir() {
		r.remove(p)
	}
}

// remove drops p and everything below it, as a whiteout does.
func (r *rootfs) remove(p string) {
	if p == "" {
		return
	}
	prefix := p + "/"
	for k, f := range r.files {
		if k == p || strings.HasPrefix(k, prefix) {
			r.stagedBytes -= f.size
			delete(r.files, k)
		}
	}
	for k := range r.links {
		if k == p || strings.HasPrefix(k, prefix) {
			delete(r.links, k)
		}
	}
	_ = os.RemoveAll(r.disk(p))
}

// opaque hides what lower layers put under dir, keeping entries of the current layer.
func (r *rootfs) opaque(dir string, layer int) {
	prefix := dir + "/"
	if dir == "" {
		prefix = ""
	}
	for k, f := range r.files {
		if f.layer < layer && strings.HasPrefix(k, prefix) {
			r.stagedBytes -= f.size
			delete(r.files, k)
			_ = os.Remove(r.disk(k))
		}
	}
	for k, l := range r.links {
		if l.layer < layer && strings.HasPrefix(k, prefix) {
			delete(r.links, k)
		}
	}
}

func (r *rootfs) regular(ctx context.Context, layer int, name string, hdr *tar.Header, src io.Reader) error {
	info := hdr.FileInfo()
	var es []filesystem.Extractor
	if !osReleasePaths[name] {
		if es = r.ex.wanted(name, info); len(es) == 0 {
			return nil
		}
	}
	goOnly := r.ex.goOnly(es)
	if hdr.Size > r.lim.MaxStagedBytes-r.stagedBytes {
		if goOnly {
			scan := &goScan{}
			if _, err := io.Copy(scan, src); err != nil {
				return stopOr(err)
			}
			if !scan.isGo() {
				return nil
			}
		}
		r.note(fmt.Sprintf("files that hold package metadata exceed the %d byte bound", r.lim.MaxStagedBytes))
		return nil
	}
	dst := r.disk(name)
	if err := r.mkdirFor(name); err != nil {
		r.note("a file that holds package metadata could not be staged")
		return nil
	}
	mode := os.FileMode(0o600)
	if info.Mode()&0o111 != 0 {
		mode = 0o700
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("stage %s: %w", name, err)
	}
	scan := &goScan{}
	var w io.Writer = f
	if goOnly {
		w = io.MultiWriter(f, scan)
	}
	_, err = io.Copy(w, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		return stopOr(err)
	}
	if goOnly && !scan.isGo() {
		return os.Remove(dst)
	}
	r.files[name] = &keptFile{path: name, layer: layer, size: hdr.Size, extractors: es}
	r.stagedBytes += hdr.Size
	return nil
}

func stopOr(err error) error {
	var stop *errStop
	if errors.As(err, &stop) {
		return stop
	}
	return err
}

// mkdirFor creates the parent directories of name, replacing a kept file that sits where a directory is now.
func (r *rootfs) mkdirFor(name string) error {
	parent := path.Dir(name)
	if parent == "." {
		return nil
	}
	if err := os.MkdirAll(r.disk(parent), 0o700); err == nil {
		return nil
	}
	for p := parent; p != "." && p != "/"; p = path.Dir(p) {
		if r.files[p] != nil {
			r.remove(p)
		}
	}
	return os.MkdirAll(r.disk(parent), 0o700)
}

func (r *rootfs) hardlink(layer int, name, target string, hdr *tar.Header) {
	t := r.files[target]
	if t == nil {
		return
	}
	es := t.extractors
	if !osReleasePaths[name] {
		info := hdr.FileInfo()
		if es = r.ex.wanted(name, info); len(es) == 0 {
			return
		}
	}
	if r.mkdirFor(name) != nil || os.Link(r.disk(target), r.disk(name)) != nil {
		r.note("a file that holds package metadata could not be staged")
		return
	}
	r.files[name] = &keptFile{path: name, layer: layer, extractors: es}
}

// resolveLinks stages os-release targets under the symlink name so extractors can read the distribution.
func (r *rootfs) resolveLinks() {
	for name := range r.links {
		t := r.files[r.follow(name)]
		if t == nil || r.files[name] != nil || r.mkdirFor(name) != nil {
			continue
		}
		if os.Link(r.disk(t.path), r.disk(name)) == nil {
			r.files[name] = &keptFile{path: name, layer: t.layer}
		}
	}
}

func (r *rootfs) follow(name string) string {
	cur := name
	for hops := 0; hops < 8; hops++ {
		l, ok := r.links[cur]
		if !ok {
			return cur
		}
		t := l.target
		if !path.IsAbs(t) {
			t = path.Join(path.Dir("/"+cur), t)
		}
		cur = cleanName(t)
	}
	return ""
}

// kept returns the staged files that extractors read, in path order.
func (r *rootfs) kept() []keptFile {
	out := make([]keptFile, 0, len(r.files))
	for _, f := range r.files {
		if len(f.extractors) > 0 {
			out = append(out, *f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// goScan detects an ELF file carrying Go build information while it streams.
type goScan struct {
	head  []byte
	tail  []byte
	found bool
}

func (g *goScan) Write(p []byte) (int, error) {
	if len(g.head) < 4 {
		g.head = append(g.head, p[:min(4-len(g.head), len(p))]...)
	}
	if !g.found {
		buf := append(g.tail, p...)
		if bytes.Contains(buf, goBuildInfoMagic) {
			g.found = true
		}
		keep := min(len(goBuildInfoMagic)-1, len(buf))
		g.tail = append(g.tail[:0], buf[len(buf)-keep:]...)
	}
	return len(p), nil
}

func (g *goScan) isGo() bool { return g.found && bytes.Equal(g.head, []byte("\x7fELF")) }
