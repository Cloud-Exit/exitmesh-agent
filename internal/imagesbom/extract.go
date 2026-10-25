package imagesbom

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// osReleasePaths are kept so OS package extractors can name the distribution release.
var osReleasePaths = map[string]bool{"etc/os-release": true, "usr/lib/os-release": true}

type extractorSet struct {
	all []filesystem.Extractor
	// gobinary only needs files that turn out to be Go executables.
	gobinary           filesystem.Extractor
	nestedArchiveBytes int64
}

// maxNestedArchiveBytes bounds the nested Java archives read into memory per archive, within the node agent's memory limit.
const maxNestedArchiveBytes = 64 << 20

// newExtractors leaves per-file limits to the staged byte bound, so no needed file is skipped without a truncation reason.
func newExtractors(nestedArchiveBytes int64) (*extractorSet, error) {
	cfg := &cpb.PluginConfig{PluginSpecific: []*cpb.PluginSpecificConfig{
		{Config: &cpb.PluginSpecificConfig_JavaArchive{JavaArchive: &cpb.JavaArchiveConfig{MaxOpenedBytes: nestedArchiveBytes}}},
	}}
	set := &extractorSet{nestedArchiveBytes: nestedArchiveBytes}
	for _, ctor := range []func(*cpb.PluginConfig) (filesystem.Extractor, error){
		dpkg.New, apk.New, rpm.New, gobinary.New, packagejson.New, wheelegg.New, archive.New,
	} {
		e, err := ctor(cfg)
		if err != nil {
			return nil, fmt.Errorf("imagesbom: extractor: %w", err)
		}
		set.all = append(set.all, e)
		if e.Name() == gobinary.Name {
			set.gobinary = e
		}
	}
	return set, nil
}

type fileAPI struct {
	path string
	info fs.FileInfo
}

func (f fileAPI) Path() string               { return f.path }
func (f fileAPI) Stat() (fs.FileInfo, error) { return f.info, nil }

// wanted returns the extractors that read the file at path.
func (s *extractorSet) wanted(path string, info fs.FileInfo) []filesystem.Extractor {
	var out []filesystem.Extractor
	api := fileAPI{path: path, info: info}
	for _, e := range s.all {
		if e.FileRequired(api) {
			out = append(out, e)
		}
	}
	return out
}

func (s *extractorSet) goOnly(es []filesystem.Extractor) bool {
	return len(es) == 1 && es[0] == s.gobinary
}

// extract runs each kept file through the extractors that asked for it, keeping packages an extractor returns with an error; it stops at the deadline.
func (s *extractorSet) extract(ctx context.Context, root string, files []keptFile, maxPackages int) ([]Package, string) {
	fsys := scalibrfs.DirFS(root)
	seen := map[Package]bool{}
	var out []Package
	reason := ""
	for _, kf := range files {
		if err := ctx.Err(); err != nil {
			return sortPackages(out), "the build reached its time bound before every file was read"
		}
		for _, e := range kf.extractors {
			pkgs, err := s.extractFile(ctx, fsys, root, kf.path, e)
			switch {
			case ctx.Err() != nil:
				reason = "the build reached its time bound before every file was read"
			case errors.Is(err, filesystem.ErrExtractorMemoryLimitExceeded):
				reason = fmt.Sprintf("a Java archive with its nested archives exceeds the %d byte bound", s.nestedArchiveBytes)
			}
			for _, p := range pkgs {
				if seen[p] {
					continue
				}
				if len(out) >= maxPackages {
					return sortPackages(out), fmt.Sprintf("the image holds more than %d packages", maxPackages)
				}
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return sortPackages(out), reason
}

func (s *extractorSet) extractFile(ctx context.Context, fsys scalibrfs.FS, root, path string, e filesystem.Extractor) ([]Package, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	inv, err := e.Extract(ctx, &filesystem.ScanInput{FS: fsys, Path: path, Root: root, Info: info, Reader: f})
	var out []Package
	for _, p := range inv.Packages {
		eco := p.Ecosystem().String()
		if p.Name == "" || eco == "" {
			continue
		}
		pkg := Package{Ecosystem: eco, Name: p.Name, Version: p.Version, Location: absPath(path)}
		if loc := p.Location.PathOrEmpty(); loc != "" {
			pkg.Location = absPath(loc)
		}
		if u := p.PURL(); u != nil {
			pkg.PURL = u.String()
		}
		out = append(out, pkg)
	}
	return out, err
}

func absPath(p string) string { return "/" + strings.TrimPrefix(filepath.ToSlash(p), "/") }

func sortPackages(ps []Package) []Package {
	slices.SortFunc(ps, func(a, b Package) int {
		return cmp.Or(cmp.Compare(a.Ecosystem, b.Ecosystem), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version), cmp.Compare(a.Location, b.Location))
	})
	return ps
}

func removeAll(dir string) error {
	if dir == "" || dir == "/" {
		return fmt.Errorf("imagesbom: refusing to remove %q", dir)
	}
	return os.RemoveAll(dir)
}
