package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/prometheus/prometheus/promql/parser"
	"gopkg.in/yaml.v3"
)

// Archive limits enforced during extraction.
const (
	MaxArchiveBytes = 16 << 20
	MaxMemberBytes  = 4 << 20
	MaxMembers      = 512
)

// SchemaVersion is the bundle.yaml schema version implemented by this agent.
const SchemaVersion = 1

// Archive layout.
const (
	ManifestFile  = "bundle.yaml"
	DirState      = "state"
	DirPrometheus = "prometheus"
	DirLoki       = "loki"
)

// ErrInvalid wraps every archive, schema, and validation failure.
var ErrInvalid = errors.New("bundle: invalid")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

var ruleDirs = map[string]string{DirState: ClassState, DirPrometheus: ClassPromQL, DirLoki: ClassLogQL}

// Parse extracts and decodes bundle.tar.gz and binds every rule to its metadata.
func Parse(archive []byte) (*Bundle, error) {
	if len(archive) > MaxArchiveBytes {
		return nil, invalidf("archive is %d bytes, limit %d", len(archive), MaxArchiveBytes)
	}
	files, err := extract(archive)
	if err != nil {
		return nil, err
	}
	raw, ok := files[ManifestFile]
	if !ok {
		return nil, invalidf("archive has no %s", ManifestFile)
	}
	b := &Bundle{Digest: sha256.Sum256(archive), Files: files}
	if err := decodeStrict(raw, &b.Manifest); err != nil {
		return nil, invalidf("%s: %v", ManifestFile, err)
	}
	if err := bind(b); err != nil {
		return nil, err
	}
	return b, nil
}

func decodeStrict(raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty document")
		}
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple YAML documents are not allowed")
	}
	return nil
}

func extract(archive []byte) (map[string][]byte, error) {
	br := bytes.NewReader(archive)
	zr, err := gzip.NewReader(br)
	if err != nil {
		return nil, invalidf("gzip: %v", err)
	}
	zr.Multistream(false)
	lr := &capReader{r: zr, left: MaxArchiveBytes + (MaxMembers+4)*1024}
	tr := tar.NewReader(lr)
	files := map[string][]byte{}
	seen := map[string]bool{}
	members, total := 0, int64(0)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if lr.over {
				return nil, invalidf("archive exceeds %d decompressed bytes", MaxArchiveBytes)
			}
			return nil, invalidf("tar: %v", err)
		}
		members++
		if members > MaxMembers {
			return nil, invalidf("archive has more than %d members", MaxMembers)
		}
		name, err := memberName(h.Name)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, invalidf("duplicate member %q", name)
		}
		seen[name] = true
		switch h.Typeflag {
		case tar.TypeDir:
			if _, ok := ruleDirs[name]; !ok && name != "." {
				return nil, invalidf("unexpected directory %q", name)
			}
			continue
		case tar.TypeReg:
		default:
			return nil, invalidf("member %q has type %q: only regular files and directories are allowed", name, string(h.Typeflag))
		}
		if !allowedFile(name) {
			return nil, invalidf("unexpected member %q", name)
		}
		if h.Size < 0 || h.Size > MaxMemberBytes {
			return nil, invalidf("member %q is %d bytes, limit %d", name, h.Size, MaxMemberBytes)
		}
		total += h.Size
		if total > MaxArchiveBytes {
			return nil, invalidf("archive exceeds %d decompressed bytes", MaxArchiveBytes)
		}
		body, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(body)) != h.Size {
			return nil, invalidf("member %q is truncated", name)
		}
		files[name] = body
	}
	if _, err := io.Copy(io.Discard, lr); err != nil {
		if lr.over {
			return nil, invalidf("archive exceeds %d decompressed bytes", MaxArchiveBytes)
		}
		return nil, invalidf("gzip: %v", err)
	}
	if br.Len() != 0 {
		return nil, invalidf("trailing data after gzip stream")
	}
	return files, nil
}

type capReader struct {
	r    io.Reader
	left int64
	over bool
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		c.over = true
		return 0, errors.New("size limit exceeded")
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func memberName(n string) (string, error) {
	orig := n
	n = strings.TrimPrefix(n, "./")
	n = strings.TrimSuffix(n, "/")
	if n == "" || n == "." {
		return ".", nil
	}
	if strings.HasPrefix(n, "/") || strings.ContainsAny(n, "\\\x00") || path.Clean(n) != n {
		return "", invalidf("unsafe member path %q", orig)
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." || seg == "." {
			return "", invalidf("unsafe member path %q", orig)
		}
	}
	return n, nil
}

func allowedFile(name string) bool {
	if name == ManifestFile {
		return true
	}
	dir, base := path.Split(name)
	if _, ok := ruleDirs[strings.TrimSuffix(dir, "/")]; !ok || strings.HasPrefix(base, ".") {
		return false
	}
	return strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}

func bind(b *Bundle) error {
	metas := map[string]int{}
	for i, m := range b.Manifest.Rules {
		if _, dup := metas[m.ID]; dup {
			return invalidf("duplicate rule id %q", m.ID)
		}
		metas[m.ID] = i
	}
	names := make([]string, 0, len(b.Files))
	for n := range b.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	boundAlert := map[string]string{}
	boundState := map[string]bool{}
	for _, name := range names {
		dir := path.Dir(name)
		class, ok := ruleDirs[dir]
		if !ok {
			continue
		}
		if class == ClassState {
			rules, err := parseStateFile(name, b.Files[name])
			if err != nil {
				return err
			}
			for _, r := range rules {
				i, ok := metas[r.ID]
				if !ok {
					return invalidf("%s: state rule %q has no entry in %s", name, r.ID, ManifestFile)
				}
				if b.Manifest.Rules[i].Class != ClassState {
					return invalidf("%s: state rule %q has metadata of class %q", name, r.ID, b.Manifest.Rules[i].Class)
				}
				if boundState[r.ID] {
					return invalidf("%s: duplicate state rule %q", name, r.ID)
				}
				boundState[r.ID] = true
				r.Meta = b.Manifest.Rules[i]
				b.State = append(b.State, r)
			}
			continue
		}
		rules, err := parseRuleGroupFile(name, b.Files[name])
		if err != nil {
			return err
		}
		for _, r := range rules {
			var match []int
			for i, m := range b.Manifest.Rules {
				if m.Class == class && m.File == r.File && m.Group == r.Group && m.Alert == r.Alert && labelsMatch(m.Match, r.Labels) {
					match = append(match, i)
				}
			}
			switch len(match) {
			case 0:
				return invalidf("%s: alerting rule %q in group %q has no rule metadata", name, r.Alert, r.Group)
			case 1:
			default:
				return invalidf("%s: alerting rule %q in group %q matches %d rule metadata entries", name, r.Alert, r.Group, len(match))
			}
			m := b.Manifest.Rules[match[0]]
			if prev, dup := boundAlert[m.ID]; dup {
				return invalidf("rule %q resolves to more than one alerting rule (%s and %s/%s); set match to disambiguate", m.ID, prev, r.Group, r.Alert)
			}
			boundAlert[m.ID] = r.Group + "/" + r.Alert
			r.Meta = m
			if class == ClassPromQL {
				b.PromQL = append(b.PromQL, r)
			} else {
				b.LogQL = append(b.LogQL, r)
			}
		}
	}
	for _, m := range b.Manifest.Rules {
		if effectiveMinEngine(m) > EngineVersion {
			continue
		}
		switch m.Class {
		case ClassState:
			if !boundState[m.ID] {
				return invalidf("rule %q has no state rule in %s/", m.ID, DirState)
			}
		case ClassPromQL, ClassLogQL:
			if _, ok := boundAlert[m.ID]; !ok {
				return invalidf("rule %q does not resolve to an alerting rule %q in group %q of %q", m.ID, m.Alert, m.Group, m.File)
			}
		}
	}
	return nil
}

func labelsMatch(want, have map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func parseStateFile(name string, raw []byte) ([]StateRule, error) {
	var rules []StateRule
	if err := decodeStrict(raw, &rules); err != nil {
		return nil, invalidf("%s: %v", name, err)
	}
	return rules, nil
}

// exprOnly defers expression validation to Validate so rules needing a newer engine stay loadable.
type exprOnly struct{ parser.Parser }

func (exprOnly) ParseExpr(input string) (parser.Expr, error) {
	return &parser.StringLiteral{Val: input}, nil
}

var discardLogger = slog.New(slog.DiscardHandler)

func parseRuleGroupFile(name string, raw []byte) ([]AlertRule, error) {
	if err := decodeStrict(raw, &rulefmt.RuleGroups{}); err != nil {
		return nil, invalidf("%s: %v", name, err)
	}
	groups, errs := rulefmt.Parse(raw, false, model.UTF8Validation, exprOnly{parser.NewParser(parser.Options{})}, discardLogger)
	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return nil, invalidf("%s: %s", name, strings.Join(msgs, "; "))
	}
	var out []AlertRule
	for _, g := range groups.Groups {
		if g.QueryOffset != nil || g.Limit != 0 {
			return nil, invalidf("%s: group %q: query_offset and limit are not supported", name, g.Name)
		}
		for _, r := range g.Rules {
			if r.Record != "" {
				return nil, invalidf("%s: group %q: recording rule %q is not allowed", name, g.Name, r.Record)
			}
			labels := map[string]string{}
			for k, v := range g.Labels {
				labels[k] = v
			}
			for k, v := range r.Labels {
				labels[k] = v
			}
			if len(labels) == 0 {
				labels = nil
			}
			out = append(out, AlertRule{
				File:          name,
				Group:         g.Name,
				GroupInterval: time.Duration(g.Interval),
				Alert:         r.Alert,
				Expr:          r.Expr,
				For:           time.Duration(r.For),
				KeepFiringFor: time.Duration(r.KeepFiringFor),
				Labels:        labels,
				Annotations:   r.Annotations,
			})
		}
	}
	return out, nil
}

// Build packs a bundle directory into a reproducible bundle.tar.gz and checks that it parses.
func Build(dir string) ([]byte, error) {
	var names []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		n := e.Name()
		switch {
		case n == ManifestFile && e.Type().IsRegular():
			names = append(names, n)
		case e.IsDir():
			if _, ok := ruleDirs[n]; !ok {
				return nil, fmt.Errorf("bundle: unexpected directory %q in %s", n, dir)
			}
			sub, err := os.ReadDir(filepath.Join(dir, n))
			if err != nil {
				return nil, err
			}
			for _, s := range sub {
				p := n + "/" + s.Name()
				if !s.Type().IsRegular() || !allowedFile(p) {
					return nil, fmt.Errorf("bundle: unexpected entry %q in %s", p, dir)
				}
				names = append(names, p)
			}
		default:
			return nil, fmt.Errorf("bundle: unexpected entry %q in %s", n, dir)
		}
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	for _, n := range names {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			return nil, err
		}
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
	if _, err := Parse(buf.Bytes()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
