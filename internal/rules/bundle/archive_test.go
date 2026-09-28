package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseFixture(t *testing.T) {
	a := buildFiles(t, fixtureFiles())
	b, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if b.Digest != sha256.Sum256(a) {
		t.Fatal("digest is not the archive sha256")
	}
	if b.Manifest.Version != "2026.09.1" || len(b.Manifest.Rules) != 3 || !b.Manifest.CreatedAt.Equal(t0) {
		t.Fatalf("manifest: %+v", b.Manifest)
	}
	if len(b.State) != 1 || b.State[0].Meta.ID != "pod-crashloop" || b.State[0].For != 5*time.Minute {
		t.Fatalf("state: %+v", b.State)
	}
	if len(b.PromQL) != 1 || len(b.LogQL) != 1 {
		t.Fatalf("promql %d logql %d", len(b.PromQL), len(b.LogQL))
	}
	p := b.PromQL[0]
	if p.Meta.ID != "node-high-cpu" || p.Group != "node" || p.GroupInterval != 30*time.Second || p.For != 10*time.Minute {
		t.Fatalf("promql rule: %+v", p)
	}
	if p.Labels["team"] != "infra" || p.Labels["severity"] != "warning" || p.Annotations["runbook_url"] == "" {
		t.Fatalf("labels: %v annotations: %v", p.Labels, p.Annotations)
	}
	if b.LogQL[0].Meta.ID != "oom-logs" || !strings.Contains(b.LogQL[0].Expr, "|=") {
		t.Fatalf("logql rule: %+v", b.LogQL[0])
	}
	if len(b.Files) != 4 {
		t.Fatalf("files: %d", len(b.Files))
	}
}

func TestBuildReproducible(t *testing.T) {
	a1 := buildFiles(t, fixtureFiles())
	a2 := buildFiles(t, fixtureFiles())
	if !bytes.Equal(a1, a2) {
		t.Fatal("build is not reproducible")
	}
}

func TestBuildRejectsUnexpectedEntries(t *testing.T) {
	for _, extra := range []string{"README.md", "state/run.sh", "scripts/x.yaml"} {
		if _, err := Build(writeDir(t, withFile(fixtureFiles(), extra, "x"))); err == nil {
			t.Errorf("%s: build accepted", extra)
		}
	}
}

func TestExtractRejects(t *testing.T) {
	good := reg("bundle.yaml", fixtureManifest)
	big := bytes.Repeat([]byte("a"), MaxMemberBytes+1)
	manyMembers := []member{good}
	for i := 0; i < MaxMembers; i++ {
		manyMembers = append(manyMembers, reg(fmt.Sprintf("state/f%d.yaml", i), ""))
	}
	var bomb []member
	for i := 0; i < 5; i++ {
		bomb = append(bomb, member{hdr: tar.Header{Name: fmt.Sprintf("state/f%d.yaml", i), Typeflag: tar.TypeReg}, body: make([]byte, MaxMemberBytes)})
	}
	cases := map[string][]member{
		"traversal":      {good, reg("state/../../etc/passwd.yaml", "x")},
		"dotdot":         {good, reg("../bundle.yaml", "x")},
		"absolute":       {reg("/bundle.yaml", fixtureManifest)},
		"backslash":      {good, reg("state\\x.yaml", "x")},
		"symlink":        {good, {hdr: tar.Header{Name: "state/x.yaml", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}},
		"hardlink":       {good, {hdr: tar.Header{Name: "state/x.yaml", Typeflag: tar.TypeLink, Linkname: "bundle.yaml"}}},
		"chardev":        {good, {hdr: tar.Header{Name: "state/x.yaml", Typeflag: tar.TypeChar}}},
		"fifo":           {good, {hdr: tar.Header{Name: "state/x.yaml", Typeflag: tar.TypeFifo}}},
		"duplicate":      {good, reg("bundle.yaml", fixtureManifest)},
		"dup-dot-prefix": {good, reg("./bundle.yaml", fixtureManifest)},
		"unexpected":     {good, reg("README.md", "x")},
		"nested":         {good, reg("state/a/b.yaml", "x")},
		"unexpected-dir": {good, {hdr: tar.Header{Name: "bin/", Typeflag: tar.TypeDir}}},
		"member-size":    {good, {hdr: tar.Header{Name: "state/big.yaml", Typeflag: tar.TypeReg}, body: big}},
		"members":        manyMembers,
		"decompressed":   append([]member{good}, bomb...),
		"no-manifest":    {reg("state/pods.yaml", fixtureState)},
	}
	for name, ms := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(rawTar(t, ms))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
			t.Log(err)
		})
	}
	t.Run("archive-size", func(t *testing.T) {
		if _, err := Parse(make([]byte, MaxArchiveBytes+1)); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("trailing", func(t *testing.T) {
		a := append(buildFiles(t, fixtureFiles()), 0x1f, 0x8b, 0)
		if _, err := Parse(a); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("not-gzip", func(t *testing.T) {
		if _, err := Parse([]byte("plain")); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	})
}

func TestExtractAcceptsDotPrefixAndDirs(t *testing.T) {
	ms := []member{
		{hdr: tar.Header{Name: "./", Typeflag: tar.TypeDir}},
		reg("./bundle.yaml", fixtureManifest),
		{hdr: tar.Header{Name: "./state/", Typeflag: tar.TypeDir}},
		reg("./state/pods.yaml", fixtureState),
		reg("prometheus/node.yaml", fixtureProm),
		reg("loki/app.yml", fixtureLoki),
	}
	m := replaceIn(fixtureManifest, "file: loki/app.yaml", "file: loki/app.yml")
	ms[1] = reg("./bundle.yaml", m)
	b, err := Parse(rawTar(t, ms))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.State) != 1 || len(b.LogQL) != 1 {
		t.Fatalf("%+v", b)
	}
}

func TestParseBindingErrors(t *testing.T) {
	f := fixtureFiles()
	cases := map[string]map[string]string{
		"alert-without-meta":  withFile(f, "prometheus/extra.yaml", "groups:\n  - name: x\n    rules:\n      - alert: Orphan\n        expr: up == 0\n"),
		"meta-without-alert":  withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "alert: NodeHighCPU", "alert: Renamed")),
		"recording-rule":      withFile(f, "prometheus/rec.yaml", "groups:\n  - name: r\n    rules:\n      - record: job:up:sum\n        expr: sum(up)\n"),
		"state-without-meta":  withFile(f, "state/more.yaml", "- id: other\n  version: 1\n  target: kubernetes\n  kinds: [Pod]\n  expr: 'true'\n"),
		"meta-without-state":  withFile(f, "state/pods.yaml", ""),
		"duplicate-state":     withFile(f, "state/again.yaml", fixtureState),
		"duplicate-id":        withFile(f, "bundle.yaml", fixtureManifest+"  - id: oom-logs\n    version: 1\n    class: state\n"),
		"unknown-field":       withFile(f, "bundle.yaml", replaceIn(fixtureManifest, "schema_version: 1", "schema_version: 1\nwebhook_url: https://x")),
		"unknown-rule-field":  withFile(f, "bundle.yaml", replaceIn(fixtureManifest, "severity: high", "severity: high\n    exec: /bin/sh")),
		"unknown-state-field": withFile(f, "state/pods.yaml", fixtureState+"  command: [sh]\n"),
		"unknown-group-field": withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "interval: 30s", "interval: 30s\n    remote_write: x")),
		"multi-document":      withFile(f, "bundle.yaml", fixtureManifest+"---\nversion: x\n"),
		"query-offset":        withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "interval: 30s", "interval: 30s\n    query_offset: 1m")),
		"class-mismatch":      withFile(f, "bundle.yaml", replaceIn(fixtureManifest, "file: loki/app.yaml", "file: prometheus/node.yaml")),
		"bad-template":        withFile(f, "prometheus/node.yaml", replaceIn(fixtureProm, "{{ $labels.node }}", "{{ $labels.node")),
		"ambiguous":           withFile(f, "prometheus/node.yaml", fixtureProm+"      - alert: NodeHighCPU\n        expr: up == 0\n"),
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(rawArchive(t, files))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
			t.Log(err)
		})
	}
}

func rawArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var ms []member
	for n, b := range files {
		ms = append(ms, reg(n, b))
	}
	return rawTar(t, ms)
}

func TestParseMatchDisambiguates(t *testing.T) {
	prom := fixtureProm + "      - alert: NodeHighCPU\n        expr: avg by (node) (rate(node_cpu_seconds_total[5m])) > 0.99\n        labels:\n          severity: critical\n"
	man := replaceIn(fixtureManifest, "    alert: NodeHighCPU\n", "    alert: NodeHighCPU\n    match: {severity: warning}\n") +
		"  - id: node-cpu-critical\n    version: 1\n    class: promql\n    target: kubernetes\n    scope: node\n    file: prometheus/node.yaml\n    group: node\n    alert: NodeHighCPU\n    match: {severity: critical}\n    category: saturation\n    severity: critical\n    capabilities: [metrics]\n"
	b, err := Parse(buildFiles(t, withFile(withFile(fixtureFiles(), "prometheus/node.yaml", prom), "bundle.yaml", man)))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.PromQL) != 2 || b.PromQL[0].Meta.ID != "node-high-cpu" || b.PromQL[1].Meta.ID != "node-cpu-critical" {
		t.Fatalf("%+v", b.PromQL)
	}
	if b.PromQL[1].Labels["severity"] != "critical" {
		t.Fatal("wrong binding")
	}
}
