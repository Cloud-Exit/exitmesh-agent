package rulesdefault

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/validators"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// loadBundle parses and validates the default archive of target with the real validators.
func loadBundle(t *testing.T, target string) (*bundle.Bundle, bundle.Result) {
	t.Helper()
	a, err := Archive(target)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	p := bundle.DefaultPolicy()
	p.TargetType = target
	res, err := bundle.Validate(b, validators.For(target), p)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	return b, res
}

func ruleIDs(b *bundle.Bundle) []string {
	var ids []string
	for _, m := range b.Manifest.Rules {
		ids = append(ids, m.ID)
	}
	return ids
}

func TestArchivesValidate(t *testing.T) {
	for _, target := range Targets() {
		b, res := loadBundle(t, target)
		if len(res.Rejected) > 0 || len(res.Unsupported) > 0 || len(res.Disabled) > 0 {
			t.Fatalf("%s: rejected %v unsupported %v disabled %v", target, res.Rejected, res.Unsupported, res.Disabled)
		}
		if len(res.Active) != len(b.Manifest.Rules) || len(res.Active) == 0 {
			t.Fatalf("%s: %d active of %d rules", target, len(res.Active), len(b.Manifest.Rules))
		}
		if b.Manifest.TargetType != target {
			t.Fatalf("%s: target type %q", target, b.Manifest.TargetType)
		}
		for _, m := range b.Manifest.Rules {
			if m.Target != target {
				t.Fatalf("%s: rule %s targets %s", target, m.ID, m.Target)
			}
		}
	}
}

func TestArchiveMatchesBuild(t *testing.T) {
	for _, target := range Targets() {
		a, err := Archive(target)
		if err != nil {
			t.Fatal(err)
		}
		want, err := bundle.Build(filepath.Join(repoRoot(t), "rules", target))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, want) {
			t.Fatalf("%s: embedded archive differs from bundle.Build of the source directory", target)
		}
		again, _ := Archive(target)
		if !bytes.Equal(a, again) {
			t.Fatalf("%s: archive is not reproducible", target)
		}
	}
}

func TestSources(t *testing.T) {
	src, err := Sources(bundle.TargetHost)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src[bundle.ManifestFile]; !ok {
		t.Fatalf("host sources lack %s: %v", bundle.ManifestFile, src)
	}
	for n := range src {
		if strings.HasSuffix(n, ".go") {
			t.Fatalf("source %s is not a bundle member", n)
		}
	}
	if _, err := Sources("windows"); err == nil {
		t.Fatal("unknown target type accepted")
	}
	if _, err := Archive("windows"); err == nil {
		t.Fatal("unknown target type archived")
	}
}

func TestCoverageDocListsEveryRule(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "insight-coverage.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range Targets() {
		b, _ := loadBundle(t, target)
		for _, id := range ruleIDs(b) {
			if !bytes.Contains(doc, []byte("`"+id+"`")) {
				t.Errorf("docs/insight-coverage.md does not list rule %s", id)
			}
		}
	}
	for _, insight := range []string{
		"log.process_failure", "log.error_rate_spike", "log.severity_mix_shift", "log.new_fingerprint_burst", "log.dominant_fingerprint",
		"metric.saturation", "metric.active_series_spike", "metric.slope_change", "metric.volume_saturation", "metric.volume_fill_trend",
		"event.warning_spike", "event.reason_spike", "event.new_reason", "event.backoff_loop", "event.scheduling_failure",
		"event.image_pull_failure", "event.volume_failure", "event.node_pressure",
		"manifest.pod_status_failure", "manifest.sveltos_feature_failure", "cross_signal_correlation",
	} {
		if !bytes.Contains(doc, []byte("\n|`"+insight+"`|")) {
			t.Errorf("docs/insight-coverage.md has no row for insight %s", insight)
		}
	}
	for _, r := range []rune{0x2013, 0x2014} {
		if bytes.ContainsRune(doc, r) {
			t.Fatalf("docs/insight-coverage.md contains a dash character %U", r)
		}
	}
}

func TestEveryRuleHasFixture(t *testing.T) {
	have := map[string]bool{}
	for _, f := range fixtures() {
		if have[f.id] {
			t.Fatalf("duplicate fixture %s", f.id)
		}
		have[f.id] = true
	}
	var all []string
	for _, target := range Targets() {
		b, _ := loadBundle(t, target)
		all = append(all, ruleIDs(b)...)
	}
	for _, id := range all {
		if !have[id] {
			t.Errorf("rule %s has no fixture", id)
		}
	}
	for id := range have {
		if !slices.Contains(all, id) {
			t.Errorf("fixture %s names no rule", id)
		}
	}
}
