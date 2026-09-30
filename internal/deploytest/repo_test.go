package deploytest

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
)

func readFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWorkflowsParse(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	names := map[string]bool{}
	for _, f := range files {
		names[filepath.Base(f)] = true
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf map[string]any
		if err := yaml.Unmarshal(b, &wf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if wf["on"] == nil || wf["name"] == nil {
			t.Fatalf("%s: missing name or on", f)
		}
		jobs, ok := wf["jobs"].(map[string]any)
		if !ok || len(jobs) == 0 {
			t.Fatalf("%s: no jobs", f)
		}
		for id, j := range jobs {
			job, _ := j.(map[string]any)
			if u, ok := job["uses"].(string); ok {
				if !strings.HasPrefix(u, "./.github/workflows/") {
					t.Errorf("%s job %s: reusable workflow %s must be local", f, id, u)
				} else if _, err := os.Stat(filepath.Join(repoRoot(t), strings.TrimPrefix(u, "./"))); err != nil {
					t.Errorf("%s job %s: %v", f, id, err)
				}
				continue
			}
			if job["runs-on"] == nil {
				t.Errorf("%s job %s: missing runs-on", f, id)
			}
			steps, _ := job["steps"].([]any)
			if len(steps) == 0 {
				t.Errorf("%s job %s: no steps", f, id)
			}
			for i, s := range steps {
				st, _ := s.(map[string]any)
				if (st["uses"] == nil) == (st["run"] == nil) {
					t.Errorf("%s job %s step %d: exactly one of uses and run is required", f, id, i)
				}
				if u, ok := st["uses"].(string); ok && !strings.Contains(u, "@") {
					t.Errorf("%s job %s step %d: action %s is not pinned", f, id, i, u)
				}
				if r, ok := st["run"].(string); ok {
					for _, m := range regexp.MustCompile(`\.github/scripts/[a-z0-9-]+\.sh`).FindAllString(r, -1) {
						if fi, err := os.Stat(filepath.Join(repoRoot(t), m)); err != nil || fi.Mode()&0o111 == 0 {
							t.Errorf("%s job %s: %s missing or not executable", f, id, m)
						}
					}
				}
			}
		}
	}
	for _, want := range []string{"ci.yml", "quality.yml", "artifacts.yml", "loki-oracle.yml", "release.yml"} {
		if !names[want] {
			t.Errorf("workflow %s missing", want)
		}
	}
	gates := string(readFile(t, ".github/workflows/quality.yml")) + string(readFile(t, ".github/workflows/artifacts.yml"))
	for _, s := range []string{"go vet", "golangci-lint", "go test -race", "govulncheck", "go-licenses", "check-forbidden-modules.sh", "protocol/reference", "fuzz-smoke.sh",
		"helm lint", "ct lint", "chart-validate.sh", "internal/deploytest", "reproducible-build.sh", "goreleaser", "check-static.sh", "linux/$arch",
		"package-smoke.sh", "uninstall.sh", "host-smoke.sh", "kind-integration.sh", "helm package", "ko build"} {
		if !strings.Contains(gates, s) {
			t.Errorf("quality and artifact gates do not run %s", s)
		}
	}
	ci := string(readFile(t, ".github/workflows/ci.yml"))
	for _, s := range []string{"./.github/workflows/quality.yml", "./.github/workflows/artifacts.yml", "dco.sh", "release: false"} {
		if !strings.Contains(ci, s) {
			t.Errorf("ci.yml does not use %s", s)
		}
	}
	if lo := string(readFile(t, ".github/workflows/loki-oracle.yml")); !strings.Contains(lo, "LOKI_URL") || !strings.Contains(lo, "internal/rules/logql") {
		t.Error("loki-oracle.yml must run internal/rules/logql with LOKI_URL")
	}
	var rel struct {
		On struct {
			Push struct {
				Branches []string `yaml:"branches"`
			} `yaml:"push"`
			Dispatch struct {
				Inputs struct {
					Bump struct {
						Options []string `yaml:"options"`
						Default string   `yaml:"default"`
					} `yaml:"bump"`
				} `yaml:"inputs"`
			} `yaml:"workflow_dispatch"`
		} `yaml:"on"`
		Concurrency any `yaml:"concurrency"`
		Jobs        map[string]struct {
			If    string         `yaml:"if"`
			Needs yaml.Node      `yaml:"needs"`
			Uses  string         `yaml:"uses"`
			With  map[string]any `yaml:"with"`
		} `yaml:"jobs"`
	}
	relText := readFile(t, ".github/workflows/release.yml")
	if err := yaml.Unmarshal(relText, &rel); err != nil {
		t.Fatal(err)
	}
	if len(rel.On.Push.Branches) != 1 || rel.On.Push.Branches[0] != "main" {
		t.Errorf("release must trigger on push to main, got %v", rel.On.Push.Branches)
	}
	if v := rel.Jobs["version"].If; !strings.Contains(v, "[skip ci]") || !strings.Contains(v, "github.ref == 'refs/heads/main'") {
		t.Error("release version job must skip [skip ci] bump commits and release only main")
	}
	if b := rel.On.Dispatch.Inputs.Bump; !slices.Equal(b.Options, []string{"minor", "major"}) || b.Default != "minor" || !strings.Contains(string(relText), "inputs.bump || 'minor'") {
		t.Errorf("pushes must bump minor and only a manual run may bump major, got %+v", b)
	}
	if rel.Concurrency != nil {
		t.Error("a workflow concurrency group cancels pending release runs, so a push could go unreleased")
	}
	if a := rel.Jobs["artifacts"]; a.Uses != "./.github/workflows/artifacts.yml" || a.With["release"] != true {
		t.Error("release must build release artifacts through artifacts.yml")
	}
	var needs []string
	pub := rel.Jobs["publish"]
	if err := pub.Needs.Decode(&needs); err != nil {
		t.Fatal(err)
	}
	if n := needs; !slices.Contains(n, "quality") || !slices.Contains(n, "artifacts") {
		t.Errorf("publish must be gated on quality and artifacts, needs %v", n)
	}
	for _, s := range []string{"reserve-version.sh", "release-push.sh", "unreserve", "crane tag", "cosign sign", "cosign sign-blob", "helm push", "package-repo.sh", "gh release create", "cosign verify"} {
		if !strings.Contains(string(relText), s) {
			t.Errorf("release.yml does not run %s", s)
		}
	}
}

func TestLicenseExceptionsApproved(t *testing.T) {
	approved := []string{"github.com/cyphar/filepath-securejoin", "github.com/hashicorp/go-envparse"}
	ignore := regexp.MustCompile(`--ignore\s+(\S+)`)
	for _, f := range []string{".github/workflows/quality.yml", "Makefile"} {
		var got []string
		for _, m := range ignore.FindAllStringSubmatch(string(readFile(t, f)), -1) {
			if m[1] != "github.com/cloud-exit/exitmesh-agent" {
				got = append(got, m[1])
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, approved) {
			t.Errorf("%s ignores %v in the license check, approved exceptions are %v (CONTRIBUTING.md)", f, got, approved)
		}
	}
	notice, contributing := string(readFile(t, "NOTICE")), string(readFile(t, "CONTRIBUTING.md"))
	for _, m := range approved {
		if !strings.Contains(notice, m) || !strings.Contains(contributing, "`"+m+"`") {
			t.Errorf("approved exception %s must be named in NOTICE and CONTRIBUTING.md", m)
		}
	}
}

func TestReleaseConfigsParse(t *testing.T) {
	for _, f := range []string{".goreleaser.yaml", ".ko.yaml", ".golangci.yml"} {
		var v map[string]any
		if err := yaml.Unmarshal(readFile(t, f), &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	var gr struct {
		Builds []struct {
			Env     []string `yaml:"env"`
			Flags   []string `yaml:"flags"`
			Goarch  []string `yaml:"goarch"`
			ModTime string   `yaml:"mod_timestamp"`
		} `yaml:"builds"`
		Nfpms []struct {
			Formats []string `yaml:"formats"`
		} `yaml:"nfpms"`
		Signs []map[string]any `yaml:"signs"`
		Sboms []map[string]any `yaml:"sboms"`
	}
	if err := yaml.Unmarshal(readFile(t, ".goreleaser.yaml"), &gr); err != nil {
		t.Fatal(err)
	}
	b := gr.Builds[0]
	if !contains(b.Env, "CGO_ENABLED=0") || !contains(b.Flags, "-trimpath") || b.ModTime == "" || !contains(b.Goarch, "amd64") || !contains(b.Goarch, "arm64") {
		t.Fatalf("goreleaser build is not static and reproducible: %+v", b)
	}
	if !contains(gr.Nfpms[0].Formats, "deb") || !contains(gr.Nfpms[0].Formats, "rpm") || len(gr.Signs) == 0 || len(gr.Sboms) == 0 {
		t.Fatal("goreleaser must build deb and rpm, sign artifacts, and produce SBOMs")
	}
	gl := string(readFile(t, ".golangci.yml"))
	if !strings.HasPrefix(strings.TrimSpace(gl), `version: "2"`) {
		t.Fatal(".golangci.yml must use the v2 format")
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

var forbiddenModule = regexp.MustCompile(`^(github\.com/grafana/(loki|grafana|mimir|tempo|pyroscope|alloy|agent|oncall|phlare|k6)|go\.k6\.io/k6)(/|$)`)

func TestNoForbiddenModules(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader(string(readFile(t, "go.mod"))))
	n := 0
	for sc.Scan() {
		f := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(f) == 0 {
			continue
		}
		if f[0] == "require" && len(f) > 1 && f[1] != "(" {
			f = f[1:]
		}
		if !strings.Contains(f[0], ".") {
			continue
		}
		n++
		if forbiddenModule.MatchString(f[0]) || strings.Contains(f[0], "/loki") {
			t.Errorf("go.mod requires forbidden module %s", f[0])
		}
	}
	if n == 0 {
		t.Fatal("no modules parsed from go.mod")
	}
	for _, m := range []string{"github.com/grafana/loki/v3", "github.com/grafana/mimir", "github.com/grafana/grafana/pkg"} {
		if !forbiddenModule.MatchString(m) {
			t.Errorf("deny list misses %s", m)
		}
	}
	if forbiddenModule.MatchString("github.com/grafana/regexp") {
		t.Error("deny list must not reject the BSD-licensed grafana/regexp used by Prometheus")
	}
}

func TestHostDefaultConfig(t *testing.T) {
	b := readFile(t, "deploy/packaging/config/agent.yaml")
	var c config.Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("default host config has unknown keys: %v", err)
	}
	if c.Role != config.RoleHost || c.StateDir != "/var/lib/exitmesh" || c.EnrollmentTokenFile != "/etc/exitmesh/enrollment-token" {
		t.Fatalf("default host config = %+v", c)
	}
	withEndpoint := strings.Replace(string(b), `endpoint: ""`, `endpoint: "https://cp.example.com"`, 1)
	withEndpoint = strings.Replace(withEndpoint, "  roots: []", `  roots: ["root-1:AAAA"]`, 1)
	if _, err := config.Parse([]byte(strings.Replace(string(b), `endpoint: ""`, `endpoint: "https://cp.example.com"`, 1))); err == nil || !strings.Contains(err.Error(), "trust.roots") {
		t.Fatalf("default host config without trust roots must fail with a clear message: %v", err)
	}
	if _, err := config.Parse([]byte(withEndpoint)); err != nil {
		t.Fatalf("default host config with an endpoint does not validate: %v", err)
	}
}

func unitDirectives(t *testing.T) map[string][]string {
	out := map[string][]string{}
	sc := bufio.NewScanner(strings.NewReader(string(readFile(t, "deploy/packaging/systemd/exitmesh-agent.service"))))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed unit line %q", line)
		}
		out[k] = append(out[k], v)
	}
	return out
}

func TestSystemdUnitHardening(t *testing.T) {
	d := unitDirectives(t)
	want := map[string]string{
		"User": "exitmesh", "Group": "exitmesh", "NoNewPrivileges": "yes", "ProtectSystem": "strict",
		"ReadWritePaths": "/var/lib/exitmesh", "ProtectHome": "yes", "PrivateTmp": "yes",
		"CapabilityBoundingSet": "", "AmbientCapabilities": "", "StateDirectory": "exitmesh", "StateDirectoryMode": "0700",
		"RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX AF_NETLINK", "ProtectKernelTunables": "yes",
		"ProtectKernelModules": "yes", "ProtectKernelLogs": "yes", "LockPersonality": "yes", "MemoryMax": "192M",
		"CPUQuota": "10%", "SupplementaryGroups": "systemd-journal", "Environment": "GOMEMLIMIT=172MiB",
		"ExecStart": "/usr/bin/exitmesh-agent run --config /etc/exitmesh/agent.yaml",
	}
	for k, v := range want {
		if got := d[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"ReadWriteDirectories", "DynamicUser"} {
		if _, ok := d[k]; ok {
			t.Errorf("unit must not set %s", k)
		}
	}
	if su := string(readFile(t, "deploy/packaging/sysusers.d/exitmesh-agent.conf")); !strings.HasPrefix(su, "u exitmesh ") {
		t.Errorf("sysusers entry = %q", su)
	}
}

func TestMaintainerScripts(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	scripts := map[string][]string{
		"deploy/packaging/scripts/deb/postinst":      {"configure", "systemctl enable", "install -d -m 0700 -o exitmesh -g exitmesh"},
		"deploy/packaging/scripts/deb/prerm":         {"systemctl stop", "deenroll --config"},
		"deploy/packaging/scripts/deb/postrm":        {"purge)", "purge-state --dir \"$STATE\"", "does not de-enroll"},
		"deploy/packaging/scripts/rpm/post":          {"systemctl enable", "install -d -m 0700 -o exitmesh -g exitmesh"},
		"deploy/packaging/scripts/rpm/preun":         {"systemctl stop", "purge-state --dir \"$STATE\"", "EXITMESH_PURGE"},
		"deploy/packaging/scripts/rpm/postun":        {"try-restart"},
		"deploy/packaging/tarball/install.sh":        {"systemctl enable", "install -d -m 0700 -o exitmesh -g exitmesh"},
		"deploy/packaging/tarball/uninstall.sh":      {"--purge", "purge-state --dir \"$STATE\"", "deenroll --config"},
		".github/scripts/kind-integration.sh":        {"helm uninstall", "--cascade foreground"},
		".github/scripts/reproducible-build.sh":      {"-trimpath"},
		".github/scripts/check-forbidden-modules.sh": {"grafana"},
	}
	for rel, needles := range scripts {
		p := filepath.Join(repoRoot(t), rel)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable", rel)
		}
		shell := sh
		if strings.HasPrefix(rel, ".github/") {
			if shell, err = exec.LookPath("bash"); err != nil {
				continue
			}
		}
		if out, err := exec.Command(shell, "-n", p).CombinedOutput(); err != nil {
			t.Errorf("%s: syntax error: %s", rel, out)
		}
		body := string(readFile(t, rel))
		for _, n := range needles {
			if !strings.Contains(body, n) {
				t.Errorf("%s does not contain %q", rel, n)
			}
		}
	}
	prerm := string(readFile(t, "deploy/packaging/scripts/deb/prerm"))
	if strings.Index(prerm, "systemctl stop") > strings.Index(prerm, "install -m 0755") {
		t.Error("prerm must stop the service before anything else")
	}
	for _, rel := range []string{"deploy/packaging/scripts/deb/prerm", "deploy/packaging/scripts/deb/postrm", "deploy/packaging/scripts/rpm/preun"} {
		for _, line := range strings.Split(string(readFile(t, rel)), "\n") {
			if strings.Contains(line, "deenroll") && !strings.HasPrefix(strings.TrimSpace(line), "echo ") {
				t.Errorf("%s must offer, never perform, de-enrollment: %q", rel, line)
			}
		}
	}
	un := string(readFile(t, "deploy/packaging/tarball/uninstall.sh"))
	if ask, run := strings.Index(un, "read -r answer"), strings.Index(un, `"$BIN" deenroll`); ask < 0 || run < ask {
		t.Error("uninstall.sh may de-enroll only after an explicit prompt")
	}
}

func TestNoDashCharacters(t *testing.T) {
	roots := []string{"deploy", ".github", "internal/deploytest", "docs/install-kubernetes.md", "docs/install-host.md", "docs/uninstall.md",
		"docs/operations.md", "docs/security.md", "docs/configuration.md", "docs/upgrades.md", "docs/airgap.md",
		"README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "NOTICE", "LICENSE", "Makefile", ".goreleaser.yaml", ".ko.yaml", ".golangci.yml"}
	for _, r := range roots {
		root := filepath.Join(repoRoot(t), r)
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.ContainsRune(string(b), rune(0x2014)) || strings.ContainsRune(string(b), rune(0x2013)) {
				t.Errorf("%s contains an em or en dash", p)
			}
			return nil
		})
		if err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
}
