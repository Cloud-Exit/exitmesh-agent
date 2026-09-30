package deploytest

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

type gitEnv struct {
	t    *testing.T
	dir  string
	env  []string
	root string
}

func newGitEnv(t *testing.T) *gitEnv {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	g := &gitEnv{t: t, dir: dir, root: repoRoot(t), env: append(os.Environ(),
		"HOME="+dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(dir, "gitconfig"),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")}
	g.run(dir, "git", "init", "-q", "--bare", "-b", "main", "remote.git")
	seed := g.path("seed")
	g.run(dir, "git", "init", "-q", "-b", "main", seed)
	chart := filepath.Join(seed, "deploy/helm/exitmesh-agent/Chart.yaml")
	if err := os.MkdirAll(filepath.Dir(chart), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chart, []byte("apiVersion: v2\nname: exitmesh-agent\nversion: 0.1.0\nappVersion: \"0.1.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"next-version.sh", "reserve-version.sh", "release-push.sh", "unreserve-version.sh"} {
		b, err := os.ReadFile(filepath.Join(g.root, ".github/scripts", s))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(seed, ".github/scripts", s)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	g.run(seed, "git", "add", "-A")
	g.run(seed, "git", "commit", "-q", "-m", "seed")
	g.run(seed, "git", "remote", "add", "origin", g.path("remote.git"))
	g.run(seed, "git", "push", "-q", "origin", "main")
	return g
}

func (g *gitEnv) path(name string) string { return filepath.Join(g.dir, name) }

func (g *gitEnv) cmd(dir, name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.Dir, c.Env = dir, g.env
	out, err := c.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (g *gitEnv) run(dir, name string, args ...string) string {
	g.t.Helper()
	out, err := g.cmd(dir, name, args...)
	if err != nil {
		g.t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

// clone checks out the remote main, as a release run's checkout does.
func (g *gitEnv) clone(name string) string {
	dir := g.path(name)
	g.run(g.dir, "git", "clone", "-q", g.path("remote.git"), dir)
	return dir
}

func (g *gitEnv) remoteChartVersion() string {
	out := g.run(g.path("remote.git"), "git", "show", "main:deploy/helm/exitmesh-agent/Chart.yaml")
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "version: "); ok {
			return v
		}
	}
	return ""
}

func (g *gitEnv) remoteTags() []string {
	out := g.run(g.path("remote.git"), "git", "tag", "--list")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func TestNextVersion(t *testing.T) {
	g := newGitEnv(t)
	a := g.clone("a")
	if v := g.run(a, ".github/scripts/next-version.sh"); v != "0.2.0" {
		t.Fatalf("default bump from 0.1.0 = %s, want minor 0.2.0", v)
	}
	if v := g.run(a, ".github/scripts/next-version.sh", "major"); v != "1.0.0" {
		t.Fatalf("major bump = %s", v)
	}
	if _, err := g.cmd(a, ".github/scripts/next-version.sh", "patch"); err == nil {
		t.Fatal("patch bumps are not a release level")
	}
	g.run(a, "git", "tag", "v0.7.3")
	if v := g.run(a, ".github/scripts/next-version.sh"); v != "0.8.0" {
		t.Fatalf("bump above the latest tag = %s, want 0.8.0", v)
	}
}

func TestReserveVersionGivesEveryRunItsOwnVersion(t *testing.T) {
	g := newGitEnv(t)
	a, b := g.clone("a"), g.clone("b")
	head := g.run(a, "git", "rev-parse", "HEAD")
	if v := g.run(a, ".github/scripts/reserve-version.sh", "minor", head); v != "0.2.0" {
		t.Fatalf("first reservation %s", v)
	}
	// b was cloned before a reserved, as a concurrent run's checkout would be.
	if v := g.run(b, ".github/scripts/reserve-version.sh", "minor", "HEAD"); v != "0.3.0" {
		t.Fatalf("second reservation %s, want 0.3.0", v)
	}
	if at := g.run(g.path("remote.git"), "git", "rev-parse", "v0.2.0^{commit}"); at != head {
		t.Fatalf("v0.2.0 tags %s, want the built commit %s", at, head)
	}

	var wg sync.WaitGroup
	got := make([]string, 4)
	for i := range got {
		dir := g.clone("c" + string(rune('0'+i)))
		wg.Go(func() {
			out, err := g.cmd(dir, ".github/scripts/reserve-version.sh", "minor", "HEAD")
			if err != nil {
				t.Errorf("concurrent reservation: %v\n%s", err, out)
			}
			got[i] = out[strings.LastIndex(out, "\n")+1:]
		})
	}
	wg.Wait()
	slices.Sort(got)
	if want := []string{"0.4.0", "0.5.0", "0.6.0", "0.7.0"}; !slices.Equal(got, want) {
		t.Fatalf("concurrent reservations %v, want %v", got, want)
	}
	if v := g.run(a, ".github/scripts/reserve-version.sh", "major", "HEAD"); v != "1.0.0" {
		t.Fatalf("major reservation %s", v)
	}
}

func TestReleasePushRecordsOnlyNewerVersions(t *testing.T) {
	g := newGitEnv(t)
	a, b := g.clone("a"), g.clone("b")
	other := g.clone("other")
	if err := os.WriteFile(filepath.Join(other, "README"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.run(other, "git", "add", "README")
	g.run(other, "git", "commit", "-q", "-m", "moved on")
	g.run(other, "git", "push", "-q", "origin", "main")

	// a's checkout is behind main; the bump lands on top of the newer commit.
	g.run(a, ".github/scripts/release-push.sh", "0.3.0")
	if v := g.remoteChartVersion(); v != "0.3.0" {
		t.Fatalf("Chart.yaml on main = %s", v)
	}
	log := g.run(g.path("remote.git"), "git", "log", "--format=%s", "main")
	if lines := strings.Split(log, "\n"); lines[0] != "release: v0.3.0 [skip ci]" || lines[1] != "moved on" {
		t.Fatalf("main history %q", log)
	}
	app := g.run(g.path("remote.git"), "git", "show", "main:deploy/helm/exitmesh-agent/Chart.yaml")
	if !strings.Contains(app, `appVersion: "0.3.0"`) {
		t.Fatalf("appVersion not bumped:\n%s", app)
	}

	// A slower concurrent release of an older version must not move Chart.yaml backwards.
	g.run(b, ".github/scripts/release-push.sh", "0.2.0")
	g.run(b, ".github/scripts/release-push.sh", "0.3.0")
	if v := g.remoteChartVersion(); v != "0.3.0" {
		t.Fatalf("Chart.yaml on main = %s after an older release", v)
	}
	if n := strings.Count(g.run(g.path("remote.git"), "git", "log", "--format=%s", "main"), "release:"); n != 1 {
		t.Fatalf("%d bump commits, want 1", n)
	}
	if tags := g.remoteTags(); len(tags) != 0 {
		t.Fatalf("release-push created tags %v; reserve-version owns tags", tags)
	}
	if out := g.run(b, "git", "worktree", "list"); strings.Count(out, "\n") != 0 {
		t.Fatalf("temporary worktrees left behind:\n%s", out)
	}
}

func TestUnreserveVersionReleasesOnlyItsOwnTag(t *testing.T) {
	g := newGitEnv(t)
	a := g.clone("a")
	head := g.run(a, "git", "rev-parse", "HEAD")
	if v := g.run(a, ".github/scripts/reserve-version.sh", "minor", head); v != "0.2.0" {
		t.Fatalf("reservation %s", v)
	}
	if err := os.WriteFile(filepath.Join(a, "README"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.run(a, "git", "add", "README")
	g.run(a, "git", "commit", "-q", "-m", "next")
	g.run(a, "git", "push", "-q", "origin", "main")
	next := g.run(a, "git", "rev-parse", "HEAD")
	if v := g.run(a, ".github/scripts/reserve-version.sh", "minor", next); v != "0.3.0" {
		t.Fatalf("second reservation %s", v)
	}

	// The unreserve job checks out only its own commit, one level deep.
	shallow := g.path("shallow")
	g.run(g.dir, "git", "clone", "-q", "--depth=1", "file://"+g.path("remote.git"), shallow)
	if out := g.run(shallow, ".github/scripts/unreserve-version.sh", "0.2.0", next); !strings.Contains(g.run(g.path("remote.git"), "git", "tag", "--list"), "v0.2.0") {
		t.Fatalf("a tag of another commit was deleted: %s", out)
	}
	if out := g.run(shallow, ".github/scripts/unreserve-version.sh", "0.3.0", next); !strings.Contains(out, "released v0.3.0") {
		t.Fatalf("unreserve output %q", out)
	}
	if tags := g.remoteTags(); !slices.Equal(tags, []string{"v0.2.0"}) {
		t.Fatalf("remote tags %v, want only v0.2.0", tags)
	}
	if out := g.run(shallow, ".github/scripts/unreserve-version.sh", "0.9.0", next); !strings.Contains(out, "not on origin") {
		t.Fatalf("absent tag: %q", out)
	}
	if v := g.run(a, ".github/scripts/reserve-version.sh", "minor", next); v != "0.3.0" {
		t.Fatalf("a released version is reserved again by the next run, got %s", v)
	}
}
