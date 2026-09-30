package privdrop

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseTarget(t *testing.T) {
	if got, err := ParseTarget("65532:65533"); err != nil || got.UID != 65532 || got.GID != 65533 {
		t.Fatalf("ParseTarget = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "65532", "0:65532", "65532:0", "a:b", "-1:5", "1:2:3"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) accepted", bad)
		}
	}
}

func TestExecRejectsInvalidTargets(t *testing.T) {
	for _, tg := range []Target{{UID: 0, GID: 1}, {UID: 1, GID: 0}, {UID: 1, GID: 1, Keep: []int{64}}, {UID: 1, GID: 1, Keep: []int{-1}}} {
		if err := Exec(tg, "/bin/true", nil, nil); err == nil || !strings.Contains(err.Error(), "privdrop:") {
			t.Errorf("Exec(%+v) = %v", tg, err)
		}
	}
}

func TestExecWithoutPrivilegeFailsBeforeExecuting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root Exec would replace the test binary")
	}
	errc := make(chan error, 1)
	// The goroutine ends with its thread locked, so the runtime discards that thread and its partial identity.
	go func() {
		errc <- Exec(Target{UID: 65532, GID: 65532, Keep: []int{unix.CAP_DAC_READ_SEARCH}}, "/bin/true", []string{"true"}, nil)
	}()
	err := <-errc
	if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "setgroups") {
		t.Fatalf("Exec without CAP_SETGID = %v, want EPERM from setgroups", err)
	}
	if os.Getuid() == 65532 {
		t.Fatal("the test process changed identity")
	}
}

func TestReadIdentity(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	id, err := readIdentity(write("agent", "Name:\texitmesh-agent\nUid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\nCapInh:\t0000000000000004\nCapPrm:\t0000000000000004\nCapEff:\t0000000000000004\nCapAmb:\t0000000000000004\n"))
	if err != nil {
		t.Fatal(err)
	}
	if id.UID != 65532 || id.GID != 65532 || id.Root() || !slices.Equal(id.Capabilities, []string{"CAP_DAC_READ_SEARCH"}) {
		t.Fatalf("identity %+v", id)
	}
	id, err = readIdentity(write("root", "Uid:\t1000\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t00000100000000c5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !id.Root() || id.GID != 0 || !slices.Equal(id.Capabilities, []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH", "CAP_SETGID", "CAP_SETUID", "CAP_40"}) {
		t.Fatalf("effective IDs or capabilities misread: %+v", id)
	}
	for name, body := range map[string]string{
		"missing": "Uid:\t1\t1\t1\t1\nGid:\t1\t1\t1\t1\n",
		"badcap":  "Uid:\t1\t1\t1\t1\nGid:\t1\t1\t1\t1\nCapEff:\tzz\n",
		"short":   "Uid:\t1\nGid:\t1\t1\nCapEff:\t0\n",
	} {
		if _, err := readIdentity(write(name, body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if cur, err := Current(); err != nil || cur.UID != os.Geteuid() || cur.GID != os.Getegid() {
		t.Fatalf("Current = %+v, %v", cur, err)
	}
}
