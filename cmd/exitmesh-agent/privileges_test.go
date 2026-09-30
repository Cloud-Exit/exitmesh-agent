package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cloud-exit/exitmesh-agent/internal/privdrop"
)

func TestDropPrivileges(t *testing.T) {
	var got []privdrop.Target
	exec := func(tg privdrop.Target) error { got = append(got, tg); return errors.New("exec failed") }
	if err := dropPrivileges("65532:65533", 0, exec); err == nil || err.Error() != "exec failed" {
		t.Fatalf("as root: %v", err)
	}
	if len(got) != 1 || got[0].UID != 65532 || got[0].GID != 65533 || !slices.Equal(got[0].Keep, []int{unix.CAP_DAC_READ_SEARCH}) {
		t.Fatalf("root did not re-execute as the target keeping only CAP_DAC_READ_SEARCH: %+v", got)
	}
	got = nil
	if err := dropPrivileges("65532:65532", 65532, exec); err != nil || got != nil {
		t.Fatalf("already the target: %v, exec %+v", err, got)
	}
	if err := dropPrivileges("65532:65532", 1000, exec); err == nil || !strings.Contains(err.Error(), "neither root nor the target") || got != nil {
		t.Fatalf("other user: %v, exec %+v", err, got)
	}
	if err := dropPrivileges("root", 0, exec); !errors.Is(err, errUsage) || got != nil {
		t.Fatalf("bad spec: %v", err)
	}
}

func TestRunAsRefusesAnUnexpectedUser(t *testing.T) {
	uid := os.Geteuid()
	if uid == 0 || uid == 1 {
		t.Skip("needs a non-root UID other than 1")
	}
	cfg := writeConfig(t, t.TempDir(), "host")
	code, _, e := runArgs(t, context.Background(), "run", "--config", cfg, "--run-as", "1:1")
	if code == 0 || !strings.Contains(e, "started as UID "+strconv.Itoa(uid)) {
		t.Fatalf("code %d stderr %q", code, e)
	}
}
