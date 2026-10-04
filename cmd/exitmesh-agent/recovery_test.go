package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestRecoverEnrollmentCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, dir, "coordinator")
	spoolDir := filepath.Join(dir, "state", "spool")
	s, err := spool.Open(spool.Options{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	id := spool.Identity{TargetID: "t-recovery", TargetType: protocol.TargetKubernetes, Credential: "fixture-credential"}
	if err := s.SetIdentity(id); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHalted("superseded", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"invalid-fixture", "emx1_c_t-other_fixture1234567890", "emx1_h_t-recovery_fixture1234567890", "emx1_c_t-recovery_fixture1234567890"} {
		if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, stderr := runArgs(t, context.Background(), "recover-enrollment", "--config", cfg)
		if strings.Contains(out+stderr, token) || strings.Contains(out+stderr, id.Credential) {
			t.Fatal("recovery exposed credentials")
		}
		want := 1
		if token == "emx1_c_t-recovery_fixture1234567890" {
			want = 0
		}
		if code != want {
			t.Fatalf("exit %d, want %d", code, want)
		}
	}
	s, err = spool.Open(spool.Options{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Identity().Credential != "" {
		t.Fatal("old credential survived")
	}
	if _, ok := s.Halted(); ok {
		t.Fatal("halt survived")
	}
}
