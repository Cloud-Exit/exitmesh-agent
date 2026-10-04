package spool

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestRecoverEnrollmentPreservesHistory(t *testing.T) {
	for _, code := range []string{"", "superseded", protocol.CodeUnauthorized} {
		t.Run(code, func(t *testing.T) {
			w := newWriter(t, nil)
			w.delta(protocol.Create("pod", "Pod", "ns", "pod", nil))
			entries := allEntries(w.s)
			epoch, _ := w.s.Epoch()
			writer, inc := w.s.WriterID(), w.s.Incarnation()
			if code != "" {
				if err := w.s.SetHalted(code, "test"); err != nil {
					t.Fatal(err)
				}
			}
			if err := RecoverEnrollment(w.s.opts.Dir, testTarget); !errors.Is(err, ErrLocked) {
				t.Fatalf("active spool: %v", err)
			}
			if err := w.s.Close(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := RecoverEnrollment(w.s.opts.Dir, testTarget); err != nil {
					t.Fatal(err)
				}
			}
			w.reopen()
			if w.s.WriterID() != writer || w.s.Incarnation() != inc+1 {
				t.Fatal("recovery changed writer identity or incarnation")
			}
			got, _ := w.s.Epoch()
			if !reflect.DeepEqual(epoch, got) || !reflect.DeepEqual(entries, allEntries(w.s)) {
				t.Fatal("recovery changed history")
			}
			id := w.s.Identity()
			if id.TargetID != testTarget || id.TargetType != protocol.TargetKubernetes || id.Credential != "" || id.CredentialID != "" {
				t.Fatal("incorrect recovered identity")
			}
			if _, ok := w.s.Halted(); ok {
				t.Fatal("halt survived recovery")
			}
		})
	}
}

func TestRecoverEnrollmentRefusesUnsafeRecovery(t *testing.T) {
	for _, code := range []string{protocol.CodeWriterRetired, protocol.CodeEpochClosed, protocol.CodeNotOwner, "superseded"} {
		t.Run(code, func(t *testing.T) {
			w := newWriter(t, nil)
			id := w.s.Identity()
			if err := w.s.SetHalted(code, "test"); err != nil {
				t.Fatal(err)
			}
			if err := w.s.Close(); err != nil {
				t.Fatal(err)
			}
			target := testTarget
			if code == "superseded" {
				target = "t-other"
			}
			if err := RecoverEnrollment(w.s.opts.Dir, target); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			w.reopen()
			if w.s.Identity() != id {
				t.Fatal("failed recovery changed credentials")
			}
			if halt, ok := w.s.Halted(); !ok || halt.Code != code {
				t.Fatal("failed recovery changed halt")
			}
		})
	}
	if err := RecoverEnrollment(t.TempDir(), testTarget); err == nil {
		t.Fatal("missing spool accepted")
	}
}
