package spool

import (
	"reflect"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestEnrollmentPreservesHistoryAndRotationFingerprint(t *testing.T) {
	for _, code := range []string{"superseded", protocol.CodeUnauthorized} {
		t.Run(code, func(t *testing.T) {
			w := newWriter(t, nil)
			w.delta(protocol.Create("pod", "Pod", "ns", "pod", nil))
			before := allEntries(w.s)
			ep, _ := w.s.Epoch()
			writer := w.s.WriterID()
			if err := w.s.SetHalted(code, "test"); err != nil {
				t.Fatal(err)
			}
			id := w.s.Identity()
			id.Credential, id.CredentialID, id.EnrollmentTokenHash = "new-fixture", "new-id", "fingerprint"
			if err := w.s.SetEnrollment(id); err != nil {
				t.Fatal(err)
			}
			w.reopen()
			gotEpoch, _ := w.s.Epoch()
			if w.s.Identity() != id || w.s.WriterID() != writer || !reflect.DeepEqual(ep, gotEpoch) || !reflect.DeepEqual(before, allEntries(w.s)) {
				t.Fatal("enrollment changed queued history or did not persist identity")
			}
			if _, ok := w.s.Halted(); ok {
				t.Fatal("successful enrollment left halt")
			}
			store := ClientStore{S: w.s}
			rotated := store.Identity()
			rotated.Credential = "rotated-fixture"
			if err := store.SetIdentity(rotated); err != nil {
				t.Fatal(err)
			}
			w.reopen()
			if w.s.Identity().EnrollmentTokenHash != id.EnrollmentTokenHash {
				t.Fatal("server credential rotation lost token fingerprint")
			}
		})
	}
}

func TestEnrollmentRefusesUnsafeReplacement(t *testing.T) {
	for _, scenario := range []string{"target", "empty credential", "halt"} {
		t.Run(scenario, func(t *testing.T) {
			w := newWriter(t, nil)
			before := w.s.Identity()
			if err := w.s.SetHalted(protocol.CodeWriterRetired, "test"); err != nil {
				t.Fatal(err)
			}
			id := before
			id.EnrollmentTokenHash = "new-fingerprint"
			switch scenario {
			case "target":
				id.TargetID = "t-other"
			case "empty credential":
				id.Credential = ""
			}
			if err := w.s.SetEnrollment(id); err == nil {
				t.Fatal("unsafe enrollment accepted")
			}
			w.reopen()
			if w.s.Identity() != before {
				t.Fatal("failed enrollment replaced identity")
			}
			if _, ok := w.s.Halted(); !ok {
				t.Fatal("failed enrollment cleared halt")
			}
		})
	}
}
