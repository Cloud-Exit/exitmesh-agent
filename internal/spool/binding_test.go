package spool

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestActiveBindingKeepsArchivedHistory(t *testing.T) {
	root := t.TempDir()
	w := newWriter(t, func(o *Options) { o.Dir = filepath.Join(root, "spool") })
	w.delta(protocol.Create("archived-only", "Pod", "old", "old", nil))
	before := allEntries(w.s)
	ep, _ := w.s.Epoch()
	oldID, oldWriter := w.s.Identity(), w.s.WriterID()
	if err := w.s.SetHalted("superseded", "test"); err != nil {
		t.Fatal(err)
	}
	for _, activate := range []bool{false, true} {
		next, dir, err := w.s.StageReplacement()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = next.Close() })
		id := Identity{TargetID: "t-new", TargetType: protocol.TargetKubernetes, Credential: "fixture", EnrollmentTokenHash: "fingerprint"}
		if err := next.SetEnrollment(id); err != nil {
			t.Fatal(err)
		}
		if activate {
			if err := w.s.ActivateReplacement(next); err != nil {
				t.Fatal(err)
			}
		}
		newWriter := next.WriterID()
		if err := next.Close(); err != nil {
			t.Fatal(err)
		}
		if err := w.s.Close(); err != nil {
			t.Fatal(err)
		}
		active, err := OpenActive(Options{Dir: filepath.Join(root, "spool")})
		if err != nil {
			t.Fatal(err)
		}
		if activate {
			if active.WriterID() != newWriter || active.Identity() != id || active.Directory() != dir {
				t.Fatal("activated binding not recovered")
			}
			if _, ok := active.Epoch(); ok {
				t.Fatal("old epoch moved to new target")
			}
			if len(allEntries(active)) != 0 {
				t.Fatal("old records moved to new target")
			}
		} else if active.WriterID() != oldWriter {
			t.Fatal("uncommitted candidate became active")
		}
		if err := active.Close(); err != nil {
			t.Fatal(err)
		}
		w.reopen()
		gotEpoch, _ := w.s.Epoch()
		if w.s.WriterID() != oldWriter || w.s.Identity() != oldID || !reflect.DeepEqual(before, allEntries(w.s)) || !reflect.DeepEqual(ep, gotEpoch) {
			t.Fatal("archive changed")
		}
		if h, ok := w.s.Halted(); !ok || h.Code != "superseded" {
			t.Fatal("archived halt changed")
		}
	}
}

func TestActiveBindingFailsClosed(t *testing.T) {
	for _, name := range []string{"../elsewhere", "/spool-writer-other", "spool-writer-missing", "spool-writer-link"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Symlink(t.TempDir(), filepath.Join(root, "spool-writer-link")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, activeSpoolFile), []byte(name), 0o600); err != nil {
				t.Fatal(err)
			}
			if s, err := OpenActive(Options{Dir: filepath.Join(root, "spool")}); err == nil {
				_ = s.Close()
				t.Fatal("invalid binding accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "spool")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid binding silently created a fresh spool")
			}
		})
	}
}

func TestReplacementRequiresEnrollment(t *testing.T) {
	w := newWriter(t, nil)
	next, _, err := w.s.StageReplacement()
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := w.s.ActivateReplacement(next); err == nil {
		t.Fatal("unenrolled replacement accepted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(w.s.Directory()), activeSpoolFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed activation changed binding")
	}
}
