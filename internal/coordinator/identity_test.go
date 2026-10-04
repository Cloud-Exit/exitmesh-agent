package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

func enrollmentCoordinator(t *testing.T, e *env, logs *syncBuffer, tuning Tuning) *Coordinator {
	t.Helper()
	c, err := New(e.config(), Deps{
		Dynamic: e.cl.dyn, Metadata: e.cl.meta, Discovery: e.cl.disc,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), Tuning: tuning,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.sp, err = spool.Open(spool.Options{Dir: filepath.Join(e.stateDir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.sp.Close() })
	return c
}

func TestEnrollmentRetriesEveryFailureAndRecovers(t *testing.T) {
	for _, failure := range []string{"unavailable", "rejected token", "missing token"} {
		t.Run(failure, func(t *testing.T) {
			e := newEnv(t)
			logs := &syncBuffer{}
			c := enrollmentCoordinator(t, e, logs, Tuning{RetryBase: time.Millisecond, BackoffMax: 8 * time.Millisecond})
			switch failure {
			case "unavailable":
				e.cp.SetUnavailable(true)
			case "rejected token":
				if err := os.WriteFile(c.cfg.EnrollmentTokenFile, []byte(e.token+"invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing token":
				if err := os.Remove(c.cfg.EnrollmentTokenFile); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan struct{})
			var runErr error
			go func() {
				runErr = c.ensureIdentity(ctx)
				close(done)
			}()
			t.Cleanup(func() { cancel(); <-done })
			eventually(t, "repeated enrollment failures logged", func() bool {
				return strings.Count(logs.String(), "enrollment failed; retrying") >= 12
			})
			e.cp.SetUnavailable(false)
			if err := os.WriteFile(c.cfg.EnrollmentTokenFile, []byte(e.token), 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				if runErr != nil {
					t.Fatal(runErr)
				}
			case <-ctx.Done():
				t.Fatal("enrollment did not recover")
			}
			var attempts int
			delay := time.Millisecond
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var entry struct {
					Message string        `json:"msg"`
					Attempt int           `json:"attempt"`
					RetryIn time.Duration `json:"retry_in"`
				}
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					t.Fatal(err)
				}
				if entry.Message != "enrollment failed; retrying" {
					continue
				}
				attempts++
				if entry.Attempt != attempts || entry.RetryIn != delay {
					t.Fatalf("retry %d: got attempt %d delay %s, want %s", attempts, entry.Attempt, entry.RetryIn, delay)
				}
				delay = min(2*delay, 8*time.Millisecond)
			}
			if attempts < 12 || c.sp.Identity().TargetID != e.targetID || c.sp.Identity().Credential == "" {
				t.Fatal("enrollment stopped retrying before recovery")
			}
			if c.lastErrs["enrollment"] != "" {
				t.Fatal("recovered enrollment still reports an error")
			}
		})
	}
}

func TestEnrollmentCancellationInterruptsMaximumBackoff(t *testing.T) {
	e := newEnv(t)
	logs := &syncBuffer{}
	c := enrollmentCoordinator(t, e, logs, Tuning{RetryBase: time.Hour, BackoffMax: time.Hour})
	if c.t.RetryBase != client.MaxBackoff || c.t.BackoffMax != client.MaxBackoff {
		t.Fatal("enrollment backoff was not capped at five minutes")
	}
	e.cp.SetUnavailable(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var runErr error
	go func() {
		runErr = c.ensureIdentity(ctx)
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	eventually(t, "retry scheduled", func() bool { return strings.Contains(logs.String(), "enrollment failed; retrying") })
	cancel()
	select {
	case <-done:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("canceled enrollment: %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for the retry delay")
	}
}

func TestStartupRefreshesRotatedEnrollmentToken(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			e := newEnv(t)
			r := e.start(e.config())
			epoch, _ := e.committed(r)
			before := r.c.sp.Identity()
			writer := r.c.sp.WriterID()
			if err := r.stop(); err != nil {
				t.Fatal(err)
			}
			s, err := spool.Open(spool.Options{Dir: filepath.Join(e.stateDir, "spool")})
			if err != nil {
				t.Fatal(err)
			}
			id := before
			id.EnrollmentTokenHash = "previous-token-fingerprint"
			if legacy {
				id.EnrollmentTokenHash = ""
			}
			if err := s.SetIdentity(id); err != nil {
				t.Fatal(err)
			}
			if err := s.SetHalted(client.HaltSuperseded, "test"); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			r = e.start(e.config())
			after := r.c.sp.Identity()
			resumedEpoch, _ := e.committed(r)
			if after.Credential == before.Credential || after.Credential == "" || after.EnrollmentTokenHash == "" {
				t.Fatal("startup did not refresh credential")
			}
			if r.c.sp.WriterID() != writer || resumedEpoch != epoch {
				t.Fatal("rotation replaced writer history")
			}
			if _, ok := r.c.sp.Halted(); ok {
				t.Fatal("halt not cleared after successful enrollment")
			}
			if err := r.stop(); err != nil {
				t.Fatal(err)
			}
			r = e.start(e.config())
			if r.c.sp.Identity() != after {
				t.Fatal("unchanged token caused re-enrollment")
			}
		})
	}
}

func TestEnrollmentRotationRefusesOwnershipAndTargetChanges(t *testing.T) {
	for _, scenario := range []string{"unchanged token", "retired", "closed epoch", "different target"} {
		t.Run(scenario, func(t *testing.T) {
			e := newEnv(t)
			c := enrollmentCoordinator(t, e, &syncBuffer{}, Tuning{})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := c.ensureIdentity(ctx); err != nil {
				t.Fatal(err)
			}
			id := c.sp.Identity()
			code := client.HaltSuperseded
			switch scenario {
			case "retired":
				code = protocol.CodeWriterRetired
				id.EnrollmentTokenHash = "old"
			case "closed epoch":
				code = protocol.CodeEpochClosed
				id.EnrollmentTokenHash = "old"
			case "different target":
				if err := os.WriteFile(c.cfg.EnrollmentTokenFile, []byte("emx1_c_t-other_fixture1234567890"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.sp.SetIdentity(id); err != nil {
				t.Fatal(err)
			}
			if err := c.sp.SetHalted(code, "test"); err != nil {
				t.Fatal(err)
			}
			if err := c.ensureIdentity(ctx); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			if c.sp.Identity() != id {
				t.Fatal("failed recovery changed identity")
			}
			if h, ok := c.sp.Halted(); !ok || h.Code != code {
				t.Fatal("failed recovery cleared halt")
			}
		})
	}
}

func TestRejectedRotationPreservesHaltAndCredential(t *testing.T) {
	e := newEnv(t)
	logs := &syncBuffer{}
	c := enrollmentCoordinator(t, e, logs, Tuning{RetryBase: time.Millisecond, BackoffMax: 2 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.ensureIdentity(ctx); err != nil {
		t.Fatal(err)
	}
	before := c.sp.Identity()
	if err := c.sp.SetHalted(client.HaltSuperseded, "test"); err != nil {
		t.Fatal(err)
	}
	bad := e.token + "invalid"
	if err := os.WriteFile(c.cfg.EnrollmentTokenFile, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	retryCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.ensureIdentity(retryCtx) }()
	t.Cleanup(func() { stop(); <-done })
	eventually(t, "rotated enrollment retries", func() bool { return strings.Count(logs.String(), "enrollment failed; retrying") >= 3 })
	stop()
	err := <-done
	done <- err
	if !errors.Is(err, context.Canceled) {
		t.Fatal("rotation did not cancel")
	}
	if c.sp.Identity() != before {
		t.Fatal("rejected token replaced credential")
	}
	if _, ok := c.sp.Halted(); !ok {
		t.Fatal("rejected token cleared halt")
	}
	if strings.Contains(logs.String(), bad) || strings.Contains(logs.String(), before.Credential) || strings.Contains(logs.String(), before.EnrollmentTokenHash) {
		t.Fatal("enrollment leaked credential or token fingerprint")
	}
}

func TestStartupSwitchesTargetAndArchivesOldSpool(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	oldEpoch, _ := e.committed(r)
	oldTarget, oldWriter := e.targetID, r.c.sp.WriterID()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	archiveDir := filepath.Join(e.stateDir, "spool")
	old, err := spool.Open(spool.Options{Dir: archiveDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := old.SetHalted(protocol.CodeWriterRetired, "test"); err != nil {
		t.Fatal(err)
	}
	if err := old.SaveRecoverySnapshot([]byte("archived-snapshot")); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	e.targetID, e.token, err = e.cp.CreateTarget(protocol.TargetKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.config().EnrollmentTokenFile, []byte(e.token), 0o600); err != nil {
		t.Fatal(err)
	}
	r = e.start(e.config())
	newEpoch, _ := e.committed(r)
	newWriter := r.c.sp.WriterID()
	if newWriter == oldWriter || newEpoch == oldEpoch || r.c.sp.Identity().TargetID != e.targetID {
		t.Fatal("target switch reused old history")
	}
	activeDir := r.c.sp.Directory()
	if activeDir == archiveDir {
		t.Fatal("target switch overwrote archive")
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	old, err = spool.Open(spool.Options{Dir: archiveDir})
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := old.Epoch()
	b, ok, err := old.LoadRecoverySnapshot()
	if err != nil || !ok || string(b) != "archived-snapshot" || old.Identity().TargetID != oldTarget || old.WriterID() != oldWriter || ep.ID != oldEpoch {
		t.Fatal("old target state not preserved")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	r = e.start(e.config())
	if r.c.sp.WriterID() != newWriter || r.c.sp.Directory() != activeDir {
		t.Fatal("restart did not select new active spool")
	}
	if ep, _ := e.committed(r); ep != newEpoch {
		t.Fatal("new target epoch did not resume")
	}
}

func TestFailedTargetSwitchKeepsActiveSpool(t *testing.T) {
	e := newEnv(t)
	logs := &syncBuffer{}
	c := enrollmentCoordinator(t, e, logs, Tuning{RetryBase: time.Millisecond, BackoffMax: 2 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.ensureIdentity(ctx); err != nil {
		t.Fatal(err)
	}
	before, writer := c.sp.Identity(), c.sp.WriterID()
	if err := c.sp.SetHalted(protocol.CodeWriterRetired, "test"); err != nil {
		t.Fatal(err)
	}
	_, token, err := e.cp.CreateTarget(protocol.TargetKubernetes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.cfg.EnrollmentTokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	e.cp.SetUnavailable(true)
	retryCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.ensureIdentity(retryCtx) }()
	t.Cleanup(func() { stop(); <-done })
	eventually(t, "target switch retries", func() bool { return strings.Count(logs.String(), "enrollment failed; retrying") >= 3 })
	stop()
	err = <-done
	done <- err
	if !errors.Is(err, context.Canceled) {
		t.Fatal("target switch did not cancel")
	}
	if c.sp.Identity() != before || c.sp.WriterID() != writer {
		t.Fatal("failed switch changed active identity")
	}
	if h, ok := c.sp.Halted(); !ok || h.Code != protocol.CodeWriterRetired {
		t.Fatal("failed switch changed halt")
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, "active-spool")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed switch activated candidate")
	}
	staged, err := filepath.Glob(filepath.Join(e.stateDir, "spool-writer-*"))
	if err != nil || len(staged) != 0 {
		t.Fatal("canceled enrollment left staged spools")
	}
	if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), before.Credential) {
		t.Fatal("target switch leaked credentials")
	}
}
