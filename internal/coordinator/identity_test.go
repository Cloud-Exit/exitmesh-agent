package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
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
