package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct {
	deenrolled string
	commit     CommitReceipt
}

func (f *fakeBackend) Status(context.Context) (any, error) {
	return map[string]any{"role": "host"}, nil
}
func (f *fakeBackend) Investigate(_ context.Context, r InvestigateRequest) (any, error) {
	if r.Tool == "boom" {
		return nil, errors.New("tool failed")
	}
	return map[string]any{"tool": r.Tool, "args": r.Args}, nil
}
func (f *fakeBackend) Export(_ context.Context, from uint64, w io.Writer) error {
	_, err := io.WriteString(w, "EMHPX1\nfrom")
	return err
}
func (f *fakeBackend) Deenroll(_ context.Context, reason string) error {
	f.deenrolled = reason
	return nil
}
func (f *fakeBackend) Commit(_ context.Context, r CommitReceipt) error { f.commit = r; return nil }

func TestServeAndClient(t *testing.T) {
	dir, err := os.MkdirTemp("", "adm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	b := &fakeBackend{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, dir, b) }()
	path := filepath.Join(dir, SocketName)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v %v", err, fi)
	}
	c := Dial(dir)
	st, err := c.Status(ctx)
	if err != nil || !strings.Contains(string(st), "host") {
		t.Fatalf("status %s %v", st, err)
	}
	res, err := c.Investigate(ctx, InvestigateRequest{Tool: "state.query", Args: json.RawMessage(`{"kind":"Pod"}`)})
	if err != nil || !strings.Contains(string(res), "Pod") {
		t.Fatalf("investigate %s %v", res, err)
	}
	if _, err := c.Investigate(ctx, InvestigateRequest{Tool: "boom"}); err == nil || !strings.Contains(err.Error(), "tool failed") {
		t.Fatalf("error not propagated: %v", err)
	}
	var buf bytes.Buffer
	if err := c.Export(ctx, 3, &buf); err != nil || buf.String() != "EMHPX1\nfrom" {
		t.Fatalf("export %q %v", buf.String(), err)
	}
	if err := c.Deenroll(ctx, "decommission"); err != nil || b.deenrolled != "decommission" {
		t.Fatal("deenroll")
	}
	if err := c.Commit(ctx, CommitReceipt{Epoch: "e", Seq: 9}); err != nil || b.commit.Seq != 9 {
		t.Fatal("commit")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket not removed")
	}
}
