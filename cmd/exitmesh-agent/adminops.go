package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/host"
)

// adminTimeout bounds admin socket calls other than investigations.
const adminTimeout = 2 * time.Minute

// offline performs the host role's direct spool operations when no agent holds the lock; tests replace it.
var offline = struct {
	export   func(cfg *config.Config, fromSeq uint64, w io.Writer) error
	deenroll func(ctx context.Context, cfg *config.Config, reason string) error
}{
	export: func(cfg *config.Config, fromSeq uint64, w io.Writer) error {
		return host.Export(cfg, fromSeq, w, host.Deps{})
	},
	deenroll: func(ctx context.Context, cfg *config.Config, reason string) error {
		return host.Deenroll(ctx, cfg, reason, host.Deps{})
	},
}

func socketError(dir string, err error) error {
	return fmt.Errorf("admin socket %s: %w (is the agent running?)", filepath.Join(dir, admin.SocketName), err)
}

func printJSON(w io.Writer, raw json.RawMessage) error {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		_, werr := w.Write(append(raw, '\n'))
		return werr
	}
	out.WriteByte('\n')
	_, err := out.WriteTo(w)
	return err
}

func statusCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfg, err := loadConfig(newFlags("status", stderr), args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, adminTimeout)
	defer cancel()
	raw, err := admin.Dial(cfg.StateDir).Status(ctx)
	if err != nil {
		return socketError(cfg.StateDir, err)
	}
	return printJSON(stdout, raw)
}

// readArgs accepts inline JSON or @file.
func readArgs(s string) (json.RawMessage, error) {
	b := []byte(s)
	if strings.HasPrefix(s, "@") {
		var err error
		if b, err = os.ReadFile(s[1:]); err != nil {
			return nil, err
		}
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		b = []byte("{}")
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("%w: --args is not valid JSON", errUsage)
	}
	return b, nil
}

func investigateCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("investigate", stderr)
	tool := fs.String("tool", "", "tool name, for example promql.query or logql.query")
	argv := fs.String("args", "{}", "tool arguments as JSON, or @file to read them from a file")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if *tool == "" {
		return fmt.Errorf("%w: --tool is required", errUsage)
	}
	a, err := readArgs(*argv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Investigation.Timeout.D()+30*time.Second)
	defer cancel()
	raw, err := admin.Dial(cfg.StateDir).Investigate(ctx, admin.InvestigateRequest{Tool: *tool, Args: a})
	if err != nil {
		return socketError(cfg.StateDir, err)
	}
	return printJSON(stdout, raw)
}

func exportCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("export", stderr)
	out := fs.String("out", "", "export file path, or - for standard output")
	from := fs.Uint64("from", 0, "first sequence to export (default: every spooled record)")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("%w: --out is required", errUsage)
	}
	write := func(w io.Writer) error {
		if cfg.Role == config.RoleHost {
			err := offline.export(cfg, *from, w)
			if !errors.Is(err, host.ErrRunning) {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(ctx, adminTimeout)
		defer cancel()
		if err := admin.Dial(cfg.StateDir).Export(ctx, *from, w); err != nil {
			return socketError(cfg.StateDir, err)
		}
		return nil
	}
	if *out == "-" {
		return write(stdout)
	}
	tmp := *out + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, *out); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "wrote %s\n", *out)
	return nil
}

func commitCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("commit", stderr)
	receipt := fs.String("receipt", "", "commit receipt file downloaded from ExitMesh after importing an export")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if *receipt == "" {
		return fmt.Errorf("%w: --receipt is required", errUsage)
	}
	b, err := os.ReadFile(*receipt)
	if err != nil {
		return err
	}
	var r admin.CommitReceipt
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return fmt.Errorf("receipt %s: %w", *receipt, err)
	}
	if r.Epoch == "" || r.Seq == 0 || r.ChainHash == "" {
		return fmt.Errorf("receipt %s: epoch, seq, and chain_hash are required", *receipt)
	}
	ctx, cancel := context.WithTimeout(ctx, adminTimeout)
	defer cancel()
	if err := admin.Dial(cfg.StateDir).Commit(ctx, r); err != nil {
		return socketError(cfg.StateDir, err)
	}
	fmt.Fprintf(stdout, "committed epoch %s through sequence %d\n", r.Epoch, r.Seq)
	return nil
}

func deenrollCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("deenroll", stderr)
	reason := fs.String("reason", "de-enrolled with exitmesh-agent deenroll", "reason recorded in ExitMesh")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, adminTimeout)
	defer cancel()
	if cfg.Role == config.RoleHost {
		err := offline.deenroll(ctx, cfg, *reason)
		if err == nil {
			fmt.Fprintln(stdout, "de-enrolled: the credential was revoked in ExitMesh and deleted locally")
			return nil
		}
		if !errors.Is(err, host.ErrRunning) {
			return err
		}
	}
	if err := admin.Dial(cfg.StateDir).Deenroll(ctx, *reason); err != nil {
		return socketError(cfg.StateDir, err)
	}
	fmt.Fprintln(stdout, "de-enrolled: the credential was revoked in ExitMesh and deleted locally; the agent stopped writing")
	return nil
}
