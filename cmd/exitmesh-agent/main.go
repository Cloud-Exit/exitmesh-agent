// Command exitmesh-agent runs the ExitMesh agent in the node, coordinator, or host role and provides its administration subcommands (docs/cli.md).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// Set by the release build with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `usage: exitmesh-agent <command> [flags]

commands:
  run            run the agent in the role set by the configuration file
  version        print the agent, protocol, schema, and rule engine versions
  status         print the running agent's status
  investigate    run a local investigation through the running agent
  export         write spooled records to an export file
  decode         print an export file as JSON lines with named fields
  commit         apply an air-gap commit receipt
  deenroll       revoke this agent's credential in ExitMesh and stop writing
  prepare-state  set ownership and mode of the state directory (init container)
  cleanup        delete the state directory after taking its lock (uninstall)
  purge-state    delete the state directory after taking its lock (package purge)
  prepare-image  empty the state directory before capturing a golden image

Run "exitmesh-agent <command> -h" for the flags of a command; see docs/cli.md.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type command func(ctx context.Context, args []string, stdout, stderr io.Writer) error

func commands() map[string]command {
	return map[string]command{
		"run": runCmd, "version": versionCmd, "status": statusCmd, "investigate": investigateCmd,
		"export": exportCmd, "decode": decodeCmd, "commit": commitCmd, "deenroll": deenrollCmd, "prepare-state": prepareStateCmd,
		"cleanup": cleanupCmd, "purge-state": purgeStateCmd, "prepare-image": prepareImageCmd,
	}
}

// errUsage marks an invalid invocation (exit status 2).
var errUsage = errors.New("usage")

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fn, ok := commands()[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "exitmesh-agent: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err := fn(ctx, args[1:], stdout, stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "exitmesh-agent %s: %v\n", args[0], err)
		if errors.Is(err, errUsage) {
			return 2
		}
		return 1
	}
	return 0
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("exitmesh-agent "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string, required ...string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	for _, name := range required {
		if f := fs.Lookup(name); f == nil || f.Value.String() == "" {
			return fmt.Errorf("%w: --%s is required", errUsage, name)
		}
	}
	return nil
}

func versionCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	if err := parse(newFlags("version", stderr), args); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "exitmesh-agent %s\ncommit: %s\nbuilt: %s\nprotocol: %d\nschema: %d\nengine: %d\nbundle schema: %d\ngo: %s %s/%s\n",
		version, commit, date, protocol.Version, protocol.SchemaVersion, bundle.EngineVersion, bundle.SchemaVersion,
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

// newLogger builds the diagnostics logger; every record passes the redaction handler first.
func newLogger(cfg *config.Config, w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Logging.Level)); err != nil {
		return nil, fmt.Errorf("logging.level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch strings.ToLower(cfg.Logging.Format) {
	case "", "json":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("logging.format must be json or text, got %q", cfg.Logging.Format)
	}
	red, err := redact.New(redact.Config{ExtraPatterns: cfg.Policy.RedactionPatterns})
	if err != nil {
		return nil, fmt.Errorf("policy.redactionPatterns: %w", err)
	}
	return slog.New(redact.NewHandler(h, red)).With("role", cfg.Role, "version", version), nil
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("config", "", "agent configuration file")
	if err := parse(fs, args, "config"); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func runCmd(ctx context.Context, args []string, _, stderr io.Writer) error {
	cfg, err := loadConfig(newFlags("run", stderr), args)
	if err != nil {
		return err
	}
	log, err := newLogger(cfg, stderr)
	if err != nil {
		return err
	}
	if limit, source, ok := applyMemoryLimit(os.Getenv, "/proc/self/cgroup", "/sys/fs/cgroup"); ok {
		log.Info("memory limit set from the cgroup", "gomemlimit_bytes", limit, "source", source)
	}
	fn, ok := roles()[cfg.Role]
	if !ok {
		return fmt.Errorf("unknown role %q", cfg.Role)
	}
	log.Info("starting", "commit", commit, "state_dir", cfg.StateDir)
	if err := fn(ctx, cfg, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("stopped", "err", err)
		return err
	}
	log.Info("stopped")
	return nil
}
