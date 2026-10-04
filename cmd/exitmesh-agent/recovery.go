package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func recoverEnrollmentCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	cfg, err := loadConfig(newFlags("recover-enrollment", stderr), args)
	if err != nil {
		return err
	}
	if cfg.Role != "coordinator" || cfg.AirGap.Enabled {
		return errors.New("enrollment recovery requires an online coordinator configuration")
	}
	b, err := os.ReadFile(cfg.EnrollmentTokenFile)
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
	}
	tok, err := protocol.ParseEnrollmentToken(strings.TrimSpace(string(b)))
	if err != nil || tok.Kind != protocol.TokenCluster {
		return errors.New("enrollment recovery requires a valid cluster enrollment token")
	}
	target, ok := tok.TargetID()
	if !ok {
		return errors.New("enrollment token has no valid target")
	}
	if err := spool.RecoverEnrollment(filepath.Join(cfg.StateDir, "spool"), target); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Enrollment recovery prepared. Queued history and writer identity preserved. Start the coordinator to enroll with the configured token; ExitMesh will verify ownership.")
	return err
}
