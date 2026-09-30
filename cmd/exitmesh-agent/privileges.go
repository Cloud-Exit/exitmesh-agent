package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/cloud-exit/exitmesh-agent/internal/privdrop"
)

// dropPrivileges re-executes the agent as spec when it runs as root; exec only returns on failure.
func dropPrivileges(spec string, euid int, exec func(privdrop.Target) error) error {
	t, err := privdrop.ParseTarget(spec)
	if err != nil {
		return fmt.Errorf("%w: --run-as: %w", errUsage, err)
	}
	switch euid {
	case 0:
		t.Keep = []int{unix.CAP_DAC_READ_SEARCH}
		return exec(t)
	case t.UID:
		return nil
	}
	return fmt.Errorf("--run-as %s: started as UID %d, which is neither root nor the target", spec, euid)
}

// execAs replaces the process with the same command line under t; the re-executed agent then matches t.UID.
func execAs(t privdrop.Target) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return privdrop.Exec(t, exe, os.Args, os.Environ())
}
