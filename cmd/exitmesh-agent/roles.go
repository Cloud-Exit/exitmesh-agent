package main

import (
	"context"
	"log/slog"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/coordinator"
	"github.com/cloud-exit/exitmesh-agent/internal/host"
	"github.com/cloud-exit/exitmesh-agent/internal/node"
)

type roleFunc func(ctx context.Context, cfg *config.Config, log *slog.Logger) error

// roles maps cfg.Role to its entry point; the version from the build is handed to the roles that report it.
func roles() map[string]roleFunc {
	coordinator.Version, host.Version, node.Version = version, version, version
	return map[string]roleFunc{
		config.RoleCoordinator: coordinator.Run,
		config.RoleNode:        node.Run,
		config.RoleHost:        host.Run,
	}
}
