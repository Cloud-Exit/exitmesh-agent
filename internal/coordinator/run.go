package coordinator

import (
	"context"
	"fmt"
	"log/slog"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
)

// Run builds the in-cluster dependencies and runs the coordinator until ctx ends.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("coordinator: in-cluster config: %w", err)
	}
	rc.UserAgent = "exitmesh-agent/" + Version
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("coordinator: dynamic client: %w", err)
	}
	meta, err := metadata.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("coordinator: metadata client: %w", err)
	}
	disc, err := discovery.NewDiscoveryClientForConfig(rc)
	if err != nil {
		return fmt.Errorf("coordinator: discovery client: %w", err)
	}
	kc, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("coordinator: typed client: %w", err)
	}
	hc, err := rest.HTTPClientFor(rc)
	if err != nil {
		return fmt.Errorf("coordinator: API server HTTP client: %w", err)
	}
	c, err := New(cfg, Deps{Dynamic: dyn, Metadata: meta, Discovery: disc, Kube: kc, APIServer: rc.Host, JWKSClient: hc, Logger: log})
	if err != nil {
		return err
	}
	return c.Run(ctx)
}
