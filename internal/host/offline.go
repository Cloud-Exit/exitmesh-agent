package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

// DeenrollDrainTimeout bounds how long offline de-enrollment waits for spooled records to be committed first.
const DeenrollDrainTimeout = 30 * time.Second

// ErrRunning is returned by offline operations while an agent holds the state directory lock.
var ErrRunning = errors.New("the agent is running and holds the state directory lock; use its admin socket")

func offlineHost(cfg *config.Config, d Deps) (*Host, error) {
	if cfg.Role != config.RoleHost {
		return nil, fmt.Errorf("offline access is implemented for the host role; a running %s agent serves it through its admin socket", cfg.Role)
	}
	h, err := New(cfg, d)
	if err != nil {
		return nil, err
	}
	if err := h.open(); err != nil {
		h.close()
		if errors.Is(err, errLockHeld) {
			return nil, ErrRunning
		}
		return nil, err
	}
	return h, nil
}

// Export writes the spooled records of a stopped host agent to w (PRD A9).
func Export(cfg *config.Config, fromSeq uint64, w io.Writer, d Deps) error {
	h, err := offlineHost(cfg, d)
	if err != nil {
		return err
	}
	werr := writeExport(h.sp, fromSeq, w, cfg.AirGap.Enabled, h.clk.Now())
	return errors.Join(werr, h.close())
}

// Deenroll connects a stopped host agent with its stored credential, de-enrolls it, and clears the credential (PRD A6).
func Deenroll(ctx context.Context, cfg *config.Config, reason string, d Deps) (err error) {
	if cfg.AirGap.Enabled {
		return errors.New("de-enrollment needs a connection to ExitMesh; in the air-gap profile an administrator de-enrolls the host in ExitMesh")
	}
	h, err := offlineHost(cfg, d)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, h.close()) }()
	if code, halted := h.sp.Halted(); halted {
		if code.Code == client.HaltDeenrolled {
			return errors.New("this host is already de-enrolled")
		}
		return fmt.Errorf("writer halted (%s): %s", code.Code, code.Message)
	}
	if h.sp.Identity().Credential == "" {
		return errors.New("no credential is stored in the state directory; there is nothing to de-enroll")
	}
	if err := h.recover(); err != nil {
		return err
	}
	if err := h.openRules(); err != nil {
		return err
	}
	topts := h.deps.Tunnel
	topts.Endpoint, topts.CAFile = cfg.Endpoint, cfg.EndpointCAFile
	topts.Credential = func() string { return h.sp.Identity().Credential }
	tr, err := tunnel.New(topts)
	if err != nil {
		return err
	}
	cl, err := client.New(client.Options{Store: h.store, Transport: tr, Hooks: hooks{h}, Agent: h.agentInfo(), Logger: h.log,
		Clock: h.clk, HealthInterval: -1, BackoffBase: h.deps.BackoffBase, BackoffMax: h.deps.BackoffMax})
	if err != nil {
		return err
	}
	h.cl = cl
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cl.Run(rctx) }()
	for !cl.Status().Connected {
		select {
		case <-ctx.Done():
			cancel()
			<-done
			return fmt.Errorf("could not connect to ExitMesh: %s", cl.Status().LastError)
		case err := <-done:
			return fmt.Errorf("session ended before de-enrollment: %w", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	drain := time.Now().Add(DeenrollDrainTimeout)
	for cl.Status().BacklogRecords > 0 && time.Now().Before(drain) && ctx.Err() == nil {
		time.Sleep(50 * time.Millisecond)
	}
	if err := cl.Deenroll(ctx, reason); err != nil {
		cancel()
		<-done
		return err
	}
	var stop *client.StopError
	if err := <-done; err != nil && !(errors.As(err, &stop) && stop.Code == client.HaltDeenrolled) {
		return err
	}
	return nil
}
