package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

const (
	keyEnrolledMachineID = "enrolled_machine_id"
	keyConflict          = "conflict"
)

type machineState struct {
	Current  string    `json:"machine_id"`
	Enrolled string    `json:"enrolled_machine_id"`
	Conflict bool      `json:"conflict"`
	Since    time.Time `json:"since,omitzero"`
	Reason   string    `json:"reason,omitempty"`
}

func readMachineID(etcRoot string) (string, error) {
	b, err := os.ReadFile(filepath.Join(etcRoot, "machine-id"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("enrollmentTokenFile is not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("enrollment token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("enrollment token file %s is empty", path)
	}
	return tok, nil
}

// ensureIdentity binds the spool to a target and reports a changed machine ID as an identity conflict (H14).
func (h *Host) ensureIdentity(ctx context.Context) error {
	cur, err := readMachineID(h.deps.Facts.EtcRoot)
	if err != nil {
		h.log.Warn("machine ID unavailable; the control plane cannot detect clones of this host", "err", err)
	}
	h.machine.Current = cur
	id := h.sp.Identity()
	if id.TargetID != "" {
		return h.checkMachine(id, cur)
	}
	tok, err := readToken(h.cfg.EnrollmentTokenFile)
	if err != nil {
		return fmt.Errorf("host: not enrolled: %w", err)
	}
	pt, err := protocol.ParseEnrollmentToken(tok)
	if err != nil {
		return fmt.Errorf("host: enrollment token: %w", err)
	}
	if pt.Kind == protocol.TokenCluster {
		return errors.New("host: the enrollment token is a cluster token; create a host connection or host group in ExitMesh")
	}
	target, ok := pt.TargetID()
	if !ok && h.cfg.AirGap.Enabled {
		return errors.New("host: the air-gap profile needs a host enrollment token (emx1_h_...), which carries the target_id")
	}
	if ok {
		if err := h.sp.SetIdentity(spool.Identity{TargetID: target, TargetType: protocol.TargetHost, MachineID: cur}); err != nil {
			return err
		}
		return h.setEnrolled(cur)
	}
	return h.enrollLoop(ctx)
}

func (h *Host) checkMachine(id spool.Identity, cur string) error {
	enrolled := id.MachineID
	if b, ok, err := h.idStore.Get(keyEnrolledMachineID); err != nil {
		return err
	} else if ok {
		enrolled = string(b)
	}
	h.machine.Enrolled = enrolled
	if b, ok, err := h.idStore.Get(keyConflict); err != nil {
		return err
	} else if ok {
		var ms machineState
		if json.Unmarshal(b, &ms) == nil && ms.Conflict {
			h.machine.Conflict, h.machine.Since, h.machine.Reason = true, ms.Since, ms.Reason
		}
	}
	if cur != "" && enrolled != "" && cur != enrolled && !h.machine.Conflict {
		h.machine.Conflict, h.machine.Since = true, h.clk.Now()
		h.machine.Reason = "machine ID differs from the enrolled one: a cloned image or a reset /etc/machine-id"
		b, _ := json.Marshal(h.machine)
		if err := h.idStore.Put(keyConflict, b); err != nil {
			return err
		}
		h.log.Warn("identity conflict: records keep spooling until an administrator resolves it in ExitMesh", "enrolled_machine_id", enrolled, "machine_id", cur)
	}
	if cur != "" && id.MachineID != cur {
		id.MachineID = cur
		return h.sp.SetIdentity(id)
	}
	return nil
}

func (h *Host) setEnrolled(machineID string) error {
	h.mu.Lock()
	h.machine.Enrolled = machineID
	h.mu.Unlock()
	return h.idStore.Put(keyEnrolledMachineID, []byte(machineID))
}

// resolveConflict clears a local conflict once the control plane accepts this machine ID.
func (h *Host) resolveConflict() {
	h.mu.Lock()
	conflict := h.machine.Conflict
	cur := h.machine.Current
	h.mu.Unlock()
	if !conflict {
		return
	}
	if err := h.idStore.Batch(map[string][]byte{keyConflict: nil, keyEnrolledMachineID: []byte(cur)}); err != nil {
		h.log.Warn("clear identity conflict", "err", err)
		return
	}
	h.mu.Lock()
	h.machine.Conflict, h.machine.Enrolled, h.machine.Reason, h.machine.Since = false, cur, "", time.Time{}
	h.mu.Unlock()
	h.log.Info("identity conflict resolved", "machine_id", cur)
}

func (h *Host) enrollTransport() (*tunnel.Transport, error) {
	o := h.deps.Tunnel
	o.Endpoint, o.CAFile = h.cfg.Endpoint, h.cfg.EndpointCAFile
	o.Credential = func() string { return "" }
	return tunnel.New(o)
}

func (h *Host) enroll(ctx context.Context) error {
	tok, err := readToken(h.cfg.EnrollmentTokenFile)
	if err != nil {
		return err
	}
	tr, err := h.enrollTransport()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	id := h.sp.Identity()
	res, err := tr.Enroll(ctx, protocol.EnrollRequest{
		Token: tok, WriterID: h.sp.WriterID(), TargetType: protocol.TargetHost,
		MachineID: h.machine.Current, Hostname: hostname, Agent: h.agentInfo(),
	})
	if err != nil {
		return err
	}
	if id.TargetID != "" && res.TargetID != id.TargetID {
		return fmt.Errorf("enrollment returned target %s, but the spool belongs to %s", res.TargetID, id.TargetID)
	}
	if err := h.sp.SetIdentity(spool.Identity{
		TargetID: res.TargetID, TargetType: protocol.TargetHost, Credential: res.Credential,
		CredentialID: res.CredentialID, MachineID: h.machine.Current,
	}); err != nil {
		return err
	}
	h.log.Info("enrolled", "target_id", res.TargetID, "credential_id", res.CredentialID)
	return h.setEnrolled(h.machine.Current)
}

// enrollLoop exchanges the enrollment token, retrying with backoff; a rejected token stops it.
func (h *Host) enrollLoop(ctx context.Context) error {
	wait := time.Second
	for {
		err := h.enroll(ctx)
		if err == nil {
			h.setErr(&h.st.enrollError, nil)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		h.setErr(&h.st.enrollError, err)
		if client.RPCErrorCode(err) == protocol.CodeUnauthorized {
			return fmt.Errorf("host: enrollment rejected: %w", err)
		}
		h.log.Warn("enrollment failed; retrying", "err", err, "in", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.clk.After(wait):
		}
		if wait *= 2; wait > 5*time.Minute {
			wait = 5 * time.Minute
		}
	}
}

// session enrolls if needed and runs the writer session until it must stop.
func (h *Host) session(ctx context.Context) {
	if h.sp.Identity().Credential == "" {
		if err := h.enrollLoop(ctx); err != nil {
			if ctx.Err() == nil {
				h.stop(err)
			}
			return
		}
	}
	err := h.cl.Run(ctx)
	if ctx.Err() != nil {
		return
	}
	var stop *client.StopError
	if errors.As(err, &stop) && stop.Code == client.HaltDeenrolled {
		h.log.Warn("de-enrolled: the credential was revoked and deleted; the agent stops writing")
		h.stop(nil)
		return
	}
	h.stop(fmt.Errorf("host: writer session stopped: %w", err))
}

// watchSession fetches the bundle on every new session and clears a resolved identity conflict.
func (h *Host) watchSession(ctx context.Context) {
	s := h.cl.Status()
	h.mu.Lock()
	prev := h.st.sessionID
	h.st.sessionID = s.SessionID
	h.mu.Unlock()
	if !s.Connected || s.SessionID == "" || s.SessionID == prev {
		return
	}
	h.resolveConflict()
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.fetchBundle(ctx)
	}()
}
