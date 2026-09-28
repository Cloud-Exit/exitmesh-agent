package coordinator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/internal/tunnel"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func (c *Coordinator) readToken() (string, protocol.EnrollmentToken, error) {
	b, err := os.ReadFile(c.cfg.EnrollmentTokenFile)
	if err != nil {
		return "", protocol.EnrollmentToken{}, fmt.Errorf("coordinator: read enrollment token: %w", err)
	}
	raw := strings.TrimSpace(string(b))
	tok, err := protocol.ParseEnrollmentToken(raw)
	if err != nil {
		return "", protocol.EnrollmentToken{}, fmt.Errorf("coordinator: enrollment token: %w", err)
	}
	if tok.Kind != protocol.TokenCluster {
		return "", protocol.EnrollmentToken{}, fmt.Errorf("coordinator: enrollment token kind %q is not a cluster token", tok.Kind)
	}
	return raw, tok, nil
}

// ensureIdentity enrolls on first start; an air-gapped coordinator takes its target id from the cluster token.
func (c *Coordinator) ensureIdentity(ctx context.Context) error {
	id := c.sp.Identity()
	if id.TargetID != "" && (c.airgap || id.Credential != "") {
		c.targetID = id.TargetID
		return nil
	}
	raw, tok, err := c.readToken()
	if err != nil {
		return err
	}
	tid, _ := tok.TargetID()
	if c.airgap {
		if !protocol.ValidTargetID(tid) {
			return fmt.Errorf("coordinator: enrollment token carries no valid target id")
		}
		if err := c.sp.SetIdentity(spool.Identity{TargetID: tid, TargetType: protocol.TargetKubernetes}); err != nil {
			return fmt.Errorf("coordinator: store identity: %w", err)
		}
		c.targetID = tid
		return nil
	}
	opts := c.tunnelOptions()
	opts.Credential = nil
	req := protocol.EnrollRequest{Token: raw, WriterID: c.sp.WriterID(), TargetType: protocol.TargetKubernetes, Agent: c.agentInfo()}
	delay := c.t.RetryBase
	var last string
	for {
		res, err := tunnel.Enroll(ctx, opts, req)
		if err == nil {
			if err := c.sp.SetIdentity(spool.Identity{TargetID: res.TargetID, TargetType: protocol.TargetKubernetes, Credential: res.Credential, CredentialID: res.CredentialID}); err != nil {
				return fmt.Errorf("coordinator: store credential: %w", err)
			}
			c.targetID = res.TargetID
			c.log.Info("enrolled", "target", res.TargetID, "credential_id", res.CredentialID)
			return nil
		}
		if msg := err.Error(); msg != last {
			c.log.Warn("enrollment failed; retrying with backoff", "err", err)
			last = msg
		}
		c.setErr("enrollment", err)
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), fmt.Errorf("coordinator: enrollment: %w", err))
		case <-time.After(delay):
		}
		if delay *= 2; delay > c.t.BackoffMax {
			delay = c.t.BackoffMax
		}
	}
}
