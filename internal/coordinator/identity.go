package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// ensureIdentity refreshes enrollment when the mounted token changes.
func (c *Coordinator) ensureIdentity(ctx context.Context) error {
	id := c.sp.Identity()
	halt, halted := c.sp.Halted()
	stopped := func() error {
		return fmt.Errorf("coordinator: writer halted (%s at %s) and refuses to run; token rotation requires an updated enrollment token for the same target; other ownership failures require resolution in ExitMesh", halt.Code, halt.At.Format(time.RFC3339))
	}
	if halted && c.airgap {
		return stopped()
	}
	if c.airgap {
		if id.TargetID != "" {
			c.targetID = id.TargetID
			return nil
		}
		_, tok, err := c.readToken()
		if err != nil {
			return err
		}
		tid, _ := tok.TargetID()
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
	req := protocol.EnrollRequest{WriterID: c.sp.WriterID(), TargetType: protocol.TargetKubernetes, Agent: c.agentInfo()}
	var candidate *spool.Spool
	candidateDir := ""
	retainCandidate := false
	defer func() {
		if candidate != nil && candidate != c.sp {
			if err := candidate.Close(); err != nil {
				c.log.Warn("close candidate spool", "err", err)
				return
			}
			if !retainCandidate {
				if err := os.RemoveAll(candidateDir); err != nil {
					c.log.Warn("remove unused candidate spool", "err", err)
				}
			}
		}
	}()
	delay := c.t.RetryBase
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, tok, err := c.readToken()
		fingerprint := ""
		var res *protocol.EnrollResponse
		if err == nil {
			target, _ := tok.TargetID()
			changingTarget := id.TargetID != "" && id.TargetID != target
			if changingTarget {
				if candidate == nil {
					candidate, candidateDir, err = c.sp.StageReplacement()
					if err != nil {
						return fmt.Errorf("coordinator: prepare target switch: %w", err)
					}
				}
				req.WriterID = candidate.WriterID()
			} else {
				req.WriterID = c.sp.WriterID()
				if halted && halt.Code != "superseded" && halt.Code != protocol.CodeUnauthorized {
					return stopped()
				}
			}
			hash := sha256.Sum256([]byte(raw))
			fingerprint = hex.EncodeToString(hash[:])
			if !changingTarget && id.EnrollmentTokenHash == fingerprint {
				if halted {
					return stopped()
				}
				if id.Credential != "" {
					c.targetID = id.TargetID
					return nil
				}
			}
			if attempt == 1 && id.TargetID != "" {
				c.log.Info("enrollment token changed or not previously tracked; refreshing enrollment")
			}
			req.Token = raw
			res, err = tunnel.Enroll(ctx, opts, req)
		}
		if err == nil {
			target, _ := tok.TargetID()
			if res.TargetID != target {
				return errors.New("coordinator: enrollment response target differs from token")
			}
			destination := c.sp
			if id.TargetID != "" && id.TargetID != res.TargetID {
				destination = candidate
			}
			if err := destination.SetEnrollment(spool.Identity{TargetID: res.TargetID, TargetType: protocol.TargetKubernetes, Credential: res.Credential, CredentialID: res.CredentialID, EnrollmentTokenHash: fingerprint}); err != nil {
				return fmt.Errorf("coordinator: store credential: %w", err)
			}
			if destination != c.sp {
				old := c.sp
				retainCandidate = true
				if err := old.ActivateReplacement(destination); err != nil {
					return fmt.Errorf("coordinator: activate target switch: %w", err)
				}
				c.sp = destination
				if err := old.Close(); err != nil {
					return fmt.Errorf("coordinator: close archived spool: %w", err)
				}
				c.log.Info("target changed; previous spool archived", "old_target", id.TargetID, "new_target", res.TargetID, "archive_dir", old.Directory(), "writer", c.sp.WriterID().String())
			}
			c.targetID = res.TargetID
			c.setErr("enrollment", nil)
			c.log.Info("enrolled", "target", res.TargetID, "credential_id", res.CredentialID)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.setErr("enrollment", err)
		c.log.Warn("enrollment failed; retrying", "err", err, "attempt", attempt, "retry_in", delay)
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), fmt.Errorf("coordinator: enrollment: %w", err))
		case <-time.After(delay):
		}
		delay = min(2*delay, c.t.BackoffMax)
	}
}
