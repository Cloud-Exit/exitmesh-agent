package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

type adminBackend struct{ c *Coordinator }

func (a adminBackend) Status(context.Context) (any, error) { return a.c.health(), nil }

func (a adminBackend) Investigate(ctx context.Context, req admin.InvestigateRequest) (any, error) {
	return a.c.inv.Call(ctx, req.Tool, req.Args)
}

func (a adminBackend) Export(_ context.Context, fromSeq uint64, w io.Writer) error {
	c := a.c
	ep, ok := c.sp.Epoch()
	if !ok {
		return spool.ErrNoEpoch
	}
	ew, err := protocol.NewExportWriter(w, c.exportHeader(ep))
	if err != nil {
		return err
	}
	return c.writeEntries(ew, fromSeq+1)
}

func (a adminBackend) Deenroll(ctx context.Context, reason string) error {
	c := a.c
	if c.airgap {
		return errors.New("coordinator: the air-gap profile has no tunnel; de-enroll the target in ExitMesh")
	}
	if err := c.cl.Deenroll(ctx, reason); err != nil {
		return err
	}
	if err := c.sp.SetHalted(client.HaltDeenrolled, "de-enrolled by the administrator: "+reason); err != nil {
		return err
	}
	c.log.Warn("de-enrolled; the writer stops", "reason", reason)
	return nil
}

// Commit applies an air-gap commit receipt with the chain hash check of the spool.
func (a adminBackend) Commit(_ context.Context, r admin.CommitReceipt) error {
	c := a.c
	if !c.airgap {
		return errors.New("coordinator: commit receipts apply only in the air-gap profile")
	}
	ep, err := protocol.ParseID(r.Epoch)
	if err != nil {
		return fmt.Errorf("receipt epoch: %w", err)
	}
	h, err := protocol.ParseHash(r.ChainHash)
	if err != nil {
		return fmt.Errorf("receipt chain hash: %w", err)
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	return c.store.commit(ep, r.Seq, h, true)
}

func (c *Coordinator) exportHeader(ep spool.EpochState) protocol.ExportHeader {
	lc, _ := c.sp.LastCommitted()
	w := c.sp.WriterID()
	return protocol.ExportHeader{TargetID: c.targetID, WriterID: w[:], Incarnation: c.sp.Incarnation(), Epoch: ep.ID[:],
		LastCommitted: lc.Seq, ExportedAt: uint64(c.now().UnixMilli()), AgentVersion: Version}
}

// writeEntries writes every spooled record from seq on in chain order.
func (c *Coordinator) writeEntries(ew *protocol.ExportWriter, from uint64) error {
	for {
		es := c.sp.Entries(from)
		if len(es) == 0 {
			return nil
		}
		for _, e := range es {
			if err := ew.Write(e.Bytes); err != nil {
				return err
			}
			from = e.Seq + 1
		}
	}
}

type exportCursor struct {
	Epoch protocol.EpochID `json:"epoch"`
	Seq   uint64           `json:"seq"`
}

func (c *Coordinator) exportLoop(ctx context.Context) {
	tick := time.NewTicker(c.t.ExportEvery)
	defer tick.Stop()
	for {
		if err := c.exportOnce(); err != nil {
			c.log.Warn("air-gap export", "err", err)
			c.setErr("export", err)
		} else {
			c.setErr("export", nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// exportOnce writes the records not yet exported to a new rolling export file; records are marked transmitted before the file is written.
func (c *Coordinator) exportOnce() error {
	ep, ok := c.sp.Epoch()
	if !ok || ep.Chain.Head == 0 {
		return nil
	}
	cur := c.sp.KV("export")
	var ec exportCursor
	if raw, found, err := cur.Get("cursor"); err != nil {
		return err
	} else if found {
		if err := json.Unmarshal(raw, &ec); err != nil {
			return err
		}
	}
	from := uint64(1)
	if ec.Epoch == ep.ID {
		from = ec.Seq + 1
	}
	es := c.sp.Entries(from)
	if len(es) == 0 {
		return nil
	}
	var fresh []uint64
	for _, e := range es {
		if e.State == spool.NeverTransmitted {
			fresh = append(fresh, e.Seq)
		}
	}
	if len(fresh) > 0 {
		if err := c.sp.MarkTransmitted(fresh...); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(c.cfg.AirGap.ExportDir, 0o700); err != nil {
		return err
	}
	first, lastSeq := es[0].Seq, es[len(es)-1].Seq
	name := fmt.Sprintf("export-%s-%020d-%020d.emhpx", ep.ID.String(), first, lastSeq)
	tmp, err := os.CreateTemp(c.cfg.AirGap.ExportDir, ".export-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	ew, err := protocol.NewExportWriter(tmp, c.exportHeader(ep))
	if err == nil {
		for _, e := range es {
			if err = ew.Write(e.Bytes); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(c.cfg.AirGap.ExportDir, name)); err != nil {
		return err
	}
	if d, err := os.Open(c.cfg.AirGap.ExportDir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	raw, err := json.Marshal(exportCursor{Epoch: ep.ID, Seq: lastSeq})
	if err != nil {
		return err
	}
	c.log.Info("air-gap export written", "file", name, "records", len(es))
	return cur.Put("cursor", raw)
}
