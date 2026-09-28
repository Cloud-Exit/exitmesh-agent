package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// decodeCmd prints an export file as JSON lines with named fields (PRD 7.4 human-readable export).
func decodeCmd(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("decode", stderr)
	in := fs.String("in", "", "export file path, or - for standard input")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if *in == "" {
		return fmt.Errorf("%w: --in is required", errUsage)
	}
	var r io.Reader = os.Stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	h, recs, err := protocol.ReadExport(r)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	if err := enc.Encode(map[string]any{
		"export_header": map[string]any{
			"target_id": h.TargetID, "writer_id": hex.EncodeToString(h.WriterID), "incarnation": h.Incarnation,
			"epoch": hex.EncodeToString(h.Epoch), "last_committed": h.LastCommitted, "exported_at_ms": h.ExportedAt,
			"agent_version": h.AgentVersion, "records": len(recs),
		},
	}); err != nil {
		return err
	}
	var chain *protocol.Chain
	if len(recs) > 0 && recs[0].Parent == 0 {
		chain = protocol.NewChain(recs[0].TargetID, recs[0].Epoch, recs[0].Writer)
	}
	for _, rec := range recs {
		var ch *protocol.Hash
		if chain != nil {
			h, err := chain.Append(rec)
			if err != nil {
				return fmt.Errorf("record %s: %w", rec.ID(), err)
			}
			ch = &h
		}
		if err := enc.Encode(protocol.Readable(rec, ch)); err != nil {
			return err
		}
	}
	return nil
}
