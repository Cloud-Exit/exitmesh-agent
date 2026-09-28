package protocol

import "fmt"

// Next returns the envelope for the next non-range record appended to the chain.
func (c *Chain) Next(t RecordType, incarnation, timeMs uint64) Envelope {
	seq := c.Head + 1
	base := c.LastCheckpoint
	if t == TypeCheckpoint {
		base = seq
	}
	return Envelope{
		Type: t, TargetID: c.TargetID, Epoch: c.Epoch, Seq: seq, Writer: c.Writer,
		Incarnation: incarnation, Parent: c.Head, Base: base, Time: timeMs, Schema: SchemaVersion,
	}
}

// NewRangeRecord builds the range record replacing a folded run whose first record's
// parent is parent and whose governing checkpoint is base.
func NewRangeRecord(tmpl Envelope, g *Range, parent, base uint64) (*Record, error) {
	if parent != g.From-1 {
		return nil, fmt.Errorf("%w: parent %d does not precede range start %d", ErrFold, parent, g.From)
	}
	env := tmpl
	env.Type, env.Seq, env.Parent, env.Base = TypeRange, g.To, parent, base
	r := &Record{Envelope: env, Range: g}
	if _, err := Encode(r); err != nil {
		return nil, err
	}
	return r, nil
}
