package protocol

import (
	"fmt"
	"sort"
)

// Chain tracks one epoch's chain position and verifies linkage (SPEC 4.1).
type Chain struct {
	TargetID       string
	Epoch          EpochID
	Writer         WriterID
	Head           uint64
	HeadHash       Hash
	LastCheckpoint uint64
}

// NewChain returns an empty chain for an epoch; Head 0 carries the genesis hash.
func NewChain(targetID string, epoch EpochID, writer WriterID) *Chain {
	return &Chain{TargetID: targetID, Epoch: epoch, Writer: writer, HeadHash: Genesis(targetID, epoch, writer)}
}

// Check verifies that r extends the chain and returns its chain hash without advancing.
func (c *Chain) Check(r *Record) (Hash, error) {
	if r.TargetID != c.TargetID || r.Epoch != c.Epoch {
		return Hash{}, fmt.Errorf("%w: record %s outside chain %s/%s", ErrInvalidChain, r.ID(), c.TargetID, c.Epoch)
	}
	if r.Writer != c.Writer {
		return Hash{}, fmt.Errorf("%w: record %s from writer %s, epoch owned by %s", ErrInvalidChain, r.ID(), r.Writer, c.Writer)
	}
	if r.Parent != c.Head {
		return Hash{}, fmt.Errorf("%w: record %d has parent %d, head is %d", ErrInvalidChain, r.Seq, r.Parent, c.Head)
	}
	if c.Head == 0 && r.Type != TypeCheckpoint {
		return Hash{}, fmt.Errorf("%w: epoch must start with a checkpoint", ErrInvalidChain)
	}
	if r.Type != TypeCheckpoint && r.Base != c.LastCheckpoint {
		return Hash{}, fmt.Errorf("%w: record %d has base %d, governing checkpoint is %d", ErrInvalidChain, r.Seq, r.Base, c.LastCheckpoint)
	}
	return ChainHash(c.HeadHash, r.Hash()), nil
}

// Append verifies and advances the chain, returning the record's chain hash.
func (c *Chain) Append(r *Record) (Hash, error) {
	h, err := c.Check(r)
	if err != nil {
		return h, err
	}
	c.Head, c.HeadHash = r.Seq, h
	if r.Type == TypeCheckpoint {
		c.LastCheckpoint = r.Seq
	}
	return h, nil
}

// Boundary is a reconstruction boundary: a checkpoint whose content did not match replayed state.
type Boundary struct {
	Seq      uint64
	Expected Hash
	Got      Hash
}

// Span is a closed sequence interval.
type Span struct{ From, To uint64 }

// Replayer reconstructs state along a chain (SPEC 6.3).
type Replayer struct {
	chain       *Chain
	state       *State
	states      map[uint64]Hash
	Boundaries  []Boundary
	Unavailable []Span
}

// NewReplayer starts at the first record of an epoch.
func NewReplayer(targetID string, epoch EpochID, writer WriterID) *Replayer {
	return &Replayer{chain: NewChain(targetID, epoch, writer), state: NewState(), states: map[uint64]Hash{}}
}

// NewReplayerAt starts from a retained anchor checkpoint whose predecessor chain hash is prev.
func NewReplayerAt(anchor *Record, prev Hash) (*Replayer, error) {
	if anchor.Type != TypeCheckpoint {
		return nil, fmt.Errorf("%w: replay must start at a checkpoint", ErrInvalidChain)
	}
	c := &Chain{TargetID: anchor.TargetID, Epoch: anchor.Epoch, Writer: anchor.Writer, Head: anchor.Parent, HeadHash: prev, LastCheckpoint: anchor.Parent}
	p := &Replayer{chain: c, state: NewState(), states: map[uint64]Hash{}}
	p.state = StateFromCheckpoint(anchor.Checkpoint)
	h, err := c.Append(anchor)
	if err != nil {
		return nil, err
	}
	_ = h
	p.states[anchor.Seq] = p.state.Hash()
	return p, nil
}

// Chain exposes the current chain position.
func (p *Replayer) Chain() Chain { return *p.chain }

// State returns the state at the chain head. Callers must not mutate it.
func (p *Replayer) State() *State { return p.state }

// Apply verifies linkage and applies r; a disagreeing checkpoint is recorded as a boundary and replaces state.
func (p *Replayer) Apply(r *Record) (Hash, error) {
	if _, err := p.chain.Check(r); err != nil {
		return Hash{}, err
	}
	switch r.Type {
	case TypeCheckpoint:
		if p.chain.Head != 0 {
			if got := p.state.Hash(); got != r.Checkpoint.StateHash {
				p.Boundaries = append(p.Boundaries, Boundary{Seq: r.Seq, Expected: r.Checkpoint.StateHash, Got: got})
			}
		}
		p.state = StateFromCheckpoint(r.Checkpoint)
	case TypeDelta, TypeRange:
		if err := p.state.ApplyRecord(r); err != nil {
			return Hash{}, fmt.Errorf("record %d: %w", r.Seq, err)
		}
		if r.Type == TypeRange && r.Range.From < r.Range.To {
			p.Unavailable = append(p.Unavailable, Span{r.Range.From, r.Range.To - 1})
		}
	}
	h, err := p.chain.Append(r)
	if err != nil {
		return h, err
	}
	p.states[r.Seq] = p.state.Hash()
	return h, nil
}

// StateHashAt returns the state hash at a replayed sequence, or ErrUnavailable for range interiors.
func (p *Replayer) StateHashAt(seq uint64) (Hash, error) {
	if IsUnavailable(p.Unavailable, seq) {
		return Hash{}, fmt.Errorf("%w: sequence %d is inside a coalesced range", ErrUnavailable, seq)
	}
	h, ok := p.states[seq]
	if !ok {
		return Hash{}, fmt.Errorf("sequence %d not replayed", seq)
	}
	return h, nil
}

// IsUnavailable reports whether seq falls in one of the spans.
func IsUnavailable(spans []Span, seq uint64) bool {
	i := sort.Search(len(spans), func(i int) bool { return spans[i].To >= seq })
	return i < len(spans) && spans[i].From <= seq
}

// Reconstruct replays an epoch's records (in chain order, starting with its first checkpoint)
// up to and including seq and returns the state there.
func Reconstruct(records []*Record, seq uint64) (*State, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: no records", ErrInvalidChain)
	}
	first := records[0]
	p := NewReplayer(first.TargetID, first.Epoch, first.Writer)
	for _, r := range records {
		if r.Type == TypeRange && r.Range.From <= seq && seq < r.Range.To {
			return nil, fmt.Errorf("%w: sequence %d is inside range [%d,%d]", ErrUnavailable, seq, r.Range.From, r.Range.To)
		}
		if r.Seq > seq {
			break
		}
		if _, err := p.Apply(r); err != nil {
			return nil, err
		}
		if r.Seq == seq {
			return p.State().Clone(), nil
		}
	}
	return nil, fmt.Errorf("sequence %d not in chain", seq)
}
