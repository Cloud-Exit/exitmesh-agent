package spool

import (
	"errors"
	"fmt"
	"math"
	"sort"

	bolt "go.etcd.io/bbolt"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// ErrRebaselineRequired: the fully coalesced never-transmitted suffix exceeds capacity (SPEC 8.7).
var ErrRebaselineRequired = errors.New("spool: capacity exceeded after full coalescing; rebaseline required")

// Relief reports one pressure relief pass (PRD S13).
type Relief struct {
	BytesBefore       int64
	BytesAfter        int64
	EvidenceEvicted   int             // records whose findings kept only one evidence sample
	SamplesCompacted  int             // records whose finding samples were compacted to counts
	RecordsCoalesced  int             // records folded into range records
	Unavailable       []protocol.Span // interiors of the range records written, ascending
	SegmentsCompacted int
	Exhausted         bool // every step ran and usage is still above the relief target
}

const (
	reliefFactor      = 0.95 // relieve below the trigger so pressure does not rewrite chain hashes on every append
	foldChunkBytes    = 1 << 20
	persistChunkBytes = 16 << 20
	rewriteBatch      = 256
	minReliefStep     = 4 << 10
)

// reliefStep bounds what relief writes before it reclaims, so disk use stays within about a segment of its limit.
func (s *Spool) reliefStep() int64 {
	return min(persistChunkBytes, max(s.opts.SegmentBytes, minReliefStep))
}

func (s *Spool) trigger() int64 {
	return int64(float64(s.opts.CapacityBytes) * s.opts.CoalesceAt)
}

func (s *Spool) reliefTarget() int64 {
	return int64(float64(s.opts.CapacityBytes) * s.opts.CoalesceAt * reliefFactor)
}

// pressure is the larger of the record bytes and the segment files, so dead frames count against the capacity too.
func (s *Spool) pressure() int64 {
	return max(s.bytes, s.segs.diskBytes())
}

// Relieve evicts evidence, compacts samples, then coalesces, stopping below the relief target.
func (s *Spool) Relieve() (Relief, error) {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Relief{}, ErrClosed
	}
	if s.fault != nil {
		return Relief{}, s.fault
	}
	rel, err := s.relieveLocked()
	s.lastReliefErr = err
	return rel, err
}

func (s *Spool) relieveLocked() (Relief, error) {
	rel := Relief{BytesBefore: s.bytes}
	target := s.reliefTarget()
	s.diskLimit = max(s.segs.diskBytes(), s.opts.CapacityBytes)
	defer func() { s.diskLimit = 0 }()
	var err error
	rewrote := false
	if s.epoch != nil && s.bytes > target {
		var n int
		n, err = s.rewriteFindings(target, &rel, flagEvicted, evictEvidence)
		rel.EvidenceEvicted, rewrote = n, n > 0
		if err == nil && s.bytes > target {
			n, err = s.rewriteFindings(target, &rel, flagCompacted, compactSamples)
			rel.SamplesCompacted, rewrote = n, rewrote || n > 0
		}
		if err == nil && s.bytes > target {
			err = s.coalesce(target, &rel)
			rewrote = rewrote || rel.RecordsCoalesced > 0
		}
	}
	if rewrote {
		err = errors.Join(err, s.rebuildChain())
	}
	if err == nil {
		err = s.compactSegments(&rel, target)
	}
	s.noteIO(s.segs.gc())
	rel.BytesAfter = s.bytes
	rel.Exhausted = s.bytes > target && err == nil
	if p := s.pressure(); p > target {
		s.nextRelief = p + (s.trigger() - target)
	} else {
		s.nextRelief = 0
	}
	if err != nil {
		return rel, err
	}
	if s.bytes > s.opts.CapacityBytes {
		s.rebaseline = true
		return rel, ErrRebaselineRequired
	}
	s.rebaseline = false
	return rel, nil
}

func (s *Spool) rewritable(m recMeta) bool {
	return m.State == NeverTransmitted && !s.isPinned(m.Seq)
}

// evictEvidence keeps one sample per finding, preferring a matching line over context.
func evictEvidence(f *protocol.Finding) bool {
	if len(f.Evidence) <= 1 {
		return false
	}
	keep := f.Evidence[0]
	for _, e := range f.Evidence {
		if !e.Context {
			keep = e
			break
		}
	}
	f.Evidence = []protocol.Evidence{keep}
	f.Flags |= protocol.FindingEvidenceTruncated
	return true
}

// compactSamples reduces samples to source, time, and count; context lines carry no count and go.
func compactSamples(f *protocol.Finding) bool {
	if len(f.Evidence) == 0 {
		return false
	}
	out := make([]protocol.Evidence, 0, len(f.Evidence))
	changed := false
	for _, e := range f.Evidence {
		if e.Context {
			changed = true
			continue
		}
		c := protocol.Evidence{Source: e.Source, Time: e.Time, Count: e.Count}
		if c.Count == 0 {
			c.Count = 1
		}
		if c.Count != e.Count || e.Text != "" || len(e.Labels) > 0 || e.Truncated {
			changed = true
		}
		out = append(out, c)
	}
	if !changed {
		return false
	}
	if len(out) == 0 {
		out = nil
	}
	f.Evidence = out
	f.Flags |= protocol.FindingSamplesCompacted
	return true
}

// rewriteFindings edits never-transmitted finding and range records, oldest first, until at target.
func (s *Spool) rewriteFindings(target int64, rel *Relief, bit uint8, edit func(*protocol.Finding) bool) (int, error) {
	rewritten := 0
	step := s.reliefStep()
	from := uint64(1)
	for s.bytes > target {
		var cands []recMeta
		err := s.db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(bucketRecords).Cursor()
			for k, v := c.Seek(seqKey(from)); k != nil; k, v = c.Next() {
				m, err := decodeMeta(k, v)
				if err != nil {
					return err
				}
				from = m.Seq + 1
				if (m.Type == protocol.TypeFinding || m.Type == protocol.TypeRange) && m.Flags&bit == 0 && s.rewritable(m) {
					if cands = append(cands, m); len(cands) >= rewriteBatch {
						return nil
					}
				}
			}
			from = math.MaxUint64
			return nil
		})
		if err != nil {
			return rewritten, err
		}
		if len(cands) == 0 {
			return rewritten, nil
		}
		var olds, news []recMeta
		var frames [][]byte
		var changed []int
		projected := s.bytes
		var written int64
		for _, m := range cands {
			if projected <= target || written >= step {
				from = m.Seq
				break
			}
			body, err := s.readBody(m)
			if err != nil {
				return rewritten, err
			}
			rec, err := protocol.Decode(body)
			if err != nil {
				return rewritten, fmt.Errorf("record %d: %w", m.Seq, err)
			}
			edited := false
			switch rec.Type {
			case protocol.TypeFinding:
				edited = edit(rec.Finding)
			case protocol.TypeRange:
				for i := range rec.Range.Findings {
					edited = edit(&rec.Range.Findings[i].Finding) || edited
				}
			}
			nm := m
			nm.Flags |= bit
			if edited {
				b, err := protocol.Encode(rec)
				if err != nil {
					return rewritten, fmt.Errorf("record %d: %w", m.Seq, err)
				}
				nm.Hash, nm.Len = rec.Hash(), uint32(len(b)) //nolint:gosec // protocol.Encode bounds records by MaxRecordBytes
				changed = append(changed, len(news))
				frames = append(frames, appendFrame(nil, b))
				projected += int64(len(b)) - int64(m.Len)
				written += int64(len(b))
			}
			olds, news = append(olds, m), append(news, nm)
		}
		if err := s.replaceMetas(olds, news, frames, changed); err != nil {
			return rewritten, err
		}
		rewritten += len(changed)
		if err := s.reclaim(rel); err != nil {
			return rewritten, err
		}
	}
	return rewritten, nil
}

// replaceMetas writes the new bodies for news[changed[i]] = frames[i], then swaps metadata.
func (s *Spool) replaceMetas(olds, news []recMeta, frames [][]byte, changed []int) error {
	undo := func() error { return nil }
	if len(frames) > 0 {
		locs, u, err := s.segs.appendFrames(frames)
		if err != nil {
			return err
		}
		undo = u
		for i, idx := range changed {
			news[idx].Seg, news[idx].Off = locs[i].seg, locs[i].off
		}
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRecords)
		for i := range news {
			if err := b.Put(seqKey(news[i].Seq), news[i].encode()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if uerr := undo(); uerr != nil {
			s.fault = fmt.Errorf("spool: rolling back unreferenced bodies: %w", uerr)
		}
		return err
	}
	for i := range news {
		s.account(olds[i], -1)
		s.account(news[i], 1)
	}
	// Segments emptied by this batch go now, so a rewrite never holds old and new copies of everything at once.
	s.noteIO(s.segs.gc())
	return nil
}

func (s *Spool) coalescible(m recMeta) bool {
	return s.rewritable(m) && m.Type != protocol.TypeCheckpoint
}

// coalesce folds the oldest never-transmitted runs without checkpoints until usage reaches target.
func (s *Spool) coalesce(target int64, rel *Relief) error {
	spans := map[uint64]uint64{}
	defer func() {
		for from, to := range spans {
			rel.Unavailable = append(rel.Unavailable, protocol.Span{From: from, To: to - 1})
		}
		sort.Slice(rel.Unavailable, func(i, j int) bool { return rel.Unavailable[i].From < rel.Unavailable[j].From })
	}()
	var after uint64
	for s.bytes > target {
		start, ok, err := s.nextRun(after)
		if err != nil || !ok {
			return err
		}
		end, err := s.coalesceRun(start, target, rel, spans)
		if err != nil {
			return err
		}
		after = end
	}
	return nil
}

// nextRun finds the first run of at least two coalescible records above after.
func (s *Spool) nextRun(after uint64) (uint64, bool, error) {
	var start uint64
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		open := false
		var prev uint64
		for k, v := c.Seek(seqKey(after + 1)); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			if !s.coalescible(m) {
				open = false
				continue
			}
			if open {
				start, found = prev, true
				return nil
			}
			open, prev = true, m.Seq
		}
		return nil
	})
	return start, found, err
}

// loadRun returns about foldChunkBytes of the run from seq and whether the run ends there.
func (s *Spool) loadRun(seq uint64, needTwo bool) ([]recMeta, bool, error) {
	chunk := min(foldChunkBytes, s.reliefStep()/4)
	var out []recMeta
	var n int64
	ended := true
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		for k, v := c.Seek(seqKey(seq)); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			if !s.coalescible(m) {
				return nil
			}
			if n >= chunk && (!needTwo || len(out) >= 2) {
				ended = false
				return nil
			}
			out = append(out, m)
			n += int64(m.Len)
		}
		return nil
	})
	return out, ended, err
}

// coalesceRun folds a run in chunks into one growing range and returns the last sequence consumed.
func (s *Spool) coalesceRun(start uint64, target int64, rel *Relief, spans map[uint64]uint64) (uint64, error) {
	var acc *protocol.Record
	var accMeta *recMeta
	var pending []recMeta
	var pendingBytes int64
	flags := flagEvicted | flagCompacted
	step := s.reliefStep()
	persist := func() error {
		nm, err := s.persistRange(acc, accMeta, pending, flags)
		if err != nil {
			return err
		}
		rel.RecordsCoalesced += len(pending)
		spans[acc.Range.From] = acc.Range.To
		pending, pendingBytes = nil, 0
		if err := s.reclaim(rel); err != nil {
			return err
		}
		// Reclaiming may have moved the range's frame.
		nm, err = s.meta(nm.Seq)
		accMeta = &nm
		return err
	}
	next, end := start, start
	for {
		chunk, ended, err := s.loadRun(next, acc == nil)
		if err != nil {
			return end, err
		}
		if len(chunk) == 0 || (acc == nil && len(chunk) < 2) {
			break
		}
		recs := make([]*protocol.Record, 0, len(chunk)+1)
		if acc != nil {
			recs = append(recs, acc)
		}
		chunkFlags := flags
		for _, m := range chunk {
			body, err := s.readBody(m)
			if err != nil {
				return end, err
			}
			rec, err := protocol.Decode(body)
			if err != nil {
				return end, fmt.Errorf("record %d: %w", m.Seq, err)
			}
			recs = append(recs, rec)
			if m.Type != protocol.TypeDelta {
				chunkFlags &= m.Flags
			}
		}
		g, err := protocol.Fold(recs)
		if err != nil {
			return end, fmt.Errorf("fold [%d,%d]: %w", recs[0].Seq, chunk[len(chunk)-1].Seq, err)
		}
		first, last := recs[0], recs[len(recs)-1]
		tmpl := protocol.Envelope{TargetID: s.chain.TargetID, Epoch: s.chain.Epoch, Writer: s.writer, Incarnation: s.incarnation, Time: last.Time, Schema: last.Schema}
		rr, err := protocol.NewRangeRecord(tmpl, g, first.Parent, first.Base)
		if err == nil && int64(len(rr.Bytes())) > step {
			err = protocol.ErrTooLarge
		}
		if errors.Is(err, protocol.ErrTooLarge) {
			// Keep the range built so far and continue with a new run after it.
			if acc == nil {
				return chunk[0].Seq, nil
			}
			if len(pending) > 0 {
				if err := persist(); err != nil {
					return end, err
				}
			}
			return acc.Seq, nil
		}
		if err != nil {
			return end, err
		}
		acc, flags = rr, chunkFlags
		pending = append(pending, chunk...)
		for _, m := range chunk {
			pendingBytes += int64(m.Len)
		}
		next, end = chunk[len(chunk)-1].Seq+1, chunk[len(chunk)-1].Seq
		projected := s.bytes - pendingBytes + int64(len(rr.Bytes()))
		if accMeta != nil {
			projected -= int64(accMeta.Len)
		}
		if projected <= target || ended || pendingBytes >= step {
			if err := persist(); err != nil {
				return end, err
			}
			if s.bytes <= target || ended {
				return end, nil
			}
		}
	}
	if acc != nil && len(pending) > 0 {
		if err := persist(); err != nil {
			return end, err
		}
	}
	return end, nil
}

// persistRange writes the range record replacing pending (and a previously persisted range).
func (s *Spool) persistRange(acc *protocol.Record, accMeta *recMeta, pending []recMeta, flags uint8) (recMeta, error) {
	locs, undo, err := s.segs.appendFrames([][]byte{appendFrame(nil, acc.Bytes())})
	if err != nil {
		return recMeta{}, err
	}
	nm := recMeta{
		Seq: acc.Seq, Type: protocol.TypeRange, State: NeverTransmitted, Flags: flags, Hash: acc.Hash(),
		Seg: locs[0].seg, Off: locs[0].off, Len: uint32(len(acc.Bytes())), Time: acc.Time, From: acc.Range.From, //nolint:gosec // protocol.Encode bounds records by MaxRecordBytes
	}
	// Usage reports the age of the oldest spooled change, so a range keeps its earliest input time.
	gone := append([]recMeta(nil), pending...)
	if accMeta != nil {
		gone = append(gone, *accMeta)
	}
	for _, m := range gone {
		nm.Time = min(nm.Time, m.Time)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRecords)
		for _, m := range gone {
			if m.Seq == nm.Seq {
				continue
			}
			if err := b.Delete(seqKey(m.Seq)); err != nil {
				return err
			}
		}
		return b.Put(seqKey(nm.Seq), nm.encode())
	})
	if err != nil {
		if uerr := undo(); uerr != nil {
			s.fault = fmt.Errorf("spool: rolling back unreferenced bodies: %w", uerr)
		}
		return recMeta{}, err
	}
	for _, m := range gone {
		s.account(m, -1)
	}
	s.account(nm, 1)
	return nm, nil
}

// meta reads the metadata of the record at seq.
func (s *Spool) meta(seq uint64) (recMeta, error) {
	var m recMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		k := seqKey(seq)
		v := tx.Bucket(bucketRecords).Get(k)
		if v == nil {
			return fmt.Errorf("%w: record %d missing", ErrCorrupt, seq)
		}
		var err error
		m, err = decodeMeta(k, v)
		return err
	})
	return m, err
}

// reclaim moves the deadest segments once relief has grown the files past its limit, so relief frees as it writes.
func (s *Spool) reclaim(rel *Relief) error {
	s.noteIO(s.segs.gc())
	if s.diskLimit == 0 || s.segs.diskBytes() <= s.diskLimit {
		return nil
	}
	dead := func(id uint64) int64 { return s.segs.segs[id].size - s.segs.segs[id].live }
	var order []uint64
	for id, st := range s.segs.segs {
		if id != s.segs.active && st.live > 0 && st.live < st.size {
			order = append(order, id)
		}
	}
	sort.Slice(order, func(i, j int) bool { return dead(order[i]) > dead(order[j]) })
	disk, goal := s.segs.diskBytes(), s.diskLimit-s.reliefStep()
	for i, id := range order {
		if disk <= goal {
			order = order[:i]
			break
		}
		disk -= dead(id)
	}
	return s.moveSegments(rel, order)
}

// compactSegments rewrites the live frames of segments that are mostly dead and, while the segment files exceed
// target, of the deadest segments with any dead frames.
func (s *Spool) compactSegments(rel *Relief, target int64) error {
	return s.moveSegments(rel, s.compactionOrder(target))
}

// moveSegments moves each segment in order whole and removes it before the next.
func (s *Spool) moveSegments(rel *Relief, order []uint64) error {
	if len(order) == 0 {
		return nil
	}
	bySeg := map[uint64][]recMeta{}
	for _, id := range order {
		bySeg[id] = nil
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			m, err := decodeMeta(k, v)
			if err != nil {
				return err
			}
			if metas, ok := bySeg[m.Seg]; ok {
				bySeg[m.Seg] = append(metas, m)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, id := range order {
		if err := s.moveFrames(bySeg[id]); err != nil {
			return err
		}
		rel.SegmentsCompacted++
	}
	return nil
}

// compactionOrder lists the segments to compact, deadest first.
func (s *Spool) compactionOrder(target int64) []uint64 {
	dead := func(id uint64) int64 { return s.segs.segs[id].size - s.segs.segs[id].live }
	var mostly, partly []uint64
	for id, st := range s.segs.segs {
		switch {
		case id == s.segs.active || st.live == 0:
		case st.live*2 < st.size:
			mostly = append(mostly, id)
		case st.live < st.size:
			partly = append(partly, id)
		}
	}
	disk := s.segs.diskBytes()
	for _, id := range mostly {
		disk -= dead(id)
	}
	sort.Slice(partly, func(i, j int) bool { return dead(partly[i]) > dead(partly[j]) })
	order := mostly
	for _, id := range partly {
		if disk <= target {
			break
		}
		order = append(order, id)
		disk -= dead(id)
	}
	sort.Slice(order, func(i, j int) bool { return dead(order[i]) > dead(order[j]) })
	return order
}

// moveFrames copies the frames of metas, unchanged, to the active segment in bounded batches.
func (s *Spool) moveFrames(metas []recMeta) error {
	for len(metas) > 0 {
		var olds []recMeta
		var frames [][]byte
		var changed []int
		var n int64
		for len(metas) > 0 && (n == 0 || n < s.reliefStep()) {
			m := metas[0]
			metas = metas[1:]
			body, err := s.readBody(m)
			if err != nil {
				return err
			}
			changed = append(changed, len(olds))
			olds = append(olds, m)
			frames = append(frames, appendFrame(nil, body))
			n += int64(m.Len)
		}
		news := append([]recMeta(nil), olds...)
		if err := s.replaceMetas(olds, news, frames, changed); err != nil {
			return err
		}
	}
	return nil
}
