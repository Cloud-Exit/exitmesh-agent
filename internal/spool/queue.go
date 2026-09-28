package spool

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ErrFull reports that an append would exceed the queue capacity.
var ErrFull = errors.New("spool: queue full")

// QueueItem is one queued payload and its sequence.
type QueueItem struct {
	Seq  uint64
	Data []byte
}

// QueueUsage reports queue occupancy.
type QueueUsage struct {
	Bytes    int64 // segment file bytes, counted against Capacity
	Capacity int64
	Items    uint64 // appended and not acknowledged
	Acked    uint64
	Next     uint64 // sequence the next append receives
}

const (
	qSuffix   = ".qlog"
	qAckName  = "ACKED"
	qSeqBytes = 8
)

type qseg struct {
	id          uint64
	f           *os.File
	size        int64
	first, last uint64 // zero when the segment holds no frames
}

// Queue is the node agent's durable, segmented, append-only queue.
type Queue struct {
	mu       sync.Mutex
	dir      string
	unlock   func() error
	capacity int64
	segBytes int64
	segs     []*qseg
	nextID   uint64
	acked    uint64
	next     uint64
	hint     qhint
	fault    error
	closed   bool
}

// qhint remembers where the frame for seq starts, so sequential Peeks do not rescan.
type qhint struct {
	seq uint64
	seg uint64
	off int64
}

// OpenQueue locks dir and recovers the queue, dropping a torn tail frame left by a crash.
func OpenQueue(dir string, capacityBytes int64) (*Queue, error) {
	if capacityBytes <= 0 {
		return nil, errors.New("spool: queue capacity must be positive")
	}
	unlock, err := LockDir(dir)
	if err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, unlock: unlock, capacity: capacityBytes, nextID: 1}
	q.segBytes = min(max(capacityBytes/16, 64<<10), 16<<20)
	if err := q.recover(); err != nil {
		for _, sg := range q.segs {
			_ = sg.f.Close()
		}
		_ = unlock()
		return nil, err
	}
	return q, nil
}

func qsegName(id uint64) string { return fmt.Sprintf("%016x%s", id, qSuffix) }

func (q *Queue) recover() error {
	acked, err := readAck(filepath.Join(q.dir, qAckName))
	if err != nil {
		return err
	}
	q.acked = acked
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	var ids []uint64
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), qSuffix) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(e.Name(), qSuffix), 16, 64)
		if err != nil || id == 0 {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var prev uint64
	for i, id := range ids {
		f, err := os.OpenFile(filepath.Join(q.dir, qsegName(id)), os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		sg := &qseg{id: id, f: f}
		q.segs = append(q.segs, sg)
		if id >= q.nextID {
			q.nextID = id + 1
		}
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		br := bufio.NewReaderSize(io.NewSectionReader(f, 0, fi.Size()), 1<<20)
		var off int64
		for {
			p, err := readFrame(br)
			if errors.Is(err, io.EOF) {
				break
			}
			if err == nil && len(p) < qSeqBytes {
				err = errTorn
			}
			if err != nil {
				if i != len(ids)-1 {
					return fmt.Errorf("%s at %d: %w", qsegName(id), off, err)
				}
				if err := f.Truncate(off); err != nil {
					return err
				}
				if err := f.Sync(); err != nil {
					return err
				}
				break
			}
			seq := binary.BigEndian.Uint64(p[:qSeqBytes])
			if prev != 0 && seq != prev+1 {
				return fmt.Errorf("%w: queue sequence %d after %d", ErrCorrupt, seq, prev)
			}
			if sg.first == 0 {
				sg.first = seq
			}
			sg.last, prev = seq, seq
			off += frameLen(len(p))
		}
		sg.size = off
	}
	q.next = max(prev, q.acked) + 1
	keep := q.segs[:0]
	for _, sg := range q.segs {
		if sg.last == 0 || sg.last <= q.acked {
			_ = sg.f.Close()
			if err := os.Remove(filepath.Join(q.dir, qsegName(sg.id))); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		keep = append(keep, sg)
	}
	q.segs = keep
	if len(q.segs) > 0 && q.segs[0].first > q.acked+1 {
		return fmt.Errorf("%w: queue items %d to %d missing", ErrCorrupt, q.acked+1, q.segs[0].first-1)
	}
	return nil
}

func readAck(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(b) != 12 || crc32.Checksum(b[:8], castagnoli) != binary.BigEndian.Uint32(b[8:]) {
		return 0, fmt.Errorf("%w: queue acknowledgement file", ErrCorrupt)
	}
	return binary.BigEndian.Uint64(b[:8]), nil
}

func (q *Queue) diskBytes() int64 {
	var n int64
	for _, sg := range q.segs {
		n += sg.size
	}
	return n
}

// Append writes b as the next item and fsyncs it before returning its sequence.
func (q *Queue) Append(b []byte) (uint64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0, ErrClosed
	}
	if q.fault != nil {
		return 0, q.fault
	}
	payload := make([]byte, qSeqBytes, qSeqBytes+len(b))
	binary.BigEndian.PutUint64(payload, q.next)
	payload = append(payload, b...)
	if len(payload) > maxFrame {
		return 0, fmt.Errorf("spool: queue item of %d bytes too large", len(b))
	}
	fl := frameLen(len(payload))
	if q.diskBytes()+fl > q.capacity {
		return 0, ErrFull
	}
	var sg *qseg
	if n := len(q.segs); n > 0 {
		sg = q.segs[n-1]
	}
	if sg == nil || (sg.size > 0 && sg.size+fl > q.segBytes) {
		id := q.nextID
		f, err := os.OpenFile(filepath.Join(q.dir, qsegName(id)), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return 0, err
		}
		if err := syncDir(q.dir); err != nil {
			_ = f.Close()
			_ = os.Remove(filepath.Join(q.dir, qsegName(id)))
			return 0, err
		}
		q.nextID++
		sg = &qseg{id: id, f: f}
		q.segs = append(q.segs, sg)
	}
	frame := appendFrame(nil, payload)
	_, err := sg.f.WriteAt(frame, sg.size)
	if err == nil {
		err = sg.f.Sync()
	}
	if err != nil {
		if terr := sg.f.Truncate(sg.size); terr != nil {
			q.fault = fmt.Errorf("spool: queue rollback: %w", terr)
		}
		return 0, err
	}
	seq := q.next
	q.next++
	sg.size += fl
	if sg.first == 0 {
		sg.first = seq
	}
	sg.last = seq
	return seq, nil
}

// Peek returns unacknowledged items from fromSeq on, up to maxBytes of data but at least one.
func (q *Queue) Peek(fromSeq uint64, maxBytes int) []QueueItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	if fromSeq <= q.acked {
		fromSeq = q.acked + 1
	}
	if fromSeq >= q.next {
		return nil
	}
	i := sort.Search(len(q.segs), func(i int) bool { return q.segs[i].last >= fromSeq })
	var out []QueueItem
	total := 0
	var off int64
	if h := q.hint; h.seq == fromSeq && i < len(q.segs) && q.segs[i].id == h.seg {
		off = h.off
	}
	for ; i < len(q.segs); i, off = i+1, 0 {
		sg := q.segs[i]
		br := bufio.NewReaderSize(io.NewSectionReader(sg.f, off, sg.size-off), 256<<10)
		for off < sg.size {
			p, err := readFrame(br)
			if err != nil {
				if q.fault == nil {
					q.fault = fmt.Errorf("%s at %d: %w", qsegName(sg.id), off, err)
				}
				return out
			}
			seq := binary.BigEndian.Uint64(p[:qSeqBytes])
			if seq >= fromSeq {
				data := p[qSeqBytes:]
				if len(out) > 0 && total+len(data) > maxBytes {
					q.hint = qhint{seq: seq, seg: sg.id, off: off}
					return out
				}
				out = append(out, QueueItem{Seq: seq, Data: data})
				total += len(data)
			}
			off += frameLen(len(p))
		}
	}
	q.hint = qhint{}
	return out
}

// Ack durably drops every item with sequence at most seq.
func (q *Queue) Ack(seq uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrClosed
	}
	if seq <= q.acked {
		return nil
	}
	if seq >= q.next {
		return fmt.Errorf("spool: ack %d beyond last queued item %d", seq, q.next-1)
	}
	var b [12]byte
	binary.BigEndian.PutUint64(b[:8], seq)
	binary.BigEndian.PutUint32(b[8:], crc32.Checksum(b[:8], castagnoli))
	if err := writeFileAtomic(filepath.Join(q.dir, qAckName), b[:]); err != nil {
		return err
	}
	q.acked = seq
	keep := q.segs[:0]
	var first error
	for _, sg := range q.segs {
		if sg.last <= seq {
			_ = sg.f.Close()
			if err := os.Remove(filepath.Join(q.dir, qsegName(sg.id))); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
				first = err
			}
			continue
		}
		keep = append(keep, sg)
	}
	q.segs = keep
	return first
}

// Usage reports queue occupancy.
func (q *Queue) Usage() QueueUsage {
	q.mu.Lock()
	defer q.mu.Unlock()
	return QueueUsage{Bytes: q.diskBytes(), Capacity: q.capacity, Items: q.next - 1 - q.acked, Acked: q.acked, Next: q.next}
}

// Err returns the first persistent queue fault, if any.
func (q *Queue) Err() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.fault
}

// Close releases the queue and its lock.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	var errs []error
	for _, sg := range q.segs {
		errs = append(errs, sg.f.Close())
	}
	errs = append(errs, q.unlock())
	return errors.Join(errs...)
}
