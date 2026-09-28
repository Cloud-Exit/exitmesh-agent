package logs

import (
	"compress/gzip"
	"container/heap"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RangeOptions bounds an on-demand read. Zero values take the defaults.
type RangeOptions struct {
	MaxLines     int
	MaxBytes     int64
	MaxScanBytes int64
	MaxLineBytes int
	Node         string
	Enrich       EnrichFunc
}

// RangeResult holds the newest matching lines in time order, newest last.
type RangeResult struct {
	Lines []Line
	// Truncated reports that older matching lines were omitted to respect MaxLines or MaxBytes.
	Truncated bool
	Omitted   int
	// ScanLimited reports that MaxScanBytes stopped the read before every candidate file was scanned.
	ScanLimited  bool
	FilesRead    int
	BytesScanned int64
}

type rangeItem struct {
	line Line
	seq  int
	size int64
}

type rangeHeap []rangeItem

func (h rangeHeap) Len() int { return len(h) }
func (h rangeHeap) Less(i, j int) bool {
	if !h[i].line.Time.Equal(h[j].line.Time) {
		return h[i].line.Time.Before(h[j].line.Time)
	}
	return h[i].seq < h[j].seq
}
func (h rangeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *rangeHeap) Push(x any)   { *h = append(*h, x.(rangeItem)) }
func (h *rangeHeap) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

type rangeFile struct {
	path   string
	gz     bool
	mod    time.Time
	labels map[string]map[string]string
	accept map[string]bool
}

// ReadRange returns bounded lines in [from, to] from streams accepted by sel, retaining nothing.
func ReadRange(ctx context.Context, root string, sel StreamFilter, from, to time.Time, o RangeOptions) (*RangeResult, error) {
	if o.MaxLines <= 0 {
		o.MaxLines = 5000
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 4 << 20
	}
	if o.MaxScanBytes <= 0 {
		o.MaxScanBytes = 256 << 20
	}
	if o.MaxLineBytes <= 0 {
		o.MaxLineBytes = DefaultMaxLineBytes
	}
	files, err := rangeFiles(root, sel, from, o)
	if err != nil {
		return nil, err
	}
	res := &RangeResult{}
	h := &rangeHeap{}
	var held int64
	seq := 0
	add := func(l Line) {
		seq++
		size := int64(len(l.Text))
		heap.Push(h, rangeItem{l, seq, size})
		held += size
		for h.Len() > o.MaxLines || held > o.MaxBytes {
			it := heap.Pop(h).(rangeItem)
			held -= it.size
			res.Omitted++
			res.Truncated = true
		}
	}
	buf := make([]byte, readChunk)
	for _, rf := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if res.BytesScanned >= o.MaxScanBytes {
			res.ScanLimited = true
			break
		}
		limited, err := scanRangeFile(ctx, rf, buf, from, to, o, res, add)
		if err != nil {
			return nil, err
		}
		res.FilesRead++
		if limited {
			res.ScanLimited = true
			break
		}
	}
	res.Lines = make([]Line, h.Len())
	for i := range res.Lines {
		res.Lines[i] = heap.Pop(h).(rangeItem).line
	}
	return res, nil
}

func rangeFiles(root string, sel StreamFilter, from time.Time, o RangeOptions) ([]rangeFile, error) {
	pods, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []rangeFile
	for _, pd := range pods {
		ns, pod, uid, ok := parsePodDir(pd.Name())
		if !ok || !pd.IsDir() {
			continue
		}
		cdirs, err := os.ReadDir(filepath.Join(root, pd.Name()))
		if err != nil {
			continue
		}
		for _, cd := range cdirs {
			if !cd.IsDir() {
				continue
			}
			var extra map[string]string
			if o.Enrich != nil {
				extra = o.Enrich(ns, pod, uid, cd.Name())
			}
			_, lbl := streamLabels(ns, pod, uid, cd.Name(), o.Node, extra)
			acc := map[string]bool{}
			for _, cs := range criStreams {
				acc[cs] = sel(lbl[cs])
			}
			if !acc["stdout"] && !acc["stderr"] {
				continue
			}
			dir := filepath.Join(root, pd.Name(), cd.Name())
			des, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, de := range des {
				_, _, gz, ok := parseLogName(de.Name())
				if !ok {
					continue
				}
				fi, err := de.Info()
				if err != nil || !fi.Mode().IsRegular() || fi.ModTime().Before(from) {
					continue
				}
				out = append(out, rangeFile{path: filepath.Join(dir, de.Name()), gz: gz, mod: fi.ModTime(), labels: lbl, accept: acc})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mod.After(out[j].mod) })
	return out, nil
}

func scanRangeFile(ctx context.Context, rf rangeFile, buf []byte, from, to time.Time, o RangeOptions, res *RangeResult, add func(Line)) (limited bool, err error) {
	f, err := os.Open(rf.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	var r io.Reader = f
	if rf.gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return false, nil
		}
		defer zr.Close()
		r = zr
	}
	asm := map[string]*assembler{}
	onLine := func(pl physLine) {
		rec, ok := parseContainerLine(pl.head, pl.tail, pl.cut)
		if !ok || !rf.accept[rec.stream] {
			return
		}
		a := asm[rec.stream]
		if a == nil {
			a = &assembler{}
			asm[rec.stream] = a
		}
		text, ts, trunc, done := a.add(rec, o.MaxLineBytes)
		if done && !ts.Before(from) && !ts.After(to) {
			add(Line{Labels: rf.labels[rec.stream], Time: ts, Text: string(text), Truncated: trunc})
		}
	}
	var sp splitter
	var pos int64
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		k, rerr := r.Read(buf)
		if k > 0 {
			sp.feed(buf[:k], pos, 2*o.MaxLineBytes+1024, onLine)
			pos += int64(k)
			res.BytesScanned += int64(k)
			if res.BytesScanned >= o.MaxScanBytes {
				return true, nil
			}
		}
		if errors.Is(rerr, io.EOF) {
			sp.flush(pos, onLine)
			return false, nil
		}
		if rerr != nil {
			if rf.gz {
				return false, nil
			}
			return false, rerr
		}
	}
}
