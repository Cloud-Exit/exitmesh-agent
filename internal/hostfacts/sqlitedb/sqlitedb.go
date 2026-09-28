// Package sqlitedb reads rowid tables of SQLite files (with committed WAL frames) in pure Go and serves them to go-rpmdb as a database/sql driver.
package sqlitedb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrCorrupt reports a structurally invalid database file.
var ErrCorrupt = errors.New("sqlitedb: corrupt database")

const (
	headerMagic   = "SQLite format 3\x00"
	maxDepth      = 64
	pageLeafTable = 13
	pageIntTable  = 5
	walMagicLE    = 0x377f0682
	walMagicBE    = 0x377f0683
	walHeaderSize = 32
	walFrameHdr   = 24
)

// DB is an open read-only database snapshot.
type DB struct {
	f        *os.File
	wal      *os.File
	pageSize int
	usable   int
	nPages   uint32
	walPages map[uint32]int64
}

// Open opens the database at path and overlays the committed frames of path-wal when present.
func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	db := &DB{f: f}
	if err := db.readHeader(); err != nil {
		f.Close()
		return nil, err
	}
	if err := db.openWAL(path + "-wal"); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the files.
func (db *DB) Close() error {
	var err error
	if db.wal != nil {
		err = db.wal.Close()
	}
	if e := db.f.Close(); e != nil && err == nil {
		err = e
	}
	return err
}

func (db *DB) readHeader() error {
	h := make([]byte, 100)
	if _, err := db.f.ReadAt(h, 0); err != nil {
		return fmt.Errorf("%w: header: %v", ErrCorrupt, err)
	}
	if string(h[:16]) != headerMagic {
		return fmt.Errorf("%w: not an SQLite 3 database", ErrCorrupt)
	}
	ps := int(binary.BigEndian.Uint16(h[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return fmt.Errorf("%w: page size %d", ErrCorrupt, ps)
	}
	db.pageSize = ps
	db.usable = ps - int(h[20])
	if db.usable < 480 {
		return fmt.Errorf("%w: usable size %d", ErrCorrupt, db.usable)
	}
	if enc := binary.BigEndian.Uint32(h[56:60]); enc != 0 && enc != 1 {
		return fmt.Errorf("sqlitedb: unsupported text encoding %d", enc)
	}
	st, err := db.f.Stat()
	if err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[28:32])
	if n == 0 || binary.BigEndian.Uint32(h[24:28]) != binary.BigEndian.Uint32(h[92:96]) {
		n = uint32(st.Size() / int64(ps))
	}
	db.nPages = n
	return nil
}

// openWAL indexes the frames of the last committed transaction in the WAL, validated by salts and checksums.
func (db *DB) openWAL(path string) error {
	w, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, err := w.Stat()
	if err != nil {
		w.Close()
		return err
	}
	hdr := make([]byte, walHeaderSize)
	if st.Size() < walHeaderSize {
		w.Close()
		return nil
	}
	if _, err := w.ReadAt(hdr, 0); err != nil {
		w.Close()
		return err
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(hdr[0:4]) {
	case walMagicLE:
		order = binary.LittleEndian
	case walMagicBE:
		order = binary.BigEndian
	default:
		w.Close()
		return nil
	}
	if int(binary.BigEndian.Uint32(hdr[8:12])) != db.pageSize {
		w.Close()
		return nil
	}
	s0, s1 := walChecksum(order, hdr[:24], 0, 0)
	if s0 != binary.BigEndian.Uint32(hdr[24:28]) || s1 != binary.BigEndian.Uint32(hdr[28:32]) {
		w.Close()
		return nil
	}
	salt := hdr[16:24]
	frame := make([]byte, walFrameHdr+db.pageSize)
	pending := map[uint32]int64{}
	committed := map[uint32]int64{}
	var dbSize uint32
	for off := int64(walHeaderSize); off+int64(len(frame)) <= st.Size(); off += int64(len(frame)) {
		if _, err := w.ReadAt(frame, off); err != nil {
			break
		}
		if !bytes.Equal(frame[8:16], salt) {
			break
		}
		s0, s1 = walChecksum(order, frame[:8], s0, s1)
		s0, s1 = walChecksum(order, frame[walFrameHdr:], s0, s1)
		if s0 != binary.BigEndian.Uint32(frame[16:20]) || s1 != binary.BigEndian.Uint32(frame[20:24]) {
			break
		}
		pg := binary.BigEndian.Uint32(frame[0:4])
		if pg == 0 {
			break
		}
		pending[pg] = off + walFrameHdr
		if commit := binary.BigEndian.Uint32(frame[4:8]); commit != 0 {
			for k, v := range pending {
				committed[k] = v
			}
			clear(pending)
			dbSize = commit
		}
	}
	if len(committed) == 0 {
		w.Close()
		return nil
	}
	db.wal = w
	db.walPages = committed
	db.nPages = dbSize
	return nil
}

func walChecksum(order binary.ByteOrder, b []byte, s0, s1 uint32) (uint32, uint32) {
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += order.Uint32(b[i:]) + s1
		s1 += order.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}

func (db *DB) page(n uint32) ([]byte, error) {
	if n == 0 || n > db.nPages {
		return nil, fmt.Errorf("%w: page %d out of range", ErrCorrupt, n)
	}
	b := make([]byte, db.pageSize)
	if off, ok := db.walPages[n]; ok {
		if _, err := db.wal.ReadAt(b, off); err != nil {
			return nil, err
		}
		return b, nil
	}
	if _, err := db.f.ReadAt(b, int64(n-1)*int64(db.pageSize)); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: page %d beyond end of file", ErrCorrupt, n)
		}
		return nil, err
	}
	return b, nil
}

func varint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// Cursor iterates the rows of one table b-tree in rowid order.
type Cursor struct {
	db    *DB
	stack []frame
	err   error
}

type frame struct {
	page  []byte
	hdr   int
	cells int
	next  int
}

func (db *DB) cursor(root uint32) *Cursor {
	c := &Cursor{db: db}
	c.push(root)
	return c
}

func (c *Cursor) push(n uint32) {
	if len(c.stack) >= maxDepth {
		c.err = fmt.Errorf("%w: b-tree too deep", ErrCorrupt)
		return
	}
	p, err := c.db.page(n)
	if err != nil {
		c.err = err
		return
	}
	hdr := 0
	if n == 1 {
		hdr = 100
	}
	if hdr+12 > len(p) {
		c.err = fmt.Errorf("%w: short page %d", ErrCorrupt, n)
		return
	}
	switch p[hdr] {
	case pageLeafTable, pageIntTable:
	default:
		c.err = fmt.Errorf("%w: page %d is not a table b-tree page (type %d)", ErrCorrupt, n, p[hdr])
		return
	}
	cells := int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
	c.stack = append(c.stack, frame{page: p, hdr: hdr, cells: cells})
}

// Next returns the next row's rowid and record payload.
func (c *Cursor) Next() (int64, []byte, bool) {
	for c.err == nil && len(c.stack) > 0 {
		top := &c.stack[len(c.stack)-1]
		p, h := top.page, top.hdr
		leaf := p[h] == pageLeafTable
		ptrBase := h + 8
		if !leaf {
			ptrBase = h + 12
		}
		if top.next > top.cells || (leaf && top.next == top.cells) {
			c.stack = c.stack[:len(c.stack)-1]
			continue
		}
		i := top.next
		top.next++
		if !leaf && i == top.cells {
			c.push(binary.BigEndian.Uint32(p[h+8 : h+12]))
			continue
		}
		if ptrBase+2*i+2 > len(p) {
			c.err = fmt.Errorf("%w: cell pointer array overflows page", ErrCorrupt)
			return 0, nil, false
		}
		off := int(binary.BigEndian.Uint16(p[ptrBase+2*i:]))
		if off+4 > c.db.usable {
			c.err = fmt.Errorf("%w: cell offset %d", ErrCorrupt, off)
			return 0, nil, false
		}
		if !leaf {
			c.push(binary.BigEndian.Uint32(p[off : off+4]))
			continue
		}
		rowid, payload, err := c.db.leafCell(p, off)
		if err != nil {
			c.err = err
			return 0, nil, false
		}
		return rowid, payload, true
	}
	return 0, nil, false
}

// Err reports the first error encountered by Next.
func (c *Cursor) Err() error { return c.err }

func (db *DB) leafCell(p []byte, off int) (int64, []byte, error) {
	plen, n := varint(p[off:db.usable])
	if n == 0 {
		return 0, nil, fmt.Errorf("%w: payload length", ErrCorrupt)
	}
	off += n
	rowid, n := varint(p[off:db.usable])
	if n == 0 {
		return 0, nil, fmt.Errorf("%w: rowid", ErrCorrupt)
	}
	off += n
	if plen > 1<<31 {
		return 0, nil, fmt.Errorf("%w: payload length %d", ErrCorrupt, plen)
	}
	total := int(plen)
	local := db.localPayload(total)
	if off+local > db.usable {
		return 0, nil, fmt.Errorf("%w: local payload overflows page", ErrCorrupt)
	}
	out := make([]byte, 0, total)
	out = append(out, p[off:off+local]...)
	if local == total {
		return int64(rowid), out, nil
	}
	if off+local+4 > db.usable {
		return 0, nil, fmt.Errorf("%w: overflow pointer", ErrCorrupt)
	}
	next := binary.BigEndian.Uint32(p[off+local:])
	for hops := uint32(0); len(out) < total; hops++ {
		if next == 0 || hops > db.nPages {
			return 0, nil, fmt.Errorf("%w: overflow chain", ErrCorrupt)
		}
		op, err := db.page(next)
		if err != nil {
			return 0, nil, err
		}
		chunk := min(total-len(out), db.usable-4)
		out = append(out, op[4:4+chunk]...)
		next = binary.BigEndian.Uint32(op[0:4])
	}
	return int64(rowid), out, nil
}

func (db *DB) localPayload(p int) int {
	u := db.usable
	x := u - 35
	if p <= x {
		return p
	}
	m := ((u-12)*32)/255 - 23
	k := m + (p-m)%(u-4)
	if k <= x {
		return k
	}
	return m
}

// DecodeRecord decodes an SQLite record into int64, float64, string, []byte, or nil values.
func DecodeRecord(rec []byte) ([]any, error) {
	hlen, n := varint(rec)
	if n == 0 || int(hlen) > len(rec) || int(hlen) < n {
		return nil, fmt.Errorf("%w: record header", ErrCorrupt)
	}
	var types []uint64
	for p := n; p < int(hlen); {
		t, m := varint(rec[p:hlen])
		if m == 0 {
			return nil, fmt.Errorf("%w: serial type", ErrCorrupt)
		}
		types = append(types, t)
		p += m
	}
	body := rec[hlen:]
	out := make([]any, len(types))
	for i, t := range types {
		size := serialSize(t)
		if size < 0 || size > len(body) {
			return nil, fmt.Errorf("%w: value %d exceeds record", ErrCorrupt, i)
		}
		v := body[:size]
		body = body[size:]
		switch {
		case t == 0:
			out[i] = nil
		case t >= 1 && t <= 6:
			out[i] = beInt(v)
		case t == 7:
			out[i] = float64FromBits(binary.BigEndian.Uint64(v))
		case t == 8:
			out[i] = int64(0)
		case t == 9:
			out[i] = int64(1)
		case t >= 12 && t%2 == 0:
			out[i] = append([]byte(nil), v...)
		case t >= 13:
			out[i] = string(v)
		default:
			return nil, fmt.Errorf("%w: reserved serial type %d", ErrCorrupt, t)
		}
	}
	return out, nil
}

func serialSize(t uint64) int {
	switch t {
	case 0, 8, 9:
		return 0
	case 1, 2, 3, 4:
		return int(t)
	case 5:
		return 6
	case 6, 7:
		return 8
	case 10, 11:
		return -1
	}
	if t > 1<<32 {
		return -1
	}
	if t%2 == 0 {
		return int((t - 12) / 2)
	}
	return int((t - 13) / 2)
}

func beInt(b []byte) int64 {
	var v int64
	if len(b) > 0 && b[0]&0x80 != 0 {
		v = -1
	}
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	return v
}

// Table describes one rowid table from the schema.
type Table struct {
	Name     string
	Root     uint32
	Columns  []string
	RowidCol int
	real     []bool
}

// Table looks up a table by case-insensitive name.
func (db *DB) Table(name string) (*Table, error) {
	c := db.cursor(1)
	for {
		_, rec, ok := c.Next()
		if !ok {
			break
		}
		v, err := DecodeRecord(rec)
		if err != nil {
			return nil, err
		}
		if len(v) < 5 {
			continue
		}
		typ, _ := v[0].(string)
		nm, _ := v[1].(string)
		if typ != "table" || !strings.EqualFold(nm, name) {
			continue
		}
		root, _ := v[3].(int64)
		sql, _ := v[4].(string)
		cols, real, rowidCol, withoutRowid, err := parseCreateTable(sql)
		if err != nil {
			return nil, err
		}
		if withoutRowid {
			return nil, fmt.Errorf("sqlitedb: table %s is WITHOUT ROWID, which is not supported", nm)
		}
		if root <= 0 || root > int64(db.nPages) {
			return nil, fmt.Errorf("%w: table %s root page %d", ErrCorrupt, nm, root)
		}
		return &Table{Name: nm, Root: uint32(root), Columns: cols, RowidCol: rowidCol, real: real}, nil
	}
	if err := c.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("sqlitedb: no such table: %s", name)
}

// Scan calls fn for every row of t with the values of the named columns.
func (db *DB) Scan(t *Table, columns []string, fn func(rowid int64, vals []any) error) error {
	rows, err := db.Rows(t, columns)
	if err != nil {
		return err
	}
	for {
		rowid, vals, ok := rows.Next()
		if !ok {
			return rows.Err()
		}
		if err := fn(rowid, vals); err != nil {
			return err
		}
	}
}

// RowIter yields projected rows.
type RowIter struct {
	c   *Cursor
	t   *Table
	idx []int
	err error
}

// Rows returns an iterator over the named columns of t.
func (db *DB) Rows(t *Table, columns []string) (*RowIter, error) {
	idx := make([]int, len(columns))
	for i, name := range columns {
		idx[i] = -1
		for j, c := range t.Columns {
			if strings.EqualFold(c, name) {
				idx[i] = j
				break
			}
		}
		if idx[i] < 0 && !strings.EqualFold(name, "rowid") {
			return nil, fmt.Errorf("sqlitedb: no such column: %s", name)
		}
	}
	return &RowIter{c: db.cursor(t.Root), t: t, idx: idx}, nil
}

// Next returns the next row.
func (r *RowIter) Next() (int64, []any, bool) {
	if r.err != nil {
		return 0, nil, false
	}
	rowid, rec, ok := r.c.Next()
	if !ok {
		r.err = r.c.Err()
		return 0, nil, false
	}
	vals, err := DecodeRecord(rec)
	if err != nil {
		r.err = err
		return 0, nil, false
	}
	out := make([]any, len(r.idx))
	for i, j := range r.idx {
		switch {
		case j < 0 || j == r.t.RowidCol:
			out[i] = rowid
		case j < len(vals):
			out[i] = vals[j]
			if iv, ok := vals[j].(int64); ok && r.t.real[j] {
				out[i] = float64(iv)
			}
		}
	}
	return rowid, out, true
}

// Err reports the iteration error, if any.
func (r *RowIter) Err() error { return r.err }
