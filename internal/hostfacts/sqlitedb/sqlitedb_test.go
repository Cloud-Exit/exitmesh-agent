package sqlitedb

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Fixtures were written by SQLite 3.45 (plain.db with 1 KiB pages; wal.db with autocheckpoint off and an uncommitted spill).

func fixtureBlob(i int) []byte {
	n := (i * 37) % 97
	if i%20 == 0 {
		n = 5000 + i
	}
	b := make([]byte, n)
	for j := range b {
		b[j] = byte(((i + j) * 7) % 251)
	}
	return b
}

func TestPlainTableScan(t *testing.T) {
	db, err := Open("testdata/plain.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tb, err := db.Table("items")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"id", "name", "data", "n", "f", "quoted col"}
	if len(tb.Columns) != len(want) || tb.RowidCol != 0 {
		t.Fatalf("columns %q rowid %d", tb.Columns, tb.RowidCol)
	}
	for i := range want {
		if tb.Columns[i] != want[i] {
			t.Fatalf("columns %q", tb.Columns)
		}
	}
	count := 0
	last := int64(0)
	err = db.Scan(tb, []string{"id", "name", "data", "n", "f", "quoted col"}, func(rowid int64, v []any) error {
		count++
		i := int(rowid)
		if rowid <= last {
			t.Fatalf("rowids out of order: %d after %d", rowid, last)
		}
		last = rowid
		if i%50 == 0 {
			t.Fatalf("deleted row %d returned", i)
		}
		if v[0].(int64) != rowid || v[1].(string) != "row-"+itoa(i) {
			t.Fatalf("row %d: %v %v", i, v[0], v[1])
		}
		if !bytes.Equal(v[2].([]byte), fixtureBlob(i)) {
			t.Fatalf("row %d blob mismatch (len %d)", i, len(v[2].([]byte)))
		}
		sign := int64(1)
		if i%2 == 1 {
			sign = -1
		}
		if v[3].(int64) != int64(i*i)*sign*1000003 {
			t.Fatalf("row %d n=%v", i, v[3])
		}
		if v[4].(float64) != float64(i)/3.0 {
			t.Fatalf("row %d f=%v", i, v[4])
		}
		if i%5 == 0 && v[5] != nil || i%5 != 0 && v[5].(string) != "q"+itoa(i) {
			t.Fatalf("row %d quoted=%v", i, v[5])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 392 {
		t.Fatalf("rows = %d, want 392", count)
	}
	if _, err := db.Table("missing"); err == nil {
		t.Fatal("missing table found")
	}
	if _, err := db.Rows(tb, []string{"nope"}); err == nil {
		t.Fatal("missing column accepted")
	}
}

func itoa(i int) string {
	return string(appendInt(nil, i))
}

func appendInt(b []byte, i int) []byte {
	if i >= 10 {
		b = appendInt(b, i/10)
	}
	return append(b, byte('0'+i%10))
}

func TestWALCommittedFramesOnly(t *testing.T) {
	db, err := Open("testdata/wal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tb, err := db.Table("Packages")
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	err = db.Scan(tb, []string{"hnum", "blob"}, func(rowid int64, v []any) error {
		ids = append(ids, rowid)
		if !bytes.Equal(v[1].([]byte), fixtureBlob(int(rowid)*7)) {
			t.Fatalf("row %d blob mismatch", rowid)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 29 || ids[0] != 1 || ids[len(ids)-1] != 30 {
		t.Fatalf("ids = %v", ids)
	}
	for _, id := range ids {
		if id == 3 {
			t.Fatal("row deleted in a committed WAL transaction is visible")
		}
	}
}

func TestWithoutWALSeesMainFileOnly(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile("testdata/wal.db")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "x.db")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tb, err := db.Table("Packages")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := db.Scan(tb, []string{"blob"}, func(int64, []any) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("rows = %d, want 10", n)
	}
	w, err := os.ReadFile("testdata/wal.db-wal")
	if err != nil {
		t.Fatal(err)
	}
	w[32+24+100] ^= 0xff
	if err := os.WriteFile(p+"-wal", w, 0o600); err != nil {
		t.Fatal(err)
	}
	db2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if db2.walPages != nil {
		t.Fatal("WAL with a corrupt first frame was applied")
	}
}

func TestCorruptInput(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.db")
	if err := os.WriteFile(p, []byte("not a database at all, just some text padding it out to one hundred bytes......................."), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
	b, _ := os.ReadFile("testdata/plain.db")
	b = b[:4096]
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tb, err := db.Table("Items")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Scan(tb, []string{"name"}, func(int64, []any) error { return nil }); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated database scan err = %v", err)
	}
}

func TestDecodeRecordSerialTypes(t *testing.T) {
	rec := []byte{8, 0, 1, 2, 8, 9, 0x11, 0x0e, 0x7f, 0x01, 0x00, 'a', 'b', 0xaa}
	v, err := DecodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if v[0] != nil || v[1].(int64) != 127 || v[2].(int64) != 256 || v[3].(int64) != 0 || v[4].(int64) != 1 || v[5].(string) != "ab" || !bytes.Equal(v[6].([]byte), []byte{0xaa}) {
		t.Fatalf("decoded %v", v)
	}
	if _, err := DecodeRecord([]byte{3, 10, 0}); err == nil {
		t.Fatal("reserved serial type accepted")
	}
	if _, err := DecodeRecord([]byte{2, 6}); err == nil {
		t.Fatal("truncated value accepted")
	}
	if got := beInt([]byte{0xff, 0xfe}); got != -2 {
		t.Fatalf("beInt = %d", got)
	}
}

func TestParseCreateTable(t *testing.T) {
	cases := []struct {
		sql     string
		cols    []string
		rowid   int
		without bool
	}{
		{"CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL)", []string{"hnum", "blob"}, 0, false},
		{"CREATE TABLE t (a TEXT, [b c] INT, `d` REAL DEFAULT (1,2), PRIMARY KEY (a)) WITHOUT ROWID", []string{"a", "b c", "d"}, -1, true},
		{`CREATE TABLE x ("primary" TEXT, id integer primary key desc, CONSTRAINT c CHECK (id > 0))`, []string{"primary", "id"}, -1, false},
	}
	for _, c := range cases {
		cols, _, rowid, without, err := parseCreateTable(c.sql)
		if err != nil {
			t.Fatal(err)
		}
		if len(cols) != len(c.cols) || rowid != c.rowid || without != c.without {
			t.Fatalf("%s: cols %q rowid %d without %v", c.sql, cols, rowid, without)
		}
		for i := range cols {
			if cols[i] != c.cols[i] {
				t.Fatalf("%s: cols %q", c.sql, cols)
			}
		}
	}
	if _, _, _, _, err := parseCreateTable("CREATE TABLE broken (a"); err == nil {
		t.Fatal("unbalanced accepted")
	}
	_, real, _, _, _ := parseCreateTable("CREATE TABLE r (a REAL NOT NULL, b DOUBLE PRECISION, c FLOATING POINT, d INTEGER, e, f TEXT DEFAULT 'REAL')")
	if want := []bool{true, true, false, false, false, false}; len(real) != len(want) || real[0] != want[0] || real[1] != want[1] || real[2] != want[2] || real[3] || real[4] || real[5] {
		t.Fatalf("real affinity %v", real)
	}
}

func TestDriver(t *testing.T) {
	if !Register() {
		t.Fatal("driver name owned by another driver")
	}
	if !Register() {
		t.Fatal("second Register lost ownership")
	}
	db, err := sql.Open(DriverName, "testdata/wal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT blob FROM Packages")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if n != 29 {
		t.Fatalf("rows = %d", n)
	}
	for _, q := range []string{"DELETE FROM Packages", "SELECT * FROM Packages", "SELECT blob FROM Packages WHERE hnum = 1"} {
		if _, err := db.Query(q); err == nil {
			t.Fatalf("%q accepted", q)
		}
	}
	if _, err := db.Exec("SELECT blob FROM Packages"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("exec err = %v", err)
	}
	if _, err := db.Begin(); err == nil {
		t.Fatal("transaction accepted")
	}
}
