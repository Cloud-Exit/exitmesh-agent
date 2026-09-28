package sqlitedb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// DriverName is the database/sql driver name go-rpmdb opens rpm sqlite databases with.
const DriverName = "sqlite"

var (
	registerMu sync.Mutex
	selectRe   = regexp.MustCompile(`(?is)^\s*SELECT\s+(.+?)\s+FROM\s+([A-Za-z_][A-Za-z0-9_]*|"[^"]+"|'[^']+'|\[[^\]]+\]|` + "`[^`]+`" + `)\s*;?\s*$`)
)

// ErrReadOnly is returned for any statement other than a plain column projection.
var ErrReadOnly = errors.New("sqlitedb: only SELECT <columns> FROM <table> is supported")

// Register installs the driver under DriverName unless another owns the name, and reports whether ours is registered.
func Register() bool {
	registerMu.Lock()
	defer registerMu.Unlock()
	if slices.Contains(sql.Drivers(), DriverName) {
		_, ours := registeredOurs()
		return ours
	}
	sql.Register(DriverName, Driver{})
	return true
}

func registeredOurs() (driver.Driver, bool) {
	db, err := sql.Open(DriverName, "")
	if err != nil {
		return nil, false
	}
	defer db.Close()
	d := db.Driver()
	_, ok := d.(Driver)
	return d, ok
}

// Driver is a read-only database/sql driver over this package's file reader.
type Driver struct{}

// Open opens the database file named by name.
func (Driver) Open(name string) (driver.Conn, error) {
	db, err := Open(name)
	if err != nil {
		return nil, err
	}
	return &conn{db: db}, nil
}

type conn struct{ db *DB }

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	m := selectRe.FindStringSubmatch(query)
	if m == nil {
		return nil, ErrReadOnly
	}
	var cols []string
	for _, col := range strings.Split(m[1], ",") {
		name, rest := firstToken(col)
		if name == "" || strings.TrimSpace(rest) != "" || name == "*" {
			return nil, ErrReadOnly
		}
		cols = append(cols, name)
	}
	table, _ := firstToken(m[2])
	return &stmt{c: c, table: table, cols: cols}, nil
}

func (c *conn) Close() error { return c.db.Close() }

func (c *conn) Begin() (driver.Tx, error) { return nil, ErrReadOnly }

type stmt struct {
	c     *conn
	table string
	cols  []string
}

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return 0 }

func (s *stmt) Exec([]driver.Value) (driver.Result, error) { return nil, ErrReadOnly }

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("sqlitedb: statement takes no arguments")
	}
	t, err := s.c.db.Table(s.table)
	if err != nil {
		return nil, err
	}
	it, err := s.c.db.Rows(t, s.cols)
	if err != nil {
		return nil, err
	}
	return &rows{it: it, cols: s.cols}, nil
}

func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vals := make([]driver.Value, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	return s.Query(vals)
}

type rows struct {
	it   *RowIter
	cols []string
}

func (r *rows) Columns() []string { return r.cols }
func (r *rows) Close() error      { return nil }

func (r *rows) Next(dest []driver.Value) error {
	_, vals, ok := r.it.Next()
	if !ok {
		if err := r.it.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	for i := range dest {
		dest[i] = vals[i]
	}
	return nil
}
