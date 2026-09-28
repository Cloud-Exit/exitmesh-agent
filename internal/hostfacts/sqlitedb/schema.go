package sqlitedb

import (
	"fmt"
	"math"
	"strings"
)

func float64FromBits(b uint64) float64 { return math.Float64frombits(b) }

// parseCreateTable returns column names, REAL affinity per column, the rowid alias column (or -1), and WITHOUT ROWID.
func parseCreateTable(sql string) ([]string, []bool, int, bool, error) {
	open := strings.IndexByte(sql, '(')
	if open < 0 {
		return nil, nil, -1, false, fmt.Errorf("%w: create table without column list", ErrCorrupt)
	}
	depth, end := 0, -1
	var quote byte
	for i := open; i < len(sql) && end < 0; i++ {
		ch := sql[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '\'' || ch == '"' || ch == '`':
			quote = ch
		case ch == '[':
			quote = ']'
		case ch == '(':
			depth++
		case ch == ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
	}
	if end < 0 {
		return nil, nil, -1, false, fmt.Errorf("%w: unbalanced create table", ErrCorrupt)
	}
	withoutRowid := strings.Contains(strings.ToUpper(strings.Join(strings.Fields(sql[end+1:]), " ")), "WITHOUT ROWID")
	var cols []string
	var real []bool
	rowid := -1
	for _, def := range splitTopLevel(sql[open+1 : end]) {
		name, rest := firstToken(def)
		if name == "" {
			continue
		}
		switch strings.ToUpper(name) {
		case "CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN":
			if !isQuoted(def) {
				continue
			}
		}
		up := strings.ToUpper(strings.Join(strings.Fields(rest), " "))
		if strings.HasPrefix(up, "INTEGER PRIMARY KEY") && !strings.HasPrefix(up, "INTEGER PRIMARY KEY DESC") {
			rowid = len(cols)
		}
		cols = append(cols, name)
		real = append(real, realAffinity(up))
	}
	return cols, real, rowid, withoutRowid, nil
}

// realAffinity applies the SQLite affinity rules to a declared type (the part before any constraint).
func realAffinity(decl string) bool {
	for _, kw := range []string{" CONSTRAINT", " PRIMARY", " NOT", " NULL", " UNIQUE", " CHECK", " DEFAULT", " COLLATE", " REFERENCES", " GENERATED", " AS"} {
		if i := strings.Index(" "+decl, kw+" "); i >= 0 {
			decl = decl[:max(i-1, 0)]
		}
	}
	if strings.Contains(decl, "INT") || strings.Contains(decl, "CHAR") || strings.Contains(decl, "CLOB") || strings.Contains(decl, "TEXT") {
		return false
	}
	return strings.Contains(decl, "REAL") || strings.Contains(decl, "FLOA") || strings.Contains(decl, "DOUB") //nolint:misspell // "DOUB" is the SQLite REAL affinity substring rule
}

func isQuoted(def string) bool {
	d := strings.TrimSpace(def)
	return d != "" && strings.ContainsRune("'\"`[", rune(d[0]))
}

func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '\'' || ch == '"' || ch == '`':
			quote = ch
		case ch == '[':
			quote = ']'
		case ch == '(':
			depth++
		case ch == ')':
			depth--
		case ch == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func firstToken(def string) (string, string) {
	d := strings.TrimSpace(def)
	if d == "" {
		return "", ""
	}
	closer := map[byte]byte{'\'': '\'', '"': '"', '`': '`', '[': ']'}
	if c, ok := closer[d[0]]; ok {
		var b strings.Builder
		for i := 1; i < len(d); i++ {
			if d[i] == c {
				if c != ']' && i+1 < len(d) && d[i+1] == c {
					b.WriteByte(c)
					i++
					continue
				}
				return b.String(), d[i+1:]
			}
			b.WriteByte(d[i])
		}
		return b.String(), ""
	}
	i := strings.IndexFunc(d, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' })
	if i < 0 {
		return d, ""
	}
	return d[:i], d[i:]
}
