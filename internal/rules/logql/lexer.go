package logql

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString
	tNumber
	tLBrace
	tRBrace
	tLParen
	tRParen
	tLBrack
	tRBrack
	tComma
	tColon
	tEq
	tNeq
	tRe
	tNre
	tPipeEq
	tPipeRe
	tPipe
	tPipeGt
	tNotGt
	tEqEq
	tGt
	tGte
	tLt
	tLte
	tAdd
	tSub
	tMul
	tDiv
	tMod
	tPow
)

var tokNames = map[tokKind]string{
	tEOF: "end of input", tIdent: "identifier", tString: "string", tNumber: "number",
	tLBrace: "'{'", tRBrace: "'}'", tLParen: "'('", tRParen: "')'", tLBrack: "'['", tRBrack: "']'",
	tComma: "','", tColon: "':'", tEq: "'='", tNeq: "'!='", tRe: "'=~'", tNre: "'!~'",
	tPipeEq: "'|='", tPipeRe: "'|~'", tPipe: "'|'", tPipeGt: "'|>'", tNotGt: "'!>'", tEqEq: "'=='",
	tGt: "'>'", tGte: "'>='", tLt: "'<'", tLte: "'<='", tAdd: "'+'", tSub: "'-'", tMul: "'*'",
	tDiv: "'/'", tMod: "'%'", tPow: "'^'",
}

type token struct {
	kind tokKind
	text string
	val  string
	pos  int
}

func (t token) describe() string {
	switch t.kind {
	case tIdent, tNumber:
		return strconv.Quote(t.text)
	case tString:
		return "string " + strconv.Quote(t.val)
	}
	return tokNames[t.kind]
}

func lex(src string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(src) {
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		start := i
		two := ""
		if i+1 < len(src) {
			two = src[i : i+2]
		}
		switch {
		case isIdentStart(c):
			for i < len(src) && isIdentChar(src[i]) {
				i++
			}
			toks = append(toks, token{kind: tIdent, text: src[start:i], pos: start})
			continue
		case isDigit(c) || (c == '.' && i+1 < len(src) && isDigit(src[i+1])):
			i = scanNumber(src, i)
			toks = append(toks, token{kind: tNumber, text: src[start:i], pos: start})
			continue
		case c == '"':
			end, ok := scanQuoted(src, i)
			if !ok {
				return nil, &ParseError{Pos: start, Msg: "unterminated string"}
			}
			v, err := strconv.Unquote(src[start:end])
			if err != nil {
				return nil, &ParseError{Pos: start, Msg: "invalid string escape"}
			}
			toks = append(toks, token{kind: tString, text: src[start:end], val: v, pos: start})
			i = end
			continue
		case c == '`':
			end := strings.IndexByte(src[i+1:], '`')
			if end < 0 {
				return nil, &ParseError{Pos: start, Msg: "unterminated raw string"}
			}
			v := src[i+1 : i+1+end]
			if !utf8.ValidString(v) {
				return nil, &ParseError{Pos: start, Msg: "raw string is not valid UTF-8"}
			}
			i += end + 2
			toks = append(toks, token{kind: tString, text: src[start:i], val: v, pos: start})
			continue
		}
		var k tokKind
		n := 1
		switch {
		case two == "!=":
			k, n = tNeq, 2
		case two == "!~":
			k, n = tNre, 2
		case two == "!>":
			k, n = tNotGt, 2
		case two == "|=":
			k, n = tPipeEq, 2
		case two == "|~":
			k, n = tPipeRe, 2
		case two == "|>":
			k, n = tPipeGt, 2
		case two == "=~":
			k, n = tRe, 2
		case two == "==":
			k, n = tEqEq, 2
		case two == ">=":
			k, n = tGte, 2
		case two == "<=":
			k, n = tLte, 2
		case c == '{':
			k = tLBrace
		case c == '}':
			k = tRBrace
		case c == '(':
			k = tLParen
		case c == ')':
			k = tRParen
		case c == '[':
			k = tLBrack
		case c == ']':
			k = tRBrack
		case c == ',':
			k = tComma
		case c == ':':
			k = tColon
		case c == '=':
			k = tEq
		case c == '|':
			k = tPipe
		case c == '>':
			k = tGt
		case c == '<':
			k = tLt
		case c == '+':
			k = tAdd
		case c == '-':
			k = tSub
		case c == '*':
			k = tMul
		case c == '/':
			k = tDiv
		case c == '%':
			k = tMod
		case c == '^':
			k = tPow
		default:
			r, _ := utf8.DecodeRuneInString(src[i:])
			return nil, &ParseError{Pos: start, Msg: "unexpected character " + strconv.QuoteRune(r)}
		}
		i += n
		toks = append(toks, token{kind: k, text: src[start:i], pos: start})
	}
	toks = append(toks, token{kind: tEOF, pos: len(src)})
	return toks, nil
}

func scanQuoted(src string, i int) (int, bool) {
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '"':
			return j + 1, true
		case '\n':
			return 0, false
		}
	}
	return 0, false
}

// scanNumber consumes numbers, durations and byte sizes such as 1.5, 1e+06, 1h30m, 250µs and 10KiB.
func scanNumber(src string, i int) int {
	for i < len(src) {
		c := src[i]
		switch {
		case isDigit(c) || c == '.' || isLetter(c) || c == '_':
			if (c == 'e' || c == 'E') && i+2 < len(src) && (src[i+1] == '+' || src[i+1] == '-') && isDigit(src[i+2]) {
				i += 2
			}
			i++
		case strings.HasPrefix(src[i:], "µ") || strings.HasPrefix(src[i:], "μ"):
			i += 2
		default:
			return i
		}
	}
	return i
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isIdentStart(c byte) bool { return isLetter(c) || c == '_' }
func isIdentChar(c byte) bool  { return isIdentStart(c) || isDigit(c) }

func isLabelName(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			return false
		}
	}
	return true
}
