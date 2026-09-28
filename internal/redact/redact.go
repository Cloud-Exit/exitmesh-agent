// Package redact removes secret-looking values from text before it reaches evidence rings,
// spools, transmission, or diagnostics (PRD L6, 10).
package redact

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

// Placeholder replaces every redacted value.
const Placeholder = "<redacted>"

type rule struct {
	re   *regexp.Regexp
	repl string
}

// Redactor applies an ordered list of redaction rules.
type Redactor struct {
	rules      []rule
	secretKeys map[string]bool
}

var defaultKeyNames = []string{
	"password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token", "id_token",
	"api_key", "apikey", "api-key", "authorization", "auth", "credential", "credentials",
	"private_key", "client_secret", "session", "sessionid", "cookie", "set-cookie", "x-api-key",
	"aws_secret_access_key", "aws_session_token", "dsn", "connection_string", "passphrase",
}

var defaultPatterns = []rule{
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)[^\r\n,;]+`), "${1}${2}" + Placeholder},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`), Placeholder},
	{regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`), "$1 " + Placeholder},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`), Placeholder},
	{regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), Placeholder},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), Placeholder},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), Placeholder},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), Placeholder},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`), Placeholder},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), Placeholder},
	{regexp.MustCompile(`\bemx1_[a-z]_[A-Za-z0-9._-]+_[A-Za-z0-9._-]{8,}\b`), Placeholder},
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^:/@\s]+):([^@/\s]+)@`), "$1$2:" + Placeholder + "@"},
}

// Config customizes a Redactor.
type Config struct {
	// ExtraKeys are additional key names whose values are always redacted.
	ExtraKeys []string
	// ExtraPatterns are additional regular expressions whose matches are replaced.
	ExtraPatterns []string
}

// New builds a Redactor with the default rules plus cfg.
func New(cfg Config) (*Redactor, error) {
	r := &Redactor{secretKeys: map[string]bool{}}
	keys := append(append([]string(nil), defaultKeyNames...), cfg.ExtraKeys...)
	for _, k := range keys {
		r.secretKeys[strings.ToLower(k)] = true
	}
	r.rules = append(r.rules, defaultPatterns...)
	alt := make([]string, 0, len(keys))
	for _, k := range keys {
		alt = append(alt, regexp.QuoteMeta(k))
	}
	keyAlt := strings.Join(alt, "|")
	// key=value, key: value, "key":"value", key="value" forms.
	r.rules = append(r.rules,
		rule{regexp.MustCompile(`(?i)("(?:` + keyAlt + `)"\s*:\s*")([^"]*)(")`), "${1}" + Placeholder + "${3}"},
		rule{regexp.MustCompile(`(?i)\b((?:` + keyAlt + `)\s*[=:]\s*")([^"]*)(")`), "${1}" + Placeholder + "${3}"},
		rule{regexp.MustCompile(`(?i)\b((?:` + keyAlt + `)\s*[=:]\s*')([^']*)(')`), "${1}" + Placeholder + "${3}"},
		rule{regexp.MustCompile(`(?i)\b((?:` + keyAlt + `)\s*[=:]\s*)([^\s,;&"'}\]]+)`), "${1}" + Placeholder},
	)
	for _, p := range cfg.ExtraPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		r.rules = append(r.rules, rule{re, Placeholder})
	}
	return r, nil
}

var def, _ = New(Config{})

// Default returns the shared default Redactor.
func Default() *Redactor { return def }

// String redacts secret-looking values in s.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	for _, ru := range r.rules {
		s = ru.re.ReplaceAllString(s, ru.repl)
	}
	return s
}

// IsSecretKey reports whether a field or label name always holds a secret.
func (r *Redactor) IsSecretKey(key string) bool {
	k := strings.ToLower(key)
	if r.secretKeys[k] {
		return true
	}
	for s := range r.secretKeys {
		if len(s) > 4 && strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// KeyValue redacts value when key names a secret, and otherwise redacts patterns inside value.
func (r *Redactor) KeyValue(key, value string) string {
	if r.IsSecretKey(key) {
		return Placeholder
	}
	return r.String(value)
}

// Handler is a slog.Handler that redacts messages and string attributes before any sink.
type Handler struct {
	next slog.Handler
	r    *Redactor
}

// NewHandler wraps next.
func NewHandler(next slog.Handler, r *Redactor) *Handler {
	if r == nil {
		r = Default()
	}
	return &Handler{next: next, r: r}
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.String(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *Handler) attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.r.KeyValue(a.Key, v.String()))
	case slog.KindGroup:
		g := v.Group()
		out := make([]any, 0, len(g))
		for _, x := range g {
			out = append(out, h.attr(x))
		}
		return slog.Group(a.Key, out...)
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, h.r.String(err.Error()))
		}
		return slog.String(a.Key, h.r.KeyValue(a.Key, v.String()))
	default:
		if h.r.IsSecretKey(a.Key) {
			return slog.String(a.Key, Placeholder)
		}
		return slog.Attr{Key: a.Key, Value: v}
	}
}

func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(as))
	for i, a := range as {
		red[i] = h.attr(a)
	}
	return &Handler{next: h.next.WithAttrs(red), r: h.r}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name), r: h.r}
}
