package redact

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	r := Default()
	cases := map[string]string{
		`password=hunter2 user=bob`:                                            `password=<redacted> user=bob`,
		`{"token":"abc123","ok":true}`:                                         `{"token":"<redacted>","ok":true}`,
		`Authorization: Bearer abcdefghijklmnop`:                               `Authorization: <redacted>`,
		`dial postgres://app:s3cr3t@db:5432/x`:                                 `dial postgres://app:<redacted>@db:5432/x`,
		`key AKIAABCDEFGHIJKLMNOP used`:                                        `key <redacted> used`,
		`jwt eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl end`:                         `jwt <redacted> end`,
		`plain log line with nothing secret`:                                   `plain log line with nothing secret`,
		`api_key: 'x-y-z'`:                                                     `api_key: '<redacted>'`,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----": "<redacted>",
	}
	for in, want := range cases {
		if got := r.String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeyValue(t *testing.T) {
	r := Default()
	if r.KeyValue("DB_PASSWORD", "x") != Placeholder {
		t.Fatal("secret key not redacted")
	}
	if r.KeyValue("replicas", "3") != "3" {
		t.Fatal("plain value changed")
	}
}

func TestExtraPatterns(t *testing.T) {
	r, err := New(Config{ExtraPatterns: []string{`\bcust-[0-9]{4}\b`}})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.String("id cust-1234 ok"); got != "id <redacted> ok" {
		t.Fatal(got)
	}
	if _, err := New(Config{ExtraPatterns: []string{"("}}); err == nil {
		t.Fatal("bad pattern accepted")
	}
}

func TestHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewTextHandler(&buf, nil), nil))
	log.With("token", "abc").Info("connect password=hunter2", "err", errors.New("dial https://u:p4ss@h/"), "n", 3, "grp", slog.Group("g", "secret", "zzz"))
	out := buf.String()
	for _, leak := range []string{"hunter2", "abc", "p4ss", "zzz"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in %s", leak, out)
		}
	}
	if !strings.Contains(out, "n=3") {
		t.Fatal("non-secret attr lost")
	}
}
