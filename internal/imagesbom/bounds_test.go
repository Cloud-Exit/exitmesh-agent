package imagesbom

import (
	"reflect"
	"strings"
	"testing"
)

func TestBoundResult(t *testing.T) {
	original := Result{
		Status: StatusReady, Digest: "sha256:" + strings.Repeat("a", 64), Scanner: Scanner,
		Labels: Labels{Source: "https://github.com/example/app"},
		Packages: []Package{
			{Ecosystem: "npm", Name: "first", Version: "1.0.0", Location: "/a/package.json"},
			{Ecosystem: "npm", Name: "second", Version: "1.0.0", Location: "/b/package.json"},
		},
	}
	for _, tc := range []struct {
		name      string
		result    Result
		items     int
		bytes     int64
		truncated bool
	}{
		{name: "exact size", result: original, bytes: resultBytes(t, original)},
		{name: "item bound", result: original, items: 1, bytes: 1024, truncated: true},
		{name: "byte bound", result: original, bytes: 256, truncated: true},
		{name: "empty packages", result: Pending(original.Digest), bytes: 256},
		{name: "large labels", result: Result{Status: StatusReady, Digest: original.Digest, Scanner: Scanner, Packages: original.Packages, Labels: Labels{Source: strings.Repeat("x", 4096)}}, bytes: 256, truncated: true},
		{name: "large reason", result: Unavailable(original.Digest, strings.Repeat("x", 4096)), bytes: 256, truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Bound(tc.result, tc.items, tc.bytes)
			if err != nil {
				t.Fatal(err)
			}
			if res.Truncated != tc.truncated || (res.Truncated && res.Reason == "") || resultBytes(t, res) > tc.bytes || (tc.items > 0 && len(res.Packages) > tc.items) || res.Packages == nil {
				t.Fatalf("incorrect bound: bytes=%d packages=%d truncated=%v reason=%q", resultBytes(t, res), len(res.Packages), res.Truncated, res.Reason)
			}
			if !tc.truncated && !reflect.DeepEqual(res, tc.result) {
				t.Fatal("result changed within its limits")
			}
		})
	}
	if original.Truncated || original.Reason != "" || len(original.Packages) != 2 || original.Labels.Source == "" {
		t.Fatal("bounding changed the original inventory")
	}
	if _, err := Bound(original, 0, 1); err == nil {
		t.Fatal("unrepresentable byte bound accepted")
	}
}

func TestBoundPreservesBuildLimitationsAndJSONSize(t *testing.T) {
	original := Result{Status: StatusReady, Digest: "sha256:" + strings.Repeat("a", 64), Scanner: Scanner, Truncated: true, Reason: "Some layers are missing.",
		Packages: []Package{{Ecosystem: "npm", Name: "<first>\"", Version: "1.0.0"}, {Ecosystem: "npm", Name: "second", Version: "2.0.0"}}}
	res, err := Bound(original, 1, 1024)
	if err != nil || len(res.Packages) != 1 || !strings.Contains(res.Reason, original.Reason) || !strings.Contains(res.Reason, responseLimitReason) {
		t.Fatalf("build limitation lost: packages=%d reason=%q err=%v", len(res.Packages), res.Reason, err)
	}
	bound := resultBytes(t, res)
	res, err = Bound(original, 1, bound)
	if err != nil || len(res.Packages) != 1 || resultBytes(t, res) != bound {
		t.Fatalf("escaped JSON size counted incorrectly: bytes=%d limit=%d err=%v", resultBytes(t, res), bound, err)
	}
	res, err = Bound(original, 1, bound-1)
	if err != nil || len(res.Packages) != 0 || resultBytes(t, res) > bound-1 {
		t.Fatalf("escaped JSON exceeded byte bound: bytes=%d limit=%d err=%v", resultBytes(t, res), bound-1, err)
	}
}
