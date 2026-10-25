package imagesbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

const responseLimitReason = "Image inventory result was truncated by its response limits."

// Bound preserves a package prefix without changing the cached inventory.
func Bound(r Result, maxPackages int, maxBytes int64) (Result, error) {
	if r.Packages == nil {
		r.Packages = []Package{}
	}
	count := len(r.Packages)
	if maxPackages > 0 && count > maxPackages {
		r.Packages = r.Packages[:maxPackages]
	}
	base := resultBaseBytes(r)
	keep := fittingPackages(r.Packages, maxBytes-base)
	if base <= maxBytes && keep == count {
		return r, nil
	}
	r.Truncated = true
	if !strings.Contains(r.Reason, responseLimitReason) {
		r.Reason = strings.TrimSpace(r.Reason + " " + responseLimitReason)
	}
	if resultBaseBytes(r) > maxBytes {
		r.Labels = Labels{}
	}
	if resultBaseBytes(r) > maxBytes {
		r.Reason = responseLimitReason
	}
	base = resultBaseBytes(r)
	if base > maxBytes {
		return Result{}, fmt.Errorf("max_bytes %d cannot hold an image inventory response", maxBytes)
	}
	r.Packages = r.Packages[:fittingPackages(r.Packages, maxBytes-base)]
	return r, nil
}

func resultBaseBytes(r Result) int64 {
	r.Packages = []Package{}
	b, _ := json.Marshal(r)
	return int64(len(b))
}

func fittingPackages(packages []Package, remaining int64) int {
	for i, p := range packages {
		b, _ := json.Marshal(p)
		size := int64(len(b))
		if i > 0 {
			size++
		}
		if size > remaining {
			return i
		}
		remaining -= size
	}
	return len(packages)
}
