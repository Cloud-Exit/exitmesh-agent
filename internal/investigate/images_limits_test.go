package investigate

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/imagesbom"
)

func TestImageSBOMResultLimits(t *testing.T) {
	d := imgDigest('a')
	r := readyResult(d, false)
	r.Labels = imagesbom.Labels{}
	r.Packages = append(r.Packages, imagesbom.Package{Ecosystem: "npm", Name: "second", Version: "1.2.3"})
	nodes := &imageNodes{answers: map[string]map[string]imagesbom.Result{"n1": {d: r}}}
	for _, tc := range []struct {
		name string
		max  config.Investigation
		lim  Limits
	}{
		{name: "requested items", lim: Limits{MaxLines: 1}},
		{name: "requested bytes", lim: Limits{MaxBytes: 256}},
		{name: "configured items", max: config.Investigation{MaxLines: 1}},
		{name: "configured bytes", max: config.Investigation{MaxBytes: 256}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var audit AuditRecord
			svc, err := NewService(Options{Role: RoleCoordinator, State: imageState, Nodes: nodes, ImageInventory: true, Limits: tc.max, Audit: func(r AuditRecord) { audit = r }})
			if err != nil {
				t.Fatal(err)
			}
			res, _ := callImage(t, svc, map[string]any{"digest": d, "limits": tc.lim})
			b, _ := json.Marshal(res)
			lim, _ := clampLimits(tc.lim, defaultLimits(tc.max))
			if !res.Truncated || res.Reason == "" || len(res.Packages) > lim.MaxLines || int64(len(b)) > lim.MaxBytes {
				t.Fatalf("result escaped limits: bytes=%d packages=%d truncated=%v reason=%q", len(b), len(res.Packages), res.Truncated, res.Reason)
			}
			if !audit.Truncated || audit.Outcome != OutcomeLimited {
				t.Fatalf("truncation not audited: %+v", audit)
			}
		})
	}
	svc, _ := newImageService(t, nodes)
	raw, _ := json.Marshal(map[string]any{"digest": d, "limits": Limits{MaxBytes: 1}})
	if _, err := svc.Call(context.Background(), ToolImageSBOM, raw); errClass(err) != ClassInvalid {
		t.Fatalf("unrepresentable byte limit should be rejected, got %v", err)
	}
}
