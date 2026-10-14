package investigate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeObjects struct {
	objs  map[string]map[string]any
	err   error
	calls []string
}

func (f *fakeObjects) LiveObject(_ context.Context, kind, namespace, name string) (map[string]any, error) {
	key := kind + "/" + namespace + "/" + name
	f.calls = append(f.calls, key)
	return f.objs[key], f.err
}

func TestObjectGet(t *testing.T) {
	fo := &fakeObjects{objs: map[string]map[string]any{
		"Pod/shop/api-1":           {"kind": "Pod", "metadata": map[string]any{"uid": "u1", "name": "api-1"}, "spec": map[string]any{"nodeName": "n1"}},
		"Pod/other/db-1":           {"kind": "Pod", "metadata": map[string]any{"uid": "u2"}},
		"apps/Deployment/shop/api": {"kind": "Deployment", "metadata": map[string]any{"uid": "replaced"}},
	}}
	h := newHarness(t, func(o *Options) { o.Objects = fo })
	if len(h.svc.Tools()) != 9 {
		t.Fatalf("tools %d", len(h.svc.Tools()))
	}
	r := h.mustCall(t, ToolObject, args(t, map[string]any{"kind": "Pod", "namespace": "shop", "name": "api-1"}))
	d := r.Data.(map[string]any)
	if d["resource"].(StateResource).UID != "u1" || d["object"].(map[string]any)["kind"] != "Pod" || r.Source != sourceLive || r.Truncated {
		t.Fatalf("object %+v", r)
	}
	if r = h.mustCall(t, ToolObject, args(t, map[string]any{"uid": "u1"})); r.Data.(map[string]any)["object"] == nil {
		t.Fatalf("by uid %+v", r)
	}
	if a := h.audit[len(h.audit)-1]; a.Tool != ToolObject || a.Source != sourceLive || a.Outcome != OutcomeOK {
		t.Fatalf("audit %+v", a)
	}

	r = h.mustCall(t, ToolObject, args(t, map[string]any{"uid": "u1", "limits": map[string]any{"max_bytes": 10}}))
	if d := r.Data.(map[string]any); !r.Truncated || d["object"] != nil || !strings.Contains(joined(r), "object omitted") {
		t.Fatalf("max_bytes %+v", r)
	}
	r = h.mustCall(t, ToolObject, args(t, map[string]any{"uid": "u1", "window": win(time.Hour, 30*time.Minute)}))
	if !strings.Contains(joined(r), "not reconstructed") {
		t.Fatalf("window %v", r.Limitations)
	}

	n := len(fo.calls)
	for name, tc := range map[string]struct {
		a     map[string]any
		class string
	}{
		"outside scope": {map[string]any{"uid": "u2"}, ClassUnauthorized},
		"not in state":  {map[string]any{"kind": "Secret", "namespace": "shop", "name": "x"}, ClassUnauthorized},
		"no ref":        {map[string]any{}, ClassInvalid},
		"unknown field": {map[string]any{"uid": "u1", "path": "spec"}, ClassInvalid},
	} {
		if _, err := h.call(t, ToolObject, args(t, tc.a)); errClass(err) != tc.class {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(fo.calls) != n {
		t.Fatalf("rejected calls reached the API: %v", fo.calls[n:])
	}
	if _, err := h.call(t, ToolObject, args(t, map[string]any{"uid": "u3"})); errClass(err) != ClassUnavailable || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("replaced %v", err)
	}
	if _, err := h.call(t, ToolObject, args(t, map[string]any{"uid": "u5"})); errClass(err) != ClassUnavailable || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("missing %v", err)
	}
	fo.err = errors.New(`secrets is forbidden: token=abcdefgh`)
	if _, err := h.call(t, ToolObject, args(t, map[string]any{"uid": "u1"})); errClass(err) != ClassUnavailable || strings.Contains(err.Error(), "abcdefgh") {
		t.Fatalf("api error %v", err)
	}
}

func TestObjectGetNotAdvertisedWithoutSource(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.call(t, ToolObject, args(t, map[string]any{"uid": "u1"})); errClass(err) != ClassInvalid {
		t.Fatalf("got %v", err)
	}
}
