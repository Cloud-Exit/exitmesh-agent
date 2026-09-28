package bundle

import (
	"errors"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func versioned(t *testing.T, version string, mutate func(map[string]string)) []byte {
	t.Helper()
	files := withFile(fixtureFiles(), "bundle.yaml", replaceIn(fixtureManifest, `version: "2026.09.1"`, `version: "`+version+`"`))
	if mutate != nil {
		mutate(files)
	}
	return buildFiles(t, files)
}

func TestStoreLastKnownGood(t *testing.T) {
	f := newTrust(t)
	s := NewStore(f.store, f.v, 0)
	if _, ok, err := s.LoadLastKnownGood(Validators{}, Policy{}); ok || err != nil {
		t.Fatalf("empty store: %v %v", ok, err)
	}
	v1 := versioned(t, "v1", nil)
	a, err := s.Activate(v1, sign(t, v1, f.signing), Validators{}, Policy{})
	if err != nil || a.Bundle.Manifest.Version != "v1" || a.KeyID != "sign-1" || len(a.Result.Active) != 3 {
		t.Fatalf("activate v1: %v", err)
	}

	bad := versioned(t, "v2", func(m map[string]string) {
		m["bundle.yaml"] = replaceIn(m["bundle.yaml"], "severity: high", "severity: nope")
	})
	if _, err := s.Activate(bad, sign(t, bad, f.signing), Validators{}, Policy{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid bundle: %v", err)
	}
	v2 := versioned(t, "v2", nil)
	other, _ := GenerateKey("sign-x")
	if _, err := s.Activate(v2, sign(t, v2, other), Validators{}, Policy{}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("untrusted bundle: %v", err)
	}
	if cur, _, _ := s.Current(); cur != "v1" {
		t.Fatalf("current after failures %q", cur)
	}

	restarted := NewStore(f.store, f.verifier(t), 0)
	lkg, ok, err := restarted.LoadLastKnownGood(Validators{}, Policy{})
	if err != nil || !ok || lkg.Bundle.Manifest.Version != "v1" || lkg.KeyID != "sign-1" {
		t.Fatalf("lkg after restart: %v", err)
	}

	if _, err := s.Activate(v2, sign(t, v2, f.signing), Validators{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	if cur, _, _ := s.Current(); cur != "v2" {
		t.Fatal("v2 not current")
	}
	rb, err := s.Rollback("v1", Validators{}, Policy{})
	if err != nil || rb.Bundle.Manifest.Version != "v1" {
		t.Fatalf("rollback: %v", err)
	}
	if cur, _, _ := s.Current(); cur != "v1" {
		t.Fatal("rollback not persisted")
	}
	if _, err := s.Rollback("v9", Validators{}, Policy{}); !errors.Is(err, ErrNotStored) {
		t.Fatal(err)
	}
	reused := versioned(t, "v2", func(m map[string]string) { m["state/pods.yaml"] = replaceIn(fixtureState, "for: 5m", "for: 6m") })
	if _, err := s.Activate(reused, sign(t, reused, f.signing), Validators{}, Policy{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("version reuse: %v", err)
	}
	if _, err := s.Activate(v2, sign(t, v2, f.signing), Validators{}, Policy{}); err != nil {
		t.Fatalf("idempotent re-activation: %v", err)
	}
	vs, err := s.Versions()
	if err != nil || len(vs) != 2 || vs[0].Version != "v1" || vs[0].Current || !vs[1].Current {
		t.Fatalf("versions %+v %v", vs, err)
	}
}

func TestStoreExpiryAndRevocation(t *testing.T) {
	f := newTrust(t)
	s := NewStore(f.store, f.v, 0)
	v1 := versioned(t, "v1", nil)
	if _, err := s.Activate(v1, sign(t, v1, f.signing), Validators{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	f.now = t0.Add(365 * 24 * time.Hour)
	if _, ok, err := s.LoadLastKnownGood(Validators{}, Policy{}); err != nil || !ok {
		t.Fatalf("expired signing key must not disable the last known good: %v", err)
	}
	k := f.window(f.signing, -time.Hour, 90*24*time.Hour)
	at := t0.Add(24 * time.Hour)
	k.RevokedAt = &at
	f.accept(t, 2, k)
	if _, _, err := s.LoadLastKnownGood(Validators{}, Policy{}); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("revoked key: %v", err)
	}
}

func TestStoreCorruptionAndPolicy(t *testing.T) {
	f := newTrust(t)
	s := NewStore(f.store, f.v, 0)
	v1 := versioned(t, "v1", nil)
	if _, err := s.Activate(v1, sign(t, v1, f.signing), Validators{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadLastKnownGood(Validators{}, Policy{TargetType: TargetHost}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("policy re-applied on load: %v", err)
	}
	if err := f.store.Put(keyVersions+"v1/archive", v1[:len(v1)-1]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadLastKnownGood(Validators{}, Policy{}); err == nil {
		t.Fatal("corrupt archive loaded")
	}
}

func TestStorePrunes(t *testing.T) {
	f := newTrust(t)
	s := NewStore(f.store, f.v, 2)
	for _, v := range []string{"v1", "v2", "v3"} {
		a := versioned(t, v, nil)
		if _, err := s.Activate(a, sign(t, a, f.signing), Validators{}, Policy{}); err != nil {
			t.Fatal(err)
		}
	}
	vs, _ := s.Versions()
	if len(vs) != 2 || vs[0].Version != "v2" || vs[1].Version != "v3" {
		t.Fatalf("%+v", vs)
	}
	if _, ok, _ := f.store.Get(keyVersions + "v1/archive"); ok {
		t.Fatal("pruned archive still stored")
	}
	if _, err := s.Rollback("v2", Validators{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	a := versioned(t, "v4", nil)
	if _, err := s.Activate(a, sign(t, a, f.signing), Validators{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	vs, _ = s.Versions()
	if len(vs) != 2 || vs[0].Version != "v3" || vs[1].Version != "v4" {
		t.Fatalf("%+v", vs)
	}
}

func TestStoreActivateFetch(t *testing.T) {
	f := newTrust(t)
	s := NewStore(f.store, f.v, 0)
	next, _ := GenerateKey("sign-2")
	v1 := versioned(t, "v1", nil)
	res := protocol.BundleFetchResult{Version: "v1", Bundle: v1, Signature: sign(t, v1, next), KeyManifest: f.signed(t, 2, f.window(next, -time.Hour, time.Hour))}
	if _, err := s.ActivateFetch(res, Validators{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	res.Version = "v7"
	if _, err := s.ActivateFetch(res, Validators{}, Policy{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("version mismatch accepted")
	}
	res.Version, res.KeyManifest = "v1", f.signed(t, 1, f.window(next, -time.Hour, time.Hour))
	if _, err := s.ActivateFetch(res, Validators{}, Policy{}); !errors.Is(err, ErrUntrusted) {
		t.Fatal("older manifest accepted over the tunnel")
	}
}
