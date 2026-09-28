package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

func TestLoadRoots(t *testing.T) {
	if _, err := NewVerifier(Roots{}, kv.NewMemory()); !errors.Is(err, ErrNoRoots) {
		t.Fatal(err)
	}
	if _, err := LoadRoots("", nil, 0); !errors.Is(err, ErrNoRoots) || !strings.Contains(err.Error(), "trust.roots") {
		t.Fatalf("got %v", err)
	}
	a, _ := GenerateKey("a")
	b, _ := GenerateKey("b")
	file := filepath.Join(t.TempDir(), "roots.json")
	doc, _ := json.Marshal(Roots{Keys: []RootKey{a.Public()}})
	if err := os.WriteFile(file, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	inline := "b:" + base64.StdEncoding.EncodeToString(b.Public().PublicKey)
	r, err := LoadRoots(file, []string{inline}, 2)
	if err != nil || len(r.Keys) != 2 || r.Threshold != 2 {
		t.Fatalf("roots %+v %v", r, err)
	}
	for _, bad := range []string{"nocolon", "x:!!!", "y:" + base64.StdEncoding.EncodeToString([]byte("short")), inline} {
		if _, err := LoadRoots(file, []string{inline, bad}, 0); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := LoadRoots(file, nil, 3); err == nil {
		t.Fatal("threshold above key count accepted")
	}
}

func TestManifestChainFollowsRootRotation(t *testing.T) {
	f := newTrust(t)
	next, _ := GenerateKey("root-2")
	sk2, _ := GenerateKey("sign-2")
	m2, err := NewKeyManifest(2, t0, []ManifestKey{f.window(f.signing, -time.Hour, 90*24*time.Hour)},
		[]SuccessorRoot{{ID: next.ID, PublicKey: next.Public().PublicKey, NotBefore: t0.Add(-time.Minute)}})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := SignManifest(m2, f.root)
	if err != nil {
		t.Fatal(err)
	}
	m3, err := NewKeyManifest(3, t0, []ManifestKey{f.window(sk2, -time.Hour, 90*24*time.Hour)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := SignManifest(m3, next)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewVerifier(f.roots(), kv.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	fresh.SetClock(func() time.Time { return f.now })
	if _, err := fresh.AcceptManifest(s3); err == nil {
		t.Fatal("manifest signed by an unknown successor root accepted without the chain")
	}
	got, err := fresh.AcceptManifests(f.signed(t, 1, f.window(f.signing, -time.Hour, 90*24*time.Hour)), s2, s3)
	if err != nil || got.Sequence != 3 {
		t.Fatalf("chain: %v %+v", err, got)
	}
	if _, err := fresh.AcceptManifests(s2, s3); err != nil {
		t.Fatalf("replaying an older chain must be a no-op: %v", err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, DirKeyManifestChain), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, DirKeyManifestChain, "b.json"), s2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileKeyManifest), s3, 0o600); err != nil {
		t.Fatal(err)
	}
	archive := buildFiles(t, fixtureFiles())
	if err := os.WriteFile(filepath.Join(dir, FileArchive), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileSignature), sign(t, archive, sk2), 0o600); err != nil {
		t.Fatal(err)
	}
	airgap, _ := NewVerifier(f.roots(), kv.NewMemory())
	airgap.SetClock(func() time.Time { return f.now })
	if _, _, err := airgap.VerifyFiles(dir); err != nil {
		t.Fatalf("air-gap chain: %v", err)
	}
}

func TestParseRoots(t *testing.T) {
	k, _ := GenerateKey("r")
	good, _ := json.Marshal(Roots{Keys: []RootKey{k.Public()}})
	if r, err := ParseRoots(good); err != nil || len(r.Keys) != 1 {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"keys":[{"id":"a","public_key":"AAAA"}]}`,
		`{"keys":[],"extra":1}`,
		`{"threshold":2,"keys":[{"id":"a","public_key":"` + b64(k.Public().PublicKey) + `"}]}`,
	} {
		if _, err := ParseRoots([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func b64(b []byte) string {
	s, _ := json.Marshal(b)
	return strings.Trim(string(s), `"`)
}

func TestVerifyBundle(t *testing.T) {
	f := newTrust(t)
	a := buildFiles(t, fixtureFiles())
	if id, err := f.v.VerifyBundle(a, sign(t, a, f.signing)); err != nil || id != "sign-1" {
		t.Fatalf("%q %v", id, err)
	}
	other, _ := GenerateKey("sign-9")
	if _, err := f.v.VerifyBundle(a, sign(t, a, other)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("unknown key accepted")
	}
	impostor := SigningKey{ID: "sign-1", PrivateKey: other.PrivateKey}
	if _, err := f.v.VerifyBundle(a, sign(t, a, impostor)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("wrong key accepted")
	}
	tampered := append([]byte(nil), a...)
	tampered[len(tampered)/2] ^= 1
	if _, err := f.v.VerifyBundle(tampered, sign(t, a, f.signing)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("tampered archive accepted")
	}
	wrongDomain, _ := json.Marshal(Signature{KeyID: "sign-1", Signature: ed25519.Sign(f.signing.PrivateKey, domainDigest(DomainKeyManifest, a))})
	if _, err := f.v.VerifyBundle(a, wrongDomain); !errors.Is(err, ErrUntrusted) {
		t.Fatal("cross-domain signature accepted")
	}
	f.now = t0.Add(-2 * time.Hour)
	if _, err := f.v.VerifyBundle(a, sign(t, a, f.signing)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("key used before not_before")
	}
	fresh, _ := NewVerifier(f.roots(), kv.NewMemory())
	if _, err := fresh.VerifyBundle(a, sign(t, a, f.signing)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("accepted without a key manifest")
	}
}

func TestKeyRotationAndRevocation(t *testing.T) {
	f := newTrust(t)
	next, _ := GenerateKey("sign-2")
	old := f.window(f.signing, -time.Hour, 10*24*time.Hour)
	incoming := f.window(next, 5*24*time.Hour, 100*24*time.Hour)
	f.accept(t, 2, old, incoming)
	a := buildFiles(t, fixtureFiles())
	byOld, byNew := sign(t, a, f.signing), sign(t, a, next)

	f.now = t0.Add(time.Hour)
	if _, err := f.v.VerifyBundle(a, byNew); err == nil {
		t.Fatal("incoming key accepted before its window")
	}
	f.now = t0.Add(7 * 24 * time.Hour)
	for _, s := range [][]byte{byOld, byNew} {
		if _, err := f.v.VerifyBundle(a, s); err != nil {
			t.Fatalf("overlap: %v", err)
		}
	}
	f.now = t0.Add(11 * 24 * time.Hour)
	if _, err := f.v.VerifyBundle(a, byOld); !errors.Is(err, ErrUntrusted) {
		t.Fatal("expired key accepted")
	}

	f.now = t0.Add(7 * 24 * time.Hour)
	revokedAt := t0.Add(6 * 24 * time.Hour)
	old.RevokedAt = &revokedAt
	f.accept(t, 3, old, incoming)
	if _, err := f.v.VerifyBundle(a, byOld); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked key: %v", err)
	}
	if !f.v.KeyRevoked("sign-1") || f.v.KeyRevoked("sign-2") {
		t.Fatal("KeyRevoked")
	}
	if _, err := f.v.VerifyBundle(a, byNew); err != nil {
		t.Fatal(err)
	}
	f.accept(t, 4, incoming)
	if _, err := f.v.VerifyBundle(a, byOld); !errors.Is(err, ErrUntrusted) {
		t.Fatal("key absent from latest manifest accepted")
	}
}

func TestManifestSequence(t *testing.T) {
	f := newTrust(t)
	k := f.window(f.signing, -time.Hour, time.Hour)
	seq5 := f.signed(t, 5, k)
	if _, err := f.v.AcceptManifest(seq5); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.AcceptManifest(seq5); err != nil {
		t.Fatalf("re-delivery of the same manifest: %v", err)
	}
	other := f.signed(t, 5, f.window(f.signing, -time.Hour, 2*time.Hour))
	if _, err := f.v.AcceptManifest(other); !errors.Is(err, ErrUntrusted) {
		t.Fatal("equal sequence with different content accepted")
	}
	if _, err := f.v.AcceptManifest(f.signed(t, 4, k)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("older manifest accepted")
	}
	restarted := f.verifier(t)
	if restarted.Sequence() != 5 {
		t.Fatalf("sequence after restart %d", restarted.Sequence())
	}
	if _, err := restarted.AcceptManifest(f.signed(t, 3, k)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("older manifest accepted after restart")
	}
	if m, ok := restarted.Manifest(); !ok || m.Sequence != 5 {
		t.Fatal("latest manifest not restored")
	}
	stranger, _ := GenerateKey("root-x")
	m, _ := NewKeyManifest(9, t0, []ManifestKey{k}, nil)
	forged, _ := SignManifest(m, stranger)
	if _, err := restarted.AcceptManifest(forged); !errors.Is(err, ErrUntrusted) {
		t.Fatal("manifest signed by unknown root accepted")
	}
	var w SignedManifest
	_ = json.Unmarshal(f.signed(t, 9, k), &w)
	w.Manifest = []byte(strings.Replace(string(w.Manifest), `"sequence":9`, `"sequence":10`, 1))
	tampered, _ := json.Marshal(w)
	if _, err := restarted.AcceptManifest(tampered); !errors.Is(err, ErrUntrusted) {
		t.Fatal("tampered manifest accepted")
	}
}

func TestSuccessorRoots(t *testing.T) {
	f := newTrust(t)
	succ, _ := GenerateKey("root-2")
	k := f.window(f.signing, -time.Hour, 90*24*time.Hour)
	bySucc := func(seq uint64) []byte {
		m, _ := NewKeyManifest(seq, t0, []ManifestKey{k}, nil)
		b, _ := SignManifest(m, succ)
		return b
	}
	if _, err := f.v.AcceptManifest(bySucc(2)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("successor trusted before introduction")
	}
	m, _ := NewKeyManifest(2, t0, []ManifestKey{k}, []SuccessorRoot{{ID: succ.ID, PublicKey: succ.Public().PublicKey, NotBefore: t0.Add(24 * time.Hour)}})
	intro, _ := SignManifest(m, f.root)
	if _, err := f.v.AcceptManifest(intro); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.AcceptManifest(bySucc(3)); !errors.Is(err, ErrUntrusted) {
		t.Fatal("successor trusted before not_before")
	}
	f.now = t0.Add(25 * time.Hour)
	restarted := f.verifier(t)
	if _, err := restarted.AcceptManifest(bySucc(3)); err != nil {
		t.Fatalf("successor after restart: %v", err)
	}
	if len(restarted.TrustedRoots()) != 2 {
		t.Fatal("trusted roots")
	}
	evil, _ := GenerateKey("root-1")
	m4, _ := NewKeyManifest(4, t0, []ManifestKey{k}, []SuccessorRoot{{ID: "root-1", PublicKey: evil.Public().PublicKey}})
	conflict, _ := SignManifest(m4, succ)
	if _, err := restarted.AcceptManifest(conflict); !errors.Is(err, ErrUntrusted) {
		t.Fatal("conflicting successor accepted")
	}
}

func TestRootThreshold(t *testing.T) {
	r1, _ := GenerateKey("r1")
	r2, _ := GenerateKey("r2")
	sk, _ := GenerateKey("s")
	v, err := NewVerifier(Roots{Threshold: 2, Keys: []RootKey{r1.Public(), r2.Public()}}, kv.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := NewKeyManifest(1, t0, []ManifestKey{{ID: "s", PublicKey: sk.Public().PublicKey, NotBefore: t0, NotAfter: t0.Add(time.Hour)}}, nil)
	one, _ := SignManifest(m, r1, r1)
	if _, err := v.AcceptManifest(one); !errors.Is(err, ErrUntrusted) {
		t.Fatal("threshold not enforced")
	}
	two, _ := SignManifest(m, r1, r2)
	if _, err := v.AcceptManifest(two); err != nil {
		t.Fatal(err)
	}
}

func TestKeyManifestValidation(t *testing.T) {
	k, _ := GenerateKey("k")
	pub := k.Public().PublicKey
	for name, m := range map[string]*KeyManifest{
		"sequence": {IssuedAt: t0},
		"issued":   {Sequence: 1},
		"window":   {Sequence: 1, IssuedAt: t0, SigningKeys: []ManifestKey{{ID: "k", PublicKey: pub, NotBefore: t0, NotAfter: t0}}},
		"dup":      {Sequence: 1, IssuedAt: t0, SigningKeys: []ManifestKey{{ID: "k", PublicKey: pub, NotBefore: t0, NotAfter: t0.Add(1)}, {ID: "k", PublicKey: pub, NotBefore: t0, NotAfter: t0.Add(1)}}},
		"key":      {Sequence: 1, IssuedAt: t0, SigningKeys: []ManifestKey{{ID: "k", PublicKey: pub[:8], NotBefore: t0, NotAfter: t0.Add(1)}}},
		"root":     {Sequence: 1, IssuedAt: t0, SuccessorRoots: []SuccessorRoot{{ID: ""}}},
	} {
		if _, err := SignManifest(m, k); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseSigningKey([]byte(`{"id":"x","private_key":"AAAA"}`)); err == nil {
		t.Fatal("short private key accepted")
	}
	raw, _ := json.Marshal(k)
	if back, err := ParseSigningKey(raw); err != nil || !back.PrivateKey.Equal(k.PrivateKey) {
		t.Fatal(err)
	}
}

func TestVerifyFilesAirGap(t *testing.T) {
	f := newTrust(t)
	a := buildFiles(t, fixtureFiles())
	dir := t.TempDir()
	write := func(n string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	next, _ := GenerateKey("sign-2")
	write(FileArchive, a)
	write(FileSignature, sign(t, a, next))
	write(FileKeyManifest, f.signed(t, 2, f.window(next, -time.Hour, time.Hour)))
	got, sig, err := f.v.VerifyFiles(dir)
	if err != nil || string(got) != string(a) || len(sig) == 0 {
		t.Fatalf("verify files: %v", err)
	}
	if f.v.Sequence() != 2 {
		t.Fatal("out-of-band manifest not adopted")
	}
	write(FileKeyManifest, f.signed(t, 1, f.window(next, -time.Hour, time.Hour)))
	if _, _, err := f.v.VerifyFiles(dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal("older out-of-band manifest accepted")
	}
	if err := os.Remove(filepath.Join(dir, FileKeyManifest)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.v.VerifyFiles(dir); err != nil {
		t.Fatalf("without manifest file: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, FileSignature)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, FileArchive), filepath.Join(dir, FileSignature)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.v.VerifyFiles(dir); err == nil {
		t.Fatal("symlinked signature accepted")
	}
}
