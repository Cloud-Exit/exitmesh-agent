package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

// Signature domains (docs/bundle-format.md).
const (
	DomainKeyManifest = "EMBv1/keymanifest"
	DomainBundle      = "EMBv1/bundle"
)

// Air-gap file names.
const (
	FileArchive     = "bundle.tar.gz"
	FileSignature   = "bundle.sig"
	FileKeyManifest = "keymanifest.json"
)

const (
	maxManifestBytes  = 1 << 20
	maxSignatureBytes = 64 << 10
)

var (
	// ErrNoRoots means the agent has no trust root and verifies nothing.
	ErrNoRoots = errors.New("bundle: no trust roots configured: set trust.roots or trust.rootsFile to the root key set of your ExitMesh deployment (shown on its onboarding page next to the enrollment token), so no key manifest or bundle can be trusted until then")
	// ErrUntrusted wraps every signature and key manifest failure.
	ErrUntrusted = errors.New("bundle: untrusted")
)

func untrustedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUntrusted, fmt.Sprintf(format, args...))
}

// RootKey is a trusted root public key.
type RootKey struct {
	ID        string            `json:"id"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// Roots is the deployment's configured root key set; Threshold distinct root signatures are required (default 1).
type Roots struct {
	Threshold int       `json:"threshold,omitempty"`
	Keys      []RootKey `json:"keys"`
}

// ParseRoots decodes and checks a roots.json document.
func ParseRoots(b []byte) (Roots, error) {
	var r Roots
	if err := strictJSON(b, &r); err != nil {
		return r, fmt.Errorf("bundle: roots: %w", err)
	}
	ids := map[string]bool{}
	for _, k := range r.Keys {
		if k.ID == "" || ids[k.ID] || len(k.PublicKey) != ed25519.PublicKeySize {
			return r, fmt.Errorf("bundle: roots: invalid or duplicate root key %q", k.ID)
		}
		ids[k.ID] = true
	}
	if r.Threshold < 0 || (len(r.Keys) > 0 && r.Threshold > len(r.Keys)) {
		return r, fmt.Errorf("bundle: roots: threshold %d with %d keys", r.Threshold, len(r.Keys))
	}
	return r, nil
}

// LoadRoots builds the root key set from configuration: a roots file (ParseRoots format) and inline keys
// ("<id>:<base64 ed25519 public key>"), merged; an empty result is ErrNoRoots.
func LoadRoots(rootsFile string, inline []string, threshold int) (Roots, error) {
	var r Roots
	if rootsFile != "" {
		b, err := os.ReadFile(rootsFile)
		if err != nil {
			return r, fmt.Errorf("bundle: roots file: %w", err)
		}
		if r, err = ParseRoots(b); err != nil {
			return r, err
		}
	}
	for _, s := range inline {
		id, pub, ok := strings.Cut(strings.TrimSpace(s), ":")
		key, err := base64.StdEncoding.DecodeString(pub)
		if !ok || id == "" || err != nil || len(key) != ed25519.PublicKeySize {
			return r, fmt.Errorf("bundle: root key %q must be <id>:<base64 ed25519 public key>", s)
		}
		r.Keys = append(r.Keys, RootKey{ID: id, PublicKey: key})
	}
	if threshold != 0 {
		r.Threshold = threshold
	}
	if len(r.Keys) == 0 {
		return r, ErrNoRoots
	}
	b, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	return ParseRoots(b)
}

// ManifestKey is a bundle signing key with its validity window.
type ManifestKey struct {
	ID        string            `json:"id"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	NotBefore time.Time         `json:"not_before"`
	NotAfter  time.Time         `json:"not_after"`
	RevokedAt *time.Time        `json:"revoked_at,omitempty"`
}

// ValidAt reports whether the key may verify bundles at t.
func (k ManifestKey) ValidAt(t time.Time) bool {
	return !t.Before(k.NotBefore) && t.Before(k.NotAfter) && !k.RevokedBy(t)
}

// RevokedBy reports whether the key is revoked at t.
func (k ManifestKey) RevokedBy(t time.Time) bool {
	return k.RevokedAt != nil && !t.Before(*k.RevokedAt)
}

// SuccessorRoot is a root key introduced by a manifest signed by the current root set.
type SuccessorRoot struct {
	ID        string            `json:"id"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	NotBefore time.Time         `json:"not_before"`
}

// KeyManifest lists bundle signing keys and successor roots.
type KeyManifest struct {
	Sequence       uint64          `json:"sequence"`
	IssuedAt       time.Time       `json:"issued_at"`
	SigningKeys    []ManifestKey   `json:"signing_keys"`
	SuccessorRoots []SuccessorRoot `json:"successor_roots,omitempty"`
}

// Signature is one signature over a domain-separated digest.
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

// SignedManifest carries the exact manifest bytes and root signatures.
type SignedManifest struct {
	Manifest   []byte      `json:"manifest"`
	Signatures []Signature `json:"signatures"`
}

// SigningKey is a private ed25519 key with its identifier.
type SigningKey struct {
	ID         string             `json:"id"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
}

// GenerateKey creates a new signing or root key.
func GenerateKey(id string) (SigningKey, error) {
	if id == "" {
		return SigningKey{}, errors.New("bundle: key id is required")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{ID: id, PrivateKey: priv}, nil
}

// ParseSigningKey decodes a private key file.
func ParseSigningKey(b []byte) (SigningKey, error) {
	var k SigningKey
	if err := strictJSON(b, &k); err != nil {
		return k, fmt.Errorf("bundle: signing key: %w", err)
	}
	if k.ID == "" || len(k.PrivateKey) != ed25519.PrivateKeySize {
		return k, errors.New("bundle: signing key: id and a 64-byte ed25519 private key are required")
	}
	return k, nil
}

// Public returns the public half.
func (k SigningKey) Public() RootKey {
	return RootKey{ID: k.ID, PublicKey: k.PrivateKey.Public().(ed25519.PublicKey)}
}

// NewKeyManifest builds and checks a key manifest.
func NewKeyManifest(sequence uint64, issuedAt time.Time, keys []ManifestKey, successors []SuccessorRoot) (*KeyManifest, error) {
	m := &KeyManifest{Sequence: sequence, IssuedAt: issuedAt.UTC(), SigningKeys: keys, SuccessorRoots: successors}
	return m, m.Validate()
}

// Validate checks manifest structure.
func (m *KeyManifest) Validate() error {
	if m.Sequence == 0 {
		return errors.New("bundle: key manifest sequence must be at least 1")
	}
	if m.IssuedAt.IsZero() {
		return errors.New("bundle: key manifest issued_at is required")
	}
	ids := map[string]bool{}
	for _, k := range m.SigningKeys {
		if k.ID == "" || ids[k.ID] || len(k.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("bundle: key manifest: invalid or duplicate signing key %q", k.ID)
		}
		if !k.NotBefore.Before(k.NotAfter) {
			return fmt.Errorf("bundle: key manifest: signing key %q has an empty validity window", k.ID)
		}
		ids[k.ID] = true
	}
	roots := map[string]bool{}
	for _, r := range m.SuccessorRoots {
		if r.ID == "" || roots[r.ID] || len(r.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("bundle: key manifest: invalid or duplicate successor root %q", r.ID)
		}
		roots[r.ID] = true
	}
	return nil
}

// Key returns the signing key with id.
func (m *KeyManifest) Key(id string) (ManifestKey, bool) {
	for _, k := range m.SigningKeys {
		if k.ID == id {
			return k, true
		}
	}
	return ManifestKey{}, false
}

func domainDigest(domain string, b []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(b)
	return h.Sum(nil)
}

// SignManifest signs a manifest with one or more root keys.
func SignManifest(m *KeyManifest, roots ...SigningKey) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, errors.New("bundle: at least one root key is required")
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	d := domainDigest(DomainKeyManifest, body)
	sm := SignedManifest{Manifest: body}
	for _, r := range roots {
		sm.Signatures = append(sm.Signatures, Signature{KeyID: r.ID, Signature: ed25519.Sign(r.PrivateKey, d)})
	}
	return json.MarshalIndent(sm, "", "  ")
}

// ParseSignedManifest decodes the wrapper and the manifest without verifying signatures.
func ParseSignedManifest(b []byte) (*SignedManifest, *KeyManifest, error) {
	if len(b) > maxManifestBytes {
		return nil, nil, untrustedf("key manifest exceeds %d bytes", maxManifestBytes)
	}
	var sm SignedManifest
	if err := strictJSON(b, &sm); err != nil {
		return nil, nil, untrustedf("key manifest wrapper: %v", err)
	}
	var m KeyManifest
	if err := strictJSON(sm.Manifest, &m); err != nil {
		return nil, nil, untrustedf("key manifest: %v", err)
	}
	if err := m.Validate(); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrUntrusted, err)
	}
	return &sm, &m, nil
}

// Sign signs a bundle archive and returns the signature document.
func Sign(archive []byte, key SigningKey) ([]byte, error) {
	if key.ID == "" || len(key.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("bundle: invalid signing key")
	}
	return json.MarshalIndent(Signature{KeyID: key.ID, Signature: ed25519.Sign(key.PrivateKey, domainDigest(DomainBundle, archive))}, "", "  ")
}

// ParseSignature decodes a bundle signature document.
func ParseSignature(b []byte) (Signature, error) {
	var s Signature
	if len(b) > maxSignatureBytes {
		return s, untrustedf("signature exceeds %d bytes", maxSignatureBytes)
	}
	if err := strictJSON(b, &s); err != nil {
		return s, untrustedf("signature: %v", err)
	}
	if s.KeyID == "" || len(s.Signature) != ed25519.SignatureSize {
		return s, untrustedf("signature needs a key id and a 64-byte ed25519 signature")
	}
	return s, nil
}

func strictJSON(b []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

const (
	keyTrustState = "trust/state"
	keyRootPrefix = "trust/root/"
)

type trustState struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
	Manifest []byte `json:"manifest"`
}

// Verifier holds the trust state: pinned roots, adopted successor roots, and the latest verified key manifest.
type Verifier struct {
	mu      sync.Mutex
	pinned  Roots
	store   kv.Store
	now     func() time.Time
	adopted map[string]SuccessorRoot
	state   trustState
	latest  *KeyManifest
}

// NewVerifier returns a Verifier over roots, loading persisted trust state from store.
func NewVerifier(roots Roots, store kv.Store) (*Verifier, error) {
	if len(roots.Keys) == 0 {
		return nil, ErrNoRoots
	}
	if roots.Threshold == 0 {
		roots.Threshold = 1
	}
	v := &Verifier{pinned: roots, store: store, now: time.Now, adopted: map[string]SuccessorRoot{}}
	raw, ok, err := store.Get(keyTrustState)
	if err != nil {
		return nil, err
	}
	if ok {
		if err := json.Unmarshal(raw, &v.state); err != nil {
			return nil, fmt.Errorf("bundle: trust state: %w", err)
		}
		w, m, err := ParseSignedManifest(v.state.Manifest)
		if err != nil {
			return nil, fmt.Errorf("bundle: trust state: %w", err)
		}
		if hex.EncodeToString(domainDigest(DomainKeyManifest, w.Manifest)) != v.state.Digest || m.Sequence != v.state.Sequence {
			return nil, errors.New("bundle: trust state: stored manifest does not match its digest")
		}
		v.latest = m
	}
	err = store.ForEach(keyRootPrefix, func(_ string, val []byte) error {
		var r SuccessorRoot
		if err := json.Unmarshal(val, &r); err != nil {
			return err
		}
		v.adopted[r.ID] = r
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bundle: adopted roots: %w", err)
	}
	return v, nil
}

// SetClock replaces the clock used for validity windows.
func (v *Verifier) SetClock(now func() time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.now = now
}

// Sequence returns the highest verified manifest sequence (0 when none).
func (v *Verifier) Sequence() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state.Sequence
}

// Manifest returns the latest verified key manifest.
func (v *Verifier) Manifest() (*KeyManifest, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.latest, v.latest != nil
}

// TrustedRoots returns the pinned roots followed by adopted successor roots, sorted by id.
func (v *Verifier) TrustedRoots() []RootKey {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := append([]RootKey(nil), v.pinned.Keys...)
	ids := make([]string, 0, len(v.adopted))
	for id := range v.adopted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, RootKey{ID: id, PublicKey: v.adopted[id].PublicKey})
	}
	return out
}

func (v *Verifier) rootKey(id string, now time.Time) (ed25519.PublicKey, bool) {
	for _, k := range v.pinned.Keys {
		if k.ID == id {
			return k.PublicKey, true
		}
	}
	if r, ok := v.adopted[id]; ok && !now.Before(r.NotBefore) {
		return r.PublicKey, true
	}
	return nil, false
}

// AcceptManifests accepts a chain of signed key manifests in ascending sequence, skipping ones older than
// the verified sequence, and returns the latest verified manifest (nil when none is known).
func (v *Verifier) AcceptManifests(chain ...[]byte) (*KeyManifest, error) {
	for _, signed := range chain {
		if len(signed) == 0 {
			continue
		}
		_, m, err := ParseSignedManifest(signed)
		if err != nil {
			return nil, err
		}
		if m.Sequence < v.Sequence() {
			continue
		}
		if _, err := v.AcceptManifest(signed); err != nil {
			return nil, err
		}
	}
	m, _ := v.Manifest()
	return m, nil
}

// AcceptManifest verifies a signed key manifest against the current roots and persists it if it advances.
func (v *Verifier) AcceptManifest(signed []byte) (*KeyManifest, error) {
	w, m, err := ParseSignedManifest(signed)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	d := domainDigest(DomainKeyManifest, w.Manifest)
	valid := map[string]bool{}
	for _, s := range w.Signatures {
		pub, ok := v.rootKey(s.KeyID, now)
		if ok && ed25519.Verify(pub, d, s.Signature) {
			valid[s.KeyID] = true
		}
	}
	if len(valid) < v.pinned.Threshold {
		return nil, untrustedf("key manifest sequence %d has %d valid root signature(s), %d required", m.Sequence, len(valid), v.pinned.Threshold)
	}
	digest := hex.EncodeToString(d)
	switch {
	case m.Sequence < v.state.Sequence:
		return nil, untrustedf("key manifest sequence %d is older than verified sequence %d", m.Sequence, v.state.Sequence)
	case m.Sequence == v.state.Sequence && digest != v.state.Digest:
		return nil, untrustedf("key manifest sequence %d differs from the verified manifest with the same sequence", m.Sequence)
	case m.Sequence == v.state.Sequence:
		return v.latest, nil
	}
	ops := map[string][]byte{}
	adopt := map[string]SuccessorRoot{}
	for _, r := range m.SuccessorRoots {
		if pub, ok := v.knownRoot(r.ID); ok {
			if !bytes.Equal(pub, r.PublicKey) {
				return nil, untrustedf("successor root %q conflicts with a trusted root of the same id", r.ID)
			}
			continue
		}
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		ops[keyRootPrefix+r.ID] = b
		adopt[r.ID] = r
	}
	st := trustState{Sequence: m.Sequence, Digest: digest, Manifest: append([]byte(nil), signed...)}
	b, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	ops[keyTrustState] = b
	if err := v.store.Batch(ops); err != nil {
		return nil, fmt.Errorf("bundle: persist key manifest: %w", err)
	}
	for id, r := range adopt {
		v.adopted[id] = r
	}
	v.state, v.latest = st, m
	return m, nil
}

func (v *Verifier) knownRoot(id string) (ed25519.PublicKey, bool) {
	for _, k := range v.pinned.Keys {
		if k.ID == id {
			return k.PublicKey, true
		}
	}
	r, ok := v.adopted[id]
	return r.PublicKey, ok
}

// VerifyBundle checks a bundle signature against the latest verified key manifest and returns the key id.
func (v *Verifier) VerifyBundle(archive, signature []byte) (string, error) {
	s, err := ParseSignature(signature)
	if err != nil {
		return "", err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.latest == nil {
		return "", untrustedf("no verified key manifest")
	}
	k, ok := v.latest.Key(s.KeyID)
	if !ok {
		return "", untrustedf("signing key %q is not in the verified key manifest (sequence %d)", s.KeyID, v.latest.Sequence)
	}
	now := v.now()
	if k.RevokedBy(now) {
		return "", untrustedf("signing key %q is revoked", s.KeyID)
	}
	if !k.ValidAt(now) {
		return "", untrustedf("signing key %q is outside its validity window [%s, %s)", s.KeyID, k.NotBefore.Format(time.RFC3339), k.NotAfter.Format(time.RFC3339))
	}
	if !ed25519.Verify(k.PublicKey, domainDigest(DomainBundle, archive), s.Signature) {
		return "", untrustedf("bundle signature by %q does not verify", s.KeyID)
	}
	return s.KeyID, nil
}

// KeyRevoked reports whether the latest verified manifest revokes keyID now.
func (v *Verifier) KeyRevoked(keyID string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.latest == nil {
		return false
	}
	k, ok := v.latest.Key(keyID)
	return ok && k.RevokedBy(v.now())
}

// VerifyFiles verifies an air-gap directory (optional keymanifests/*.json chain, keymanifest.json,
// bundle.tar.gz, bundle.sig) like tunnel delivery.
func (v *Verifier) VerifyFiles(dir string) (archive, signature []byte, err error) {
	chainDir := filepath.Join(dir, DirKeyManifestChain)
	names, err := os.ReadDir(chainDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	var chain [][]byte
	for _, e := range names {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, ok, err := readRegular(filepath.Join(chainDir, e.Name()), maxManifestBytes)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			chain = append(chain, b)
		}
	}
	sort.SliceStable(chain, func(i, j int) bool { return manifestSeq(chain[i]) < manifestSeq(chain[j]) })
	if _, err := v.AcceptManifests(chain...); err != nil {
		return nil, nil, err
	}
	man, ok, err := readRegular(filepath.Join(dir, FileKeyManifest), maxManifestBytes)
	if err != nil {
		return nil, nil, err
	}
	if ok {
		if _, err := v.AcceptManifest(man); err != nil {
			return nil, nil, err
		}
	}
	archive, ok, err = readRegular(filepath.Join(dir, FileArchive), MaxArchiveBytes)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("bundle: %s not found in %s", FileArchive, dir)
	}
	signature, ok, err = readRegular(filepath.Join(dir, FileSignature), maxSignatureBytes)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("bundle: %s not found in %s", FileSignature, dir)
	}
	if _, err := v.VerifyBundle(archive, signature); err != nil {
		return nil, nil, err
	}
	return archive, signature, nil
}

func readRegular(p string, limit int64) ([]byte, bool, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("bundle: %s is not a regular file", p)
	}
	if fi.Size() > limit {
		return nil, false, fmt.Errorf("bundle: %s exceeds %d bytes", p, limit)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > limit {
		return nil, false, fmt.Errorf("bundle: %s exceeds %d bytes", p, limit)
	}
	return b, true, nil
}

func (v *Verifier) clock() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.now()
}

// DirKeyManifestChain is the air-gap subdirectory holding earlier key manifests.
const DirKeyManifestChain = "keymanifests"

func manifestSeq(b []byte) uint64 {
	if _, m, err := ParseSignedManifest(b); err == nil {
		return m.Sequence
	}
	return 0
}
