package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// DefaultKeepVersions is how many verified versions the store retains for rollback.
const DefaultKeepVersions = 5

const (
	keyCurrent  = "lkg/current"
	keyVersions = "lkg/v/"
	keyOrder    = "lkg/order"
)

// Active is a verified, validated bundle ready to activate between evaluation cycles.
type Active struct {
	Bundle *Bundle
	Result Result
	KeyID  string
}

// StoredVersion describes one retained bundle version.
type StoredVersion struct {
	Version  string    `json:"version"`
	Digest   string    `json:"digest"`
	KeyID    string    `json:"key_id"`
	StoredAt time.Time `json:"stored_at"`
	Order    uint64    `json:"order"`
	Current  bool      `json:"-"`
}

// Store keeps the last known good bundle and prior versions for rollback.
type Store struct {
	mu   sync.Mutex
	kv   kv.Store
	v    *Verifier
	keep int
}

// NewStore returns a Store; keep <= 0 uses DefaultKeepVersions.
func NewStore(s kv.Store, v *Verifier, keep int) *Store {
	if keep <= 0 {
		keep = DefaultKeepVersions
	}
	return &Store{kv: s, v: v, keep: keep}
}

// Activate verifies and validates a bundle and makes it the last known good; on failure nothing changes.
func (s *Store) Activate(archive, signature []byte, vals Validators, pol Policy) (*Active, error) {
	return s.activate(archive, signature, "", vals, pol)
}

func (s *Store) activate(archive, signature []byte, want string, vals Validators, pol Policy) (*Active, error) {
	keyID, err := s.v.VerifyBundle(archive, signature)
	if err != nil {
		return nil, err
	}
	a, err := load(archive, vals, pol)
	if err != nil {
		return nil, err
	}
	if want != "" && want != a.Bundle.Manifest.Version {
		return nil, invalidf("fetched version %q carries bundle version %q", want, a.Bundle.Manifest.Version)
	}
	a.KeyID = keyID
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store(a, archive, signature); err != nil {
		return nil, err
	}
	return a, nil
}

// ActivateFetch accepts the key manifest of a bundle.fetch result, then activates its bundle.
func (s *Store) ActivateFetch(res protocol.BundleFetchResult, vals Validators, pol Policy) (*Active, error) {
	if _, err := s.v.AcceptManifests(res.KeyManifestChain...); err != nil {
		return nil, err
	}
	if len(res.KeyManifest) > 0 {
		if _, err := s.v.AcceptManifest(res.KeyManifest); err != nil {
			return nil, err
		}
	}
	return s.activate(res.Bundle, res.Signature, res.Version, vals, pol)
}

func load(archive []byte, vals Validators, pol Policy) (*Active, error) {
	b, err := Parse(archive)
	if err != nil {
		return nil, err
	}
	r, err := Validate(b, vals, pol)
	if err != nil {
		return nil, err
	}
	return &Active{Bundle: b, Result: r}, nil
}

func (s *Store) store(a *Active, archive, signature []byte) error {
	ver := a.Bundle.Manifest.Version
	digest := hex.EncodeToString(a.Bundle.Digest[:])
	prev, ok, err := s.meta(ver)
	if err != nil {
		return err
	}
	if ok && prev.Digest != digest {
		return invalidf("version %q is already stored with different content", ver)
	}
	ops := map[string][]byte{keyCurrent: []byte(ver)}
	if !ok {
		order, err := s.nextOrder()
		if err != nil {
			return err
		}
		m := StoredVersion{Version: ver, Digest: digest, KeyID: a.KeyID, StoredAt: s.v.clock().UTC(), Order: order}
		mb, err := json.Marshal(m)
		if err != nil {
			return err
		}
		ob, err := json.Marshal(order)
		if err != nil {
			return err
		}
		ops[keyVersions+ver+"/meta"] = mb
		ops[keyVersions+ver+"/archive"] = archive
		ops[keyVersions+ver+"/sig"] = signature
		ops[keyOrder] = ob
	}
	if err := s.kv.Batch(ops); err != nil {
		return fmt.Errorf("bundle: persist last known good: %w", err)
	}
	return s.prune(ver)
}

func (s *Store) nextOrder() (uint64, error) {
	raw, ok, err := s.kv.Get(keyOrder)
	if err != nil || !ok {
		return 1, err
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n + 1, nil
}

func (s *Store) meta(ver string) (StoredVersion, bool, error) {
	var m StoredVersion
	raw, ok, err := s.kv.Get(keyVersions + ver + "/meta")
	if err != nil || !ok {
		return m, false, err
	}
	return m, true, json.Unmarshal(raw, &m)
}

func (s *Store) prune(current string) error {
	vs, err := s.versions()
	if err != nil {
		return err
	}
	if len(vs) <= s.keep {
		return nil
	}
	ops := map[string][]byte{}
	for _, v := range vs[:len(vs)-s.keep] {
		if v.Version == current {
			continue
		}
		for _, suffix := range []string{"/meta", "/archive", "/sig"} {
			ops[keyVersions+v.Version+suffix] = nil
		}
	}
	return s.kv.Batch(ops)
}

func (s *Store) versions() ([]StoredVersion, error) {
	var out []StoredVersion
	err := s.kv.ForEach(keyVersions, func(k string, v []byte) error {
		if len(k) < 5 || k[len(k)-5:] != "/meta" {
			return nil
		}
		var m StoredVersion
		if err := json.Unmarshal(v, &m); err != nil {
			return err
		}
		out = append(out, m)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out, err
}

// Versions lists retained versions, oldest first.
func (s *Store) Versions() ([]StoredVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vs, err := s.versions()
	if err != nil {
		return nil, err
	}
	cur, _, err := s.kv.Get(keyCurrent)
	if err != nil {
		return nil, err
	}
	for i := range vs {
		vs[i].Current = vs[i].Version == string(cur)
	}
	return vs, nil
}

// Current returns the last known good version.
func (s *Store) Current() (string, bool, error) {
	cur, ok, err := s.kv.Get(keyCurrent)
	return string(cur), ok, err
}

// LoadLastKnownGood reloads the current version; key expiry is not re-checked, revocation is.
func (s *Store) LoadLastKnownGood(vals Validators, pol Policy) (*Active, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok, err := s.kv.Get(keyCurrent)
	if err != nil || !ok {
		return nil, false, err
	}
	a, err := s.loadStored(string(cur), vals, pol)
	if err != nil {
		return nil, false, err
	}
	return a, true, nil
}

// Rollback makes a retained version current again.
func (s *Store) Rollback(version string, vals Validators, pol Policy) (*Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.loadStored(version, vals, pol)
	if err != nil {
		return nil, err
	}
	if err := s.kv.Put(keyCurrent, []byte(version)); err != nil {
		return nil, fmt.Errorf("bundle: persist rollback: %w", err)
	}
	return a, nil
}

// ErrNotStored means the requested version is not retained.
var ErrNotStored = errors.New("bundle: version is not stored")

func (s *Store) loadStored(ver string, vals Validators, pol Policy) (*Active, error) {
	m, ok, err := s.meta(ver)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotStored, ver)
	}
	archive, ok, err := s.kv.Get(keyVersions + ver + "/archive")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(archive)
	if !ok || hex.EncodeToString(sum[:]) != m.Digest {
		return nil, fmt.Errorf("bundle: stored version %q is corrupt", ver)
	}
	if s.v.KeyRevoked(m.KeyID) {
		return nil, untrustedf("stored version %q was signed by revoked key %q", ver, m.KeyID)
	}
	a, err := load(archive, vals, pol)
	if err != nil {
		return nil, err
	}
	a.KeyID = m.KeyID
	return a, nil
}
