package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

// StatusPath serves the dev-only JSON status used by CI smoke tests.
const StatusPath = "/_refcp/status"

// trust is a generated deployment trust root with one signing key.
type trust struct {
	root     bundle.SigningKey
	signing  bundle.SigningKey
	manifest []byte
}

// newTrust generates keys and writes roots.txt (a trust.roots entry) and roots.json (for trust.rootsFile) to dir.
func newTrust(dir string, now time.Time) (*trust, error) {
	root, err := bundle.GenerateKey("refcp-root")
	if err != nil {
		return nil, err
	}
	signing, err := bundle.GenerateKey("refcp-signing")
	if err != nil {
		return nil, err
	}
	pub := signing.Public()
	m, err := bundle.NewKeyManifest(1, now, []bundle.ManifestKey{{ID: pub.ID, PublicKey: pub.PublicKey, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}}, nil)
	if err != nil {
		return nil, err
	}
	signed, err := bundle.SignManifest(m, root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	rp := root.Public()
	entry := rp.ID + ":" + base64.StdEncoding.EncodeToString(rp.PublicKey)
	if err := os.WriteFile(filepath.Join(dir, "roots.txt"), []byte(entry+"\n"), 0o644); err != nil {
		return nil, err
	}
	doc, err := json.Marshal(bundle.Roots{Keys: []bundle.RootKey{rp}})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "roots.json"), doc, 0o644); err != nil {
		return nil, err
	}
	return &trust{root: root, signing: signing, manifest: signed}, nil
}

// publish builds, signs, and publishes the bundle in dir for targetType.
func (t *trust) publish(cp *refcp.Server, targetType, dir string) (string, error) {
	archive, err := bundle.Build(dir)
	if err != nil {
		return "", err
	}
	b, err := bundle.Parse(archive)
	if err != nil {
		return "", err
	}
	if b.Manifest.TargetType != targetType {
		return "", fmt.Errorf("bundle in %s targets %q, not %q", dir, b.Manifest.TargetType, targetType)
	}
	sig, err := bundle.Sign(archive, t.signing)
	if err != nil {
		return "", err
	}
	return b.Manifest.Version, cp.PublishBundle(targetType, b.Manifest.Version, archive, sig, t.manifest)
}

type targetStatus struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	Epochs        []epochStatus   `json:"epochs"`
	Committed     int             `json:"committed"`
	Rejected      int             `json:"rejected"`
	Divergences   int             `json:"divergences"`
	Findings      int             `json:"findings"`
	HealthReports int             `json:"health_reports"`
	LastHealth    json.RawMessage `json:"last_health,omitempty"`
	Error         string          `json:"error,omitempty"`
}

type epochStatus struct {
	ID   string `json:"id"`
	Open bool   `json:"open"`
	Head uint64 `json:"head"`
}

// statusHandler reports progress of the targets this process created.
type statusHandler struct {
	cp      *refcp.Server
	mu      sync.Mutex
	targets []targetStatus
}

func (s *statusHandler) add(id, typ string) {
	s.mu.Lock()
	s.targets = append(s.targets, targetStatus{ID: id, Type: typ})
	s.mu.Unlock()
}

func (s *statusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	base := append([]targetStatus(nil), s.targets...)
	s.mu.Unlock()
	out := make([]targetStatus, 0, len(base))
	for _, t := range base {
		out = append(out, s.describe(t))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"targets": out})
}

func (s *statusHandler) describe(t targetStatus) targetStatus {
	eps, err := s.cp.Epochs(t.ID)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	for _, e := range eps {
		t.Epochs = append(t.Epochs, epochStatus{ID: e.ID.String(), Open: e.Open, Head: e.Head.Seq})
	}
	if st, err := s.cp.Stats(t.ID); err == nil {
		t.Committed, t.Rejected, t.Divergences = st.Committed, st.Rejected, st.Divergences
	}
	if fs, err := s.cp.Findings(t.ID); err == nil {
		t.Findings = len(fs)
	}
	if hs, err := s.cp.HealthReports(t.ID); err == nil {
		t.HealthReports = len(hs)
		if len(hs) > 0 {
			t.LastHealth = hs[len(hs)-1]
		}
	}
	return t
}

// withStatus serves StatusPath and passes every other request to the control plane.
func withStatus(cp http.Handler, st http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == StatusPath {
			st.ServeHTTP(w, r)
			return
		}
		cp.ServeHTTP(w, r)
	})
}
