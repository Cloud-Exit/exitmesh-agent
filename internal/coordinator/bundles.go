package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/client"
)

const distKey = "current"

type rejection struct {
	Version string    `json:"version"`
	Reason  string    `json:"reason"`
	Time    time.Time `json:"time"`
}

// bundleState holds the last known good bundle and the signed payload distributed to node agents.
type bundleState struct {
	store *bundle.Store
	ver   *bundle.Verifier
	dist  kv.Store
	pol   bundle.Policy
	vals  bundle.Validators

	mu       sync.Mutex
	active   *bundle.Active
	payload  *nodeapi.BundlePayload
	changed  chan struct{}
	rejected *rejection
	fetch    bool
	wake     chan struct{}
	airgapFP [32]byte
}

func newBundleState(s *bundle.Store, v *bundle.Verifier, dist kv.Store, pol bundle.Policy, vals bundle.Validators) *bundleState {
	return &bundleState{store: s, ver: v, dist: dist, pol: pol, vals: vals, changed: make(chan struct{}), fetch: true, wake: make(chan struct{}, 1)}
}

func (b *bundleState) current() (*bundle.Active, *nodeapi.BundlePayload, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.active, b.payload, b.changed
}

func (b *bundleState) version() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == nil {
		return ""
	}
	return b.active.Bundle.Manifest.Version
}

func (b *bundleState) meta(ruleID string) (bundle.RuleMeta, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == nil {
		return bundle.RuleMeta{}, false
	}
	for _, m := range b.active.Bundle.Manifest.Rules {
		if m.ID == ruleID {
			return m, true
		}
	}
	return bundle.RuleMeta{}, false
}

func (b *bundleState) set(a *bundle.Active, p *nodeapi.BundlePayload) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active, b.payload, b.rejected = a, p, nil
	close(b.changed)
	b.changed = make(chan struct{})
}

func (b *bundleState) reject(version string, err error, at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rejected = &rejection{Version: version, Reason: err.Error(), Time: at}
}

func (b *bundleState) want() {
	b.mu.Lock()
	b.fetch = true
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// loadBundle restores the last known good bundle and its distribution payload after a restart.
func (c *Coordinator) loadBundle() {
	b := c.bundles
	a, ok, err := b.store.LoadLastKnownGood(b.vals, b.pol)
	if err != nil {
		c.log.Warn("last known good bundle unavailable", "err", err)
		c.setErr("bundle", err)
		return
	}
	if !ok {
		return
	}
	var p *nodeapi.BundlePayload
	if raw, found, err := b.dist.Get(distKey); err == nil && found {
		var d nodeapi.BundlePayload
		if json.Unmarshal(raw, &d) == nil && d.Version == a.Bundle.Manifest.Version {
			p = &d
		}
	}
	if err := c.activate(a, p, false); err != nil {
		c.log.Warn("restore bundle", "err", err)
	}
}

// activate switches the engine to a verified bundle and publishes it to node agents.
func (c *Coordinator) activate(a *bundle.Active, p *nodeapi.BundlePayload, persist bool) error {
	if err := c.eng.SetBundle(a.Bundle, engine.BundleResult{Unsupported: a.Result.Unsupported}); err != nil {
		return err
	}
	if persist && p != nil {
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err := c.bundles.dist.Put(distKey, raw); err != nil {
			return err
		}
	}
	c.bundles.set(a, p)
	c.setErr("bundle", nil)
	c.log.Info("rule bundle active", "bundle_version", a.Bundle.Manifest.Version, "rules", len(a.Result.Active), "unsupported", len(a.Result.Unsupported))
	return nil
}

func (c *Coordinator) bundleLoop(ctx context.Context) {
	b := c.bundles
	var backoff time.Duration
	lastErr := ""
	for {
		if c.airgap {
			c.loadAirgapBundle()
		} else {
			b.mu.Lock()
			due := b.fetch
			b.mu.Unlock()
			if due && c.cl.Status().Connected {
				if err := c.fetchBundle(ctx); err == nil {
					b.mu.Lock()
					b.fetch = false
					b.mu.Unlock()
					backoff = 0
					if lastErr != "" {
						c.log.Info("bundle fetch recovered")
						lastErr = ""
					}
				} else if ctx.Err() == nil {
					backoff = min(max(2*backoff, c.t.HousekeepEvery), c.t.BundleEvery)
					// A control plane without a published bundle answers every retry the same way; say so once.
					if msg := err.Error(); msg != lastErr {
						c.log.Warn("bundle fetch failed; retrying with backoff", "err", err, "retry_in", backoff)
						lastErr = msg
					} else {
						c.log.Debug("bundle fetch failed", "err", err, "retry_in", backoff)
					}
				}
			}
		}
		wait := c.t.BundleEvery
		b.mu.Lock()
		if b.fetch && !c.airgap {
			wait = c.t.HousekeepEvery
			if backoff > 0 {
				wait = backoff
			}
		}
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
		case <-time.After(wait):
		}
	}
}

func (c *Coordinator) fetchBundle(ctx context.Context) error {
	b := c.bundles
	fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := c.cl.FetchBundle(fctx, b.version())
	if err != nil {
		if errors.Is(err, client.ErrNotConnected) {
			return err
		}
		c.setErr("bundle", err)
		return err
	}
	if res == nil || res.Version == "" || res.Version == b.version() {
		return nil
	}
	a, err := b.store.ActivateFetch(*res, b.vals, b.pol)
	if err != nil {
		c.rejectBundle(res.Version, err)
		return nil
	}
	p := &nodeapi.BundlePayload{Version: a.Bundle.Manifest.Version, Archive: res.Bundle, Signature: res.Signature, KeyManifest: res.KeyManifest, KeyManifestChain: res.KeyManifestChain}
	return c.activate(a, p, true)
}

func (c *Coordinator) rejectBundle(version string, err error) {
	c.log.Error("rule bundle rejected; the last known good bundle stays active", "version", version, "err", err)
	c.bundles.reject(version, err, c.now())
	c.setErr("bundle", err)
}

// loadAirgapBundle verifies the out-of-band bundle directory like tunnel delivery and activates a new version.
func (c *Coordinator) loadAirgapBundle() {
	b := c.bundles
	dir := c.cfg.AirGap.BundleDir
	fp, err := dirFingerprint(dir)
	if err != nil {
		c.setErr("bundle", err)
		return
	}
	b.mu.Lock()
	same := fp == b.airgapFP
	b.airgapFP = fp
	b.mu.Unlock()
	if same {
		return
	}
	archive, sig, err := b.ver.VerifyFiles(dir)
	if err != nil {
		c.rejectBundle(filepath.Base(dir), err)
		return
	}
	parsed, err := bundle.Parse(archive)
	if err != nil {
		c.rejectBundle(filepath.Base(dir), err)
		return
	}
	if parsed.Manifest.Version == b.version() {
		return
	}
	a, err := b.store.Activate(archive, sig, b.vals, b.pol)
	if err != nil {
		c.rejectBundle(parsed.Manifest.Version, err)
		return
	}
	man, chain, err := readManifests(dir)
	if err != nil {
		c.rejectBundle(parsed.Manifest.Version, err)
		return
	}
	p := &nodeapi.BundlePayload{Version: a.Bundle.Manifest.Version, Archive: archive, Signature: sig, KeyManifest: man, KeyManifestChain: chain}
	if err := c.activate(a, p, true); err != nil {
		c.rejectBundle(parsed.Manifest.Version, err)
	}
}

func dirFingerprint(dir string) ([32]byte, error) {
	h := sha256.New()
	names := []string{bundle.FileKeyManifest, bundle.FileArchive, bundle.FileSignature}
	if es, err := os.ReadDir(filepath.Join(dir, bundle.DirKeyManifestChain)); err == nil {
		for _, e := range es {
			names = append(names, filepath.Join(bundle.DirKeyManifestChain, e.Name()))
		}
	}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return [32]byte{}, err
		}
		fmt.Fprintf(h, "%s:%d:", n, len(b))
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// readManifests returns the key manifest and the ascending chain in the air-gap directory, forwarded to node agents.
func readManifests(dir string) ([]byte, [][]byte, error) {
	man, err := os.ReadFile(filepath.Join(dir, bundle.FileKeyManifest))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	type seqd struct {
		seq uint64
		b   []byte
	}
	var chain []seqd
	es, err := os.ReadDir(filepath.Join(dir, bundle.DirKeyManifestChain))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	for _, e := range es {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, bundle.DirKeyManifestChain, e.Name()))
		if err != nil {
			return nil, nil, err
		}
		_, m, err := bundle.ParseSignedManifest(b)
		if err != nil {
			return nil, nil, err
		}
		chain = append(chain, seqd{m.Sequence, b})
	}
	sort.SliceStable(chain, func(i, j int) bool { return chain[i].seq < chain[j].seq })
	out := make([][]byte, 0, len(chain))
	for _, s := range chain {
		if len(man) > 0 && bytes.Equal(s.b, man) {
			continue
		}
		out = append(out, s.b)
	}
	return man, out, nil
}

// bundleView reports the bundle and its convergence across node agents (PRD R5).
type bundleView struct {
	Target      string         `json:"target"`
	Coordinator string         `json:"coordinator"`
	State       string         `json:"state"`
	Versions    map[string]int `json:"versions"`
	Uncovered   []string       `json:"uncovered,omitempty"`
	Rejected    *rejection     `json:"rejected,omitempty"`
	KeySequence uint64         `json:"key_manifest_sequence"`
}

func (c *Coordinator) convergence() bundleView {
	b := c.bundles
	b.mu.Lock()
	v := bundleView{Rejected: b.rejected}
	if b.active != nil {
		v.Target = b.active.Bundle.Manifest.Version
	}
	b.mu.Unlock()
	v.KeySequence = b.ver.Sequence()
	v.Coordinator = c.eng.BundleVersion()
	v.Versions = map[string]int{}
	converged := v.Coordinator == v.Target
	for _, n := range c.nodes.list() {
		if !n.Covered {
			v.Uncovered = append(v.Uncovered, n.Name)
			continue
		}
		v.Versions[n.BundleVersion]++
		if n.BundleVersion != v.Target {
			converged = false
		}
	}
	v.State = "converging"
	if converged {
		v.State = "converged"
	}
	return v
}

func protocolBundleAvailable(p protocol.BundleAvailableParams) bool {
	return p.TargetType == "" || p.TargetType == protocol.TargetKubernetes
}
