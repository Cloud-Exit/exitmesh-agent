package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/admin"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/engine"
	"github.com/cloud-exit/exitmesh-agent/internal/spool"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

func TestBundleActivationInvalidKeepsLastKnownGoodAndConvergence(t *testing.T) {
	e := newEnv(t)
	r := e.start(e.config())
	e.committed(r)
	ctx := context.Background()
	archive, sig := e.trust.signed(t, "2026.09.1", badImageExpr)
	if err := e.cp.PublishBundle("kubernetes", "2026.09.1", archive, sig, e.trust.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bundle active", func() bool { return r.c.eng.BundleVersion() == "2026.09.1" })
	n1 := e.nodeClient(t, r, "node-1", "node-1")
	n2 := e.nodeClient(t, r, "node-2", "node-2")
	p, err := n1.WaitBundle(ctx, "")
	if err != nil || p == nil || p.Version != "2026.09.1" || !bytes.Equal(p.Archive, archive) || !bytes.Equal(p.Signature, sig) || !bytes.Equal(p.KeyManifest, e.trust.manifest) {
		t.Fatalf("bundle distribution %+v %v", p, err)
	}
	if _, err := n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test", BundleVersion: "2026.09.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := n2.Register(ctx, nodeapi.RegisterRequest{Node: "node-2", AgentVersion: "test", BundleVersion: "2026.08.9"}); err != nil {
		t.Fatal(err)
	}
	cv := r.c.convergence()
	if cv.State != "converging" || cv.Versions["2026.09.1"] != 1 || cv.Versions["2026.08.9"] != 1 {
		t.Fatalf("convergence with an outdated node %+v", cv)
	}
	if got := r.c.clusterCoverage("cluster-rule", 1); got != engine.CoverageConverging {
		t.Fatalf("cluster coverage with an outdated node %v", got)
	}
	part := func(bv string) []nodeapi.Item {
		return []nodeapi.Item{{Seq: 1, Kind: nodeapi.KindSeries, Part: &nodeapi.Part{RuleID: "cluster-rule", RuleVersion: 1, BundleVersion: bv,
			EvalTimeMs: e.clock.Now().UnixMilli(), Samples: []nodeapi.Sample{{Labels: map[string]string{"namespace": "shop"}, Value: 3, TimestampMs: e.clock.Now().UnixMilli()}}}}}
	}
	if _, err := n1.Submit(ctx, "", part("2026.09.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := n2.Submit(ctx, "", part("2026.08.9")); err != nil {
		t.Fatal(err)
	}
	srcs := r.c.mem.Sources()
	if !contains(joinStrings(srcs), "part/node-1/cluster-rule") || contains(joinStrings(srcs), "part/node-2/") {
		t.Fatalf("parts from an incompatible bundle version counted: %v", srcs)
	}
	bad, badSig := e.trust.signed(t, "2026.09.2", `field(r, `)
	if err := e.cp.PublishBundle("kubernetes", "2026.09.2", bad, badSig, e.trust.manifest); err != nil {
		t.Fatal(err)
	}
	eventually(t, "invalid bundle rejected", func() bool {
		cv := r.c.convergence()
		return cv.Rejected != nil && cv.Rejected.Version == "2026.09.2"
	})
	if r.c.eng.BundleVersion() != "2026.09.1" || r.c.bundles.version() != "2026.09.1" {
		t.Fatal("invalid bundle replaced the last known good")
	}
	if p, err := n1.WaitBundle(ctx, "2026.09.1"); err != nil || p != nil {
		t.Fatalf("node offered a bundle after an invalid one: %+v %v", p, err)
	}
	eventually(t, "stale node uncovered", func() bool {
		_, _ = n1.Register(ctx, nodeapi.RegisterRequest{Node: "node-1", AgentVersion: "test", BundleVersion: "2026.09.1"})
		cv := r.c.convergence()
		return len(cv.Uncovered) == 1 && cv.Uncovered[0] == "node-2" && cv.State == "converged"
	})
	if got := r.c.clusterCoverage("cluster-rule", 1); got != engine.CoverageUncovered {
		t.Fatalf("cluster coverage with an uncovered node %v", got)
	}
	if _, err := n2.Register(ctx, nodeapi.RegisterRequest{Node: "node-2", AgentVersion: "test", BundleVersion: "2026.09.1"}); err != nil {
		t.Fatal(err)
	}
	if cv := r.c.convergence(); cv.State != "converged" || cv.Versions["2026.09.1"] != 2 {
		t.Fatalf("node did not converge on reconnect %+v", cv)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	r2 := e.start(e.config())
	if r2.c.bundles.version() != "2026.09.1" {
		t.Fatal("last known good bundle not restored after restart")
	}
	if _, pl, _ := r2.c.bundles.current(); pl == nil || !bytes.Equal(pl.Archive, archive) {
		t.Fatal("distribution payload not restored after restart")
	}
}

func joinStrings(s []string) string {
	var b bytes.Buffer
	for _, x := range s {
		b.WriteString(x)
		b.WriteByte(' ')
	}
	return b.String()
}

func TestPeriodicAnchorsOnlyWhileConnected(t *testing.T) {
	e := newEnv(t)
	e.tune = func(t *Tuning) { t.AnchorDeltas = 3 }
	r := e.start(e.config())
	id, _ := e.committed(r)
	anchors := func() int {
		n := 0
		for _, rec := range e.records(id) {
			if rec.Checkpoint != nil && rec.Checkpoint.Reason == protocol.ReasonAnchor {
				n++
			}
		}
		return n
	}
	for i := 0; i < 4; i++ {
		e.cl.setImage(t, "web-1", "nginx:1."+string(rune('a'+i)))
		time.Sleep(30 * time.Millisecond)
	}
	eventually(t, "periodic anchor", func() bool { return anchors() >= 1 })
	e.committed(r)
	e.cp.SetUnavailable(true)
	if err := e.cp.Disconnect(e.targetID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnected", func() bool { return !r.c.cl.Status().Connected })
	for i := 0; i < 8; i++ {
		e.cl.setImage(t, "web-2", "nginx:2."+string(rune('a'+i)))
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	for _, en := range r.c.sp.Entries(0) {
		rec, err := protocol.Decode(en.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Checkpoint != nil {
			t.Fatalf("anchor appended while unreachable at %d", rec.Seq)
		}
	}
}

func writeAirgapBundle(t *testing.T, e *env, version string) []byte {
	t.Helper()
	dir := filepath.Join(e.aux, "bundles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	archive, sig := e.trust.signed(t, version, badImageExpr)
	for name, b := range map[string][]byte{bundle.FileArchive: archive, bundle.FileSignature: sig, bundle.FileKeyManifest: e.trust.manifest} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return archive
}

func readExports(t *testing.T, dir string) (protocol.ExportHeader, []*protocol.Record) {
	t.Helper()
	names, _ := filepath.Glob(filepath.Join(dir, "export-*.emhpx"))
	sort.Strings(names)
	var hdr protocol.ExportHeader
	var out []*protocol.Record
	for _, n := range names {
		f, err := os.Open(n)
		if err != nil {
			t.Fatal(err)
		}
		h, rs, err := protocol.ReadExport(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		hdr = h
		out = append(out, rs...)
	}
	return hdr, out
}

func TestAirgapExportAndCommitReceipt(t *testing.T) {
	e := newEnv(t, withAirgap())
	archive := writeAirgapBundle(t, e, "2026.09.1")
	r := e.start(e.config())
	ctx := context.Background()
	if r.c.targetID != e.targetID {
		t.Fatalf("air-gap target id %q, token names %q", r.c.targetID, e.targetID)
	}
	eventually(t, "air-gap bundle active", func() bool { return r.c.eng.BundleVersion() == "2026.09.1" })
	n1 := e.nodeClient(t, r, "node-1", "node-1")
	if p, err := n1.WaitBundle(ctx, ""); err != nil || p == nil || !bytes.Equal(p.Archive, archive) || !bytes.Equal(p.KeyManifest, e.trust.manifest) {
		t.Fatalf("air-gap bundle distribution %+v %v", p, err)
	}
	e.cl.setImage(t, "web-1", "nginx:bad")
	e.advancing("finding exported", 20*time.Second, func() bool {
		_, rs := readExports(t, filepath.Join(e.aux, "export"))
		for _, rec := range rs {
			if rec.Finding != nil && rec.Finding.Provenance.RuleID == "bad-image" {
				return true
			}
		}
		return false
	})
	hdr, rs := readExports(t, filepath.Join(e.aux, "export"))
	w := r.c.sp.WriterID()
	if hdr.TargetID != e.targetID || !bytes.Equal(hdr.WriterID, w[:]) || hdr.Incarnation != 1 || rs[0].Checkpoint == nil || rs[0].Seq != 1 {
		t.Fatalf("export header %+v first %+v", hdr, rs[0].Envelope)
	}
	var ep protocol.EpochID
	copy(ep[:], hdr.Epoch)
	rp := protocol.NewReplayer(e.targetID, ep, w)
	var last protocol.Hash
	for i, rec := range rs {
		if rec.Seq != uint64(i+1) {
			t.Fatalf("export records out of order: %d at %d", rec.Seq, i)
		}
		h, err := rp.Apply(rec)
		if err != nil {
			t.Fatal(err)
		}
		last = h
	}
	for _, en := range r.c.sp.Entries(0) {
		if en.Seq <= rs[len(rs)-1].Seq && en.State == spool.NeverTransmitted {
			t.Fatalf("exported record %d still never-transmitted", en.Seq)
		}
	}
	ac := admin.Dial(e.stateDir)
	head := rs[len(rs)-1].Seq
	var wrong protocol.Hash
	if err := ac.Commit(ctx, admin.CommitReceipt{Epoch: ep.String(), Seq: head, ChainHash: hex.EncodeToString(wrong[:])}); err == nil {
		t.Fatal("receipt with a wrong chain hash accepted")
	}
	if err := ac.Commit(ctx, admin.CommitReceipt{Epoch: ep.String(), Seq: head, ChainHash: last.String()}); err != nil {
		t.Fatal(err)
	}
	if lc, _ := r.c.sp.LastCommitted(); lc.Seq != head {
		t.Fatalf("committed head %d, want %d", lc.Seq, head)
	}
	var buf bytes.Buffer
	if err := ac.Export(ctx, 0, &buf); err != nil {
		t.Fatal(err)
	}
	if _, more, err := protocol.ReadExport(&buf); err != nil || (len(more) > 0 && more[0].Seq <= head) {
		t.Fatalf("admin export after commit %v %v", more, err)
	}
	if err := ac.Deenroll(ctx, "x"); err == nil {
		t.Fatal("de-enrollment accepted in the air-gap profile")
	}
	if len(e.epochs()) != 0 {
		t.Fatal("air-gapped coordinator contacted the control plane")
	}
}
