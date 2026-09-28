package findings

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

const target = "tgt-1"

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type sink struct {
	t    *testing.T
	seq  uint64
	out  []protocol.Finding
	fail error
}

func (s *sink) emit(f protocol.Finding) (uint64, error) {
	if s.fail != nil {
		return 0, s.fail
	}
	s.seq++
	seq := s.seq + 1
	rec := &protocol.Record{Envelope: protocol.Envelope{Type: protocol.TypeFinding, TargetID: target, Seq: seq, Parent: seq - 1, Base: 1, Incarnation: 1, Time: 1, Schema: 1}, Finding: &f}
	b, err := protocol.Encode(rec)
	if err != nil {
		s.t.Fatalf("emitted finding does not encode: %v", err)
	}
	back, err := protocol.Decode(b)
	if err != nil {
		s.t.Fatalf("emitted finding does not decode: %v", err)
	}
	s.out = append(s.out, *back.Finding)
	return seq, nil
}

func (s *sink) last() protocol.Finding { return s.out[len(s.out)-1] }

type env struct {
	tr    *Tracker
	store *kv.Memory
	now   time.Time
	sink  *sink
}

func newEnv(t *testing.T, o Options) *env {
	t.Helper()
	e := &env{store: kv.NewMemory(), now: t0, sink: &sink{t: t}}
	e.tr = e.open(t, o)
	return e
}

func (e *env) open(t *testing.T, o Options) *Tracker {
	t.Helper()
	o.TargetID, o.Store, o.Clock = target, e.store, func() time.Time { return e.now }
	tr, err := NewTracker(o)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func (e *env) observe(t *testing.T, o Observation) int {
	t.Helper()
	n, err := e.tr.Observe(o, e.sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func fire(labels map[string]string, at time.Time, ev ...protocol.Evidence) Observation {
	return Observation{Kind: Firing, RuleID: "oom-logs", RuleVersion: 3, BundleVersion: "b1", Labels: labels, Category: "errors", Severity: protocol.SeverityHigh, EvalTime: at, Evidence: ev, Resources: []string{"uid-" + labels["pod"]}}
}

func pod(name string) map[string]string {
	return map[string]string{"namespace": "prod", "pod": name, "value": "3"}
}

func TestLifecycle(t *testing.T) {
	e := newEnv(t, Options{})
	e.observe(t, fire(pod("a"), t0))
	f := e.sink.last()
	if f.Transition != protocol.TransitionFiring || f.Count != 1 || f.FirstSeen != uint64(t0.UnixMilli()) {
		t.Fatalf("%+v", f)
	}
	if f.ID != protocol.FindingID(target, `oom-logs{namespace="prod",pod="a"}`, uint64(t0.UnixMilli())) || f.DedupKey != `oom-logs{namespace="prod",pod="a"}` {
		t.Fatalf("id %s key %s", f.ID, f.DedupKey)
	}
	if f.Provenance.RuleID != "oom-logs" || f.Provenance.RuleVersion != 3 || f.Provenance.BundleVersion != "b1" || f.Labels["value"] != "3" {
		t.Fatalf("%+v", f.Provenance)
	}

	e.now = t0.Add(30 * time.Second)
	if n := e.observe(t, fire(pod("a"), e.now)); n != 0 {
		t.Fatal("update emitted before the interval")
	}
	e.now = t0.Add(61 * time.Second)
	o := fire(pod("a"), e.now)
	o.BundleVersion = "b2"
	if n := e.observe(t, o); n != 1 {
		t.Fatal("update not emitted after the interval")
	}
	u := e.sink.last()
	if u.Transition != protocol.TransitionUpdate || u.Count != 3 || u.ID != f.ID || u.LastSeen != uint64(e.now.UnixMilli()) || u.Provenance.BundleVersion != "b2" {
		t.Fatalf("%+v", u)
	}
	e.now = t0.Add(62 * time.Second)
	e.observe(t, Observation{Kind: Resolved, RuleID: "oom-logs", Labels: pod("a"), EvalTime: e.now})
	r := e.sink.last()
	if r.Transition != protocol.TransitionResolved || r.ID != f.ID || r.Count != 3 {
		t.Fatalf("%+v", r)
	}
	if e.tr.OpenCount() != 0 {
		t.Fatal("still open")
	}
	if n := e.observe(t, Observation{Kind: Resolved, RuleID: "oom-logs", Labels: pod("a")}); n != 0 {
		t.Fatal("resolve without an open episode emitted")
	}
	e.now = t0.Add(2 * time.Minute)
	e.observe(t, fire(pod("a"), e.now))
	if n := e.sink.last(); n.Transition != protocol.TransitionFiring || n.ID == f.ID || n.Count != 1 {
		t.Fatalf("new episode: %+v", n)
	}
}

func TestDedupKeys(t *testing.T) {
	e := newEnv(t, Options{VolatileLabels: []string{"attempt"}})
	a := pod("a")
	b := map[string]string{"pod": "a", "namespace": "prod", "value": "9", "attempt": "2"}
	if e.tr.DedupKey(fire(a, t0)) != e.tr.DedupKey(fire(b, t0)) {
		t.Fatal("volatile labels change the key")
	}
	if e.tr.DedupKey(fire(pod("a"), t0)) == e.tr.DedupKey(fire(pod("b"), t0)) {
		t.Fatal("distinct labels share a key")
	}
	o := fire(a, t0)
	o.DedupLabels = []string{"namespace"}
	if got := e.tr.DedupKey(o); got != `oom-logs{namespace="prod"}` {
		t.Fatal(got)
	}
	o.DedupKey = "explicit"
	if e.tr.DedupKey(o) != "explicit" {
		t.Fatal("explicit key ignored")
	}
	secret := map[string]string{"token": "abc", "pod": "a"}
	if k := e.tr.DedupKey(fire(secret, t0)); strings.Contains(k, "abc") {
		t.Fatalf("secret label in key: %s", k)
	}
	e.observe(t, fire(pod("a"), t0))
	e.observe(t, fire(pod("b"), t0))
	e.observe(t, fire(b, t0.Add(time.Second)))
	if e.tr.OpenCount() != 2 || len(e.sink.out) != 2 {
		t.Fatalf("open %d emitted %d", e.tr.OpenCount(), len(e.sink.out))
	}
}

func TestEvidenceAggregationAndCaps(t *testing.T) {
	e := newEnv(t, Options{MaxSamples: 2, MaxBytes: 64, MaxSampleBytes: 16, UpdateInterval: time.Nanosecond})
	line := func(text string, at time.Time) protocol.Evidence {
		return protocol.Evidence{Source: "logs:app", Time: uint64(at.UnixMilli()), Text: text}
	}
	e.observe(t, fire(pod("a"), t0, line("OutOfMemory", t0), line("OutOfMemory", t0.Add(time.Second))))
	f := e.sink.last()
	if len(f.Evidence) != 1 || f.Evidence[0].Count != 2 || f.Evidence[0].Time != uint64(t0.UnixMilli()) || f.Flags&protocol.FindingEvidenceTruncated != 0 {
		t.Fatalf("%+v", f.Evidence)
	}
	e.now = t0.Add(time.Minute)
	e.observe(t, fire(pod("a"), e.now, line("password=hunter2 failed", e.now), line("third distinct", e.now)))
	u := e.sink.last()
	if len(u.Evidence) != 2 || u.Flags&protocol.FindingEvidenceTruncated == 0 {
		t.Fatalf("%+v", u)
	}
	if strings.Contains(u.Evidence[1].Text, "hunter2") || !u.Evidence[1].Truncated || len(u.Evidence[1].Text) > 16 {
		t.Fatalf("sample not redacted and truncated: %+v", u.Evidence[1])
	}
	ep := e.tr.byID[u.ID]
	if ep.Dropped != 1 || ep.Samples[0].LastSeen != uint64(t0.Add(time.Second).UnixMilli()) {
		t.Fatalf("dropped %d samples %+v", ep.Dropped, ep.Samples)
	}
	e.now = t0.Add(2 * time.Minute)
	o := fire(pod("a"), e.now)
	o.Resources = nil
	e.observe(t, o)
	if n := e.sink.last(); n.Transition != protocol.TransitionUpdate || len(n.Evidence) != 0 {
		t.Fatal("unchanged evidence resent")
	}
	per := fire(pod("z"), e.now, line("one", e.now), line("two", e.now))
	per.MaxSamples = 1
	e.observe(t, per)
	if n := e.sink.last(); len(n.Evidence) != 1 || n.Flags&protocol.FindingEvidenceTruncated == 0 {
		t.Fatalf("per-rule cap: %+v", n)
	}
}

func TestStaleNeverResolves(t *testing.T) {
	e := newEnv(t, Options{})
	e.observe(t, fire(pod("a"), t0))
	e.observe(t, fire(pod("b"), t0))
	other := fire(pod("c"), t0)
	other.RuleID = "other"
	e.observe(t, other)
	if n := e.observe(t, Observation{Kind: Stale, RuleID: "oom-logs", EvalTime: t0.Add(time.Minute)}); n != 2 {
		t.Fatalf("rule-wide stale emitted %d", n)
	}
	if n := e.observe(t, Observation{Kind: Stale, RuleID: "oom-logs"}); n != 0 {
		t.Fatal("stale twice")
	}
	for _, f := range e.sink.out[3:] {
		if f.Transition != protocol.TransitionStale {
			t.Fatalf("%+v", f)
		}
	}
	if e.tr.OpenCount() != 3 {
		t.Fatal("stale closed an episode")
	}
	s := e.tr.Summary(0, e.sink.seq+1)
	states := map[string]string{}
	for _, x := range s {
		states[x.DedupKey] = x.State
	}
	if states[`oom-logs{namespace="prod",pod="a"}`] != StateStale || states[`other{namespace="prod",pod="c"}`] != StateFiring {
		t.Fatalf("%v", states)
	}
	if n := e.observe(t, Observation{Kind: Fresh, RuleID: "oom-logs", Labels: pod("a"), EvalTime: t0.Add(2 * time.Minute)}); n != 1 || e.sink.last().Transition != protocol.TransitionFresh {
		t.Fatal("fresh")
	}
	if n := e.observe(t, Observation{Kind: Fresh, RuleID: "other"}); n != 0 {
		t.Fatal("fresh without stale")
	}
	e.observe(t, fire(pod("b"), t0.Add(3*time.Minute)))
	if f := e.sink.last(); f.Transition != protocol.TransitionFresh || f.Count != 2 {
		t.Fatalf("firing on stale episode: %+v", f)
	}
	e.observe(t, Observation{Kind: Stale, RuleID: "other", Node: "n2"})
	if e.tr.byID[e.sink.out[2].ID].State != StateFiring {
		t.Fatal("stale on another node applied")
	}
}

func TestFlushRateLimit(t *testing.T) {
	e := newEnv(t, Options{UpdateInterval: time.Minute})
	e.observe(t, fire(pod("a"), t0))
	e.now = t0.Add(10 * time.Second)
	e.observe(t, fire(pod("a"), e.now))
	if n, _ := e.tr.Flush(e.sink.emit); n != 0 {
		t.Fatal("flushed early")
	}
	e.now = t0.Add(time.Minute)
	if n, _ := e.tr.Flush(e.sink.emit); n != 1 || e.sink.last().Transition != protocol.TransitionUpdate || e.sink.last().Count != 2 {
		t.Fatal("flush after interval")
	}
	e.now = t0.Add(3 * time.Minute)
	if n, _ := e.tr.Flush(e.sink.emit); n != 0 {
		t.Fatal("flushed without changes")
	}
}

func TestEmitFailureLeavesStateUnchanged(t *testing.T) {
	e := newEnv(t, Options{})
	e.sink.fail = errors.New("spool full")
	if _, err := e.tr.Observe(fire(pod("a"), t0), e.sink.emit); err == nil {
		t.Fatal("expected error")
	}
	if e.tr.OpenCount() != 0 {
		t.Fatal("episode opened without emission")
	}
	e.sink.fail = nil
	e.observe(t, fire(pod("a"), t0))
	e.sink.fail = errors.New("spool full")
	if _, err := e.tr.Observe(Observation{Kind: Resolved, RuleID: "oom-logs", Labels: pod("a")}, e.sink.emit); err == nil {
		t.Fatal("expected error")
	}
	if e.tr.OpenCount() != 1 {
		t.Fatal("resolved without emission")
	}
}

func TestSummaryWindows(t *testing.T) {
	e := newEnv(t, Options{UpdateInterval: time.Nanosecond})
	e.observe(t, fire(pod("a"), t0))
	e.observe(t, fire(pod("b"), t0))
	aID, bID := e.sink.out[0].ID, e.sink.out[1].ID
	h := e.sink.seq + 1
	if err := e.tr.Commit(h); err != nil {
		t.Fatal(err)
	}
	e.now = t0.Add(time.Hour)
	e.observe(t, Observation{Kind: Resolved, RuleID: "oom-logs", Labels: pod("a"), EvalTime: t0.Add(time.Minute)})
	e.observe(t, fire(pod("c"), t0.Add(2*time.Minute)))
	e.now = t0.Add(time.Hour + time.Second)
	e.observe(t, fire(pod("c"), t0.Add(3*time.Minute)))
	w := e.sink.seq + 2
	s := e.tr.Summary(h, w)
	if len(s) != 2 {
		t.Fatalf("summary %+v", s)
	}
	byKey := map[string]protocol.SummaryEntry{}
	for _, x := range s {
		byKey[x.FindingID] = x
	}
	if a := byKey[aID]; a.State != StateResolved || a.RuleID != "oom-logs" || a.BundleVersion != "b1" || a.Severity != "high" || a.EvalTime != uint64(t0.Add(time.Minute).UnixMilli()) {
		t.Fatalf("%+v", a)
	}
	if _, ok := byKey[bID]; ok {
		t.Fatal("untouched finding in summary")
	}
	cID := e.sink.out[3].ID
	if c := byKey[cID]; c.State != StateFiring || c.LastTransition != e.sink.seq+1 || c.FirstSeen != uint64(t0.Add(2*time.Minute).UnixMilli()) {
		t.Fatalf("%+v", c)
	}
	if s[0].FindingID >= s[1].FindingID {
		t.Fatal("summary order")
	}
	mid := e.tr.Summary(h, h+1)
	if len(mid) != 1 || mid[0].FindingID != aID || mid[0].State != StateResolved {
		t.Fatalf("summary at earlier watermark %+v", mid)
	}
	if got := e.tr.Summary(h, h); len(got) != 0 {
		t.Fatalf("empty window %+v", got)
	}
	if err := e.tr.Commit(w); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.tr.byID[aID]; ok {
		t.Fatal("resolved episode not pruned after commit")
	}
	if _, ok, _ := e.store.Get(keyPrefix + aID); ok {
		t.Fatal("resolved episode still persisted")
	}
	if n := len(e.tr.byID[cID].Transitions); n != 1 {
		t.Fatalf("history not compacted: %d", n)
	}
	if got := e.tr.Summary(w, w+5); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	e := newEnv(t, Options{UpdateInterval: time.Minute})
	o := fire(pod("a"), t0, protocol.Evidence{Source: "logs:app", Time: uint64(t0.UnixMilli()), Text: "boom", Labels: map[string]string{"stream": "stderr"}})
	o.Facts = map[string]any{"restarts": 7, "reason": "OOMKilled", "nested": map[string]any{"limit": 1.5}}
	o.Coverage = []string{"node n3 unreachable"}
	o.Node = "n1"
	e.observe(t, o)
	e.observe(t, fire(pod("b"), t0))
	e.observe(t, Observation{Kind: Stale, RuleID: "oom-logs", Labels: pod("b")})
	e.now = t0.Add(10 * time.Second)
	e.observe(t, fire(pod("a"), e.now))
	first := e.sink.out[0]
	if first.Flags&protocol.FindingIncompleteCoverage == 0 || first.Facts["restarts"] != int64(7) {
		t.Fatalf("%+v", first)
	}

	e.tr = e.open(t, Options{UpdateInterval: time.Minute})
	if e.tr.OpenCount() != 2 {
		t.Fatalf("open after restart %d", e.tr.OpenCount())
	}
	e.now = t0.Add(59 * time.Second)
	if n, _ := e.tr.Flush(e.sink.emit); n != 0 {
		t.Fatal("rate limit not resumed")
	}
	e.now = t0.Add(time.Minute)
	if n, _ := e.tr.Flush(e.sink.emit); n != 1 {
		t.Fatal("pending update lost across restart")
	}
	u := e.sink.last()
	if u.ID != first.ID || u.Count != 2 || u.Node != "n1" || !reflect.DeepEqual(u.Facts, first.Facts) || u.Evidence != nil {
		t.Fatalf("%+v", u)
	}
	e.observe(t, fire(pod("b"), e.now))
	if f := e.sink.last(); f.Transition != protocol.TransitionFresh {
		t.Fatal("stale state lost across restart")
	}
	if len(e.tr.Summary(0, e.sink.seq+1)) != 2 {
		t.Fatal("transition history lost across restart")
	}
}

func TestLateFlag(t *testing.T) {
	e := newEnv(t, Options{LateThreshold: 15 * time.Minute})
	e.now = t0.Add(16 * time.Minute)
	e.observe(t, fire(pod("a"), t0))
	if e.sink.last().Flags&protocol.FindingLateAtWriter == 0 {
		t.Fatal("late flag missing")
	}
	e.observe(t, fire(pod("b"), t0.Add(10*time.Minute)))
	if e.sink.last().Flags&protocol.FindingLateAtWriter != 0 {
		t.Fatal("late flag on timely finding")
	}
	o := fire(pod("c"), e.now)
	o.Flags = protocol.FindingLateAtWriter | protocol.FindingEvidenceLimited
	e.observe(t, o)
	if f := e.sink.last(); f.Flags&protocol.FindingLateAtWriter != 0 || f.Flags&protocol.FindingEvidenceLimited == 0 {
		t.Fatalf("flags %b", f.Flags)
	}
}

func TestQueryFinding(t *testing.T) {
	e := newEnv(t, Options{})
	h := protocol.QueryHash("promql", "up == 0", "local")
	o := Observation{Query: &QueryProvenance{Hash: h, Requester: "user:alice"}, Category: "investigation", Severity: protocol.SeverityLow, EvalTime: t0, Labels: map[string]string{"job": "api"}}
	if _, err := e.tr.AddQueryFinding(o, e.sink.emit); err != nil {
		t.Fatal(err)
	}
	f := e.sink.last()
	if f.Provenance.Kind != protocol.ProvenanceQuery || f.Provenance.QueryHash != h || f.Provenance.Requester != "user:alice" || !strings.HasPrefix(f.DedupKey, "query:") {
		t.Fatalf("%+v", f)
	}
	s := e.tr.Summary(0, 10)
	if len(s) != 1 || s[0].RuleID != "" || s[0].State != StateFiring {
		t.Fatalf("%+v", s)
	}
	if _, err := e.tr.AddQueryFinding(Observation{Query: &QueryProvenance{Hash: h}, Severity: protocol.SeverityLow, EvalTime: t0}, e.sink.emit); err == nil {
		t.Fatal("query finding without requester accepted")
	}
}

func TestObservationValidation(t *testing.T) {
	e := newEnv(t, Options{})
	bad := []Observation{
		{Kind: 9},
		{Kind: Firing, RuleID: "r", Severity: protocol.SeverityLow, EvalTime: t0},
		{Kind: Firing, RuleID: "r", BundleVersion: "b", EvalTime: t0},
		{Kind: Firing, RuleID: "r", BundleVersion: "b", Severity: protocol.SeverityLow},
		{Kind: Firing, RuleID: "r", BundleVersion: "b", Severity: protocol.SeverityLow, EvalTime: t0, Facts: map[string]any{"x": func() {}}},
		{Kind: Stale},
	}
	for i, o := range bad {
		if _, err := e.tr.Observe(o, e.sink.emit); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := NewTracker(Options{Store: kv.NewMemory()}); err == nil {
		t.Fatal("tracker without target id")
	}
}

func TestConcurrentObservers(t *testing.T) {
	e := newEnv(t, Options{UpdateInterval: time.Nanosecond})
	var mu sync.Mutex
	emit := func(f protocol.Finding) (uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		return e.sink.emit(f)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := e.tr.Observe(fire(pod(strconv.Itoa(i%4)), t0.Add(time.Duration(j)*time.Second)), emit); err != nil {
					t.Error(err)
				}
				_ = e.tr.Summary(0, 1<<20)
			}
		}(i)
	}
	wg.Wait()
	if e.tr.OpenCount() != 4 {
		t.Fatalf("open %d", e.tr.OpenCount())
	}
	var total uint64
	for _, id := range e.tr.open {
		total += e.tr.byID[id].Count
	}
	if total != 160 {
		t.Fatalf("count %d", total)
	}
}
