package scrape

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"

	"github.com/cloud-exit/exitmesh-agent/internal/telemetry/tsdb"
)

func TestRetainedSeriesDropsAndCoverageRecovery(t *testing.T) {
	db, err := tsdb.Open(t.TempDir(), tsdb.Options{MaxSeries: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ex := &exposition{}
	ex.set("a 1\nb 1\n", "text/plain", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	l := testLoop(newTestManager(db, Budgets{MaxSeries: 10}), Target{URL: srv.URL})
	now := time.Now()
	l.scrapeOnce(now)
	ex.set("c 1\n", "text/plain", 200)
	l.scrapeOnce(now.Add(time.Second))
	if st := l.snapshot(); !st.BudgetLimited || st.SeriesDropped != 1 || st.AppendErrors != 0 {
		t.Fatalf("retained series limit not disclosed: %+v", st)
	}
	if err := db.RelieveSeriesPressure(); err != nil {
		t.Fatal(err)
	}
	l.scrapeOnce(now.Add(2 * time.Second))
	if st := l.snapshot(); st.BudgetLimited || st.Series != 1 || st.SeriesDropped != 1 {
		t.Fatalf("coverage failed to recover: %+v", st)
	}
}

type heldCommit struct {
	memApp
	entered chan struct{}
	release chan struct{}
}

func (a *heldCommit) Appender(ctx context.Context) storage.Appender {
	return &heldTransaction{Appender: a.memApp.Appender(ctx), owner: a, ctx: ctx}
}

type heldTransaction struct {
	storage.Appender
	owner *heldCommit
	ctx   context.Context
}

func (a *heldTransaction) Commit() error {
	a.owner.entered <- struct{}{}
	select {
	case <-a.owner.release:
		return a.Appender.Commit()
	case <-a.ctx.Done():
		_ = a.Appender.Rollback()
		return a.ctx.Err()
	}
}

func TestScrapeSlotCoversCommitAndCancelsWaiters(t *testing.T) {
	requests := make(chan struct{}, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		_, _ = w.Write([]byte("metric 1\n"))
	}))
	defer srv.Close()
	app := &heldCommit{entered: make(chan struct{}, 3), release: make(chan struct{})}
	defer close(app.release)
	m := NewManager(Options{Appendable: app, MaxConcurrentScrapes: 1})
	first, second := testLoop(m, Target{URL: srv.URL + "/a"}), testLoop(m, Target{URL: srv.URL + "/b"})
	defer first.cancel()
	defer second.cancel()
	doneFirst, doneSecond := make(chan struct{}), make(chan struct{})
	go func() { defer close(doneFirst); first.scrapeOnce(time.Now()) }()
	select {
	case <-app.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first scrape never reached commit")
	}
	<-requests
	go func() { defer close(doneSecond); second.scrapeOnce(time.Now()) }()
	select {
	case <-requests:
		t.Fatal("second scrape fetched while the first held its response through commit")
	case <-time.After(100 * time.Millisecond):
	}
	second.cancel()
	select {
	case <-doneSecond:
	case <-time.After(5 * time.Second):
		t.Fatal("waiting scrape ignored cancellation")
	}
	first.cancel()
	<-doneFirst
}

func TestScrapeSlotTimeoutAndFreshTimestamp(t *testing.T) {
	app := &memApp{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("metric 1\n"))
	}))
	defer srv.Close()
	m := NewManager(Options{Appendable: app, MaxConcurrentScrapes: 1})
	l := testLoop(m, Target{URL: srv.URL, Timeout: 20 * time.Millisecond})
	defer l.cancel()
	m.slots <- struct{}{}
	l.scrapeOnce(time.Now())
	if st := l.snapshot(); st.Reason != ReasonTimeout || !st.BudgetLimited {
		t.Fatalf("slot timeout not disclosed: %+v", st)
	}
	if len(app.find("metric", nil)) != 0 {
		t.Fatal("timed out scrape fetched data")
	}
	l.t.Timeout = time.Second
	done := make(chan struct{})
	go func() { defer close(done); l.scrapeOnce(time.Now().Add(-10 * time.Minute)) }()
	time.AfterFunc(20*time.Millisecond, func() { <-m.slots })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("queued scrape did not finish")
	}
	if got := app.last(t, "metric", nil); time.Since(time.UnixMilli(got.t)) > time.Second {
		t.Fatal("queued scrape used an old timestamp for fresh data")
	}
	if l.snapshot().BudgetLimited {
		t.Fatal("slot timeout coverage did not recover")
	}
}

func TestMalformedScrapeReleasesRetainedCapacity(t *testing.T) {
	db, err := tsdb.Open(t.TempDir(), tsdb.Options{MaxSeries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ex := &exposition{}
	ex.set("a 1\nb 1\nbroken{\n", "text/plain", 200)
	srv := httptest.NewServer(ex)
	defer srv.Close()
	l := testLoop(newTestManager(db, Budgets{MaxSeries: 10}), Target{URL: srv.URL})
	now := time.Now()
	l.scrapeOnce(now)
	if l.snapshot().Reason != ReasonParse {
		t.Fatal("malformed scrape was accepted")
	}
	if err := db.RelieveSeriesPressure(); err != nil {
		t.Fatal(err)
	}
	ex.set("c 1\n", "text/plain", 200)
	l.scrapeOnce(now.Add(time.Second))
	if l.snapshot().Series != 1 {
		t.Fatal("rolled-back series permanently consumed retained capacity")
	}
	q, err := db.Querier(now.UnixMilli(), now.Add(time.Second).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	set := q.Select(context.Background(), false, nil, labels.MustNewMatcher(labels.MatchRegexp, "__name__", "a|b"))
	for set.Next() {
		it := set.At().Iterator(nil)
		for it.Next() != 0 {
			_, v := it.At()
			if !isStale(v) {
				t.Fatal("malformed scrape retained rolled-back values")
			}
		}
		if err := it.Err(); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Err(); err != nil {
		t.Fatal(err)
	}
}
