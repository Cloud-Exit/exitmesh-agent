package scrape

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/textparse"
	"github.com/prometheus/prometheus/model/value"
	"github.com/prometheus/prometheus/storage"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

const acceptHeader = "application/openmetrics-text;version=1.0.0;q=0.75,text/plain;version=0.0.4;q=0.5,*/*;q=0.1"

const tokenChunk = 512

var reportNames = [3]string{"up", "scrape_duration_seconds", "scrape_samples_scraped"}

type entry struct {
	lset labels.Labels
	ref  storage.SeriesRef
	iter uint64
}

type loop struct {
	m    *Manager
	t    Target
	key  string
	tl   map[string]string
	base labels.Labels

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	token *watchedFile
	ca    *watchedFile
	cli   *http.Client

	cache     map[string]*entry
	iter      uint64
	reportRef [3]storage.SeriesRef
	reported  bool
	lastTS    int64

	mu sync.Mutex
	st TargetStatus
}

func newLoop(m *Manager, t Target) *loop {
	tl, _ := t.targetLabels()
	ctx, cancel := context.WithCancel(context.Background())
	l := &loop{
		m: m, t: t, key: t.Key(), tl: tl, base: labels.FromMap(tl),
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		cache: map[string]*entry{},
		st:    TargetStatus{Key: t.Key(), URL: t.URL, Labels: copyMap(tl), Health: HealthUnknown},
	}
	if t.BearerTokenFile != "" {
		l.token = &watchedFile{path: t.BearerTokenFile}
	}
	if t.TLS.CAFile != "" {
		l.ca = &watchedFile{path: t.TLS.CAFile}
	}
	return l
}

func (l *loop) snapshot() TargetStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.st
	s.Labels = copyMap(l.st.Labels)
	return s
}

func (l *loop) run() {
	defer close(l.done)
	h := fnv.New64a()
	h.Write([]byte(l.key))
	offset := time.Duration(h.Sum64() % uint64(l.t.Interval))
	timer := time.NewTimer(offset)
	defer timer.Stop()
	select {
	case <-l.ctx.Done():
		l.end()
		return
	case <-timer.C:
	}
	tick := time.NewTicker(l.t.Interval)
	defer tick.Stop()
	for {
		l.scrapeOnce(time.Now())
		select {
		case <-l.ctx.Done():
			l.end()
			return
		case <-tick.C:
		}
	}
}

func (l *loop) stop() {
	l.cancel()
	<-l.done
}

// end writes staleness markers for every series of the target, report series included.
func (l *loop) end() {
	ts := max(time.Now().UnixMilli(), l.lastTS+1)
	app := l.m.o.Appendable.Appender(context.Background())
	l.iter++
	l.staleUnseen(app, ts)
	if l.reported {
		for i, n := range reportNames {
			_, _ = app.Append(l.reportRef[i], l.reportLabels(n), ts, math.Float64frombits(value.StaleNaN))
		}
	}
	if err := app.Commit(); err != nil {
		l.m.o.Logger.Warn("scrape staleness commit failed", "target", l.t.URL, "err", err)
	}
	if l.cli != nil {
		l.cli.CloseIdleConnections()
	}
}

type scrapeResult struct {
	scraped, appended          int
	seriesDropped, rateDropped uint64
	appendErrors               uint64
}

func (l *loop) scrapeOnce(start time.Time) {
	ts := max(start.UnixMilli(), l.lastTS+1)
	body, ctype, err := l.fetch()
	app := l.m.o.Appendable.Appender(l.ctx)
	var res scrapeResult
	l.iter++
	if err == nil {
		res, err = l.appendBody(app, body, ctype, ts)
		if err != nil {
			_ = app.Rollback()
			app = l.m.o.Appendable.Appender(l.ctx)
			l.iter++
		}
	}
	l.staleUnseen(app, ts)
	dur := time.Since(start)
	up := 1.0
	if err != nil {
		up = 0
	}
	for i, v := range [3]float64{up, dur.Seconds(), float64(res.scraped)} {
		ref, aerr := app.Append(l.reportRef[i], l.reportLabels(reportNames[i]), ts, v)
		if aerr == nil {
			l.reportRef[i] = ref
		}
	}
	l.reported = true
	if cerr := app.Commit(); cerr != nil && err == nil {
		err = fmt.Errorf("commit: %w", cerr)
	}
	l.lastTS = ts

	l.mu.Lock()
	defer l.mu.Unlock()
	l.st.LastScrape = start
	l.st.LastDuration = dur
	l.st.Samples = res.scraped
	l.st.Series = len(l.cache)
	l.st.SeriesDropped += res.seriesDropped
	l.st.SamplesDropped += res.rateDropped
	l.st.AppendErrors += res.appendErrors
	if err != nil {
		l.st.Health = HealthDown
		l.st.Reason = classify(err)
		l.st.LastError = redact.Default().String(err.Error())
		return
	}
	l.st.Health, l.st.Reason, l.st.LastError = HealthUp, "", ""
}

func (l *loop) reportLabels(name string) labels.Labels {
	b := labels.NewBuilder(l.base)
	b.Set(labels.MetricName, name)
	return b.Labels()
}

func (l *loop) staleUnseen(app storage.Appender, ts int64) {
	n := 0
	for k, e := range l.cache {
		if e.iter == l.iter {
			continue
		}
		_, _ = app.Append(e.ref, e.lset, ts, math.Float64frombits(value.StaleNaN))
		delete(l.cache, k)
		n++
	}
	l.m.releaseSeries(n)
}

func (l *loop) appendBody(app storage.Appender, body []byte, ctype string, ts int64) (scrapeResult, error) {
	var res scrapeResult
	p, perr := textparse.New(body, ctype, nil, textparse.ParserOptions{FallbackContentType: "text/plain"})
	if p == nil {
		return res, &parseError{perr}
	}
	allowance := 0
	defer func() { l.m.limiter.giveBack(allowance) }()
	maxPer := l.m.o.Budgets.MaxSeriesPerTarget
	var lset labels.Labels
	for {
		e, err := p.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, &parseError{err}
		}
		if e != textparse.EntrySeries {
			continue
		}
		met, _, v := p.Series()
		res.scraped++
		ce, cached := l.cache[string(met)]
		if cached && ce.iter == l.iter {
			res.appendErrors++
			continue
		}
		if !cached {
			p.Labels(&lset)
			final := l.mutate(lset)
			if final.Get(labels.MetricName) == "" {
				res.appendErrors++
				continue
			}
			if (maxPer > 0 && len(l.cache) >= maxPer) || !l.m.reserveSeries() {
				res.seriesDropped++
				continue
			}
			ce = &entry{lset: final}
		}
		if allowance == 0 {
			allowance = l.m.limiter.take(tokenChunk)
		}
		if allowance == 0 {
			res.rateDropped++
			if !cached {
				l.m.releaseSeries(1)
			}
			continue
		}
		allowance--
		ref, aerr := app.Append(ce.ref, ce.lset, ts, v)
		if aerr != nil {
			res.appendErrors++
			if !cached {
				l.m.releaseSeries(1)
			}
			continue
		}
		ce.ref, ce.iter = ref, l.iter
		if !cached {
			l.cache[string(met)] = ce
		}
		res.appended++
	}
	return res, nil
}

// mutate applies honor_labels false: target labels win and conflicting scraped labels move to exported_*.
func (l *loop) mutate(scraped labels.Labels) labels.Labels {
	b := labels.NewBuilder(scraped)
	for _, k := range sortedKeys(l.tl) {
		if ev := scraped.Get(k); ev != "" {
			name := "exported_" + k
			for scraped.Has(name) {
				name = "exported_" + name
			}
			b.Set(name, ev)
		}
		b.Set(k, l.tl[k])
	}
	return b.Labels()
}

func (l *loop) fetch() ([]byte, string, error) {
	cli, err := l.client()
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(l.ctx, l.t.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.t.URL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("User-Agent", "exitmesh-agent")
	req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", strconv.FormatFloat(l.t.Timeout.Seconds(), 'f', -1, 64))
	if l.token != nil {
		tok, _, terr := l.token.read()
		if terr != nil {
			return nil, "", &credError{terr}
		}
		req.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(tok)))
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", &statusError{resp.StatusCode}
	}
	limit := l.m.o.MaxBodyBytes
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > limit {
		return nil, "", errBodyLimit
	}
	return body, resp.Header.Get("Content-Type"), nil
}

func (l *loop) client() (*http.Client, error) {
	var pem []byte
	changed := false
	if l.ca != nil {
		b, ch, err := l.ca.read()
		if err != nil {
			return nil, &tlsSetupError{err}
		}
		pem, changed = b, ch
	}
	if l.cli != nil && !changed {
		return l.cli, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: l.t.TLS.InsecureSkipVerify, ServerName: l.t.TLS.ServerName} //nolint:gosec // opt-in per target
	if pem != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			l.ca.reset()
			return nil, &tlsSetupError{fmt.Errorf("no certificates in %s", l.t.TLS.CAFile)}
		}
		tc.RootCAs = pool
	}
	if l.cli != nil {
		l.cli.CloseIdleConnections()
	}
	l.cli = &http.Client{
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: l.t.Timeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:     tc,
			TLSHandshakeTimeout: l.t.Timeout,
			MaxIdleConns:        1,
			IdleConnTimeout:     2 * l.t.Interval,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return l.cli, nil
}

// watchedFile rereads a file when its inode, size, or modification time changes.
type watchedFile struct {
	path string
	mu   sync.Mutex
	ino  uint64
	size int64
	mod  time.Time
	data []byte
	ok   bool
}

func (w *watchedFile) read() ([]byte, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fi, err := os.Stat(w.path)
	if err != nil {
		return nil, false, err
	}
	var ino uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = st.Ino
	}
	if w.ok && ino == w.ino && fi.Size() == w.size && fi.ModTime().Equal(w.mod) {
		return w.data, false, nil
	}
	b, err := os.ReadFile(w.path)
	if err != nil {
		return nil, false, err
	}
	w.ino, w.size, w.mod, w.data, w.ok = ino, fi.Size(), fi.ModTime(), b, true
	return b, true, nil
}

func (w *watchedFile) reset() {
	w.mu.Lock()
	w.ok = false
	w.mu.Unlock()
}

type statusError struct{ code int }

func (e *statusError) Error() string {
	return fmt.Sprintf("server returned HTTP status %d %s", e.code, http.StatusText(e.code))
}

type parseError struct{ err error }

func (e *parseError) Error() string { return "parse: " + fmt.Sprint(e.err) }

type credError struct{ err error }

func (e *credError) Error() string { return "bearer token: " + e.err.Error() }

type tlsSetupError struct{ err error }

func (e *tlsSetupError) Error() string { return "tls: " + e.err.Error() }

var errBodyLimit = errors.New("response body exceeds size limit")

func classify(err error) string {
	var se *statusError
	var pe *parseError
	var ce *credError
	var te *tlsSetupError
	var op *net.OpError
	var ne net.Error
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	var rh tls.RecordHeaderError
	switch {
	case errors.As(err, &se):
		if se.code == http.StatusUnauthorized || se.code == http.StatusForbidden {
			return ReasonUnauthorized
		}
		return ReasonHTTPStatus
	case errors.As(err, &pe):
		return ReasonParse
	case errors.As(err, &ce):
		return ReasonCredentials
	case errors.Is(err, errBodyLimit):
		return ReasonBodyLimit
	case errors.As(err, &te), errors.As(err, &ua), errors.As(err, &he), errors.As(err, &ci), errors.As(err, &cv), errors.As(err, &rh):
		return ReasonTLS
	case errors.As(err, &op) && op.Op == "dial", errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return ReasonUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ReasonTimeout
	}
	return ReasonError
}
