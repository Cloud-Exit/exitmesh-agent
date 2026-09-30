package investigate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/common/model"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
)

// Lookback adapter bounds.
const (
	SourceConcurrency  = 2
	maxResponseBytes   = 64 << 20
	maxUpstreamMessage = 256
	vmMonth            = 31 * 24 * time.Hour
)

var tenantIDRE = regexp.MustCompile(`^[0-9]{1,10}$`)

// source is one configured read-only lookback endpoint.
type source struct {
	cfg    config.Lookback
	base   *url.URL
	client *http.Client
	sem    chan struct{}

	mu             sync.Mutex
	retention      time.Duration
	retentionKnown bool
	retentionDone  bool
}

func newSource(cfg config.Lookback, hc *http.Client) (*source, error) {
	switch cfg.Type {
	case config.SourcePrometheus, config.SourceMimir, config.SourceVictoriaMetrics, config.SourceLoki, config.SourceVictoriaLogs:
	default:
		return nil, fmt.Errorf("lookback %s: unknown type %q", cfg.Name, cfg.Type)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("lookback %s: url must be http(s)", cfg.Name)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("lookback %s: url must not carry credentials, a query, or a fragment", cfg.Name)
	}
	if cfg.AccountID != "" && !tenantIDRE.MatchString(cfg.AccountID) || cfg.ProjectID != "" && !tenantIDRE.MatchString(cfg.ProjectID) {
		return nil, fmt.Errorf("lookback %s: accountID and projectID must be numeric", cfg.Name)
	}
	if cfg.ProjectID != "" && cfg.AccountID == "" {
		return nil, fmt.Errorf("lookback %s: projectID requires accountID", cfg.Name)
	}
	rt := http.DefaultTransport
	if hc != nil && hc.Transport != nil {
		rt = hc.Transport
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("lookback %s: ca file: %w", cfg.Name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("lookback %s: ca file holds no certificates", cfg.Name)
		}
		base, ok := rt.(*http.Transport)
		if !ok {
			base = http.DefaultTransport.(*http.Transport)
		}
		tr := base.Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		rt = tr
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = config.Duration(30 * time.Second)
	}
	client := &http.Client{
		Transport:     rt,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return &source{cfg: cfg, base: u, client: client, sem: make(chan struct{}, SourceConcurrency)}, nil
}

func (s *source) metrics() bool {
	return s.cfg.Type == config.SourcePrometheus || s.cfg.Type == config.SourceMimir || s.cfg.Type == config.SourceVictoriaMetrics
}

func (s *source) acquire(ctx context.Context) (func(), error) {
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, nil
	case <-ctx.Done():
		return nil, errorf(ClassBusy, "lookback source %s is at its concurrency limit", s.cfg.Name)
	}
}

// upstreamError is a failed lookback request reported as a limitation.
type upstreamError struct {
	class string
	msg   string
}

func (e *upstreamError) Error() string { return e.msg }

func readSecretFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// get performs one read-only GET; overCap reports a body cut at limit bytes.
func (s *source) get(ctx context.Context, path string, params url.Values, limit int64) (body []byte, overCap bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout.D())
	defer cancel()
	u := *s.base
	u.Path += path
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, &upstreamError{ClassInternal, "request: " + err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "exitmesh-agent")
	switch s.cfg.Type {
	case config.SourceMimir, config.SourceLoki:
		if s.cfg.Tenant != "" {
			req.Header.Set("X-Scope-OrgID", s.cfg.Tenant)
		}
	case config.SourceVictoriaLogs:
		if s.cfg.AccountID != "" {
			req.Header.Set("AccountID", s.cfg.AccountID)
		}
		if s.cfg.ProjectID != "" {
			req.Header.Set("ProjectID", s.cfg.ProjectID)
		}
	}
	switch {
	case s.cfg.BearerTokenFile != "":
		tok, err := readSecretFile(s.cfg.BearerTokenFile)
		if err != nil {
			return nil, false, &upstreamError{ClassUnauthorized, "bearer token file cannot be read"}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	case s.cfg.BasicUsernameFile != "" || s.cfg.BasicPasswordFile != "":
		user, err1 := readSecretFile(s.cfg.BasicUsernameFile)
		pass, err2 := readSecretFile(s.cfg.BasicPasswordFile)
		if err1 != nil || err2 != nil {
			return nil, false, &upstreamError{ClassUnauthorized, "basic auth files cannot be read"}
		}
		req.SetBasicAuth(user, pass)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, false, &upstreamError{ClassTimeout, "request timed out"}
		}
		return nil, false, &upstreamError{ClassUnavailable, "endpoint unreachable: " + sanitizeNetErr(err)}
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, false, &upstreamError{ClassUnavailable, "reading response: " + sanitizeNetErr(err)}
	}
	if int64(len(body)) > limit {
		body, overCap = body[:limit], true
	}
	switch code := resp.StatusCode; {
	case code == http.StatusOK:
		return body, overCap, nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return nil, false, &upstreamError{ClassUnauthorized, fmt.Sprintf("insufficient authorization (HTTP %d)", code)}
	case code >= 300 && code < 400:
		return nil, false, &upstreamError{ClassUnavailable, fmt.Sprintf("redirect (HTTP %d) not followed; only the configured endpoint is used", code)}
	case code == http.StatusNotFound || code == http.StatusTooManyRequests || code >= 500:
		return nil, false, &upstreamError{ClassUnavailable, fmt.Sprintf("endpoint unavailable (HTTP %d)", code)}
	default:
		return nil, false, &upstreamError{ClassSourceRejected, fmt.Sprintf("query rejected (HTTP %d): %s", code, upstreamMessage(body))}
	}
}

func sanitizeNetErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return truncateString(err.Error(), maxUpstreamMessage)
}

func upstreamMessage(body []byte) string {
	var env struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error != "" {
		return truncateString(env.Error, maxUpstreamMessage)
	}
	return truncateString(strings.TrimSpace(string(body)), maxUpstreamMessage)
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// retentionOf returns the configured or discovered retention; ok is false when unknown.
func (s *source) retentionOf(ctx context.Context) (time.Duration, bool) {
	if s.cfg.Retention > 0 {
		return s.cfg.Retention.D(), true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retentionDone {
		return s.retention, s.retentionKnown
	}
	var (
		r     time.Duration
		known bool
		err   error
	)
	switch {
	case s.cfg.Type == config.SourcePrometheus:
		r, known, err = s.promRetention(ctx)
	case s.cfg.Type == config.SourceVictoriaLogs || s.cfg.Type == config.SourceVictoriaMetrics && s.cfg.AccountID == "":
		r, known, err = s.vmRetention(ctx)
	}
	if err != nil {
		return 0, false
	}
	s.retention, s.retentionKnown, s.retentionDone = r, known, true
	return r, known
}

func (s *source) promRetention(ctx context.Context) (time.Duration, bool, error) {
	body, _, err := s.get(ctx, "/api/v1/status/flags", nil, 1<<20)
	if err != nil {
		return 0, false, err
	}
	var env struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return 0, false, nil
	}
	d, err := model.ParseDuration(env.Data["storage.tsdb.retention.time"])
	if err != nil || d <= 0 {
		return 0, false, nil
	}
	return time.Duration(d), true, nil
}

func (s *source) vmRetention(ctx context.Context) (time.Duration, bool, error) {
	body, _, err := s.get(ctx, "/flags", nil, 1<<20)
	if err != nil {
		return 0, false, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "-retentionPeriod="); ok {
			d, ok := parseVMRetention(strings.Trim(v, `"`))
			return d, ok, nil
		}
	}
	return 0, false, nil
}

func parseVMRetention(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	unit := vmMonth
	switch v[len(v)-1] {
	case 'h':
		unit = time.Hour
	case 'd':
		unit = 24 * time.Hour
	case 'w':
		unit = 7 * 24 * time.Hour
	case 'y':
		unit = 365 * 24 * time.Hour
	}
	num := v
	if unit != vmMonth {
		num = v[:len(v)-1]
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f <= 0 {
		return 0, false
	}
	return time.Duration(f * float64(unit)), true
}

func promTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64)
}

func promDuration(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) + "s"
}

func (s *source) metricsPath(rangeQuery bool) string {
	p := "/api/v1/query"
	if rangeQuery {
		p += "_range"
	}
	switch s.cfg.Type {
	case config.SourceMimir:
		return "/prometheus" + p
	case config.SourceVictoriaMetrics:
		if s.cfg.AccountID != "" {
			tenant := s.cfg.AccountID
			if s.cfg.ProjectID != "" {
				tenant += ":" + s.cfg.ProjectID
			}
			return "/select/" + tenant + "/prometheus" + p
		}
	}
	return p
}

// lookbackQuery is one validated query for an adapter.
type lookbackQuery struct {
	query      string
	metric     bool
	start, end time.Time
	step       time.Duration
	forward    bool
	lim        Limits
}

func responseCap(lim Limits) int64 { return min(max(lim.MaxBytes*4, 1<<20), maxResponseBytes) }

// queryMetrics runs a PromQL or MetricsQL query against Prometheus, Mimir, or VictoriaMetrics.
func (s *source) queryMetrics(ctx context.Context, q lookbackQuery) (*TaskResponse, error) {
	params := url.Values{"query": {q.query}, "timeout": {promDuration(q.lim.timeout())}}
	if q.step > 0 {
		params.Set("start", promTime(q.start))
		params.Set("end", promTime(q.end))
		params.Set("step", promDuration(q.step))
	} else {
		params.Set("time", promTime(q.end))
	}
	body, over, err := s.get(ctx, s.metricsPath(q.step > 0), params, responseCap(q.lim))
	if err != nil {
		return nil, err
	}
	return decodePromEnvelope(body, over, q.lim)
}

// queryLoki runs a LogQL query against Loki.
func (s *source) queryLoki(ctx context.Context, q lookbackQuery) (*TaskResponse, error) {
	params := url.Values{"query": {q.query}, "limit": {strconv.Itoa(q.lim.MaxLines + 1)}}
	path := "/loki/api/v1/query_range"
	switch {
	case q.metric && q.step == 0:
		path = "/loki/api/v1/query"
		params.Set("time", strconv.FormatInt(q.end.UnixNano(), 10))
	default:
		params.Set("start", strconv.FormatInt(q.start.UnixNano(), 10))
		params.Set("end", strconv.FormatInt(q.end.UnixNano(), 10))
		if q.step > 0 {
			params.Set("step", promDuration(q.step))
		}
		params.Set("direction", map[bool]string{true: "forward", false: "backward"}[q.forward])
	}
	body, over, err := s.get(ctx, path, params, responseCap(q.lim))
	if err != nil {
		return nil, err
	}
	return decodePromEnvelope(body, over, q.lim)
}

// queryVictoriaLogs runs LogsQL: log queries on /select/logsql/query, stats on stats_query or stats_query_range.
func (s *source) queryVictoriaLogs(ctx context.Context, q lookbackQuery) (*TaskResponse, error) {
	if !q.metric {
		params := url.Values{"query": {q.query}, "limit": {strconv.Itoa(q.lim.MaxLines + 1)},
			"start": {q.start.UTC().Format(time.RFC3339Nano)}, "end": {q.end.UTC().Format(time.RFC3339Nano)}}
		body, over, err := s.get(ctx, "/select/logsql/query", params, responseCap(q.lim))
		if err != nil {
			return nil, err
		}
		return decodeVictoriaLogsLines(body, over, q.lim)
	}
	params := url.Values{"query": {q.query}}
	path := "/select/logsql/stats_query"
	if q.step > 0 {
		path = "/select/logsql/stats_query_range"
		params.Set("start", q.start.UTC().Format(time.RFC3339Nano))
		params.Set("end", q.end.UTC().Format(time.RFC3339Nano))
		params.Set("step", promDuration(q.step))
	} else {
		params.Set("time", q.end.UTC().Format(time.RFC3339Nano))
	}
	body, over, err := s.get(ctx, path, params, responseCap(q.lim))
	if err != nil {
		return nil, err
	}
	return decodePromEnvelope(body, over, q.lim)
}

type promEnvelope struct {
	Status    string   `json:"status"`
	ErrorType string   `json:"errorType"`
	Error     string   `json:"error"`
	Warnings  []string `json:"warnings"`
	Data      struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type promSample struct {
	T int64
	V string
}

func (p *promSample) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 2 {
		return fmt.Errorf("sample must be [time, value]")
	}
	var ts json.Number
	if err := json.Unmarshal(raw[0], &ts); err != nil {
		var s string
		if err := json.Unmarshal(raw[0], &s); err != nil {
			return err
		}
		ts = json.Number(s)
	}
	f, err := strconv.ParseFloat(string(ts), 64)
	if err != nil {
		return err
	}
	p.T = int64(math.Round(f * 1000))
	return json.Unmarshal(raw[1], &p.V)
}

func (p promSample) point() (Point, error) {
	v, err := strconv.ParseFloat(p.V, 64)
	return Point{p.T, v}, err
}

func decodePromEnvelope(body []byte, over bool, lim Limits) (*TaskResponse, error) {
	if over {
		return &TaskResponse{Truncated: true, Data: Telemetry{ResultType: TypeVector},
			Limitations: []string{fmt.Sprintf("response exceeded the %d byte cap; no result", responseCap(lim))}}, nil
	}
	var env promEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &upstreamError{ClassUnavailable, "malformed response: " + truncateString(err.Error(), maxUpstreamMessage)}
	}
	if env.Status != "success" {
		return nil, &upstreamError{ClassSourceRejected, "query rejected: " + truncateString(env.Error, maxUpstreamMessage)}
	}
	resp := &TaskResponse{Data: Telemetry{ResultType: env.Data.ResultType}}
	for _, w := range env.Warnings {
		resp.Limitations = append(resp.Limitations, "source warning: "+truncateString(w, maxUpstreamMessage))
	}
	bad := func(err error) (*TaskResponse, error) {
		return nil, &upstreamError{ClassUnavailable, "malformed result: " + truncateString(err.Error(), maxUpstreamMessage)}
	}
	var series []Series
	switch env.Data.ResultType {
	case TypeMatrix:
		var rs []struct {
			Metric map[string]string `json:"metric"`
			Values []promSample      `json:"values"`
		}
		if err := json.Unmarshal(env.Data.Result, &rs); err != nil {
			return bad(err)
		}
		for _, r := range rs {
			s := Series{Metric: r.Metric, Points: make([]Point, 0, len(r.Values))}
			for _, v := range r.Values {
				p, err := v.point()
				if err != nil {
					return bad(err)
				}
				s.Points = append(s.Points, p)
			}
			series = append(series, s)
		}
	case TypeVector:
		var rs []struct {
			Metric map[string]string `json:"metric"`
			Value  promSample        `json:"value"`
		}
		if err := json.Unmarshal(env.Data.Result, &rs); err != nil {
			return bad(err)
		}
		for _, r := range rs {
			p, err := r.Value.point()
			if err != nil {
				return bad(err)
			}
			series = append(series, Series{Metric: r.Metric, Points: []Point{p}})
		}
	case TypeScalar:
		var v promSample
		if err := json.Unmarshal(env.Data.Result, &v); err != nil {
			return bad(err)
		}
		p, err := v.point()
		if err != nil {
			return bad(err)
		}
		series = []Series{{Metric: map[string]string{}, Points: []Point{p}}}
	case TypeStreams:
		var rs []struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"`
		}
		if err := json.Unmarshal(env.Data.Result, &rs); err != nil {
			return bad(err)
		}
		var lines []LogLine
		for _, r := range rs {
			for _, v := range r.Values {
				ns, err := strconv.ParseInt(v[0], 10, 64)
				if err != nil {
					return bad(err)
				}
				lines = append(lines, LogLine{Time: time.Unix(0, ns).UTC(), Labels: r.Stream, Text: v[1]})
			}
		}
		resp.Data.Lines = lines
		return resp, nil
	default:
		return nil, &upstreamError{ClassSourceRejected, fmt.Sprintf("unsupported result type %q", env.Data.ResultType)}
	}
	resp.Data.Series = series
	return resp, nil
}

func decodeVictoriaLogsLines(body []byte, over bool, lim Limits) (*TaskResponse, error) {
	resp := &TaskResponse{Data: Telemetry{ResultType: TypeStreams}}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), len(body)+1)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			if over {
				break
			}
			return nil, &upstreamError{ClassUnavailable, "malformed log row: " + truncateString(err.Error(), maxUpstreamMessage)}
		}
		l := LogLine{Labels: map[string]string{}}
		for k, v := range row {
			str, ok := v.(string)
			if !ok {
				str = fmt.Sprint(v)
			}
			switch k {
			case "_msg":
				l.Text = str
			case "_time":
				t, err := time.Parse(time.RFC3339Nano, str)
				if err != nil {
					return nil, &upstreamError{ClassUnavailable, "malformed _time in log row"}
				}
				l.Time = t
			default:
				l.Labels[k] = str
			}
		}
		resp.Data.Lines = append(resp.Data.Lines, l)
	}
	if over {
		resp.Truncated = true
		resp.Limitations = append(resp.Limitations, fmt.Sprintf("response exceeded the %d byte cap; later rows were dropped", responseCap(lim)))
	}
	return resp, nil
}
