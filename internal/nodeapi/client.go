package nodeapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Client defaults.
const (
	DefaultClientTimeout   = 30 * time.Second
	DefaultLongPollTimeout = DefaultLongPollMax + 20*time.Second
)

// Error is a failed API call; Retryable is set for network errors, 5xx, 408, and 429.
type Error struct {
	Op         string
	StatusCode int
	Message    string
	Retryable  bool
	// Malformed is set when the request content itself is refused (HTTP 400 or 413) or cannot be encoded.
	Malformed bool
	Err       error
}

func (e *Error) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("nodeapi: %s: HTTP %d: %s", e.Op, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("nodeapi: %s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// IsRetryable reports whether err is an Error worth retrying.
func IsRetryable(err error) bool {
	e, ok := errors.AsType[*Error](err)
	return ok && e.Retryable
}

// IsMalformed reports whether the request content was refused; authentication, authorization, and transport failures never are.
func IsMalformed(err error) bool {
	e, ok := errors.AsType[*Error](err)
	return ok && e.Malformed
}

func malformedStatus(code int) bool {
	return code == http.StatusBadRequest || code == http.StatusRequestEntityTooLarge
}

func retryableStatus(code int) bool {
	return code >= 500 || code == http.StatusTooManyRequests || code == http.StatusRequestTimeout
}

// ClientOptions configures NewClient.
type ClientOptions struct {
	BaseURL string
	// CAFile verifies the coordinator certificate; empty uses the system roots.
	CAFile string
	// TokenFile is reread on every request because the kubelet rotates it.
	TokenFile       string
	Node            string
	Timeout         time.Duration
	LongPollTimeout time.Duration
}

// Client is the node agent side of the API. Retries are the caller's job.
type Client struct {
	base      string
	hc        *http.Client
	tokenFile string
	node      string
	timeout   time.Duration
	longPoll  time.Duration
}

// NewClient builds a client for the coordinator Service.
func NewClient(o ClientOptions) (*Client, error) {
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("nodeapi: base URL %q must be an https URL", o.BaseURL)
	}
	if o.TokenFile == "" {
		return nil, errors.New("nodeapi: client requires a token file")
	}
	if err := checkNode(o.Node); err != nil {
		return nil, err
	}
	tlsc := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("nodeapi: reading CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("nodeapi: CA file %s holds no certificates", o.CAFile)
		}
		tlsc.RootCAs = pool
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultClientTimeout
	}
	if o.LongPollTimeout <= 0 {
		o.LongPollTimeout = DefaultLongPollTimeout
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsc,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	return &Client{
		base: strings.TrimRight(u.String(), "/"), hc: &http.Client{Transport: tr},
		tokenFile: o.TokenFile, node: o.Node, timeout: o.Timeout, longPoll: o.LongPollTimeout,
	}, nil
}

func (c *Client) token() (string, error) {
	b, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("token file is empty")
	}
	return t, nil
}

// do performs one call; it returns false without error on 204.
func (c *Client) do(ctx context.Context, op, method, path string, timeout time.Duration, in, out any) (bool, error) {
	var body io.Reader
	if in != nil {
		b, err := Marshal(in)
		if err != nil {
			return false, &Error{Op: op, Malformed: true, Err: err}
		}
		body = bytes.NewReader(b)
	}
	tok, err := c.token()
	if err != nil {
		return false, &Error{Op: op, Retryable: true, Err: fmt.Errorf("reading token: %w", err)}
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, method, c.base+path, body)
	if err != nil {
		return false, &Error{Op: op, Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", ContentType)
	if in != nil {
		req.Header.Set("Content-Type", ContentType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, &Error{Op: op, Retryable: true, Err: err}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return false, nil
	case http.StatusOK:
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, &Error{Op: op, StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(msg)), Retryable: retryableStatus(resp.StatusCode),
			Malformed: malformedStatus(resp.StatusCode)}
	}
	if out == nil {
		return true, nil
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != ContentType {
		return false, &Error{Op: op, Err: fmt.Errorf("unexpected response content type %q", resp.Header.Get("Content-Type"))}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, &Error{Op: op, Retryable: true, Err: err}
	}
	if err := decode(b, out, MaxResponseBytes, true); err != nil {
		return false, &Error{Op: op, Err: err}
	}
	return true, nil
}

// Register announces the node and returns the target bundle version.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	req.Node = c.node
	var resp RegisterResponse
	_, err := c.do(ctx, "register", http.MethodPost, "/v1/node/register", c.timeout, req, &resp)
	return resp, err
}

// Submit sends items of the queue in ascending sequence order and returns the highest durably acknowledged sequence.
func (c *Client) Submit(ctx context.Context, queue string, items []Item) (uint64, error) {
	var resp SubmitResponse
	_, err := c.do(ctx, "submit", http.MethodPost, "/v1/node/records", c.timeout, SubmitRequest{Node: c.node, Queue: queue, Items: items}, &resp)
	return resp.AckedThrough, err
}

// WaitBundle long-polls for a target bundle other than have; nil means no change before the poll ended.
func (c *Client) WaitBundle(ctx context.Context, have string) (*BundlePayload, error) {
	var p BundlePayload
	ok, err := c.do(ctx, "bundle", http.MethodGet, "/v1/node/bundle?have="+url.QueryEscape(have), c.longPoll, nil, &p)
	if !ok {
		return nil, err
	}
	return &p, nil
}

// WaitKube long-polls for a kube series revision above since; nil means no change.
func (c *Client) WaitKube(ctx context.Context, since uint64) (*KubeUpdate, error) {
	var u KubeUpdate
	ok, err := c.do(ctx, "kube", http.MethodGet, "/v1/node/kube?since="+strconv.FormatUint(since, 10), c.longPoll, nil, &u)
	if !ok {
		return nil, err
	}
	return &u, nil
}

// WaitTasks long-polls for pending tasks; nil means none arrived.
func (c *Client) WaitTasks(ctx context.Context) ([]Task, error) {
	var l TaskList
	_, err := c.do(ctx, "tasks", http.MethodGet, "/v1/node/tasks", c.longPoll, nil, &l)
	return l.Tasks, err
}

// PostResult reports a task result.
func (c *Client) PostResult(ctx context.Context, res TaskResult) error {
	if !validID(res.ID) {
		return &Error{Op: "task result", Err: invalid("task id %q", res.ID)}
	}
	_, err := c.do(ctx, "task result", http.MethodPost, "/v1/node/tasks/"+url.PathEscape(res.ID), c.timeout, res, nil)
	return err
}
