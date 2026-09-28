// Package admin is the local unix-socket administration API used by the CLI while the agent holds its lock.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// SocketName is the socket file name inside the state directory.
const SocketName = "admin.sock"

// InvestigateRequest runs one investigation tool locally.
type InvestigateRequest struct {
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args"`
}

// CommitReceipt is an air-gap import receipt confirming the committed head.
type CommitReceipt struct {
	Epoch     string `json:"epoch"`
	Seq       uint64 `json:"seq"`
	ChainHash string `json:"chain_hash"`
}

// Backend is implemented by each role.
type Backend interface {
	Status(ctx context.Context) (any, error)
	Investigate(ctx context.Context, req InvestigateRequest) (any, error)
	// Export writes an export file (protocol.ExportWriter format) of spooled records above fromSeq.
	Export(ctx context.Context, fromSeq uint64, w io.Writer) error
	Deenroll(ctx context.Context, reason string) error
	Commit(ctx context.Context, r CommitReceipt) error
}

// Serve listens on dir/admin.sock (mode 0600) until ctx ends.
func Serve(ctx context.Context, dir string, b Backend) error {
	path := filepath.Join(dir, SocketName)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return errors.Join(err, ln.Close())
	}
	srv := &http.Server{Handler: Handler(b), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err = srv.Serve(ln)
	_ = os.Remove(path)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler exposes the backend over HTTP.
func Handler(b Backend) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		v, err := b.Status(r.Context())
		reply(w, v, err)
	})
	mux.HandleFunc("POST /v1/investigate", func(w http.ResponseWriter, r *http.Request) {
		var req InvestigateRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			reply(w, nil, fmt.Errorf("%w: %w", errBadRequest, err))
			return
		}
		v, err := b.Investigate(r.Context(), req)
		reply(w, v, err)
	})
	mux.HandleFunc("GET /v1/export", func(w http.ResponseWriter, r *http.Request) {
		var from uint64
		if s := r.URL.Query().Get("from"); s != "" {
			if _, err := fmt.Sscan(s, &from); err != nil {
				reply(w, nil, fmt.Errorf("%w: from", errBadRequest))
				return
			}
		}
		var buf bytes.Buffer
		if err := b.Export(r.Context(), from, &buf); err != nil {
			reply(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("POST /v1/deenroll", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req)
		reply(w, map[string]string{"status": "deenrolled"}, b.Deenroll(r.Context(), req.Reason))
	})
	mux.HandleFunc("POST /v1/commit", func(w http.ResponseWriter, r *http.Request) {
		var rc CommitReceipt
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&rc); err != nil {
			reply(w, nil, fmt.Errorf("%w: %w", errBadRequest, err))
			return
		}
		reply(w, map[string]string{"status": "committed"}, b.Commit(r.Context(), rc))
	})
	return mux
}

var errBadRequest = errors.New("bad request")

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errBadRequest) {
			code = http.StatusBadRequest
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// Client talks to a running agent's admin socket.
type Client struct {
	hc *http.Client
}

// Dial returns a client for dir/admin.sock.
func Dial(dir string) *Client {
	path := filepath.Join(dir, SocketName)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
	return &Client{hc: &http.Client{Transport: tr, Timeout: 5 * time.Minute}}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, rd)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("agent admin socket: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("agent: %s", e.Error)
	}
	if w, ok := out.(io.Writer); ok {
		_, err = io.Copy(w, resp.Body)
		return err
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Status returns the agent status document.
func (c *Client) Status(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	return out, c.do(ctx, http.MethodGet, "/v1/status", nil, &out)
}

// Investigate runs a tool and returns its JSON result.
func (c *Client) Investigate(ctx context.Context, req InvestigateRequest) (json.RawMessage, error) {
	var out json.RawMessage
	return out, c.do(ctx, http.MethodPost, "/v1/investigate", req, &out)
}

// Export streams an export file into w.
func (c *Client) Export(ctx context.Context, fromSeq uint64, w io.Writer) error {
	return c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/export?from=%d", fromSeq), nil, w)
}

// Deenroll asks the agent to de-enroll.
func (c *Client) Deenroll(ctx context.Context, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/deenroll", map[string]string{"reason": reason}, nil)
}

// Commit applies an air-gap commit receipt.
func (c *Client) Commit(ctx context.Context, r CommitReceipt) error {
	return c.do(ctx, http.MethodPost, "/v1/commit", r, nil)
}
