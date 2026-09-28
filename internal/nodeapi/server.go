package nodeapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

// Server defaults.
const (
	DefaultLongPollMax  = 55 * time.Second
	DefaultAuthLogEvery = 10 * time.Second
)

// AuditImpersonation is the AuditEvent kind for a submission naming another node.
const AuditImpersonation = "impersonation"

// ErrUnknownTask is returned by Backend.TaskResult for a task not assigned to the node.
var ErrUnknownTask = errors.New("nodeapi: unknown task")

// AuditEvent records a security-relevant rejection.
type AuditEvent struct {
	Kind              string
	Time              time.Time
	AuthenticatedNode string
	ClaimedNode       string
	Namespace         string
	Pod               string
	PodUID            string
	Method            string
	Path              string
	RemoteAddr        string
}

// Backend is the coordinator side of the API; node is always the authenticated node.
type Backend interface {
	Register(ctx context.Context, node string, req RegisterRequest) (RegisterResponse, error)
	// Submit returns only after the items are durably stored.
	Submit(ctx context.Context, node string, items []Item) (ackedThrough uint64, err error)
	// Bundle returns nil when have is current; changed is closed once the answer may differ.
	Bundle(ctx context.Context, node, have string) (*BundlePayload, <-chan struct{}, error)
	// Kube reports nothing new while the revision is at most since.
	Kube(ctx context.Context, node string, since uint64) (KubeUpdate, <-chan struct{}, error)
	Tasks(ctx context.Context, node string) ([]Task, <-chan struct{}, error)
	TaskResult(ctx context.Context, node string, res TaskResult) error
}

// Options configures NewServer.
type Options struct {
	Auth         *Authenticator
	Backend      Backend
	Audit        func(AuditEvent)
	Clock        func() time.Time
	MaxBody      int64
	LongPollMax  time.Duration
	Logger       *slog.Logger
	AuthLogEvery time.Duration
}

type server struct {
	o          Options
	logMu      sync.Mutex
	lastLog    time.Time
	suppressed int
}

// NewServer returns the node API handler; the http.Server write timeout must exceed LongPollMax.
func NewServer(o Options) http.Handler {
	if o.Auth == nil || o.Backend == nil {
		panic("nodeapi: NewServer requires Auth and Backend")
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.MaxBody <= 0 {
		o.MaxBody = MaxRequestBytes
	}
	if o.LongPollMax <= 0 {
		o.LongPollMax = DefaultLongPollMax
	}
	if o.AuthLogEvery <= 0 {
		o.AuthLogEvery = DefaultAuthLogEvery
	}
	if o.Logger == nil {
		o.Logger = slog.New(redact.NewHandler(slog.Default().Handler(), redact.Default()))
	}
	s := &server{o: o}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/node/register", s.auth(s.register))
	mux.HandleFunc("POST /v1/node/records", s.auth(s.records))
	mux.HandleFunc("GET /v1/node/bundle", s.auth(s.bundle))
	mux.HandleFunc("GET /v1/node/kube", s.auth(s.kube))
	mux.HandleFunc("GET /v1/node/tasks", s.auth(s.tasks))
	mux.HandleFunc("POST /v1/node/tasks/{id}", s.auth(s.taskResult))
	return mux
}

func (s *server) auth(h func(http.ResponseWriter, *http.Request, Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var id Identity
		err := unauthenticated("missing bearer token")
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			id, err = s.o.Auth.Authenticate(r.Context(), strings.TrimSpace(tok))
		}
		if err != nil {
			s.logAuthFailure(r, err)
			if errors.Is(err, ErrAuthUnavailable) {
				http.Error(w, "token verification unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="exitmesh-coordinator"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r, id)
	}
}

func (s *server) logAuthFailure(r *http.Request, err error) {
	s.logMu.Lock()
	now := s.o.Clock()
	if !s.lastLog.IsZero() && now.Sub(s.lastLog) < s.o.AuthLogEvery {
		s.suppressed++
		s.logMu.Unlock()
		return
	}
	n := s.suppressed
	s.lastLog, s.suppressed = now, 0
	s.logMu.Unlock()
	s.o.Logger.Warn("node api authentication failed", "remote", r.RemoteAddr, "path", r.URL.Path, "error", err.Error(), "suppressed", n)
}

func (s *server) read(w http.ResponseWriter, r *http.Request, v any, validate bool) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != ContentType {
		http.Error(w, "content type must be "+ContentType, http.StatusUnsupportedMediaType)
		return false
	}
	if r.ContentLength > s.o.MaxBody {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.o.MaxBody))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "reading request body failed", http.StatusBadRequest)
		}
		return false
	}
	if err := decode(b, v, s.o.MaxBody, validate); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func (s *server) write(w http.ResponseWriter, v any) {
	b, err := Marshal(v)
	if err != nil {
		s.o.Logger.Error("node api response encoding failed", "error", err.Error())
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *server) backendError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, ErrUnknownTask):
		http.Error(w, "unknown task", http.StatusNotFound)
	case r.Context().Err() != nil:
	default:
		s.o.Logger.Error("node api backend failed", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "coordinator unavailable", http.StatusServiceUnavailable)
	}
}

func (s *server) impersonation(w http.ResponseWriter, r *http.Request, id Identity, claimed string) {
	if s.o.Audit != nil {
		s.o.Audit(AuditEvent{
			Kind: AuditImpersonation, Time: s.o.Clock(), AuthenticatedNode: id.Node, ClaimedNode: claimed,
			Namespace: id.Namespace, Pod: id.Pod, PodUID: id.PodUID, Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr,
		})
	}
	http.Error(w, "request names a node other than the authenticated node", http.StatusForbidden)
}

func (s *server) register(w http.ResponseWriter, r *http.Request, id Identity) {
	var req RegisterRequest
	if !s.read(w, r, &req, false) {
		return
	}
	if req.Node != id.Node {
		s.impersonation(w, r, id, req.Node)
		return
	}
	if err := req.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.o.Backend.Register(r.Context(), id.Node, req)
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	resp.ServerTimeMs = s.o.Clock().UnixMilli()
	s.write(w, resp)
}

func (s *server) records(w http.ResponseWriter, r *http.Request, id Identity) {
	var req SubmitRequest
	if !s.read(w, r, &req, false) {
		return
	}
	if req.Node != id.Node {
		s.impersonation(w, r, id, req.Node)
		return
	}
	nodes, err := req.claims()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, n := range nodes {
		if n != id.Node {
			s.impersonation(w, r, id, n)
			return
		}
	}
	acked, err := s.o.Backend.Submit(r.Context(), id.Node, req.Items)
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	s.write(w, SubmitResponse{AckedThrough: acked})
}

// poll answers from fetch, waiting on its change channel until LongPollMax, then replies 204.
func (s *server) poll(w http.ResponseWriter, r *http.Request, fetch func(context.Context) (any, <-chan struct{}, error)) {
	ctx := r.Context()
	timer := time.NewTimer(s.o.LongPollMax)
	defer timer.Stop()
	var woke <-chan struct{}
	for {
		body, changed, err := fetch(ctx)
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		if body != nil {
			s.write(w, body)
			return
		}
		if changed == woke {
			// A closed channel returned again would spin; wait for the deadline instead.
			changed = nil
		}
		select {
		case <-changed:
			woke = changed
		case <-timer.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *server) bundle(w http.ResponseWriter, r *http.Request, id Identity) {
	have := r.URL.Query().Get("have")
	if len(have) > maxVersion {
		http.Error(w, "have is too long", http.StatusBadRequest)
		return
	}
	s.poll(w, r, func(ctx context.Context) (any, <-chan struct{}, error) {
		p, ch, err := s.o.Backend.Bundle(ctx, id.Node, have)
		if err != nil || p == nil || p.Version == have {
			return nil, ch, err
		}
		return p, ch, nil
	})
}

func (s *server) kube(w http.ResponseWriter, r *http.Request, id Identity) {
	var since uint64
	if q := r.URL.Query().Get("since"); q != "" {
		v, err := strconv.ParseUint(q, 10, 64)
		if err != nil {
			http.Error(w, "since must be an unsigned integer", http.StatusBadRequest)
			return
		}
		since = v
	}
	s.poll(w, r, func(ctx context.Context) (any, <-chan struct{}, error) {
		u, ch, err := s.o.Backend.Kube(ctx, id.Node, since)
		if err != nil || u.Revision <= since {
			return nil, ch, err
		}
		return u, ch, nil
	})
}

func (s *server) tasks(w http.ResponseWriter, r *http.Request, id Identity) {
	s.poll(w, r, func(ctx context.Context) (any, <-chan struct{}, error) {
		ts, ch, err := s.o.Backend.Tasks(ctx, id.Node)
		if err != nil || len(ts) == 0 {
			return nil, ch, err
		}
		return TaskList{Tasks: ts}, ch, nil
	})
}

func (s *server) taskResult(w http.ResponseWriter, r *http.Request, id Identity) {
	tid := r.PathValue("id")
	if !validID(tid) {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}
	var res TaskResult
	if !s.read(w, r, &res, true) {
		return
	}
	if res.ID != tid {
		http.Error(w, "task id does not match the path", http.StatusBadRequest)
		return
	}
	if err := s.o.Backend.TaskResult(r.Context(), id.Node, res); err != nil {
		s.backendError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
