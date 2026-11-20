// Package api implements the BSKG REST server: routing, authentication, rate
// limiting, request logging, timeouts, and the response envelope.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bellu/bskg/internal/apikey"
	"github.com/bellu/bskg/internal/graph"
)

// HealthTimeout bounds the /healthz connectivity check (answer within 2 s).
const HealthTimeout = 1500 * time.Millisecond

// Authenticator verifies a raw API key and returns its name. *apikey.Verifier
// implements it. Any failure caused by the key must be apikey.ErrUnauthorized.
type Authenticator interface {
	Verify(ctx context.Context, key string) (string, error)
}

// Config holds the server dependencies and settings.
type Config struct {
	Version      string
	Auth         Authenticator
	Limiter      *KeyRateLimiter
	Meta         MetaReader
	Ping         func(ctx context.Context) error // graph connectivity check, e.g. graph.Client.Verify
	Logger       *slog.Logger
	QueryTimeout time.Duration
	StaleAfter   time.Duration
	Sources      []string // sources listed in graph.sources; default vulkg, nvd
	Now          func() time.Time
}

// Server is the HTTP server skeleton. Later tasks add routes with Handle.
type Server struct {
	cfg  Config
	mux  *http.ServeMux
	meta *metaProvider
}

// New builds a Server. Auth, Limiter, Meta, Ping, and Logger are required.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 10 * time.Second
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 48 * time.Hour
	}
	if len(cfg.Sources) == 0 {
		cfg.Sources = []string{"vulkg", "nvd"}
	}
	s := &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
		meta: &metaProvider{
			reader: cfg.Meta, version: cfg.Version, sources: cfg.Sources,
			stale: cfg.StaleAfter, now: cfg.Now, timeout: HealthTimeout,
		},
	}
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.Handle("/v1/", s.protect(http.HandlerFunc(s.notFound)))
	s.mux.HandleFunc("/", s.notFound)
	return s
}

// Handler returns the root handler with request logging applied.
func (s *Server) Handler() http.Handler { return s.logged(s.mux) }

// Handle registers an authenticated, rate-limited route under /v1. The
// pattern is a Go 1.22 pattern without the prefix, for example
// "GET /vulnerabilities/{id}".
func (s *Server) Handle(pattern string, h http.HandlerFunc) {
	method, path, found := strings.Cut(pattern, " ")
	if !found {
		method, path = "", pattern
	}
	full := "/v1" + path
	if method != "" {
		full = method + " " + full
	}
	s.mux.Handle(full, s.protect(h))
}

// QueryContext returns a context that expires after the per-query timeout.
func (s *Server) QueryContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.cfg.QueryTimeout)
}

// ErrorBody is the "error" object of an error response.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Parameter string `json:"parameter,omitempty"`
}

// WriteJSON writes body (a JSON object) with the graph envelope added.
func (s *Server) WriteJSON(w http.ResponseWriter, r *http.Request, status int, body map[string]any) {
	out := make(map[string]any, len(body)+1)
	for k, v := range body {
		out[k] = v
	}
	out["graph"] = s.meta.get(r.Context())
	writeRaw(w, status, out)
}

// WriteError writes {"error":{...},"graph":{...}}.
func (s *Server) WriteError(w http.ResponseWriter, r *http.Request, status int, e ErrorBody) {
	s.WriteJSON(w, r, status, map[string]any{"error": e})
}

// WriteGraphError maps a Graph_Store failure to a response: 504 on timeout,
// 503 when Neo4j is unreachable, 500 otherwise. No driver text is returned.
func (s *Server) WriteGraphError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		s.WriteError(w, r, http.StatusGatewayTimeout, ErrorBody{Code: "timeout", Message: "the query exceeded its time limit"})
	case graph.Classify(err) == graph.ClassTransient:
		s.WriteError(w, r, http.StatusServiceUnavailable, ErrorBody{Code: "unavailable", Message: "the graph store is unavailable"})
	default:
		s.cfg.Logger.Error("graph query failed", "error", err.Error())
		s.WriteError(w, r, http.StatusInternalServerError, ErrorBody{Code: "internal", Message: "internal error"})
	}
}

func writeRaw(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":{"code":"internal","message":"internal error"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.WriteError(w, r, http.StatusNotFound, ErrorBody{Code: "not_found", Message: "no such route"})
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), HealthTimeout)
	defer cancel()
	if err := s.cfg.Ping(ctx); err != nil {
		writeRaw(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeRaw(w, http.StatusOK, map[string]string{"status": "ok"})
}

type ctxKey struct{}

// KeyName returns the authenticated key name stored by the auth middleware.
func KeyName(ctx context.Context) string {
	n, _ := ctx.Value(ctxKey{}).(string)
	return n
}

// protect applies authentication and the per-key rate limit.
func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			token = ""
		}
		name, err := s.cfg.Auth.Verify(r.Context(), strings.TrimSpace(token))
		if err != nil {
			if errors.Is(err, apikey.ErrUnauthorized) {
				// One body for missing, malformed, unknown, and revoked keys.
				s.WriteError(w, r, http.StatusUnauthorized, ErrorBody{Code: "unauthorized", Message: "missing or invalid API key"})
				return
			}
			s.WriteGraphError(w, r, err)
			return
		}
		if h, ok := r.Context().Value(holderKey{}).(*keyHolder); ok {
			h.name = name
		}
		if allowed, retry := s.cfg.Limiter.Allow(name); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
			s.WriteError(w, r, http.StatusTooManyRequests, ErrorBody{Code: "rate_limited", Message: "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, name)))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// logged writes one log line per request: key name, method, path (no query
// string), status, and duration. The key itself is never logged.
func (s *Server) logged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.cfg.Now()
		holder := &keyHolder{}
		r = r.WithContext(context.WithValue(r.Context(), holderKey{}, holder))
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		name := holder.name
		if name == "" {
			name = "none"
		}
		s.cfg.Logger.Info("request",
			"keyName", name, "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "durationMs", s.cfg.Now().Sub(start).Milliseconds())
	})
}

type holderKey struct{}

type keyHolder struct{ name string }
