// Package api is the versioned HTTP API and the process's HTTP router.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/configsync"
	"github.com/Arequ/mission-control/internal/httpx"
	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/version"
	"github.com/Arequ/mission-control/openapi"
)

type contextKey int

const (
	principalKey contextKey = iota
	runnerKey
)

// Server is the HTTP application.
type Server struct {
	Store        store.Store
	EnrollSecret string
	CORSOrigins  []string
	WebDir       string
	Sync         *configsync.Syncer
	started      time.Time
}

// New builds a server. CORSOrigins may contain "*" or explicit origins.
func New(st store.Store, enrollSecret string) *Server {
	return &Server{Store: st, EnrollSecret: enrollSecret, started: time.Now().UTC()}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/openapi.yaml", s.openAPI)

	osq := &osquery.Handler{Store: s.Store, EnrollSecret: s.EnrollSecret}
	osq.Register(mux)

	mux.HandleFunc("GET /api/v1/me", s.me)
	mux.HandleFunc("POST /api/v1/tokens", s.createToken)

	mux.HandleFunc("GET /api/v1/fleet/summary", s.fleetSummary)
	mux.HandleFunc("GET /api/v1/devices", s.listDevices)
	mux.HandleFunc("GET /api/v1/devices/{id}", s.getDevice)
	mux.HandleFunc("GET /api/v1/devices/{id}/apps", s.listApps)
	mux.HandleFunc("GET /api/v1/devices/{id}/results", s.listResults)

	mux.HandleFunc("GET /api/v1/resources", s.listResources)
	mux.HandleFunc("GET /api/v1/resources/{kind}", s.listResourcesByKind)
	mux.HandleFunc("GET /api/v1/resources/{kind}/{name}", s.getResource)
	mux.HandleFunc("GET /api/v1/resources/{kind}/{namespace}/{name}", s.getResourceNS)

	mux.HandleFunc("POST /api/v1/config/validate", s.validateConfig)
	mux.HandleFunc("POST /api/v1/config/plan", s.planConfig)
	mux.HandleFunc("POST /api/v1/config/apply", s.applyConfig)
	mux.HandleFunc("POST /api/v1/config/sync", s.syncConfig)
	mux.HandleFunc("GET /api/v1/config/status", s.configStatus)
	mux.HandleFunc("GET /api/v1/config/export", s.exportConfig)

	mux.HandleFunc("POST /api/v1/queries/live", s.createLiveQuery)
	mux.HandleFunc("GET /api/v1/queries/live", s.listLiveQueries)
	mux.HandleFunc("GET /api/v1/queries/live/{id}", s.getLiveQuery)

	mux.HandleFunc("GET /api/v1/munki/repo", s.munkiRepoResource)
	mux.HandleFunc("GET /api/v1/munki/catalogs", s.munkiCatalogs)
	mux.HandleFunc("GET /api/v1/munki/manifests", s.munkiManifests)
	mux.HandleFunc("GET /api/v1/munki/packages", s.munkiPackages)
	mux.HandleFunc("GET /munki/repo/{path...}", s.munkiClient)

	mux.HandleFunc("GET /api/v1/autopkg/repos", s.autopkgRepos)
	mux.HandleFunc("GET /api/v1/autopkg/pipelines", s.autopkgPipelines)
	mux.HandleFunc("POST /api/v1/autopkg/pipelines/{name}/runs", s.runPipeline)
	mux.HandleFunc("GET /api/v1/autopkg/runs", s.listJobs)
	mux.HandleFunc("GET /api/v1/autopkg/runs/{id}", s.getJob)
	mux.HandleFunc("GET /api/v1/runners", s.listRunners)
	mux.HandleFunc("POST /api/v1/runners", s.createRunner)

	mux.HandleFunc("POST /api/v1/runner/heartbeat", s.runnerHeartbeat)
	mux.HandleFunc("POST /api/v1/runner/jobs/claim", s.runnerClaim)
	mux.HandleFunc("POST /api/v1/runner/jobs/{id}/logs", s.runnerLogs)
	mux.HandleFunc("POST /api/v1/runner/jobs/{id}/complete", s.runnerComplete)

	if s.WebDir != "" {
		mux.Handle("/", s.spa(s.WebDir))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			httpx.WriteJSON(w, http.StatusOK, map[string]any{
				"name":    "mission-control",
				"version": version.Version,
				"api":     "/api/v1",
				"openapi": "/api/openapi.yaml",
			})
		})
	}
	return s.wrap(mux)
}

func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Mission-Control-Version", version.Version)
		ww := &statusWriter{ResponseWriter: w, status: 200}
		if s.cors(ww, r) {
			return
		}
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "err", rec, "path", r.URL.Path)
				httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
			}
			slog.Info("request", "method", r.Method, "path", r.URL.Path, "status", ww.status, "ms", time.Since(start).Milliseconds())
		}()
		if !isPublic(r) {
			if !s.authenticate(ww, r) {
				return
			}
		}
		next.ServeHTTP(ww, r)
	})
}

func isPublic(r *http.Request) bool {
	if r.Method == http.MethodOptions {
		return true
	}
	p := r.URL.Path
	switch {
	case p == "/healthz" || p == "/api/openapi.yaml":
		return true
	case strings.HasPrefix(p, "/osquery/"):
		return true
	case strings.HasPrefix(p, "/api/"):
		return false
	default:
		return true
	}
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	token := bearer(r)
	if token == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "bearer token required")
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/runner/") {
		runner, err := s.Store.AuthenticateRunner(r.Context(), token)
		if err != nil {
			s.writeStoreErr(w, r, err)
			return false
		}
		*r = *r.WithContext(context.WithValue(r.Context(), runnerKey, runner))
		return true
	}
	principal, err := s.Store.AuthenticateToken(r.Context(), token)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return false
	}
	*r = *r.WithContext(context.WithValue(r.Context(), principalKey, principal))
	return true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, prefix))
}

func principalFrom(r *http.Request) auth.Principal {
	p, _ := r.Context().Value(principalKey).(auth.Principal)
	return p
}

func runnerFrom(r *http.Request) store.Runner {
	runner, _ := r.Context().Value(runnerKey).(store.Runner)
	return runner
}

func (s *Server) require(w http.ResponseWriter, r *http.Request, role string) bool {
	if !auth.Allows(principalFrom(r).Role, role) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden", "requires role "+role)
		return false
	}
	return true
}

func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" && s.originAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func (s *Server) originAllowed(origin string) bool {
	if len(s.CORSOrigins) == 0 {
		return false
	}
	for _, allowed := range s.CORSOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version.Version})
}

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapi.Spec)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, principalFrom(r))
}

func (s *Server) writeStoreErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, store.ErrConflict):
		httpx.WriteError(w, http.StatusConflict, "conflict", "already exists")
	case errors.Is(err, store.ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid request")
	case errors.Is(err, store.ErrUnauthorized):
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
	default:
		slog.Error("request failed", "err", err, "path", r.URL.Path)
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (s *Server) spa(dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		clean := filepath.Clean(r.URL.Path)
		target := filepath.Join(dir, clean)
		info, err := os.Stat(target)
		if err != nil || info.IsDir() {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}
