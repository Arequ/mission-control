// Package httpapi is the versioned HTTP API and the Munki repo server.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/configrepo"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/store"
)

type principalKey struct{}

// Server is the Mission Control HTTP server.
type Server struct {
	store        *store.Store
	blobs        storage.Storage
	log          *slog.Logger
	webDir       string
	repoToken    string
	devCORS      bool
	offlineAfter time.Duration
	maxUpload    int64
	inventory    time.Duration
	forward      osquery.Forwarder
	logRetention time.Duration
	configRepo   configrepo.Repo
}

// Options configures the server.
type Options struct {
	Store             *store.Store
	Blobs             storage.Storage
	Logger            *slog.Logger
	WebDir            string
	RepoToken         string
	DevCORS           bool
	OfflineAfter      time.Duration
	MaxUpload         int64
	InventoryInterval time.Duration
	Forwarder         osquery.Forwarder
	LogRetention      time.Duration
	ConfigRepo        configrepo.Repo
}

// New builds a server.
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.OfflineAfter == 0 {
		opts.OfflineAfter = 45 * time.Second
	}
	if opts.MaxUpload == 0 {
		opts.MaxUpload = 512 << 20
	}
	if opts.InventoryInterval == 0 {
		opts.InventoryInterval = 5 * time.Minute
	}
	if opts.Forwarder == nil {
		opts.Forwarder = osquery.NopForwarder{}
	}
	if opts.ConfigRepo.Slug == "" {
		opts.ConfigRepo = configrepo.Default()
	}
	return &Server{
		store:        opts.Store,
		blobs:        opts.Blobs,
		log:          opts.Logger,
		webDir:       opts.WebDir,
		repoToken:    opts.RepoToken,
		devCORS:      opts.DevCORS,
		offlineAfter: opts.OfflineAfter,
		maxUpload:    opts.MaxUpload,
		inventory:    opts.InventoryInterval,
		forward:      opts.Forwarder,
		logRetention: opts.LogRetention,
		configRepo:   opts.ConfigRepo,
	}
}

// Tick runs one scheduler, reclaim, and promotion pass.
func (s *Server) Tick(ctx context.Context) error {
	if _, err := s.store.EnqueueDue(ctx); err != nil {
		return err
	}
	if _, _, err := s.store.ReclaimExpired(ctx); err != nil {
		return err
	}
	if _, err := s.store.PromoteDue(ctx); err != nil {
		return err
	}
	if err := s.store.ExpireLiveQueries(ctx); err != nil {
		return err
	}
	if err := s.store.SyncDueConnectors(ctx); err != nil {
		return err
	}
	if err := s.store.CorrelateVulnerabilities(ctx, false); err != nil {
		return err
	}
	if err := s.store.SyncVulnerabilitiesDue(ctx); err != nil {
		return err
	}
	if s.logRetention > 0 {
		if _, err := s.store.PurgeOsqueryLogs(ctx, s.logRetention); err != nil {
			return err
		}
	}
	return nil
}

// Handler is the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/openapi.yaml", s.openAPI)
	mux.HandleFunc("GET /openapi.yaml", s.openAPI)
	mux.HandleFunc("GET /api/v1/meta", s.meta)

	mux.Handle("GET /api/v1/audit", s.withAPI("audit:read", http.HandlerFunc(s.listAudit)))
	mux.Handle("POST /api/v1/tokens", s.withAPI("admin", http.HandlerFunc(s.createToken)))
	mux.Handle("GET /api/v1/tokens", s.withAPI("admin", http.HandlerFunc(s.listTokens)))
	mux.Handle("DELETE /api/v1/tokens/{id}", s.withAPI("admin", http.HandlerFunc(s.deleteToken)))

	mux.Handle("GET /api/v1/recipe-repos", s.withAPI("config:read", http.HandlerFunc(s.listRepos)))
	mux.Handle("POST /api/v1/recipe-repos", s.withConfigWrite(http.HandlerFunc(s.createRepo)))
	mux.Handle("GET /api/v1/recipe-repos/{id}", s.withAPI("config:read", http.HandlerFunc(s.getRepo)))
	mux.Handle("PUT /api/v1/recipe-repos/{id}", s.withConfigWrite(http.HandlerFunc(s.updateRepo)))
	mux.Handle("DELETE /api/v1/recipe-repos/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteRepo)))

	mux.Handle("GET /api/v1/recipes", s.withAPI("config:read", http.HandlerFunc(s.listRecipes)))
	mux.Handle("POST /api/v1/recipes", s.withConfigWrite(http.HandlerFunc(s.createRecipe)))
	mux.Handle("GET /api/v1/recipes/{id}", s.withAPI("config:read", http.HandlerFunc(s.getRecipe)))
	mux.Handle("PUT /api/v1/recipes/{id}", s.withConfigWrite(http.HandlerFunc(s.updateRecipe)))
	mux.Handle("DELETE /api/v1/recipes/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteRecipe)))

	mux.Handle("GET /api/v1/schedules", s.withAPI("config:read", http.HandlerFunc(s.listSchedules)))
	mux.Handle("POST /api/v1/schedules", s.withConfigWrite(http.HandlerFunc(s.createSchedule)))
	mux.Handle("GET /api/v1/schedules/{id}", s.withAPI("config:read", http.HandlerFunc(s.getSchedule)))
	mux.Handle("PUT /api/v1/schedules/{id}", s.withConfigWrite(http.HandlerFunc(s.updateSchedule)))
	mux.Handle("DELETE /api/v1/schedules/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteSchedule)))

	mux.Handle("GET /api/v1/pipeline-settings", s.withAPI("config:read", http.HandlerFunc(s.getSettings)))
	mux.Handle("PUT /api/v1/pipeline-settings", s.withConfigWrite(http.HandlerFunc(s.updateSettings)))
	mux.Handle("DELETE /api/v1/pipeline-settings", s.withConfigWrite(http.HandlerFunc(s.resetSettings)))

	mux.Handle("GET /api/v1/promotion-rules", s.withAPI("config:read", http.HandlerFunc(s.listRules)))
	mux.Handle("POST /api/v1/promotion-rules", s.withConfigWrite(http.HandlerFunc(s.createRule)))
	mux.Handle("GET /api/v1/promotion-rules/{id}", s.withAPI("config:read", http.HandlerFunc(s.getRule)))
	mux.Handle("PUT /api/v1/promotion-rules/{id}", s.withConfigWrite(http.HandlerFunc(s.updateRule)))
	mux.Handle("DELETE /api/v1/promotion-rules/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteRule)))

	mux.Handle("GET /api/v1/runner-pools", s.withAPI("config:read", http.HandlerFunc(s.listPools)))
	mux.Handle("POST /api/v1/runner-pools", s.withConfigWrite(http.HandlerFunc(s.createPool)))
	mux.Handle("GET /api/v1/runner-pools/{id}", s.withAPI("config:read", http.HandlerFunc(s.getPool)))
	mux.Handle("PUT /api/v1/runner-pools/{id}", s.withConfigWrite(http.HandlerFunc(s.updatePool)))
	mux.Handle("DELETE /api/v1/runner-pools/{id}", s.withConfigWrite(http.HandlerFunc(s.deletePool)))

	mux.Handle("GET /api/v1/manifests", s.withAPI("config:read", http.HandlerFunc(s.listManifests)))
	mux.Handle("POST /api/v1/manifests", s.withConfigWrite(http.HandlerFunc(s.createManifest)))
	mux.Handle("GET /api/v1/manifests/{id}", s.withAPI("config:read", http.HandlerFunc(s.getManifest)))
	mux.Handle("PUT /api/v1/manifests/{id}", s.withConfigWrite(http.HandlerFunc(s.updateManifest)))
	mux.Handle("DELETE /api/v1/manifests/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteManifest)))

	mux.Handle("GET /api/v1/osquery/queries", s.withAPI("config:read", http.HandlerFunc(s.listOsqueryQueries)))
	mux.Handle("POST /api/v1/osquery/queries", s.withConfigWrite(http.HandlerFunc(s.createOsqueryQuery)))
	mux.Handle("GET /api/v1/osquery/queries/{id}", s.withAPI("config:read", http.HandlerFunc(s.getOsqueryQuery)))
	mux.Handle("PUT /api/v1/osquery/queries/{id}", s.withConfigWrite(http.HandlerFunc(s.updateOsqueryQuery)))
	mux.Handle("DELETE /api/v1/osquery/queries/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteOsqueryQuery)))

	mux.Handle("GET /api/v1/osquery/packs", s.withAPI("config:read", http.HandlerFunc(s.listOsqueryPacks)))
	mux.Handle("POST /api/v1/osquery/packs", s.withConfigWrite(http.HandlerFunc(s.createOsqueryPack)))
	mux.Handle("GET /api/v1/osquery/packs/{id}", s.withAPI("config:read", http.HandlerFunc(s.getOsqueryPack)))
	mux.Handle("PUT /api/v1/osquery/packs/{id}", s.withConfigWrite(http.HandlerFunc(s.updateOsqueryPack)))
	mux.Handle("DELETE /api/v1/osquery/packs/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteOsqueryPack)))

	mux.Handle("GET /api/v1/osquery/labels", s.withAPI("config:read", http.HandlerFunc(s.listOsqueryLabels)))
	mux.Handle("POST /api/v1/osquery/labels", s.withConfigWrite(http.HandlerFunc(s.createOsqueryLabel)))
	mux.Handle("GET /api/v1/osquery/labels/{id}", s.withAPI("config:read", http.HandlerFunc(s.getOsqueryLabel)))
	mux.Handle("PUT /api/v1/osquery/labels/{id}", s.withConfigWrite(http.HandlerFunc(s.updateOsqueryLabel)))
	mux.Handle("DELETE /api/v1/osquery/labels/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteOsqueryLabel)))

	mux.Handle("GET /api/v1/osquery/enroll-secrets", s.withAPI("config:read", http.HandlerFunc(s.listEnrollSecrets)))
	mux.Handle("POST /api/v1/osquery/enroll-secrets", s.withConfigWrite(http.HandlerFunc(s.createEnrollSecret)))
	mux.Handle("GET /api/v1/osquery/enroll-secrets/{id}", s.withAPI("config:read", http.HandlerFunc(s.getEnrollSecret)))
	mux.Handle("PUT /api/v1/osquery/enroll-secrets/{id}", s.withConfigWrite(http.HandlerFunc(s.updateEnrollSecret)))
	mux.Handle("DELETE /api/v1/osquery/enroll-secrets/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteEnrollSecret)))

	mux.Handle("GET /api/v1/log-views", s.withAPI("config:read", http.HandlerFunc(s.listLogViews)))
	mux.Handle("POST /api/v1/log-views", s.withConfigWrite(http.HandlerFunc(s.createLogView)))
	mux.Handle("GET /api/v1/log-views/{id}", s.withAPI("config:read", http.HandlerFunc(s.getLogView)))
	mux.Handle("PUT /api/v1/log-views/{id}", s.withConfigWrite(http.HandlerFunc(s.updateLogView)))
	mux.Handle("DELETE /api/v1/log-views/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteLogView)))
	mux.Handle("POST /api/v1/log-views/{id}/query", s.withAPI("logs:read", http.HandlerFunc(s.queryLogView)))
	mux.Handle("POST /api/v1/log-views/{id}/tail", s.withAPI("logs:read", http.HandlerFunc(s.tailLogView)))
	mux.Handle("POST /api/v1/log-views/{id}/context", s.withAPI("logs:read", http.HandlerFunc(s.contextLogView)))

	mux.Handle("GET /api/v1/source-connectors", s.withAPI("config:read", http.HandlerFunc(s.listConnectors)))
	mux.Handle("POST /api/v1/source-connectors", s.withConfigWrite(http.HandlerFunc(s.createConnector)))
	mux.Handle("GET /api/v1/source-connectors/{id}", s.withAPI("config:read", http.HandlerFunc(s.getConnector)))
	mux.Handle("PUT /api/v1/source-connectors/{id}", s.withConfigWrite(http.HandlerFunc(s.updateConnector)))
	mux.Handle("DELETE /api/v1/source-connectors/{id}", s.withConfigWrite(http.HandlerFunc(s.deleteConnector)))

	mux.Handle("GET /api/v1/coverage/matrix", s.withAPI("osquery:read", http.HandlerFunc(s.coverageMatrix)))
	mux.Handle("GET /api/v1/coverage/devices/{id}", s.withAPI("osquery:read", http.HandlerFunc(s.coverageDevice)))
	mux.Handle("GET /api/v1/coverage/connectors", s.withAPI("osquery:read", http.HandlerFunc(s.coverageConnectors)))

	mux.Handle("GET /api/v1/fleet/summary", s.withAPI("osquery:read", http.HandlerFunc(s.fleetSummary)))
	mux.Handle("GET /api/v1/devices", s.withAPI("osquery:read", http.HandlerFunc(s.listDevices)))
	mux.Handle("GET /api/v1/devices/{id}", s.withAPI("osquery:read", http.HandlerFunc(s.getDevice)))
	mux.Handle("GET /api/v1/devices/{id}/results", s.withAPI("osquery:read", http.HandlerFunc(s.listDeviceResults)))
	mux.Handle("POST /api/v1/devices/{id}/invalidate", s.withAPI("osquery:write", http.HandlerFunc(s.invalidateDevice)))
	mux.Handle("POST /api/v1/live-queries", s.withAPI("osquery:write", http.HandlerFunc(s.createLiveQuery)))
	mux.Handle("GET /api/v1/live-queries/{id}", s.withAPI("osquery:read", http.HandlerFunc(s.getLiveQuery)))

	mux.Handle("GET /api/v1/vulnerability-settings", s.withAPI("config:read", http.HandlerFunc(s.getVulnerabilitySettings)))
	mux.Handle("PUT /api/v1/vulnerability-settings", s.withConfigWrite(http.HandlerFunc(s.updateVulnerabilitySettings)))
	mux.Handle("DELETE /api/v1/vulnerability-settings", s.withConfigWrite(http.HandlerFunc(s.resetVulnerabilitySettings)))
	mux.Handle("GET /api/v1/vulnerability-issues", s.withAPI("vuln:read", http.HandlerFunc(s.listVulnerabilityIssues)))
	mux.Handle("GET /api/v1/vulnerability-issues/{id}", s.withAPI("vuln:read", http.HandlerFunc(s.getVulnerabilityIssue)))
	mux.Handle("POST /api/v1/vulnerability-issues/{id}", s.withAPI("vuln:write", http.HandlerFunc(s.updateVulnerabilityIssue)))
	mux.Handle("POST /api/v1/vulnerability-issues/{id}/notes", s.withAPI("vuln:write", http.HandlerFunc(s.addVulnerabilityNote)))
	mux.Handle("POST /api/v1/vulnerability-issues/{id}/run-recipe", s.withAPI("vuln:write", http.HandlerFunc(s.runVulnerabilityRecipe)))
	mux.Handle("POST /api/v1/vulnerabilities/sync", s.withAPI("vuln:write", http.HandlerFunc(s.syncVulnerabilities)))
	mux.Handle("GET /api/v1/devices/{id}/vulnerabilities", s.withAPI("vuln:read", http.HandlerFunc(s.deviceVulnerabilities)))

	mux.HandleFunc("POST /enroll", s.osqueryEnroll)
	mux.HandleFunc("POST /config", s.osqueryConfig)
	mux.HandleFunc("POST /logger", s.osqueryLogger)
	mux.HandleFunc("POST /distributed_read", s.osqueryDistributedRead)
	mux.HandleFunc("POST /distributed_write", s.osqueryDistributedWrite)

	mux.Handle("GET /api/v1/runners", s.withAPI("runners:read", http.HandlerFunc(s.listRunners)))
	mux.Handle("DELETE /api/v1/runners/{id}", s.withAPI("runners:write", http.HandlerFunc(s.deleteRunner)))

	mux.Handle("GET /api/v1/jobs", s.withAPI("jobs:read", http.HandlerFunc(s.listJobs)))
	mux.Handle("POST /api/v1/jobs", s.withAPI("jobs:write", http.HandlerFunc(s.enqueueJob)))
	mux.Handle("GET /api/v1/jobs/{id}", s.withAPI("jobs:read", http.HandlerFunc(s.getJob)))

	mux.Handle("GET /api/v1/catalogs", s.withAPI("munki:read", http.HandlerFunc(s.listCatalogs)))
	mux.Handle("GET /api/v1/packages", s.withAPI("munki:read", http.HandlerFunc(s.listPackages)))
	mux.Handle("GET /api/v1/packages/{id}", s.withAPI("munki:read", http.HandlerFunc(s.getPackage)))
	mux.Handle("POST /api/v1/packages/{id}/promote", s.withAPI("munki:write", http.HandlerFunc(s.promotePackage)))
	mux.Handle("POST /api/v1/promotions/run", s.withAPI("munki:write", http.HandlerFunc(s.runPromotions)))

	mux.Handle("POST /api/v1/runners/register", s.withBootstrap(http.HandlerFunc(s.registerRunner)))
	mux.Handle("POST /api/v1/runners/heartbeat", s.withRunner(http.HandlerFunc(s.heartbeat)))
	mux.Handle("POST /api/v1/runners/lease", s.withRunner(http.HandlerFunc(s.lease)))
	mux.Handle("POST /api/v1/jobs/{id}/logs", s.withRunner(http.HandlerFunc(s.appendLogs)))
	mux.Handle("POST /api/v1/jobs/{id}/renew", s.withRunner(http.HandlerFunc(s.renew)))
	mux.Handle("POST /api/v1/jobs/{id}/artifacts", s.withRunner(http.HandlerFunc(s.uploadArtifact)))
	mux.Handle("POST /api/v1/jobs/{id}/complete", s.withRunner(http.HandlerFunc(s.completeJob)))

	repo := s.withRepo(http.HandlerFunc(s.serveRepo))
	mux.Handle("GET /repo/catalogs/{name}", repo)
	mux.Handle("GET /repo/manifests/{name}", repo)
	mux.Handle("GET /repo/pkgs/{path...}", repo)

	mux.HandleFunc("GET /{path...}", s.spa)

	return s.wrap(mux)
}

func devOrigin(origin string) bool {
	switch origin {
	case "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8080", "http://127.0.0.1:8080":
		return true
	default:
		return false
	}
}

func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.devCORS {
			origin := r.Header.Get("Origin")
			if devOrigin(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Mission-Control-Client")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		rec := &statusRec{ResponseWriter: w, code: 200}
		start := time.Now()
		defer func() {
			if recov := recover(); recov != nil {
				s.log.Error("panic", "err", recov, "path", r.URL.Path)
				if !rec.wrote {
					writeJSON(rec, http.StatusInternalServerError, errBody{"internal error"})
				}
			}
			s.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.code, "ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(rec, r)
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Pool().Ping(r.Context()); err != nil {
		http.Error(w, "db", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

type statusRec struct {
	http.ResponseWriter
	code  int
	wrote bool
}

func (s *statusRec) WriteHeader(code int) {
	s.code = code
	s.wrote = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRec) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

type errBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func (s *Server) writeStoreErr(w http.ResponseWriter, err error) {
	var ve *store.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, errBody{ve.Error()})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody{"not found"})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, errBody{err.Error()})
	case errors.Is(err, store.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errBody{"forbidden"})
	default:
		s.log.Error("store", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{"internal error"})
	}
}

func withPrincipal(ctx context.Context, p model.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func principal(r *http.Request) model.Principal {
	p, _ := r.Context().Value(principalKey{}).(model.Principal)
	return p
}

func flag(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

func badJSON(w http.ResponseWriter, err error) {
	msg := "invalid json"
	if err != nil {
		msg = strings.TrimPrefix(err.Error(), "json: ")
	}
	writeJSON(w, http.StatusBadRequest, errBody{msg})
}
