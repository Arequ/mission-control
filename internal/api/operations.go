package api

import (
	"net/http"
	"strings"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/httpx"
	"github.com/Arequ/mission-control/internal/store"
)

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleAdmin) {
		return
	}
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := httpx.ReadJSON(r, 1<<20, &req, true); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid json")
		return
	}
	token, principal, err := s.Store.CreateToken(r.Context(), strings.TrimSpace(req.Name), req.Role)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"token":     token,
		"principal": principal,
	})
}

func (s *Server) createLiveQuery(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleOperator) {
		return
	}
	var req struct {
		SQL       string   `json:"sql"`
		DeviceIDs []string `json:"deviceIds"`
	}
	if err := httpx.ReadJSON(r, 1<<20, &req, true); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid json")
		return
	}
	sql := strings.TrimSpace(req.SQL)
	upper := strings.ToUpper(sql)
	if sql == "" || (!strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH")) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "sql must be a SELECT query")
		return
	}
	query, err := s.Store.CreateLiveQuery(r.Context(), sql, principalFrom(r).Name, req.DeviceIDs)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, query)
}

func (s *Server) listLiveQueries(w http.ResponseWriter, r *http.Request) {
	queries, err := s.Store.ListLiveQueries(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"queries": queries})
}

func (s *Server) getLiveQuery(w http.ResponseWriter, r *http.Request) {
	query, err := s.Store.GetLiveQuery(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, query)
}

func (s *Server) munkiRepoResource(w http.ResponseWriter, r *http.Request) {
	s.writeKind(w, r, config.KindMunkiRepo, "repos")
}

func (s *Server) munkiCatalogs(w http.ResponseWriter, r *http.Request) {
	s.writeKind(w, r, config.KindMunkiCatalog, "catalogs")
}

func (s *Server) munkiManifests(w http.ResponseWriter, r *http.Request) {
	s.writeKind(w, r, config.KindMunkiManifest, "manifests")
}

func (s *Server) munkiPackages(w http.ResponseWriter, r *http.Request) {
	s.writeKind(w, r, config.KindMunkiPkgInfo, "packages")
}

func (s *Server) munkiClient(w http.ResponseWriter, r *http.Request) {
	httpx.WriteError(w, http.StatusNotImplemented, "not_implemented",
		"Munki client repo serving is phase 2. Catalogs, manifests, and pkginfo are already stored as config.")
}

func (s *Server) autopkgRepos(w http.ResponseWriter, r *http.Request) {
	s.writeKind(w, r, config.KindAutoPkgRepo, "repos")
}

func (s *Server) autopkgPipelines(w http.ResponseWriter, r *http.Request) {
	s.writeKind(w, r, config.KindAutoPkgPipeline, "pipelines")
}

func (s *Server) writeKind(w http.ResponseWriter, r *http.Request, kind, key string) {
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	filtered := make([]config.Resource, 0)
	for _, res := range resources {
		if res.Kind == kind {
			filtered = append(filtered, res)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{key: filtered})
}

func (s *Server) runPipeline(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleOperator) {
		return
	}
	name := r.PathValue("name")
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	var spec map[string]any
	found := false
	for _, res := range resources {
		if res.Kind == config.KindAutoPkgPipeline && res.Metadata.Name == name {
			spec = res.Spec
			found = true
			break
		}
	}
	if !found {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "pipeline not found")
		return
	}
	job, err := s.Store.CreateJob(r.Context(), name, spec)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, job)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.Store.ListJobs(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"runs": jobs})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.Store.GetJob(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, job)
}

func (s *Server) listRunners(w http.ResponseWriter, r *http.Request) {
	runners, err := s.Store.ListRunners(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"runners": runners})
}

func (s *Server) createRunner(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleAdmin) {
		return
	}
	var req struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	}
	if err := httpx.ReadJSON(r, 1<<20, &req, true); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "name is required")
		return
	}
	runner, err := s.Store.CreateRunner(r.Context(), req.Name, req.Labels)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, runner)
}

func (s *Server) runnerHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AutoPkgVersion string            `json:"autopkgVersion"`
		OSVersion      string            `json:"osVersion"`
		Labels         map[string]string `json:"labels"`
	}
	if err := httpx.ReadJSON(r, 1<<20, &req, true); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid json")
		return
	}
	runner := runnerFrom(r)
	if err := s.Store.HeartbeatRunner(r.Context(), runner.ID, store.RunnerHeartbeat{
		AutoPkgVersion: req.AutoPkgVersion,
		OSVersion:      req.OSVersion,
		Labels:         req.Labels,
	}); err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) runnerClaim(w http.ResponseWriter, r *http.Request) {
	job, ok, err := s.Store.ClaimJob(r.Context(), runnerFrom(r).ID)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	if !ok {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"job": nil})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"job": job})
}

func (s *Server) runnerLogs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Chunk string `json:"chunk"`
	}
	if err := httpx.ReadJSON(r, 2<<20, &req, true); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid json")
		return
	}
	if err := s.Store.AppendJobLog(r.Context(), r.PathValue("id"), runnerFrom(r).ID, req.Chunk); err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) runnerComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string         `json:"status"`
		Logs   string         `json:"logs"`
		Result map[string]any `json:"result"`
	}
	if err := httpx.ReadJSON(r, 8<<20, &req, true); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid json")
		return
	}
	if err := s.Store.FinishJob(r.Context(), r.PathValue("id"), runnerFrom(r).ID, req.Status, req.Logs, req.Result); err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
