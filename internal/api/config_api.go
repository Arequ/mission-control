package api

import (
	"net/http"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/httpx"
)

type configBody struct {
	Resources []config.Resource `json:"resources"`
	Prune     bool              `json:"prune"`
	Verbose   bool              `json:"verbose"`
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleViewer) {
		return
	}
	resources, ok := s.readResources(w, r)
	if !ok {
		return
	}
	diags := config.Validate(resources)
	status := http.StatusOK
	if len(diags) > 0 {
		status = http.StatusUnprocessableEntity
	}
	httpx.WriteJSON(w, status, map[string]any{
		"valid":       len(diags) == 0,
		"diagnostics": diags,
		"resources":   len(resources),
	})
}

func (s *Server) planConfig(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleOperator) {
		return
	}
	body, resources, ok := s.readConfigBody(w, r)
	if !ok {
		return
	}
	plan, err := config.PlanAgainst(r.Context(), s.Store, resources, config.ApplyOptions{
		Prune:   body.Prune,
		Verbose: body.Verbose,
	})
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, plan)
}

func (s *Server) applyConfig(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleAdmin) {
		return
	}
	body, resources, ok := s.readConfigBody(w, r)
	if !ok {
		return
	}
	plan, err := config.Apply(r.Context(), s.Store, resources, config.ApplyOptions{
		Prune:   body.Prune,
		Verbose: body.Verbose,
	})
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, plan)
}

func (s *Server) syncConfig(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, auth.RoleAdmin) {
		return
	}
	if s.Sync == nil || s.Sync.Dir == "" {
		httpx.WriteError(w, http.StatusConflict, "not_configured", "MC_CONFIG_DIR is not set")
		return
	}
	s.Sync.Tick(r.Context())
	status := s.Sync.Status()
	code := http.StatusOK
	if status.LastError != "" {
		code = http.StatusUnprocessableEntity
	}
	httpx.WriteJSON(w, code, status)
}

func (s *Server) configStatus(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"directory": "", "summary": config.PlanSummary{}})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.Sync.Status())
}

func (s *Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"resources": resources})
}

func (s *Server) listResources(w http.ResponseWriter, r *http.Request) {
	s.writeResources(w, r, "")
}

func (s *Server) listResourcesByKind(w http.ResponseWriter, r *http.Request) {
	s.writeResources(w, r, r.PathValue("kind"))
}

func (s *Server) writeResources(w http.ResponseWriter, r *http.Request, kind string) {
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	if kind != "" {
		filtered := make([]config.Resource, 0)
		for _, res := range resources {
			if res.Kind == kind {
				filtered = append(filtered, res)
			}
		}
		resources = filtered
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"resources": resources})
}

func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	s.writeOneResource(w, r, r.PathValue("kind"), "default", r.PathValue("name"))
}

func (s *Server) getResourceNS(w http.ResponseWriter, r *http.Request) {
	s.writeOneResource(w, r, r.PathValue("kind"), r.PathValue("namespace"), r.PathValue("name"))
}

func (s *Server) writeOneResource(w http.ResponseWriter, r *http.Request, kind, namespace, name string) {
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	for _, res := range resources {
		if res.Kind == kind && res.Metadata.Namespace == namespace && res.Metadata.Name == name {
			httpx.WriteJSON(w, http.StatusOK, res)
			return
		}
	}
	httpx.WriteError(w, http.StatusNotFound, "not_found", "resource not found")
}

func (s *Server) readResources(w http.ResponseWriter, r *http.Request) ([]config.Resource, bool) {
	_, resources, ok := s.readConfigBody(w, r)
	return resources, ok
}

func (s *Server) readConfigBody(w http.ResponseWriter, r *http.Request) (configBody, []config.Resource, bool) {
	var body configBody
	if err := httpx.ReadJSON(r, 8<<20, &body, false); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid", "invalid json")
		return configBody{}, nil, false
	}
	if body.Resources == nil {
		body.Resources = []config.Resource{}
	}
	diags := config.Validate(body.Resources)
	if len(diags) > 0 {
		httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"valid":       false,
			"diagnostics": diags,
		})
		return configBody{}, nil, false
	}
	return body, body.Resources, true
}
