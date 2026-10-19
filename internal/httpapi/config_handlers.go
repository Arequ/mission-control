package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/Arequ/mission-control/internal/model"
)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListAudit(r.Context(), 100)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": items})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	tok, err := s.store.CreateAPIToken(r.Context(), principal(r), in.Name, in.Scopes)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tok)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListAPITokens(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": items})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAPIToken(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRepos(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRecipeRepos(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recipe_repos": items})
}

func (s *Server) createRepo(w http.ResponseWriter, r *http.Request) {
	var in model.RecipeRepo
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.CreateRecipeRepo(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getRepo(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetRecipeRepo(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateRepo(w http.ResponseWriter, r *http.Request) {
	var in model.RecipeRepo
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdateRecipeRepo(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteRepo(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRecipeRepo(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type recipeIn struct {
	Identifier   string          `json:"identifier"`
	Name         string          `json:"name"`
	RepoID       *string         `json:"repo_id"`
	Enabled      *bool           `json:"enabled"`
	Override     string          `json:"override"`
	TrustInfo    json.RawMessage `json:"trust_info"`
	RunnerPoolID *string         `json:"runner_pool_id"`
	Labels       []string        `json:"labels"`
	ManagedBy    string          `json:"managed_by"`
}

func (in recipeIn) model() model.Recipe {
	return model.Recipe{
		Identifier: in.Identifier, Name: in.Name, RepoID: in.RepoID, Enabled: flag(in.Enabled, true),
		Override: in.Override, TrustInfo: in.TrustInfo, RunnerPoolID: in.RunnerPoolID,
		Labels: in.Labels, ManagedBy: in.ManagedBy,
	}
}

func (s *Server) listRecipes(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRecipes(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recipes": items})
}

func (s *Server) createRecipe(w http.ResponseWriter, r *http.Request) {
	var in recipeIn
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.CreateRecipe(r.Context(), principal(r), in.model())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getRecipe(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetRecipe(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateRecipe(w http.ResponseWriter, r *http.Request) {
	var in recipeIn
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdateRecipe(r.Context(), principal(r), r.PathValue("id"), in.model())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteRecipe(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRecipe(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type scheduleIn struct {
	Name      string `json:"name"`
	RecipeID  string `json:"recipe_id"`
	Cron      string `json:"cron"`
	Enabled   *bool  `json:"enabled"`
	ManagedBy string `json:"managed_by"`
}

func (in scheduleIn) model() model.Schedule {
	return model.Schedule{Name: in.Name, RecipeID: in.RecipeID, Cron: in.Cron, Enabled: flag(in.Enabled, true), ManagedBy: in.ManagedBy}
}

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListSchedules(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedules": items})
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	var in scheduleIn
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.CreateSchedule(r.Context(), principal(r), in.model())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getSchedule(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateSchedule(w http.ResponseWriter, r *http.Request) {
	var in scheduleIn
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdateSchedule(r.Context(), principal(r), r.PathValue("id"), in.model())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSchedule(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetPipelineSettings(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var in model.PipelineSettings
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdatePipelineSettings(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) resetSettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ResetPipelineSettings(r.Context(), principal(r))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type ruleIn struct {
	Name        string `json:"name"`
	FromCatalog string `json:"from_catalog"`
	ToCatalog   string `json:"to_catalog"`
	SoakDays    int    `json:"soak_days"`
	ManualHold  bool   `json:"manual_hold"`
	Enabled     *bool  `json:"enabled"`
	ManagedBy   string `json:"managed_by"`
}

func (in ruleIn) model() model.PromotionRule {
	return model.PromotionRule{
		Name: in.Name, FromCatalog: in.FromCatalog, ToCatalog: in.ToCatalog, SoakDays: in.SoakDays,
		ManualHold: in.ManualHold, Enabled: flag(in.Enabled, true), ManagedBy: in.ManagedBy,
	}
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListPromotionRules(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"promotion_rules": items})
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var in ruleIn
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.CreatePromotionRule(r.Context(), principal(r), in.model())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getRule(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetPromotionRule(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	var in ruleIn
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdatePromotionRule(r.Context(), principal(r), r.PathValue("id"), in.model())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeletePromotionRule(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listPools(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRunnerPools(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runner_pools": items})
}

func (s *Server) createPool(w http.ResponseWriter, r *http.Request) {
	var in model.RunnerPool
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.CreateRunnerPool(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getPool(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetRunnerPool(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updatePool(w http.ResponseWriter, r *http.Request) {
	var in model.RunnerPool
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdateRunnerPool(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deletePool(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRunnerPool(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listManifests(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListManifests(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"manifests": items})
}

func (s *Server) createManifest(w http.ResponseWriter, r *http.Request) {
	var in model.Manifest
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.CreateManifest(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getManifest(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetManifest(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateManifest(w http.ResponseWriter, r *http.Request) {
	var in model.Manifest
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdateManifest(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteManifest(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteManifest(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
