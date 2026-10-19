package httpapi

import (
	"net/http"
	"strconv"

	"github.com/Arequ/mission-control/internal/model"
)

func (s *Server) getVulnerabilitySettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetVulnerabilitySettings(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateVulnerabilitySettings(w http.ResponseWriter, r *http.Request) {
	var in model.VulnerabilitySettings
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdateVulnerabilitySettings(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) resetVulnerabilitySettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ResetVulnerabilitySettings(r.Context(), principal(r))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listVulnerabilityIssues(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListVulnerabilityIssues(r.Context(), issueFilter(r))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getVulnerabilityIssue(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetVulnerabilityIssue(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateVulnerabilityIssue(w http.ResponseWriter, r *http.Request) {
	var in model.IssueUpdate
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.UpdateVulnerabilityIssue(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) addVulnerabilityNote(w http.ResponseWriter, r *http.Request) {
	var in model.IssueNote
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.AddVulnerabilityNote(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) runVulnerabilityRecipe(w http.ResponseWriter, r *http.Request) {
	if !principal(r).Allows("jobs:write") {
		writeJSON(w, http.StatusForbidden, errBody{"forbidden"})
		return
	}
	job, err := s.store.RunVulnerabilityRecipe(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func (s *Server) syncVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if err := s.store.SyncVulnerabilities(r.Context()); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	out, err := s.store.GetVulnerabilitySettings(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deviceVulnerabilities(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.DeviceVulnerabilities(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issues": out})
}

func issueFilter(r *http.Request) model.IssueFilter {
	q := r.URL.Query()
	f := model.IssueFilter{
		Severity: q.Get("severity"),
		Status:   q.Get("status"),
		Q:        q.Get("q"),
		Active:   q.Get("active") == "1" || q.Get("active") == "true",
	}
	if v := q.Get("kev"); v == "true" || v == "false" {
		b := v == "true"
		f.KEV = &b
	}
	if v := q.Get("has_fix"); v == "true" || v == "false" {
		b := v == "true"
		f.HasFix = &b
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	return f
}
