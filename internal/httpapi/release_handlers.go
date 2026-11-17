package httpapi

import (
	"errors"
	"net/http"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/store"
)

func (s *Server) listReleaseReviews(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "rushed", "normal", "rejected", "superseded":
	default:
		writeJSON(w, http.StatusBadRequest, errBody{"status must be pending, rushed, normal, rejected, or superseded"})
		return
	}
	items, err := s.store.ListReleaseReviews(r.Context(), status)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reviews": items})
}

func (s *Server) getReleaseReview(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetReleaseReview(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) decideReleaseReview(w http.ResponseWriter, r *http.Request) {
	var in model.ReleaseDecision
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.DecideRelease(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) evaluateReleaseReview(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RefreshRelease(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	s.getReleaseReview(w, r)
}

func (s *Server) leaseReleaseNotes(w http.ResponseWriter, r *http.Request) {
	task, err := s.store.LeaseReleaseNotes(r.Context(), principal(r))
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) submitReleaseNotes(w http.ResponseWriter, r *http.Request) {
	var in model.ReleaseNotesInput
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.SubmitReleaseNotes(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) failReleaseNotes(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Error string `json:"error"`
	}
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	if err := s.store.FailReleaseNotes(r.Context(), principal(r), r.PathValue("id"), in.Error); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
