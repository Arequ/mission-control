package httpapi

import (
	"net/http"
	"strconv"

	"github.com/Arequ/mission-control/internal/model"
)

func (s *Server) listConnectors(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListConnectors(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connectors": items})
}

func (s *Server) createConnector(w http.ResponseWriter, r *http.Request) {
	var in model.Connector
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateConnector(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out.Public())
}

func (s *Server) getConnector(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetConnector(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) updateConnector(w http.ResponseWriter, r *http.Request) {
	var in model.Connector
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateConnector(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) deleteConnector(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteConnector(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) coverageMatrix(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	days, _ := strconv.Atoi(q.Get("stale_days"))
	out, err := s.store.CoverageMatrix(r.Context(), q.Get("filter"), q.Get("source"), q.Get("q"), days, limit, offset)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) coverageDevice(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.CoverageDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) coverageConnectors(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListConnectors(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	for i := range items {
		items[i] = items[i].Public()
	}
	writeJSON(w, http.StatusOK, map[string]any{"connectors": items})
}
