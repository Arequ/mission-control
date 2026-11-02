package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/Arequ/mission-control/internal/logs"
	"github.com/Arequ/mission-control/internal/model"
)

func (s *Server) listLogViews(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListLogViews(r.Context(), r.URL.Query().Get("name"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	for i := range items {
		items[i] = items[i].Public()
	}
	writeJSON(w, http.StatusOK, map[string]any{"views": items})
}

func (s *Server) createLogView(w http.ResponseWriter, r *http.Request) {
	var in model.LogView
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateLogView(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out.Public())
}

func (s *Server) getLogView(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetLogView(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) updateLogView(w http.ResponseWriter, r *http.Request) {
	var in model.LogView
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateLogView(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) deleteLogView(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteLogView(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type logQueryBody struct {
	From     string `json:"from"`
	To       string `json:"to"`
	DeviceID string `json:"device_id"`
	Limit    int    `json:"limit"`
	Cursor   string `json:"cursor"`
	Dir      string `json:"dir"`
	Align    string `json:"align"`
}

func (s *Server) queryLogView(w http.ResponseWriter, r *http.Request) {
	var body logQueryBody
	if err := readJSON(r, &body); err != nil {
		badJSON(w, err)
		return
	}
	run, err := queryRun(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), logs.QueryTimeout)
	defer cancel()
	page, err := s.store.RunLogView(ctx, principal(r), r.PathValue("id"), run)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

type logTailBody struct {
	DeviceID string `json:"device_id"`
	Limit    int    `json:"limit"`
	Cursor   string `json:"cursor"`
}

func (s *Server) tailLogView(w http.ResponseWriter, r *http.Request) {
	var body logTailBody
	if err := readJSON(r, &body); err != nil {
		badJSON(w, err)
		return
	}
	if body.Cursor == "" {
		writeJSON(w, http.StatusBadRequest, errBody{"cursor is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), logs.QueryTimeout)
	defer cancel()
	page, err := s.store.TailLogView(ctx, principal(r), r.PathValue("id"), model.LogRun{
		DeviceID: body.DeviceID, Limit: body.Limit, Cursor: body.Cursor,
	})
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

type logContextBody struct {
	DeviceID string `json:"device_id"`
	LineID   string `json:"line_id"`
	Before   int    `json:"before"`
	After    int    `json:"after"`
}

func (s *Server) contextLogView(w http.ResponseWriter, r *http.Request) {
	var body logContextBody
	if err := readJSON(r, &body); err != nil {
		badJSON(w, err)
		return
	}
	if body.LineID == "" {
		writeJSON(w, http.StatusBadRequest, errBody{"line_id is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), logs.QueryTimeout)
	defer cancel()
	out, err := s.store.ContextLogView(ctx, principal(r), r.PathValue("id"), body.LineID, body.DeviceID, body.Before, body.After)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func queryRun(body logQueryBody) (model.LogRun, error) {
	var from, to time.Time
	var err error
	if body.From != "" {
		from, err = time.Parse(time.RFC3339, body.From)
		if err != nil {
			return model.LogRun{}, errString("from must be RFC3339")
		}
	}
	if body.To != "" {
		to, err = time.Parse(time.RFC3339, body.To)
		if err != nil {
			return model.LogRun{}, errString("to must be RFC3339")
		}
	}
	return model.LogRun{
		From: from, To: to, DeviceID: body.DeviceID, Limit: body.Limit,
		Cursor: body.Cursor, Dir: body.Dir, Align: body.Align,
	}, nil
}

type errString string

func (e errString) Error() string { return string(e) }
