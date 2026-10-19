// Package osquery implements the osquery TLS remote API: enroll, config, log,
// and distributed read/write.
package osquery

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/httpx"
	"github.com/Arequ/mission-control/internal/store"
)

// Handler serves the osquery TLS endpoints on mux.
type Handler struct {
	Store        store.Store
	EnrollSecret string
}

// Register mounts the osquery routes.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /osquery/enroll", h.enroll)
	mux.HandleFunc("POST /osquery/config", h.config)
	mux.HandleFunc("POST /osquery/log", h.log)
	mux.HandleFunc("POST /osquery/distributed/read", h.distributedRead)
	mux.HandleFunc("POST /osquery/distributed/write", h.distributedWrite)
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnrollSecret   string         `json:"enroll_secret"`
		HostIdentifier string         `json:"host_identifier"`
		HostDetails    map[string]any `json:"host_details"`
	}
	if err := readOsquery(r, &req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"node_invalid": true, "error": "invalid json"})
		return
	}
	if !auth.SecretMatch(h.EnrollSecret, req.EnrollSecret) {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]any{"node_invalid": true})
		return
	}
	if req.HostIdentifier == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"node_invalid": true, "error": "host_identifier required"})
		return
	}
	nodeKey, err := auth.NewSecret("")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if _, err := h.Store.EnrollDevice(r.Context(), nodeKey, DeviceFromEnroll(req.HostIdentifier, req.HostDetails)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"node_key": nodeKey, "node_invalid": false})
}

func (h *Handler) config(w http.ResponseWriter, r *http.Request) {
	dev, ok := h.device(w, r)
	if !ok {
		return
	}
	resources, err := h.Store.ListResources(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	cfg, hash := BuildConfig(resources, dev.Platform)
	_ = h.Store.TouchDevice(r.Context(), dev.ID, hash)
	cfg["node_invalid"] = false
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handler) log(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeKey string `json:"node_key"`
		LogType string `json:"log_type"`
		Data    any    `json:"data"`
	}
	if err := readOsquery(r, &req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"node_invalid": true})
		return
	}
	dev, found, err := h.Store.DeviceByNodeKey(r.Context(), req.NodeKey)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"node_invalid": true})
		return
	}
	if req.LogType == "result" || req.LogType == "" {
		for _, item := range logItems(req.Data) {
			if err := IngestResult(r.Context(), h.Store, dev.ID, item); err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
				return
			}
		}
	}
	_ = h.Store.TouchDevice(r.Context(), dev.ID, "")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"node_invalid": false})
}

func (h *Handler) distributedRead(w http.ResponseWriter, r *http.Request) {
	dev, ok := h.device(w, r)
	if !ok {
		return
	}
	queries, err := h.Store.PendingQueries(r.Context(), dev.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if queries == nil {
		queries = map[string]string{}
	}
	_ = h.Store.TouchDevice(r.Context(), dev.ID, "")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"node_invalid": false, "queries": queries})
}

func (h *Handler) distributedWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeKey  string                     `json:"node_key"`
		Queries  map[string]json.RawMessage `json:"queries"`
		Statuses map[string]json.RawMessage `json:"statuses"`
	}
	if err := readOsquery(r, &req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"node_invalid": true})
		return
	}
	dev, found, err := h.Store.DeviceByNodeKey(r.Context(), req.NodeKey)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"node_invalid": true})
		return
	}
	statuses := map[string]int{}
	for id, raw := range req.Statuses {
		statuses[id] = parseStatus(raw)
	}
	if err := h.Store.WriteQueryResults(r.Context(), dev.ID, req.Queries, statuses); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	_ = h.Store.TouchDevice(r.Context(), dev.ID, "")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"node_invalid": false})
}

func (h *Handler) device(w http.ResponseWriter, r *http.Request) (store.Device, bool) {
	var req struct {
		NodeKey string `json:"node_key"`
	}
	if err := readOsquery(r, &req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"node_invalid": true})
		return store.Device{}, false
	}
	dev, found, err := h.Store.DeviceByNodeKey(r.Context(), req.NodeKey)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
		return store.Device{}, false
	}
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"node_invalid": true})
		return store.Device{}, false
	}
	return dev, true
}

func readOsquery(r *http.Request, dest any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 32<<20))
	dec.UseNumber()
	return dec.Decode(dest)
}

func logItems(data any) []map[string]any {
	switch t := data.(type) {
	case []any:
		return asRows(t)
	case string:
		var items []map[string]any
		for _, line := range strings.Split(t, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var item map[string]any
			if err := json.Unmarshal([]byte(line), &item); err == nil {
				items = append(items, item)
			}
		}
		return items
	default:
		return nil
	}
}

func parseStatus(raw json.RawMessage) int {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return asInt(s)
	}
	return 1
}
