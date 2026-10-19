package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/Arequ/mission-control/internal/store"
)

const osqueryMaxBody = 32 << 20

var errOsqueryTooLarge = errors.New("osquery payload too large")

func decodeOsquery(r *http.Request, dst any) error {
	body, err := readOsqueryBody(r)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing json")
		}
		return err
	}
	return nil
}

func readOsqueryBody(r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, osqueryMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > osqueryMaxBody {
		return nil, errOsqueryTooLarge
	}
	enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	gzipped := enc == "gzip" || (len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b)
	if !gzipped {
		return raw, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, osqueryMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(out) > osqueryMaxBody {
		return nil, errOsqueryTooLarge
	}
	return out, nil
}

func rejectOsqueryDecode(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errOsqueryTooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, errBody{"payload too large"})
		return true
	}
	badJSON(w, err)
	return true
}

func writeNodeInvalid(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]bool{"node_invalid": true})
}

func (s *Server) forwardResults(ctx context.Context, events []osquery.ResultEvent) {
	if s.forward == nil || len(events) == 0 {
		return
	}
	fctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.forward.Forward(fctx, events); err != nil {
		s.log.Error("osquery forward", "err", err, "count", len(events))
	}
}

type enrollBody struct {
	EnrollSecret   string         `json:"enroll_secret"`
	HostIdentifier string         `json:"host_identifier"`
	HostDetails    map[string]any `json:"host_details"`
}

func (s *Server) osqueryEnroll(w http.ResponseWriter, r *http.Request) {
	var body enrollBody
	if err := decodeOsquery(r, &body); rejectOsqueryDecode(w, err) {
		return
	}
	id, key, err := s.store.EnrollHost(r.Context(), body.EnrollSecret, body.HostIdentifier, body.HostDetails)
	if errors.Is(err, store.ErrEnrollRejected) {
		writeJSON(w, http.StatusUnauthorized, errBody{"enroll secret rejected"})
		return
	}
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	s.log.Info("osquery enroll", "device_id", id)
	writeJSON(w, http.StatusOK, map[string]any{"node_key": key, "node_invalid": false})
}

type nodeBody struct {
	NodeKey string `json:"node_key"`
}

func (s *Server) osqueryConfig(w http.ResponseWriter, r *http.Request) {
	var body nodeBody
	if err := decodeOsquery(r, &body); rejectOsqueryDecode(w, err) {
		return
	}
	cfg, invalid, err := s.store.OsqueryConfig(r.Context(), body.NodeKey, s.inventory)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if invalid {
		writeNodeInvalid(w)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

type loggerBody struct {
	NodeKey string          `json:"node_key"`
	LogType string          `json:"log_type"`
	Data    json.RawMessage `json:"data"`
}

func (s *Server) osqueryLogger(w http.ResponseWriter, r *http.Request) {
	var body loggerBody
	if err := decodeOsquery(r, &body); rejectOsqueryDecode(w, err) {
		return
	}
	events, invalid, err := s.store.IngestLogs(r.Context(), body.NodeKey, body.LogType, body.Data)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if invalid {
		writeNodeInvalid(w)
		return
	}
	s.forwardResults(r.Context(), events)
	writeJSON(w, http.StatusOK, map[string]bool{"node_invalid": false})
}

func (s *Server) osqueryDistributedRead(w http.ResponseWriter, r *http.Request) {
	var body nodeBody
	if err := decodeOsquery(r, &body); rejectOsqueryDecode(w, err) {
		return
	}
	queries, invalid, err := s.store.DistributedRead(r.Context(), body.NodeKey)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if invalid {
		writeNodeInvalid(w)
		return
	}
	if queries == nil {
		queries = map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_invalid": false, "queries": queries})
}

type distWriteBody struct {
	NodeKey  string                     `json:"node_key"`
	Queries  map[string]json.RawMessage `json:"queries"`
	Statuses map[string]json.Number     `json:"statuses"`
	Messages map[string]string          `json:"messages"`
}

func (s *Server) osqueryDistributedWrite(w http.ResponseWriter, r *http.Request) {
	var body distWriteBody
	if err := decodeOsquery(r, &body); rejectOsqueryDecode(w, err) {
		return
	}
	results := map[string][]map[string]string{}
	for id, raw := range body.Queries {
		if len(raw) == 0 || string(raw) == "null" {
			results[id] = []map[string]string{}
			continue
		}
		var rows []map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rows); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid distributed results"})
			return
		}
		converted := make([]map[string]string, 0, len(rows))
		for _, row := range rows {
			m := make(map[string]string, len(row))
			for k, v := range row {
				m[k] = flexString(v)
			}
			converted = append(converted, m)
		}
		results[id] = converted
	}
	statuses := map[string]int{}
	for id, n := range body.Statuses {
		i, err := n.Int64()
		if err != nil {
			f, ferr := n.Float64()
			if ferr != nil {
				writeJSON(w, http.StatusBadRequest, errBody{"invalid status"})
				return
			}
			i = int64(f)
		}
		statuses[id] = int(i)
	}
	invalid, err := s.store.DistributedWrite(r.Context(), body.NodeKey, results, statuses, body.Messages)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if invalid {
		writeNodeInvalid(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"node_invalid": false})
}

func flexString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "1"
		}
		return "0"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func (s *Server) listOsqueryQueries(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListOsqueryQueries(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"queries": items})
}

func (s *Server) createOsqueryQuery(w http.ResponseWriter, r *http.Request) {
	var in model.OsqueryQuery
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateOsqueryQuery(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getOsqueryQuery(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetOsqueryQuery(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateOsqueryQuery(w http.ResponseWriter, r *http.Request) {
	var in model.OsqueryQuery
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateOsqueryQuery(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteOsqueryQuery(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteOsqueryQuery(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listOsqueryPacks(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListOsqueryPacks(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": items})
}

func (s *Server) createOsqueryPack(w http.ResponseWriter, r *http.Request) {
	var in model.OsqueryPack
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateOsqueryPack(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getOsqueryPack(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetOsqueryPack(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateOsqueryPack(w http.ResponseWriter, r *http.Request) {
	var in model.OsqueryPack
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateOsqueryPack(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteOsqueryPack(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteOsqueryPack(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listOsqueryLabels(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListOsqueryLabels(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"labels": items})
}

func (s *Server) createOsqueryLabel(w http.ResponseWriter, r *http.Request) {
	var in model.OsqueryLabel
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateOsqueryLabel(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getOsqueryLabel(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetOsqueryLabel(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateOsqueryLabel(w http.ResponseWriter, r *http.Request) {
	var in model.OsqueryLabel
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateOsqueryLabel(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteOsqueryLabel(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteOsqueryLabel(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listEnrollSecrets(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListEnrollSecrets(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enroll_secrets": items})
}

func (s *Server) createEnrollSecret(w http.ResponseWriter, r *http.Request) {
	var in model.EnrollSecret
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateEnrollSecret(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getEnrollSecret(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetEnrollSecret(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateEnrollSecret(w http.ResponseWriter, r *http.Request) {
	var in model.EnrollSecret
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateEnrollSecret(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteEnrollSecret(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteEnrollSecret(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) fleetSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.store.FleetSummary(r.Context(), s.offlineAfter)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, total, err := s.store.ListDevices(r.Context(), model.DeviceListFilter{
		Q: r.URL.Query().Get("q"), Platform: r.URL.Query().Get("platform"),
		Status: r.URL.Query().Get("status"), Label: r.URL.Query().Get("label"),
		Limit: limit, Offset: offset, OfflineAfter: s.offlineAfter,
	})
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	limit, offset = clampPage(limit, offset)
	writeJSON(w, http.StatusOK, map[string]any{"devices": items, "limit": limit, "offset": offset, "total": total})
}

func clampPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetDevice(r.Context(), r.PathValue("id"), s.offlineAfter)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listDeviceResults(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, total, err := s.store.ListResultLogs(r.Context(), r.PathValue("id"), r.URL.Query().Get("query"), limit, offset)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	limit, offset = clampPage(limit, offset)
	writeJSON(w, http.StatusOK, map[string]any{"results": items, "limit": limit, "offset": offset, "total": total})
}

func (s *Server) invalidateDevice(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.InvalidateNode(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createLiveQuery(w http.ResponseWriter, r *http.Request) {
	var in model.LiveQueryRequest
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	out, err := s.store.CreateLiveQuery(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getLiveQuery(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetLiveQuery(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
