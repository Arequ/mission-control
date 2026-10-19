package api

import (
	"net/http"
	"strconv"

	"github.com/Arequ/mission-control/internal/httpx"
	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/Arequ/mission-control/internal/store"
)

func (s *Server) fleetSummary(w http.ResponseWriter, r *http.Request) {
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	hashes := osquery.ExpectedHashes(resources)
	summary, err := s.Store.FleetSummary(r.Context(), hashes)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	decorateDevices(summary.Recent, hashes)
	httpx.WriteJSON(w, http.StatusOK, summary)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	devices, err := s.Store.ListDevices(r.Context(), store.DeviceFilter{
		Query:  r.URL.Query().Get("q"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	decorateDevices(devices, osquery.ExpectedHashes(resources))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	device, err := s.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	resources, err := s.Store.ListResources(r.Context())
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	devices := []store.Device{device}
	decorateDevices(devices, osquery.ExpectedHashes(resources))
	apps, err := s.Store.ListApps(r.Context(), device.ID)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	results, err := s.Store.ListResults(r.Context(), device.ID, 30)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"device":  devices[0],
		"apps":    apps,
		"results": results,
	})
}

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.Store.ListApps(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

func (s *Server) listResults(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	results, err := s.Store.ListResults(r.Context(), r.PathValue("id"), limit)
	if err != nil {
		s.writeStoreErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"results": results})
}

func decorateDevices(devices []store.Device, hashes map[string]string) {
	for i := range devices {
		want := hashes[devices[i].Platform]
		if want == "" {
			want = hashes[""]
		}
		devices[i].ConfigDrift = want != "" && devices[i].ConfigHash != want
		if devices[i].Labels == nil {
			devices[i].Labels = []string{}
		}
	}
}
