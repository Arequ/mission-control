package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/keel"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/store"
)

// keelEnroll binds a device's Ed25519 public key to its serial on first use.
// The bearer is a Terraform-managed Keel enroll secret, compared against
// every enabled hash in constant time.
func (s *Server) keelEnroll(w http.ResponseWriter, r *http.Request) {
	secret := auth.Bearer(r.Header.Get("Authorization"))
	if secret == "" {
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	var body struct {
		Serial    string `json:"serial"`
		Hostname  string `json:"hostname"`
		PublicKey string `json:"public_key"`
	}
	// Unknown fields are ignored so the agent can add data without a server release.
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		badJSON(w, err)
		return
	}
	pub, perr := keel.ParsePublicKey(body.PublicKey)
	created, err := s.store.EnrollKeelDevice(r.Context(), secret, body.Serial, body.Hostname, pub)
	switch {
	case errors.Is(err, store.ErrEnrollRejected):
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	case perr != nil && err != nil:
		// The secret was good; the key was not.
		writeJSON(w, http.StatusBadRequest, errBody{perr.Error()})
		return
	case errors.Is(err, store.ErrKeelKeyMismatch):
		writeJSON(w, http.StatusConflict, errBody{"serial is enrolled with a different key; an admin must clear it first"})
		return
	case err != nil:
		s.writeStoreErr(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"serial": body.Serial, "enrolled": true})
}

// keelReport accepts one signed report. The signature covers the exact body
// bytes, so the body is read in full (at most keel.MaxBody) before anything
// is parsed. Verification happens before the JSON is decoded.
func (s *Server) keelReport(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > keel.MaxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, errBody{"report exceeds 2 MiB"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, keel.MaxBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"could not read body"})
		return
	}
	if len(body) > keel.MaxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, errBody{"report exceeds 2 MiB"})
		return
	}
	serial := r.Header.Get(keel.HeaderSerial)
	ts, err := keel.ParseTimestamp(r.Header.Get(keel.HeaderTimestamp))
	if err != nil || !keel.ValidSerial(serial) || r.Header.Get(keel.HeaderSignature) == "" {
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	// Skew is checked before the key lookup, so this answer does not reveal
	// whether the serial is enrolled.
	if err := keel.CheckSkew(ts, s.store.Now()); err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody{"timestamp outside the allowed window"})
		return
	}
	pub, err := s.store.KeelPublicKey(r.Context(), serial)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if err := keel.Verify(pub, serial, ts, r.Header.Get(keel.HeaderSignature), body); err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	report, err := keel.ParseReport(body, serial)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	if err := s.store.RecordKeelReport(r.Context(), pub, ts, report, body); err != nil {
		if errors.Is(err, store.ErrKeelReplay) {
			writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
			return
		}
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "run_id": report.RunID})
}

func (s *Server) deleteKeelKey(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteKeelKey(r.Context(), principal(r), r.PathValue("serial")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) keelOverview(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.KeelOverview(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listKeelDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	status := q.Get("status")
	switch status {
	case "", "failed", "pending", "stale", "warnings":
	default:
		writeJSON(w, http.StatusBadRequest, errBody{"status must be failed, pending, stale, or warnings"})
		return
	}
	items, total, err := s.store.ListKeelDevices(r.Context(), store.KeelDeviceFilter{
		Role: q.Get("role"), Status: status, Q: q.Get("q"), Limit: limit, Offset: offset,
	})
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": items, "total": total})
}

func (s *Server) getKeelDevice(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetKeelDevice(r.Context(), r.PathValue("serial"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listKeelRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListKeelRuns(r.Context(), r.PathValue("serial"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (s *Server) keelRoleSettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.KeelRoleSettings(r.Context(), r.PathValue("role"), r.PathValue("profile"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listKeelEnrollSecrets(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListKeelEnrollSecrets(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enroll_secrets": items})
}

func (s *Server) createKeelEnrollSecret(w http.ResponseWriter, r *http.Request) {
	var in model.KeelEnrollSecret
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateKeelEnrollSecret(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getKeelEnrollSecret(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetKeelEnrollSecret(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateKeelEnrollSecret(w http.ResponseWriter, r *http.Request) {
	var in model.KeelEnrollSecret
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateKeelEnrollSecret(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteKeelEnrollSecret(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteKeelEnrollSecret(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
