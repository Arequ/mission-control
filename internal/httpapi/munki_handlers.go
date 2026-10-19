package httpapi

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/store"
)

func (s *Server) listMunkiEnrollments(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListMunkiEnrollments(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	pub := make([]model.MunkiEnrollment, len(items))
	for i, item := range items {
		pub[i] = item.Public()
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollments": pub})
}

func (s *Server) createMunkiEnrollment(w http.ResponseWriter, r *http.Request) {
	var in model.MunkiEnrollment
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateMunkiEnrollment(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out.Public())
}

func (s *Server) getMunkiEnrollment(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetMunkiEnrollment(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) updateMunkiEnrollment(w http.ResponseWriter, r *http.Request) {
	var in model.MunkiEnrollment
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateMunkiEnrollment(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) deleteMunkiEnrollment(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteMunkiEnrollment(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listMunkiClients(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListMunkiClients(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	pub := make([]model.MunkiClient, len(items))
	for i, item := range items {
		pub[i] = item.Public()
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": pub})
}

func (s *Server) createMunkiClient(w http.ResponseWriter, r *http.Request) {
	var in model.MunkiClient
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateMunkiClient(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out.Public())
}

func (s *Server) getMunkiClient(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetMunkiClient(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) updateMunkiClient(w http.ResponseWriter, r *http.Request) {
	var in model.MunkiClient
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateMunkiClient(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) deleteMunkiClient(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteMunkiClient(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) munkiCheckin(w http.ResponseWriter, r *http.Request) {
	reportBody, installBody, err := readCheckinBody(r)
	if err != nil {
		if errors.Is(err, munki.ErrLimits) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errBody{"report exceeds limits"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errBody{"invalid report"})
		return
	}
	report, err := munki.ParseReport(reportBody, installBody)
	if err != nil {
		if errors.Is(err, munki.ErrLimits) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errBody{"report exceeds limits"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errBody{"invalid report"})
		return
	}
	authn := munkiAuthFrom(r)
	if authn.PerDevice {
		if report.Serial == "" || !strings.EqualFold(report.Serial, authn.Serial) {
			writeJSON(w, http.StatusForbidden, errBody{"report serial does not match this client"})
			return
		}
	}
	fallback := authn.Manifest
	if fallback == "" {
		fallback = "site_default"
	}
	result, err := s.store.ApplyMunkiReport(r.Context(), report, store.ReportHash(reportBody), r.Header.Get("Idempotency-Key"), fallback)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if err := s.store.ProjectMunki(r.Context()); err != nil {
		s.log.Error("munki project", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{"coverage update failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": result.DeviceID,
		"replayed":  result.Replayed,
		"status":    result.Card.Status,
		"pending":   result.Card.Pending,
		"errors":    len(result.Card.Errors),
	})
}

func readCheckinBody(r *http.Request) (report, install []byte, err error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, munki.MaxCompressedBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > munki.MaxCompressedBytes {
		return nil, nil, munki.ErrLimits
	}
	raw, err = maybeGunzip(r.Header.Get("Content-Encoding"), raw)
	if err != nil {
		return nil, nil, err
	}
	media, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.HasPrefix(media, "multipart/") {
		mr := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
		for {
			part, perr := mr.NextPart()
			if perr == io.EOF {
				break
			}
			if perr != nil {
				return nil, nil, perr
			}
			body, rerr := readLimited(part, munki.MaxReportBytes+1)
			_ = part.Close()
			if rerr != nil {
				return nil, nil, rerr
			}
			name := part.FormName()
			if name == "installinfo" || name == "install_info" || strings.Contains(strings.ToLower(part.FileName()), "installinfo") {
				install = body
				continue
			}
			report = body
		}
		if len(report) == 0 {
			return nil, nil, errors.New("missing report")
		}
		return report, install, nil
	}
	return raw, nil, nil
}

func maybeGunzip(encoding string, raw []byte) ([]byte, error) {
	gzipped := strings.EqualFold(strings.TrimSpace(encoding), "gzip") || (len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b)
	if !gzipped {
		if len(raw) > munki.MaxReportBytes {
			return nil, munki.ErrLimits
		}
		return raw, nil
	}
	if len(raw) > munki.MaxCompressedBytes {
		return nil, munki.ErrLimits
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return readLimited(zr, munki.MaxReportBytes+1)
}

func readLimited(r io.Reader, max int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(max+1)))
	if err != nil {
		return nil, err
	}
	if len(buf) > max {
		return nil, munki.ErrLimits
	}
	return buf, nil
}

func repoSegment(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") || strings.Contains(name, "..") {
		return false
	}
	return path.Clean(name) == name
}

func (s *Server) serveRepo(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/repo/catalogs/"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repo/catalogs/"), ".plist")
		if !repoSegment(name) {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid path"})
			return
		}
		body, err := s.store.CatalogBody(r.Context(), name)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		writePlist(w, body)
	case strings.HasPrefix(r.URL.Path, "/repo/manifests/"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repo/manifests/"), ".plist")
		if !repoSegment(name) {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid path"})
			return
		}
		s.serveManifest(w, r, name)
	case strings.HasPrefix(r.URL.Path, "/repo/pkgsinfo/"):
		name := strings.TrimPrefix(r.URL.Path, "/repo/pkgsinfo/")
		if !repoSegment(strings.TrimSuffix(name, ".plist")) {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid path"})
			return
		}
		body, err := s.store.PkginfoBody(r.Context(), name)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		writePlist(w, body)
	case strings.HasPrefix(r.URL.Path, "/repo/icons/"):
		name := strings.TrimPrefix(r.URL.Path, "/repo/icons/")
		if !repoSegment(name) {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid path"})
			return
		}
		s.serveBlob(w, r, "icons/"+name)
	case strings.HasPrefix(r.URL.Path, "/repo/pkgs/"):
		rel := strings.TrimPrefix(r.URL.Path, "/repo/pkgs/")
		rel = strings.TrimPrefix(path.Clean("/"+rel), "/")
		if strings.Contains(rel, "/") || !repoSegment(rel) || storage.ValidateKey("pkgs/"+rel) != nil {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid path"})
			return
		}
		s.serveBlob(w, r, "pkgs/"+rel)
	default:
		http.NotFound(w, r)
	}
}

func writePlist(w http.ResponseWriter, body []byte) {
	sum := sha256.Sum256(body)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	_, _ = w.Write(body)
}

func (s *Server) serveManifest(w http.ResponseWriter, r *http.Request, name string) {
	m, err := s.store.GetManifestByName(r.Context(), name)
	if err == nil {
		body, rerr := munki.RenderManifest(manifestDoc(m))
		if rerr != nil {
			s.writeStoreErr(w, rerr)
			return
		}
		writePlist(w, body)
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		s.writeStoreErr(w, err)
		return
	}
	if !validSerialName(name) {
		writeJSON(w, http.StatusNotFound, errBody{"not found"})
		return
	}
	authn := munkiAuthFrom(r)
	if authn.PerDevice && !strings.EqualFold(authn.Serial, name) {
		writeJSON(w, http.StatusNotFound, errBody{"not found"})
		return
	}
	included, err := s.store.ManifestForSerial(r.Context(), name, authn.Manifest)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	base, err := s.store.GetManifestByName(r.Context(), included)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	body, err := munki.RenderManifest(munki.ManifestDoc{
		Catalogs:          base.Catalogs,
		IncludedManifests: []string{included},
	})
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writePlist(w, body)
}

func manifestDoc(m model.Manifest) munki.ManifestDoc {
	doc := munki.ManifestDoc{
		Catalogs: m.Catalogs, IncludedManifests: m.IncludedManifests,
		ManagedInstalls: m.ManagedInstalls, OptionalInstalls: m.OptionalInstalls,
		ManagedUninstalls: m.ManagedUninstalls,
	}
	for _, c := range m.ConditionalItems {
		doc.ConditionalItems = append(doc.ConditionalItems, munki.Conditional{
			Condition: c.Condition, ManagedInstalls: c.ManagedInstalls,
			OptionalInstalls: c.OptionalInstalls, ManagedUninstalls: c.ManagedUninstalls,
			IncludedManifests: c.IncludedManifests,
		})
	}
	return doc
}

func validSerialName(name string) bool {
	if len(name) < 4 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func (s *Server) serveBlob(w http.ResponseWriter, r *http.Request, key string) {
	if err := storage.ValidateKey(key); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid path"})
		return
	}
	signed, err := s.blobs.Presign(r.Context(), key, 15*time.Minute)
	if err == nil && signed != "" {
		http.Redirect(w, r, signed, http.StatusTemporaryRedirect)
		return
	}
	if err != nil && !errors.Is(err, storage.ErrNoPresign) && !errors.Is(err, storage.ErrNotFound) {
		s.log.Error("storage presign", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{"storage read failed"})
		return
	}
	info, statErr := s.blobs.Stat(r.Context(), key)
	rc, err := s.blobs.Open(r.Context(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody{"not found"})
			return
		}
		s.log.Error("storage open", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{"storage read failed"})
		return
	}
	defer rc.Close()
	if statErr != nil {
		info = storage.Info{ModTime: time.Time{}}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private")
	if info.ETag != "" {
		w.Header().Set("ETag", info.ETag)
	}
	if seeker, ok := rc.(io.ReadSeeker); ok {
		http.ServeContent(w, r, path.Base(key), info.ModTime, seeker)
		return
	}
	_, _ = io.Copy(w, rc)
}
