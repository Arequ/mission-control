package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/Arequ/mission-control/internal/storage"
)

func (s *Server) listRunners(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRunners(r.Context(), s.offlineAfter)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runners": items})
}

func (s *Server) deleteRunner(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRunner(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListJobs(r.Context(), r.URL.Query().Get("recipe_id"), limit)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": items})
}

func (s *Server) enqueueJob(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RecipeID string `json:"recipe_id"`
	}
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	job, err := s.store.EnqueueManual(r.Context(), principal(r), in.RecipeID)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetJob(r.Context(), r.PathValue("id"), true)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) listCatalogs(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListCatalogs(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"catalogs": items})
}

func (s *Server) listPackages(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListPackages(r.Context(), r.URL.Query().Get("catalog"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packages": items})
}

func (s *Server) getPackage(w http.ResponseWriter, r *http.Request) {
	item, err := s.store.GetPackage(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) promotePackage(w http.ResponseWriter, r *http.Request) {
	item, err := s.store.PromotePackage(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) runPromotions(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.PromoteDue(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"promoted": n})
}

type registerIn struct {
	Name           string   `json:"name"`
	Labels         []string `json:"labels"`
	Pool           string   `json:"pool"`
	Hostname       string   `json:"hostname"`
	OSVersion      string   `json:"os_version"`
	AutopkgVersion string   `json:"autopkg_version"`
}

func (s *Server) registerRunner(w http.ResponseWriter, r *http.Request) {
	var in registerIn
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	rn, token, err := s.store.RegisterRunner(r.Context(), principal(r), in.Name, in.Labels, in.Pool, in.Hostname, in.OSVersion, in.AutopkgVersion)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"runner": rn, "token": token})
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hostname       string `json:"hostname"`
		OSVersion      string `json:"os_version"`
		AutopkgVersion string `json:"autopkg_version"`
	}
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	p := principal(r)
	if err := s.store.Heartbeat(r.Context(), p.ID, in.Hostname, in.OSVersion, in.AutopkgVersion); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) lease(w http.ResponseWriter, r *http.Request) {
	wait := 20 * time.Second
	if r.URL.Query().Get("wait") == "0" {
		wait = 0
	}
	if v := r.URL.Query().Get("wait_seconds"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 60 {
			wait = time.Duration(n) * time.Second
		}
	}
	deadline := time.Now().Add(wait)
	p := principal(r)
	for {
		lease, err := s.store.Lease(r.Context(), p.ID)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		if lease != nil {
			writeJSON(w, http.StatusOK, lease)
			return
		}
		if time.Now().After(deadline) || r.Context().Err() != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-r.Context().Done():
			w.WriteHeader(http.StatusNoContent)
			return
		case <-time.After(400 * time.Millisecond):
		}
	}
}

func (s *Server) appendLogs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Lines []model.LogLine `json:"lines"`
	}
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	if err := s.store.AppendLogs(r.Context(), r.PathValue("id"), principal(r).ID, in.Lines); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	exp, err := s.store.RenewLease(r.Context(), r.PathValue("id"), principal(r).ID)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease_expires_at": exp})
}

func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	jobID := r.PathValue("id")
	ok, err := s.store.RunnerOwnsJob(r.Context(), jobID, p.ID)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusForbidden, errBody{"forbidden"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"expected multipart pkginfo and package"})
		return
	}
	pi, _, err := r.FormFile("pkginfo")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"missing pkginfo"})
		return
	}
	defer pi.Close()
	pkg, hdr, err := r.FormFile("package")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"missing package"})
		return
	}
	defer pkg.Close()
	piBytes, err := io.ReadAll(io.LimitReader(pi, 8<<20))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	info, err := munki.ParsePkginfo(piBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	pkgBytes, err := io.ReadAll(io.LimitReader(pkg, s.maxUpload))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	filename := "package.pkg"
	if hdr != nil && hdr.Filename != "" {
		filename = path.Base(hdr.Filename)
	}
	if filename == "." || filename == "/" || filename == "" {
		filename = info["name"].(string) + "-" + info["version"].(string) + ".pkg"
	}
	catalog, err := s.store.ImportCatalog(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	munki.ApplyArtifact(info, filename, pkgBytes, catalog)
	raw, err := munki.MarshalPkginfo(info)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	job, err := s.store.GetJob(r.Context(), jobID, false)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	key := "pkgs/" + filename
	if err := s.blobs.Put(r.Context(), key, bytes.NewReader(pkgBytes), int64(len(pkgBytes)), "application/octet-stream"); err != nil {
		s.log.Error("storage put", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{"storage write failed"})
		return
	}
	jid := jobID
	inserted, imported, err := s.store.InsertPackage(r.Context(), p, model.Package{
		Name: info["name"].(string), Version: info["version"].(string), Catalog: catalog,
		Filename: filename, Pkginfo: raw, JobID: &jid, RecipeIdentifier: job.RecipeIdentifier,
	})
	if err != nil {
		_ = s.blobs.Delete(r.Context(), key)
		s.writeStoreErr(w, err)
		return
	}
	if !imported {
		// Same bytes may already be stored under this key; leave the object in place.
		_ = storage.ErrNotFound
	}
	res := model.ImportResult{Imported: imported, Package: &inserted}
	if !imported {
		res.Reason = "already_exists"
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) completeJob(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Result string `json:"result"`
		Error  string `json:"error"`
	}
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	job, err := s.store.CompleteJob(r.Context(), r.PathValue("id"), principal(r).ID, in.Result, in.Error)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) serveRepo(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/repo/catalogs/"):
		name := strings.TrimPrefix(r.URL.Path, "/repo/catalogs/")
		name = strings.TrimSuffix(name, ".plist")
		body, err := s.store.CatalogBody(r.Context(), name)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(body)
	case strings.HasPrefix(r.URL.Path, "/repo/manifests/"):
		name := strings.TrimPrefix(r.URL.Path, "/repo/manifests/")
		name = strings.TrimSuffix(name, ".plist")
		m, err := s.store.GetManifestByName(r.Context(), name)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		body, err := munki.ManifestPlist(m.Catalogs, m.IncludedManifests, m.ManagedInstalls, m.OptionalInstalls, m.ManagedUninstalls)
		if err != nil {
			s.writeStoreErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(body)
	case strings.HasPrefix(r.URL.Path, "/repo/pkgs/"):
		rel := strings.TrimPrefix(r.URL.Path, "/repo/pkgs/")
		rel = path.Clean("/" + rel)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" || strings.Contains(rel, "..") {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid path"})
			return
		}
		rc, err := s.blobs.Open(r.Context(), "pkgs/"+rel)
		if err != nil {
			if err == storage.ErrNotFound {
				writeJSON(w, http.StatusNotFound, errBody{"not found"})
				return
			}
			s.log.Error("storage open", "err", err)
			writeJSON(w, http.StatusInternalServerError, errBody{"storage read failed"})
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, rc)
	default:
		http.NotFound(w, r)
	}
}
