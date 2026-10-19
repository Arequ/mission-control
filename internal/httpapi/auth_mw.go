package httpapi

import (
	"net/http"

	"github.com/Arequ/mission-control/internal/auth"
)

func (s *Server) withAPI(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := auth.Bearer(r.Header.Get("Authorization"))
		p, err := s.store.LookupAPIToken(r.Context(), raw)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
			return
		}
		if scope != "" && !p.Allows(scope) {
			writeJSON(w, http.StatusForbidden, errBody{"forbidden"})
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

func (s *Server) withBootstrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := auth.Bearer(r.Header.Get("Authorization"))
		p, err := s.store.LookupBootstrapToken(r.Context(), raw)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

func (s *Server) withRunner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := auth.Bearer(r.Header.Get("Authorization"))
		p, err := s.store.LookupRunner(r.Context(), raw)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

func (s *Server) withRepo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.repoOK(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="mission-control"`)
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
	})
}

func (s *Server) repoOK(r *http.Request) bool {
	if user, pass, ok := r.BasicAuth(); ok {
		if s.repoToken != "" && (pass == s.repoToken || user == s.repoToken) {
			return true
		}
		if p, err := s.store.LookupAPIToken(r.Context(), pass); err == nil && p.Allows("munki:read") {
			return true
		}
	}
	raw := auth.Bearer(r.Header.Get("Authorization"))
	if raw == "" {
		if q := r.URL.Query().Get("token"); q != "" {
			raw = q
		}
	}
	if s.repoToken != "" && raw == s.repoToken {
		return true
	}
	if raw == "" {
		return false
	}
	p, err := s.store.LookupAPIToken(r.Context(), raw)
	return err == nil && p.Allows("munki:read")
}
