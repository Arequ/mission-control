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

// TerraformClientHeader is sent by terraform-provider-missioncontrol on every request.
// Config mutations require it. The UI does not send it, and neither does a raw API token.
const TerraformClientHeader = "X-Mission-Control-Client"

func terraformClient(r *http.Request) bool {
	return r.Header.Get(TerraformClientHeader) == "terraform"
}

// withConfigWrite allows config changes only from the Terraform provider.
// A token with config:write is not enough: GitOps is the only writer.
func (s *Server) withConfigWrite(next http.Handler) http.Handler {
	return s.withAPI("config:write", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !terraformClient(r) {
			writeJSON(w, http.StatusForbidden, errBody{"configuration is managed by Terraform"})
			return
		}
		next.ServeHTTP(w, r)
	}))
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
	if _, pass, ok := r.BasicAuth(); ok {
		// The password is the secret. The username is not compared, so the token is not
		// placed where access logs record the user.
		if s.repoToken != "" && auth.SecretEqual(pass, s.repoToken) {
			return true
		}
		if p, err := s.store.LookupAPIToken(r.Context(), pass); err == nil && p.Allows("munki:read") {
			return true
		}
	}
	raw := auth.Bearer(r.Header.Get("Authorization"))
	if raw == "" {
		return false
	}
	if s.repoToken != "" && auth.SecretEqual(raw, s.repoToken) {
		return true
	}
	p, err := s.store.LookupAPIToken(r.Context(), raw)
	return err == nil && p.Allows("munki:read")
}
