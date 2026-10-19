package httpapi

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/sso"
	"github.com/Arequ/mission-control/internal/store"
)

type munkiAuthKey struct{}

func withMunkiAuth(ctx context.Context, a store.MunkiAuth) context.Context {
	return context.WithValue(ctx, munkiAuthKey{}, a)
}

func munkiAuthFrom(r *http.Request) store.MunkiAuth {
	a, _ := r.Context().Value(munkiAuthKey{}).(store.MunkiAuth)
	return a
}

func (s *Server) withAPI(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A present Authorization header is exclusive. A bad bearer does not
		// fall through to a session cookie.
		if r.Header.Get("Authorization") != "" {
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
			return
		}
		raw, err := r.Cookie(sessionCookie)
		if err != nil || strings.TrimSpace(raw.Value) == "" {
			writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
			return
		}
		rec, err := s.store.LookupSession(r.Context(), raw.Value, s.sessionIdle)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
			return
		}
		if mutating(r.Method) && !csrfOK(r, rec.CSRF) {
			writeJSON(w, http.StatusForbidden, errBody{"csrf"})
			return
		}
		p := model.Principal{
			Kind:   "session",
			ID:     auth.Hash(raw.Value),
			Name:   rec.Email,
			Scopes: sso.ScopesForRole(rec.Role),
		}
		if scope != "" && !p.Allows(scope) {
			writeJSON(w, http.StatusForbidden, errBody{"forbidden"})
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

func mutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func csrfOK(r *http.Request, want string) bool {
	got := r.Header.Get(csrfHeader)
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
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
		user, secret, creds := repoCredentials(r)
		var authn store.MunkiAuth
		if creds {
			got, ok, err := s.store.AuthenticateMunki(r.Context(), user, secret)
			if err != nil {
				s.writeStoreErr(w, err)
				return
			}
			if ok {
				authn = got
			}
		}
		if s.repoOK(r) || authn.EnrollmentID != "" || authn.Serial != "" {
			next.ServeHTTP(w, r.WithContext(withMunkiAuth(r.Context(), authn)))
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="mission-control"`)
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
	})
}

func repoCredentials(r *http.Request) (user, secret string, ok bool) {
	if u, p, basic := r.BasicAuth(); basic {
		return u, p, true
	}
	if raw := auth.Bearer(r.Header.Get("Authorization")); raw != "" {
		return "", raw, true
	}
	return "", "", false
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
