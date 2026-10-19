package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/sso"
	"github.com/Arequ/mission-control/internal/store"
)

const (
	sessionCookie = "mc_session"
	oidcCookie    = "mc_oidc"
	csrfHeader    = "X-CSRF-Token"
)

func (s *Server) listSSOProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListSSOProviders(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	pub := make([]model.SSOProvider, len(items))
	for i, item := range items {
		pub[i] = item.Public()
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": pub})
}

func (s *Server) createSSOProvider(w http.ResponseWriter, r *http.Request) {
	var in model.SSOProvider
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateSSOProvider(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out.Public())
}

func (s *Server) getSSOProvider(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetSSOProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) updateSSOProvider(w http.ResponseWriter, r *http.Request) {
	var in model.SSOProvider
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateSSOProvider(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out.Public())
}

func (s *Server) deleteSSOProvider(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSSOProvider(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRoleBindings(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": items})
}

func (s *Server) createRoleBinding(w http.ResponseWriter, r *http.Request) {
	var in model.RoleBinding
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.CreateRoleBinding(r.Context(), principal(r), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) getRoleBinding(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.GetRoleBinding(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateRoleBinding(w http.ResponseWriter, r *http.Request) {
	var in model.RoleBinding
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	in.ManagedBy = "terraform"
	out, err := s.store.UpdateRoleBinding(r.Context(), principal(r), r.PathValue("id"), in)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteRoleBinding(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRoleBinding(r.Context(), principal(r), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publicSSOProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListEnabledSSOProviders(r.Context())
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if items == nil {
		items = []model.SSOProviderPublic{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": items})
}

func (s *Server) ssoLogin(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("provider"))
	prov, err := s.store.SSOProviderForLogin(r.Context(), id)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	if !prov.Enabled {
		writeJSON(w, http.StatusNotFound, errBody{"not found"})
		return
	}
	redirectURI, err := s.redirectURI(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"public url is not configured"})
		return
	}
	disc, err := sso.FetchDiscovery(r.Context(), sso.SafeClient(), prov.Issuer)
	if err != nil {
		s.log.Error("oidc discovery", "err", err)
		writeJSON(w, http.StatusBadGateway, errBody{"identity provider is unavailable"})
		return
	}
	state, err := sso.RandomToken()
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	nonce, err := sso.RandomToken()
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	pkce, err := sso.NewPKCE()
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	ret := sso.SafeReturn(r.URL.Query().Get("return"))
	if err := s.store.SaveLoginState(r.Context(), store.LoginState{
		ID: state, ProviderID: prov.ID, Nonce: nonce, Verifier: pkce.Verifier, ReturnTo: ret,
	}, sso.LoginTTL); err != nil {
		s.writeStoreErr(w, err)
		return
	}
	s.setCookie(w, oidcCookie, state, int(sso.LoginTTL.Seconds()))
	loc, err := sso.AuthCodeURL(disc, prov.ClientID, redirectURI, state, nonce, pkce.Challenge)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody{"identity provider is unavailable"})
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (s *Server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("error") != "" {
		s.clearCookie(w, oidcCookie)
		writeJSON(w, http.StatusBadRequest, errBody{"sign-in was cancelled"})
		return
	}
	cookie, err := r.Cookie(oidcCookie)
	state := q.Get("state")
	if err != nil || cookie.Value == "" || state == "" || cookie.Value != state {
		s.clearCookie(w, oidcCookie)
		writeJSON(w, http.StatusBadRequest, errBody{"sign-in state did not match"})
		return
	}
	st, err := s.store.ConsumeLoginState(r.Context(), state)
	if err != nil {
		s.clearCookie(w, oidcCookie)
		writeJSON(w, http.StatusBadRequest, errBody{"sign-in state expired"})
		return
	}
	s.clearCookie(w, oidcCookie)
	prov, err := s.store.SSOProviderForLogin(r.Context(), st.ProviderID)
	if err != nil || !prov.Enabled {
		writeJSON(w, http.StatusBadRequest, errBody{"identity provider is not available"})
		return
	}
	if iss := strings.TrimSpace(q.Get("iss")); iss != "" && iss != prov.Issuer {
		writeJSON(w, http.StatusBadRequest, errBody{"identity provider did not match"})
		return
	}
	redirectURI, err := s.redirectURI(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"public url is not configured"})
		return
	}
	hc := sso.SafeClient()
	disc, err := sso.FetchDiscovery(r.Context(), hc, prov.Issuer)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody{"identity provider is unavailable"})
		return
	}
	tok, err := sso.ExchangeCode(r.Context(), hc, disc, prov.ClientID, prov.ClientSecret, redirectURI, q.Get("code"), st.Verifier)
	if err != nil {
		s.log.Error("oidc exchange", "err", err)
		writeJSON(w, http.StatusBadRequest, errBody{"sign-in could not be completed"})
		return
	}
	keys, err := sso.FetchJWKS(r.Context(), hc, disc)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody{"identity provider is unavailable"})
		return
	}
	claims, err := sso.ValidateIDToken(time.Now(), tok.IDToken, prov.Issuer, prov.ClientID, st.Nonce, keys)
	if err != nil {
		s.log.Error("oidc token", "err", err)
		writeJSON(w, http.StatusBadRequest, errBody{"sign-in could not be completed"})
		return
	}
	var userinfo map[string]any
	if disc.UserinfoEndpoint != "" && tok.AccessToken != "" {
		userinfo, err = sso.FetchUserInfo(r.Context(), hc, disc, tok.AccessToken)
		if err != nil {
			s.log.Error("oidc userinfo", "err", err)
			writeJSON(w, http.StatusBadRequest, errBody{"sign-in could not be completed"})
			return
		}
	}
	ident := sso.IdentityFrom(claims, userinfo, prov.GroupClaim)
	if !sso.DomainAllowed(ident.Email, claims.HD, prov.AllowedDomains) {
		writeJSON(w, http.StatusForbidden, errBody{"this account is not allowed"})
		return
	}
	raw, user, err := s.store.CreateSession(r.Context(), store.SessionRecord{
		ProviderID: prov.ID, Subject: ident.Subject, Email: ident.Email, Name: ident.Name,
		Groups: ident.Groups, IDToken: tok.IDToken,
	}, s.sessionAbsolute, s.sessionIdle)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	s.setCookie(w, sessionCookie, raw, int(s.sessionAbsolute.Seconds()))
	_ = user
	http.Redirect(w, r, sso.SafeReturn(st.ReturnTo), http.StatusFound)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	raw, err := r.Cookie(sessionCookie)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	rec, err := s.store.LookupSession(r.Context(), raw.Value, s.sessionIdle)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, model.SessionUser{
		Email: rec.Email, Name: rec.Name, Role: rec.Role, CSRFToken: rec.CSRF,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	raw, err := r.Cookie(sessionCookie)
	s.clearCookie(w, sessionCookie)
	if err != nil || raw.Value == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	rec, err := s.store.RevokeSession(r.Context(), raw.Value)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	logoutURL := ""
	if rec.ProviderID != "" && rec.IDToken != "" {
		if prov, perr := s.store.SSOProviderForLogin(r.Context(), rec.ProviderID); perr == nil {
			if disc, derr := sso.FetchDiscovery(r.Context(), sso.SafeClient(), prov.Issuer); derr == nil {
				post := ""
				if s.publicURL != "" {
					post = strings.TrimRight(s.publicURL, "/") + "/"
				}
				logoutURL = sso.LogoutURL(disc, rec.IDToken, post, prov.ClientID)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "logout_url": logoutURL})
}

func (s *Server) refreshSession(w http.ResponseWriter, r *http.Request) {
	raw, err := r.Cookie(sessionCookie)
	if err != nil || raw.Value == "" {
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	next, user, err := s.store.RotateSession(r.Context(), raw.Value, s.sessionAbsolute, s.sessionIdle)
	if err != nil {
		s.clearCookie(w, sessionCookie)
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	s.setCookie(w, sessionCookie, next, int(s.sessionAbsolute.Seconds()))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) breakGlassLogin(w http.ResponseWriter, r *http.Request) {
	if !s.breakGlass {
		writeJSON(w, http.StatusNotFound, errBody{"not found"})
		return
	}
	ip := r.RemoteAddr
	if !s.loginFails.allow(ip, time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, errBody{"try again later"})
		return
	}
	if r.Header.Get("Authorization") != "" {
		p, err := s.store.LookupAPIToken(r.Context(), auth.Bearer(r.Header.Get("Authorization")))
		if err != nil || !p.Allows("admin") {
			s.loginFails.fail(ip, time.Now())
			writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
			return
		}
		s.issueBreakGlass(w, r, p.Name)
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		badJSON(w, err)
		return
	}
	if s.breakGlassPassword == "" || !auth.SecretEqual(in.Password, s.breakGlassPassword) {
		s.loginFails.fail(ip, time.Now())
		writeJSON(w, http.StatusUnauthorized, errBody{"unauthorized"})
		return
	}
	s.issueBreakGlass(w, r, "break-glass")
}

func (s *Server) issueBreakGlass(w http.ResponseWriter, r *http.Request, name string) {
	raw, user, err := s.store.CreateSession(r.Context(), store.SessionRecord{
		Email: name, Name: name, Role: sso.RoleAdmin, BreakGlass: true,
	}, s.sessionAbsolute, s.sessionIdle)
	if err != nil {
		s.writeStoreErr(w, err)
		return
	}
	s.setCookie(w, sessionCookie, raw, int(s.sessionAbsolute.Seconds()))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) redirectURI(r *http.Request) (string, error) {
	if s.publicURL != "" {
		u, err := url.Parse(s.publicURL)
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			return "", err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", err
		}
		u.Path = "/api/v1/sso/callback"
		u.RawQuery = ""
		u.Fragment = ""
		return u.String(), nil
	}
	if !store.LoopbackHost(r.Host) {
		return "", http.ErrNoLocation
	}
	return "http://" + r.Host + "/api/v1/sso/callback", nil
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true,
		Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

type failWindow struct {
	mu sync.Mutex
	at map[string][]time.Time
}

func (f *failWindow) allow(key string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune(key, now)
	return len(f.at[key]) < 8
}

func (f *failWindow) fail(key string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.at == nil {
		f.at = map[string][]time.Time{}
	}
	f.prune(key, now)
	f.at[key] = append(f.at[key], now)
}

func (f *failWindow) prune(key string, now time.Time) {
	if f.at == nil {
		f.at = map[string][]time.Time{}
		return
	}
	cut := now.Add(-15 * time.Minute)
	kept := f.at[key][:0]
	for _, t := range f.at[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	f.at[key] = kept
}
