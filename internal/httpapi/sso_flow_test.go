package httpapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestOIDCLoginSessionAndGuards(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	nonce := ""
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, http.StatusOK, map[string]string{
				"issuer": idp.URL, "authorization_endpoint": idp.URL + "/auth",
				"token_endpoint": idp.URL + "/token", "jwks_uri": idp.URL + "/keys",
				"userinfo_endpoint": idp.URL + "/userinfo",
			})
		case "/keys":
			n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
			writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "test", "alg": "RS256", "n": n,
				"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			}}})
		case "/auth":
			mu.Lock()
			nonce = r.URL.Query().Get("nonce")
			mu.Unlock()
			redir, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			q := redir.Query()
			q.Set("code", "code-1")
			q.Set("state", r.URL.Query().Get("state"))
			q.Set("iss", idp.URL)
			redir.RawQuery = q.Encode()
			http.Redirect(w, r, redir.String(), http.StatusFound)
		case "/token":
			mu.Lock()
			n := nonce
			mu.Unlock()
			tok := signID(t, key, map[string]any{
				"iss": idp.URL, "aud": "mission-control", "sub": "ava", "nonce": n,
				"email": "ava@example.com", "name": "Ava", "groups": []string{"engineering"},
				"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			})
			writeJSON(w, http.StatusOK, map[string]string{"access_token": "at", "id_token": tok, "token_type": "Bearer"})
		case "/userinfo":
			writeJSON(w, http.StatusOK, map[string]any{"email": "ava@example.com", "groups": []string{"engineering"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	ctx := t.Context()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Options{Store: st, Blobs: blobs})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	tf := map[string]string{"Authorization": "Bearer mc_admin", "X-Mission-Control-Client": "terraform", "Content-Type": "application/json"}
	status, body := do(t, ts, http.MethodPost, "/api/v1/sso/config", "", tf,
		`{"name":"dex","issuer":"`+idp.URL+`","client_id":"mission-control","client_secret":"example-oidc-client-secret","allowed_domains":["example.com"],"group_claim":"groups","enabled":true}`)
	if status != http.StatusCreated || strings.Contains(body, "example-oidc-client-secret") {
		t.Fatalf("provider %d %s", status, body)
	}
	var prov struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &prov); err != nil {
		t.Fatal(err)
	}
	status, body = do(t, ts, http.MethodGet, "/api/v1/sso/config/"+prov.ID, "mc_admin", nil, "")
	if status != http.StatusOK || strings.Contains(body, "client_secret") && strings.Contains(body, "example-oidc") {
		t.Fatalf("provider get %d %s", status, body)
	}
	status, body = do(t, ts, http.MethodPost, "/api/v1/sso/role-bindings", "", tf,
		`{"provider_id":"`+prov.ID+`","group":"engineering","role":"admin"}`)
	if status != http.StatusCreated {
		t.Fatalf("binding %d %s", status, body)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	login, err := noFollow.Get(ts.URL + "/api/v1/sso/login?provider=" + prov.ID + "&return=https://evil.test/phish")
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusFound {
		t.Fatalf("login %d", login.StatusCode)
	}
	stateCookie := cookieNamed(login, "mc_oidc")
	authRes, err := noFollow.Get(login.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authRes.Body.Close()
	cb, err := http.NewRequest(http.MethodGet, authRes.Header.Get("Location"), nil)
	if err != nil {
		t.Fatal(err)
	}
	cb.AddCookie(stateCookie)
	cbRes, err := noFollow.Do(cb)
	if err != nil {
		t.Fatal(err)
	}
	cbRes.Body.Close()
	if cbRes.StatusCode != http.StatusFound || cbRes.Header.Get("Location") != "/" {
		t.Fatalf("open redirect %d %s", cbRes.StatusCode, cbRes.Header.Get("Location"))
	}
	sessionCookie := cookieNamed(cbRes, "mc_session")
	if sessionCookie == nil || sessionCookie.Value == "" || !sessionCookie.HttpOnly {
		t.Fatal("session cookie")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/session", nil)
	req.AddCookie(sessionCookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	var user struct {
		Email string `json:"email"`
		Role  string `json:"role"`
		CSRF  string `json:"csrf_token"`
	}
	if err := json.Unmarshal(raw, &user); err != nil || user.Email != "ava@example.com" || user.Role != "admin" || user.CSRF == "" {
		t.Fatalf("session %d %s", res.StatusCode, raw)
	}

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/session/logout", nil)
	req.AddCookie(sessionCookie)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf missing %d", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer nope")
	req.AddCookie(sessionCookie)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer should not fall back to cookie %d", res.StatusCode)
	}
	status, _ = do(t, ts, http.MethodPost, "/api/v1/jobs", "mc_admin", nil, `{"recipe_id":"missing"}`)
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		t.Fatalf("bearer post required csrf %d", status)
	}

	// A pre-set session cookie is not the cookie issued by login.
	planted := &http.Cookie{Name: "mc_session", Value: "attacker-session-value"}
	login, err = noFollow.Get(ts.URL + "/api/v1/sso/login?provider=" + prov.ID + "&return=/devices")
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	authRes, err = noFollow.Get(login.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authRes.Body.Close()
	mixed, _ := url.Parse(authRes.Header.Get("Location"))
	mq := mixed.Query()
	mq.Set("iss", "https://evil.example")
	mixed.RawQuery = mq.Encode()
	cb, _ = http.NewRequest(http.MethodGet, mixed.String(), nil)
	cb.AddCookie(cookieNamed(login, "mc_oidc"))
	cb.AddCookie(planted)
	cbRes, err = noFollow.Do(cb)
	if err != nil {
		t.Fatal(err)
	}
	cbRes.Body.Close()
	if cbRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("issuer mix-up %d", cbRes.StatusCode)
	}
}

func cookieNamed(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func signID(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test"})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jsonUnmarshal(s string, dst any) error { return json.Unmarshal([]byte(s), dst) }
