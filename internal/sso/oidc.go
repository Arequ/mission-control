package sso

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	// Skew is the allowed clock difference on id_token exp, iat, and nbf.
	Skew = 2 * time.Minute
	// LoginTTL is how long a login state (state, nonce, PKCE verifier) lives.
	LoginTTL = 10 * time.Minute
)

// ErrRejected is a failed OIDC check. The text is safe to log and to show.
var ErrRejected = errors.New("oidc rejected")

func reject(msg string) error { return fmt.Errorf("%w: %s", ErrRejected, msg) }

// PKCE holds a verifier and its S256 challenge.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE returns a fresh S256 challenge.
func NewPKCE() (PKCE, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return PKCE{}, err
	}
	v := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(v))
	return PKCE{Verifier: v, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// RandomToken returns a URL-safe random string.
func RandomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SafeReturn keeps a same-origin path. Anything else becomes "/".
// Scheme-relative URLs, backslashes, encoded slashes, and userinfo are rejected.
func SafeReturn(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" {
		return "/"
	}
	if strings.ContainsAny(raw, "\\\r\n\x00") || strings.Contains(raw, "://") || strings.Contains(raw, "//") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Scheme != "" {
		return "/"
	}
	p := u.Path
	if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, "..") || strings.ContainsAny(p, "\\\r\n\x00") {
		return "/"
	}
	cleaned := path.Clean(p)
	if cleaned != p && cleaned+"/" != p {
		return "/"
	}
	if !strings.HasPrefix(cleaned, "/") || strings.Contains(cleaned, "..") {
		return "/"
	}
	out := p
	if u.RawQuery != "" {
		if strings.ContainsAny(u.RawQuery, "\\\r\n\x00") {
			return "/"
		}
		out += "?" + u.RawQuery
	}
	if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
		return "/"
	}
	return out
}

// Discovery is the subset of OpenID discovery Mission Control uses.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// Provider is the configured issuer the server will talk to.
type Provider struct {
	Issuer         string
	ClientID       string
	ClientSecret   string
	AllowedDomains []string
	GroupClaim     string
}

// NormalizeIssuer trims a trailing slash so discovery and the id_token agree.
func NormalizeIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", reject("issuer must be an http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", reject("issuer must not include credentials, a query, or a fragment")
	}
	if metadataHost(u.Hostname()) {
		return "", reject("issuer must not target the metadata service")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && deniedIP(ip) {
		return "", reject("issuer must not target a link-local address")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func metadataHost(host string) bool {
	h := strings.ToLower(host)
	return h == "metadata.google.internal" || h == "metadata.internal" || strings.HasSuffix(h, ".metadata.google.internal")
}

func deniedIP(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// 169.254.169.254 and the rest of link-local are covered. Also block the
	// IPv6 metadata address used by some clouds.
	if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return true
	}
	return false
}

// FetchDiscovery loads the OpenID document and checks the issuer and endpoints.
func FetchDiscovery(ctx context.Context, hc *http.Client, issuer string) (Discovery, error) {
	issuer, err := NormalizeIssuer(issuer)
	if err != nil {
		return Discovery{}, err
	}
	docURL := issuer + "/.well-known/openid-configuration"
	body, err := getJSON(ctx, hc, docURL, issuer)
	if err != nil {
		return Discovery{}, err
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return Discovery{}, reject("discovery document is not JSON")
	}
	got, err := NormalizeIssuer(d.Issuer)
	if err != nil || got != issuer {
		return Discovery{}, reject("discovery issuer does not match the configured issuer")
	}
	d.Issuer = got
	for _, ep := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if err := sameIssuerHost(issuer, ep); err != nil {
			return Discovery{}, err
		}
	}
	if d.UserinfoEndpoint != "" {
		if err := sameIssuerHost(issuer, d.UserinfoEndpoint); err != nil {
			return Discovery{}, err
		}
	}
	if d.EndSessionEndpoint != "" {
		if err := sameIssuerHost(issuer, d.EndSessionEndpoint); err != nil {
			d.EndSessionEndpoint = ""
		}
	}
	return d, nil
}

func sameIssuerHost(issuer, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return reject("discovery endpoint is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return reject("discovery endpoint is not an http(s) URL")
	}
	if u.User != nil {
		return reject("discovery endpoint must not include credentials")
	}
	base, _ := url.Parse(issuer)
	if !strings.EqualFold(u.Hostname(), base.Hostname()) {
		return reject("discovery endpoint host does not match the issuer")
	}
	if metadataHost(u.Hostname()) {
		return reject("discovery endpoint is not allowed")
	}
	return nil
}

func getJSON(ctx context.Context, hc *http.Client, raw, issuer string) ([]byte, error) {
	if err := sameIssuerHost(issuer, raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, reject("discovery request failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, reject("discovery request was not successful")
	}
	return body, nil
}

// AuthCodeURL builds the authorization redirect.
func AuthCodeURL(d Discovery, clientID, redirectURI, state, nonce, challenge string) (string, error) {
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid email profile groups")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TokenResponse is the token endpoint body we use.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

// ExchangeCode trades an authorization code with PKCE.
func ExchangeCode(ctx context.Context, hc *http.Client, d Discovery, clientID, clientSecret, redirectURI, code, verifier string) (TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return TokenResponse{}, reject("token endpoint request failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return TokenResponse{}, err
	}
	if res.StatusCode != http.StatusOK {
		return TokenResponse{}, reject("token endpoint rejected the code")
	}
	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return TokenResponse{}, reject("token endpoint did not return an id_token")
	}
	return tok, nil
}

// Identity is the validated user.
type Identity struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

// Claims are the id_token fields we accept.
type Claims struct {
	Issuer    string
	Audience  []string
	Subject   string
	Nonce     string
	Email     string
	Name      string
	HD        string
	Expiry    time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	HasNBF    bool
	Raw       map[string]any
}

// ValidateIDToken checks signature, issuer, audience, time, and nonce.
func ValidateIDToken(now time.Time, raw, issuer, clientID, nonce string, keys JWKS) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[2] == "" {
		return Claims{}, reject("id_token is not a signed JWT")
	}
	headJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, reject("id_token header is not base64")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headJSON, &header); err != nil {
		return Claims{}, reject("id_token header is not JSON")
	}
	if !strings.EqualFold(header.Alg, "RS256") {
		return Claims{}, reject("id_token alg must be RS256")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, reject("id_token payload is not base64")
	}
	if len(payload) > 1<<20 {
		return Claims{}, reject("id_token payload is too large")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, reject("id_token signature is not base64")
	}
	if err := verifyRS256(keys, header.Kid, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return Claims{}, err
	}
	claims, err := parseClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	wantIss, err := NormalizeIssuer(issuer)
	if err != nil {
		return Claims{}, err
	}
	gotIss, err := NormalizeIssuer(claims.Issuer)
	if err != nil || gotIss != wantIss {
		return Claims{}, reject("id_token issuer does not match the provider")
	}
	audOK := false
	for _, a := range claims.Audience {
		if subtle.ConstantTimeCompare([]byte(a), []byte(clientID)) == 1 && len(a) == len(clientID) {
			audOK = true
		}
	}
	if !audOK {
		return Claims{}, reject("id_token audience does not include the client id")
	}
	if claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 || len(claims.Nonce) != len(nonce) {
		return Claims{}, reject("id_token nonce does not match")
	}
	if claims.Expiry.IsZero() || !claims.Expiry.After(now.Add(-Skew)) {
		return Claims{}, reject("id_token is expired")
	}
	if claims.IssuedAt.IsZero() || claims.IssuedAt.After(now.Add(Skew)) {
		return Claims{}, reject("id_token iat is outside the allowed skew")
	}
	if claims.HasNBF && claims.NotBefore.After(now.Add(Skew)) {
		return Claims{}, reject("id_token is not valid yet")
	}
	if claims.Subject == "" {
		return Claims{}, reject("id_token has no subject")
	}
	return claims, nil
}

func parseClaims(payload []byte) (Claims, error) {
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Claims{}, reject("id_token payload is not JSON")
	}
	c := Claims{Raw: raw, Issuer: strClaim(raw["iss"]), Subject: strClaim(raw["sub"]), Nonce: strClaim(raw["nonce"]), Email: strClaim(raw["email"]), Name: strClaim(raw["name"]), HD: strClaim(raw["hd"])}
	c.Audience = audClaim(raw["aud"])
	var err error
	if c.Expiry, err = timeClaim(raw["exp"]); err != nil || c.Expiry.IsZero() {
		return Claims{}, reject("id_token exp is missing")
	}
	if c.IssuedAt, err = timeClaim(raw["iat"]); err != nil || c.IssuedAt.IsZero() {
		return Claims{}, reject("id_token iat is missing")
	}
	if raw["nbf"] != nil {
		c.NotBefore, err = timeClaim(raw["nbf"])
		if err != nil {
			return Claims{}, reject("id_token nbf is invalid")
		}
		c.HasNBF = true
	}
	return c, nil
}

func strClaim(v any) string {
	s, _ := v.(string)
	return s
}

func audClaim(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func timeClaim(v any) (time.Time, error) {
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			f, ferr := t.Float64()
			if ferr != nil {
				return time.Time{}, err
			}
			n = int64(f)
		}
		return time.Unix(n, 0).UTC(), nil
	case float64:
		return time.Unix(int64(t), 0).UTC(), nil
	default:
		return time.Time{}, errors.New("not a time")
	}
}

// Groups reads the configured claim from the id_token or userinfo.
func Groups(claim string, sources ...map[string]any) []string {
	if claim == "" {
		claim = "groups"
	}
	var out []string
	seen := map[string]bool{}
	for _, src := range sources {
		if src == nil {
			continue
		}
		for _, g := range groupValues(src[claim]) {
			if g == "" || seen[g] {
				continue
			}
			seen[g] = true
			out = append(out, g)
		}
		if len(out) > 0 {
			return out
		}
	}
	return out
}

func groupValues(v any) []string {
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return []string{strings.TrimSpace(t)}
	case []any:
		var out []string
		for _, item := range t {
			switch g := item.(type) {
			case string:
				if strings.TrimSpace(g) != "" {
					out = append(out, strings.TrimSpace(g))
				}
			case map[string]any:
				if s, ok := g["name"].(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				} else if s, ok := g["value"].(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
		}
		return out
	default:
		return nil
	}
}

// DomainAllowed checks the email domain and Google's hd claim.
// An empty allow list accepts any domain. A missing email is rejected when
// the list is non-empty.
func DomainAllowed(email, hd string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	domain := ""
	if at := strings.LastIndex(email, "@"); at > 0 && at < len(email)-1 {
		domain = strings.ToLower(email[at+1:])
	}
	ok := false
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" && a == domain {
			ok = true
		}
	}
	if !ok {
		return false
	}
	if hd == "" {
		return true
	}
	hd = strings.ToLower(hd)
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == hd {
			return true
		}
	}
	return false
}

// IdentityFrom builds the user after the token is validated.
func IdentityFrom(claims Claims, userinfo map[string]any, groupClaim string) Identity {
	id := Identity{Subject: claims.Subject, Email: claims.Email, Name: claims.Name}
	if id.Email == "" {
		id.Email = strClaim(userinfo["email"])
	}
	if id.Name == "" {
		id.Name = strClaim(userinfo["name"])
	}
	if id.Name == "" {
		id.Name = id.Email
	}
	id.Groups = Groups(groupClaim, claims.Raw, userinfo)
	return id
}

// FetchUserInfo calls the userinfo endpoint when groups were not in the id_token.
func FetchUserInfo(ctx context.Context, hc *http.Client, d Discovery, accessToken string) (map[string]any, error) {
	if d.UserinfoEndpoint == "" || accessToken == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return nil, reject("userinfo request failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, reject("userinfo was not successful")
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, reject("userinfo is not JSON")
	}
	return m, nil
}

// JWKS is a decoded key set.
type JWKS struct {
	Keys []JWK
}

// JWK is one RSA key.
type JWK struct {
	Kid string
	N   *big.Int
	E   int
}

// FetchJWKS downloads the key set from discovery.
func FetchJWKS(ctx context.Context, hc *http.Client, d Discovery) (JWKS, error) {
	body, err := getJSON(ctx, hc, d.JWKSURI, d.Issuer)
	if err != nil {
		return JWKS{}, err
	}
	return ParseJWKS(body)
}

// ParseJWKS decodes an RSA JWKS document.
func ParseJWKS(body []byte) (JWKS, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return JWKS{}, reject("jwks is not JSON")
	}
	var out JWKS
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		if k.Alg != "" && !strings.EqualFold(k.Alg, "RS256") {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(eb) == 0 || len(eb) > 4 {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e <= 1 {
			continue
		}
		out.Keys = append(out.Keys, JWK{Kid: k.Kid, N: new(big.Int).SetBytes(nb), E: e})
	}
	if len(out.Keys) == 0 {
		return JWKS{}, reject("jwks has no RSA signing key")
	}
	return out, nil
}

func verifyRS256(keys JWKS, kid string, signed, sig []byte) error {
	sum := sha256.Sum256(signed)
	matched := false
	for _, k := range keys.Keys {
		if kid != "" && k.Kid != kid {
			continue
		}
		matched = true
		pub := &rsa.PublicKey{N: k.N, E: k.E}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err == nil {
			return nil
		}
	}
	if kid != "" && !matched {
		return reject("id_token kid was not in the jwks")
	}
	return reject("id_token signature is invalid")
}

// LogoutURL builds an RP-initiated logout URL when the provider published one.
// postLogout must already be a same-origin absolute URL we control.
func LogoutURL(d Discovery, idToken, postLogout, clientID string) string {
	if d.EndSessionEndpoint == "" || idToken == "" {
		return ""
	}
	u, err := url.Parse(d.EndSessionEndpoint)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("id_token_hint", idToken)
	if postLogout != "" {
		q.Set("post_logout_redirect_uri", postLogout)
	}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// dialSafe refuses the metadata service and any address that resolves to a
// link-local IP, including a hostname that only looks private after DNS.
func dialSafe(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if metadataHost(host) {
		return nil, fmt.Errorf("host %s is not allowed", host)
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		resolved, rerr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if rerr != nil {
			return nil, rerr
		}
		for _, item := range resolved {
			ips = append(ips, item.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("host %s did not resolve", host)
	}
	for _, ip := range ips {
		if deniedIP(ip) {
			return nil, fmt.Errorf("address %s is not allowed", ip)
		}
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// SafeClient does not follow redirects and refuses link-local addresses.
func SafeClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("oidc redirects are not followed")
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialSafe,
			ResponseHeaderTimeout: 8 * time.Second,
		},
	}
}
