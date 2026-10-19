package sso

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestSafeReturn(t *testing.T) {
	cases := map[string]string{
		"":                    "/",
		"/devices":            "/devices",
		"/devices?q=1":        "/devices?q=1",
		"https://evil.test":   "/",
		"//evil.test":         "/",
		"/\\evil.test":        "/",
		"/devices/../../etc":  "/",
		"/%2f%2fevil.example": "/",
		"/%5c%5cevil.example": "/",
		"/devices/%2e%2e/etc": "/",
		"/%0d%0aLocation:%20https://evil.example": "/",
	}
	for in, want := range cases {
		if got := SafeReturn(in); got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestDialSafeRejectsMetadata(t *testing.T) {
	ctx := context.Background()
	for _, addr := range []string{"169.254.169.254:80", "[fd00:ec2::254]:80", "metadata.google.internal:80"} {
		if _, err := dialSafe(ctx, "tcp", addr); err == nil {
			t.Fatalf("dial %s was allowed", addr)
		}
	}
}

func TestPKCEChallenge(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want || p.Verifier == "" {
		t.Fatalf("%+v", p)
	}
}

func TestValidateIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := jwksFor(t, key)
	now := time.Now().UTC().Truncate(time.Second)
	good := signToken(t, key, map[string]any{
		"iss": "http://127.0.0.1:9/dex", "aud": "mission-control", "sub": "ava",
		"nonce": "n1", "email": "ava@example.com", "groups": []string{"engineering"},
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	})
	claims, err := ValidateIDToken(now, good, "http://127.0.0.1:9/dex", "mission-control", "n1", keys)
	if err != nil {
		t.Fatal(err)
	}
	if Groups("groups", claims.Raw)[0] != "engineering" {
		t.Fatal(claims.Raw)
	}
	if _, err := ValidateIDToken(now, good, "http://evil.example/dex", "mission-control", "n1", keys); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	if _, err := ValidateIDToken(now, good, "http://127.0.0.1:9/dex", "other-client", "n1", keys); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, err := ValidateIDToken(now, good, "http://127.0.0.1:9/dex", "mission-control", "other", keys); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	expired := signToken(t, key, map[string]any{
		"iss": "http://127.0.0.1:9/dex", "aud": "mission-control", "sub": "ava", "nonce": "n1",
		"exp": now.Add(-time.Hour).Unix(), "iat": now.Add(-2 * time.Hour).Unix(),
	})
	if _, err := ValidateIDToken(now, expired, "http://127.0.0.1:9/dex", "mission-control", "n1", keys); err == nil {
		t.Fatal("expired token accepted")
	}
	skewed := signToken(t, key, map[string]any{
		"iss": "http://127.0.0.1:9/dex", "aud": "mission-control", "sub": "ava", "nonce": "n1",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(Skew + time.Minute).Unix(),
	})
	if _, err := ValidateIDToken(now, skewed, "http://127.0.0.1:9/dex", "mission-control", "n1", keys); err == nil {
		t.Fatal("future iat accepted")
	}
	within := signToken(t, key, map[string]any{
		"iss": "http://127.0.0.1:9/dex", "aud": "mission-control", "sub": "ava", "nonce": "n1",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(Skew - time.Second).Unix(),
	})
	if _, err := ValidateIDToken(now, within, "http://127.0.0.1:9/dex", "mission-control", "n1", keys); err != nil {
		t.Fatal(err)
	}
}

func TestMapRole(t *testing.T) {
	bindings := []Binding{{Group: "engineering", Role: RoleAdmin}, {Group: "*", Role: RoleViewer}}
	role, ok := MapRole([]string{"engineering"}, bindings)
	if !ok || role != RoleAdmin {
		t.Fatalf("%s %v", role, ok)
	}
	role, ok = MapRole(nil, bindings)
	if !ok || role != RoleViewer {
		t.Fatalf("catch-all %s %v", role, ok)
	}
	if _, ok := MapRole([]string{"other"}, []Binding{{Group: "engineering", Role: RoleAdmin}}); ok {
		t.Fatal("unmapped group matched")
	}
}

func jwksFor(t *testing.T, key *rsa.PrivateKey) JWKS {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	body := []byte(`{"keys":[{"kty":"RSA","kid":"test","alg":"RS256","n":"` + n + `","e":"` + e + `"}]}`)
	keys, err := ParseJWKS(body)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func signToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}
