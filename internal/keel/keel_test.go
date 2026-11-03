package keel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T, seed string) ed25519.PrivateKey {
	t.Helper()
	sum := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(sum[:])
}

func TestMessageMatchesContract(t *testing.T) {
	body := []byte(`{"schema":"keel.report/v1"}`)
	sum := sha256.Sum256(body)
	want := "keel-report-v1\nDF7XP7HY3N\n1793750400\n" + hex.EncodeToString(sum[:])
	if got := string(Message("DF7XP7HY3N", 1793750400, body)); got != want {
		t.Fatalf("message\n%q\nwant\n%q", got, want)
	}
	if strings.HasSuffix(want, "\n") {
		t.Fatal("contract has no trailing newline")
	}
}

func TestParseTimestamp(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"1793750400", true},
		{"0", true},
		{"", false},
		{"+1793750400", false},
		{"-1", false},
		{"01793750400", false},
		{"1793750400.5", false},
		{" 1793750400", false},
		{"99999999999999999999", false},
	} {
		_, err := ParseTimestamp(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("%q err=%v want ok=%v", tc.in, err, tc.ok)
		}
	}
}

func TestVerifyAndSkew(t *testing.T) {
	priv := testKey(t, "device")
	pub := priv.Public().(ed25519.PublicKey)
	other := testKey(t, "other").Public().(ed25519.PublicKey)
	now := time.Unix(1793750400, 0)
	body := []byte(`{"schema":"keel.report/v1","run_id":"r1"}`)
	ts := now.Unix()
	sig := Sign(priv, "DF7XP7HY3N", ts, body)

	cases := []struct {
		name   string
		pub    ed25519.PublicKey
		serial string
		ts     int64
		sig    string
		body   []byte
		want   error
	}{
		{"good signature", pub, "DF7XP7HY3N", ts, sig, body, nil},
		{"tampered body", pub, "DF7XP7HY3N", ts, sig, []byte(`{"schema":"keel.report/v1","run_id":"r2"}`), ErrBadSignature},
		{"trailing whitespace changes the digest", pub, "DF7XP7HY3N", ts, sig, append(append([]byte{}, body...), '\n'), ErrBadSignature},
		{"wrong key", other, "DF7XP7HY3N", ts, sig, body, ErrBadSignature},
		{"serial swapped", pub, "C02OTHER01", ts, sig, body, ErrBadSignature},
		{"timestamp swapped", pub, "DF7XP7HY3N", ts + 1, sig, body, ErrBadSignature},
		{"not base64", pub, "DF7XP7HY3N", ts, "!!!", body, ErrBadSignature},
		{"short signature", pub, "DF7XP7HY3N", ts, base64.StdEncoding.EncodeToString([]byte("short")), body, ErrBadSignature},
		{"unpadded base64 is not standard", pub, "DF7XP7HY3N", ts, strings.TrimRight(sig, "="), body, ErrBadSignature},
		{"no key", nil, "DF7XP7HY3N", ts, sig, body, ErrBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(tc.pub, tc.serial, tc.ts, tc.sig, tc.body)
			if !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}

	skew := []struct {
		name string
		ts   int64
		ok   bool
	}{
		{"now", now.Unix(), true},
		{"300s old", now.Unix() - 300, true},
		{"300s ahead", now.Unix() + 300, true},
		{"too old", now.Unix() - 301, false},
		{"too new", now.Unix() + 301, false},
		{"epoch", 0, false},
	}
	for _, tc := range skew {
		t.Run("skew "+tc.name, func(t *testing.T) {
			err := CheckSkew(tc.ts, now)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrSkew) {
				t.Fatal(err)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	pub := testKey(t, "k").Public().(ed25519.PublicKey)
	if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "AAAA", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.RawStdEncoding.EncodeToString(pub), "not base64!"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

const goodBody = `{
  "schema": "keel.report/v1",
  "run_id": "6f1c2a7e",
  "keel_version": "0.1.0+abc1234",
  "mode": "apply",
  "started_at": "2026-11-03T15:04:05Z",
  "duration_ms": 812,
  "device": {"serial": "DF7XP7HY3N", "hostname": "CW-DF7XP7HY3N-L"},
  "roles": [{"name": "baseline", "parents": []}, {"name": "employee", "parents": ["baseline"], "match": "default"}],
  "facts": {"serial": "DF7XP7HY3N"},
  "profiles": [{"name": "netskope", "enabled": true, "settings": {"enrollment": {"auth_token": "[redacted]"}}}],
  "resources": [],
  "summary": {"total": 42, "ok": 40, "changed": 1, "would_change": 0, "failed": 1, "skipped": 0},
  "warnings": ["netskope disabled: missing secrets [NETSKOPE_CC_ORG_KEY]"],
  "overlays": ["/etc/keel/overlays.d/50-pilot.yaml"],
  "future_field": {"anything": true}
}`

func TestParseReport(t *testing.T) {
	r, err := ParseReport([]byte(goodBody), "DF7XP7HY3N")
	if err != nil {
		t.Fatal(err)
	}
	if r.LeafRole() != "employee" || strings.Join(r.RoleNames(), ",") != "baseline,employee" {
		t.Fatalf("roles %+v", r.Roles)
	}
	if r.DurationMS != 812 || r.Summary.Failed != 1 || r.Summary.Total != 42 || r.Mode != "apply" {
		t.Fatalf("%+v", r)
	}
	if r.LeafMatch() != "default" || len(r.Warnings) != 1 || len(r.Overlays) != 1 || r.CompileFailed() {
		t.Fatalf("warnings %+v overlays %+v", r.Warnings, r.Overlays)
	}
	compile := strings.Replace(goodBody, `"warnings": [`, `"warnings": ["compile: roles/x.yaml:1: bad", `, 1)
	if c, err := ParseReport([]byte(compile), "DF7XP7HY3N"); err != nil || !c.CompileFailed() {
		t.Fatalf("compile warning %v", err)
	}
	if !r.StartedAt.Equal(time.Date(2026, 11, 3, 15, 4, 5, 0, time.UTC)) {
		t.Fatal(r.StartedAt)
	}

	cases := []struct {
		name, body, serial string
	}{
		{"serial header and body disagree", goodBody, "C02OTHER01"},
		{"wrong schema", strings.Replace(goodBody, "keel.report/v1", "keel.report/v2", 1), "DF7XP7HY3N"},
		{"missing run id", strings.Replace(goodBody, `"run_id": "6f1c2a7e",`, "", 1), "DF7XP7HY3N"},
		{"bad mode", strings.Replace(goodBody, `"mode": "apply"`, `"mode": "yolo"`, 1), "DF7XP7HY3N"},
		{"bad started_at", strings.Replace(goodBody, "2026-11-03T15:04:05Z", "yesterday", 1), "DF7XP7HY3N"},
		{"negative duration", strings.Replace(goodBody, `"duration_ms": 812`, `"duration_ms": -1`, 1), "DF7XP7HY3N"},
		{"resources not an array", strings.Replace(goodBody, `"resources": []`, `"resources": {}`, 1), "DF7XP7HY3N"},
		{"facts not an object", strings.Replace(goodBody, `"facts": {"serial": "DF7XP7HY3N"}`, `"facts": [1]`, 1), "DF7XP7HY3N"},
		{"not json", "nope", "DF7XP7HY3N"},
		{"warnings not strings", strings.Replace(goodBody, `"warnings": [`, `"warnings": [1, `, 1), "DF7XP7HY3N"},
		{"two documents", goodBody + goodBody, "DF7XP7HY3N"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseReport([]byte(tc.body), tc.serial)
			var be *BodyError
			if !errors.As(err, &be) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
