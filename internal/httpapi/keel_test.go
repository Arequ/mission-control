package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/keel"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/testutil"
)

const keelSecret = "example-keel-enroll-secret"

type keelHarness struct {
	t   *testing.T
	st  *store.Store
	ts  *httptest.Server
	clk *clock.Manual
}

func newKeelHarness(t *testing.T) *keelHarness {
	t.Helper()
	ctx := context.Background()
	st := testutil.NewStore(t)
	clk := &clock.Manual{T: time.Date(2026, 11, 3, 15, 0, 0, 0, time.UTC)}
	st.SetClock(clk)
	p := model.Principal{Kind: "system", Name: "test"}
	if _, err := st.CreateKeelEnrollSecret(ctx, p, model.KeelEnrollSecret{Name: "fleet", Secret: keelSecret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateKeelEnrollSecret(ctx, p, model.KeelEnrollSecret{Name: "old", Secret: "disabled-keel-secret", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	for name, scopes := range map[string][]string{
		"mc_admin":   {"*"},
		"mc_viewer":  {"keel:read", "osquery:read"},
		"mc_keeladm": {"keel:admin"},
	} {
		if err := st.EnsureAPIToken(ctx, name, name, scopes); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(Options{Store: st})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &keelHarness{t: t, st: st, ts: ts, clk: clk}
}

func (h *keelHarness) enroll(secret, serial string, pub ed25519.PublicKey) (int, string) {
	h.t.Helper()
	body := fmt.Sprintf(`{"serial":%q,"hostname":"CW-%s-L","public_key":%q,"extra":"ignored"}`,
		serial, serial, base64.StdEncoding.EncodeToString(pub))
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/keel/enroll", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return h.send(req)
}

func (h *keelHarness) send(req *http.Request) (int, string) {
	h.t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

type signed struct {
	serial    string
	timestamp string
	signature string
	body      []byte
}

func sign(priv ed25519.PrivateKey, serial string, ts int64, body []byte) signed {
	return signed{serial: serial, timestamp: strconv.FormatInt(ts, 10), signature: keel.Sign(priv, serial, ts, body), body: body}
}

func (h *keelHarness) report(s signed) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/keel/report", bytes.NewReader(s.body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(keel.HeaderSerial, s.serial)
	req.Header.Set(keel.HeaderTimestamp, s.timestamp)
	req.Header.Set(keel.HeaderSignature, s.signature)
	return h.send(req)
}

func (h *keelHarness) get(token, path string) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.send(req)
}

func keelReportBody(serial, runID, mode string, failed int) []byte {
	return []byte(fmt.Sprintf(`{
  "schema": "keel.report/v1",
  "run_id": %q,
  "keel_version": "0.1.0+abc1234",
  "mode": %q,
  "started_at": "2026-11-03T14:59:00Z",
  "duration_ms": 812,
  "device": {"serial": %q, "hostname": "CW-%s-L", "model": "MacBook Pro", "os_version": "27.0", "arch": "arm64", "console_user": "ava"},
  "roles": [{"name": "baseline", "parents": []}, {"name": "employee", "parents": ["baseline"]}],
  "facts": {"serial": %q, "groups": ["it"], "markers": []},
  "profiles": [{"name": "netskope", "enabled": true, "settings": {"mode": "idp", "enrollment": {"auth_token": "[redacted]"}}}],
  "resources": [{"id": "file[/etc/paths.d/cpe_pathsd]", "type": "file", "profile": "pathsd", "status": "ok", "message": "", "duration_ms": 1}],
  "summary": {"total": 42, "ok": %d, "changed": 1, "would_change": 0, "failed": %d, "skipped": 0},
  "added_in_a_later_keel": [1, 2, 3]
}`, runID, mode, serial, serial, serial, 41-failed, failed))
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestKeelEnrollTOFU(t *testing.T) {
	h := newKeelHarness(t)
	pub, _ := newKey(t)
	other, _ := newKey(t)

	steps := []struct {
		name   string
		secret string
		serial string
		key    ed25519.PublicKey
		want   int
	}{
		{"no secret", "", "DF7XP7HY3N", pub, http.StatusUnauthorized},
		{"wrong secret", "not-the-secret", "DF7XP7HY3N", pub, http.StatusUnauthorized},
		{"disabled secret", "disabled-keel-secret", "DF7XP7HY3N", pub, http.StatusUnauthorized},
		{"api token is not an enroll secret", "mc_admin", "DF7XP7HY3N", pub, http.StatusUnauthorized},
		{"unknown serial binds", keelSecret, "DF7XP7HY3N", pub, http.StatusCreated},
		{"same key is idempotent", keelSecret, "DF7XP7HY3N", pub, http.StatusOK},
		{"different key is refused", keelSecret, "DF7XP7HY3N", other, http.StatusConflict},
		{"bad serial", keelSecret, "../etc", pub, http.StatusBadRequest},
		{"short key", keelSecret, "C02SHORTKEY", pub[:16], http.StatusBadRequest},
	}
	for _, step := range steps {
		status, body := h.enroll(step.secret, step.serial, step.key)
		if status != step.want {
			t.Fatalf("%s: %d %s, want %d", step.name, status, body, step.want)
		}
		if strings.Contains(body, keelSecret) {
			t.Fatalf("%s: response echoed the secret", step.name)
		}
	}
	// The mismatch did not replace the bound key.
	got, err := h.st.KeelPublicKey(context.Background(), "DF7XP7HY3N")
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("key replaced: %v", err)
	}

	// Clearing is admin only. A viewer token is 403, no token 401.
	del := func(token string) int {
		req, _ := http.NewRequest(http.MethodDelete, h.ts.URL+"/api/v1/keel/devices/DF7XP7HY3N/key", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		status, _ := h.send(req)
		return status
	}
	if s := del(""); s != http.StatusUnauthorized {
		t.Fatalf("anonymous delete %d", s)
	}
	if s := del("mc_viewer"); s != http.StatusForbidden {
		t.Fatalf("viewer delete %d", s)
	}
	if s := del("mc_keeladm"); s != http.StatusNoContent {
		t.Fatalf("keel:admin delete %d", s)
	}
	if s := del("mc_admin"); s != http.StatusNotFound {
		t.Fatalf("second delete %d", s)
	}
	if status, body := h.enroll(keelSecret, "DF7XP7HY3N", other); status != http.StatusCreated {
		t.Fatalf("re-enroll after clear %d %s", status, body)
	}

	// Enroll secrets are config and never come back from the API.
	status, body := h.get("mc_admin", "/api/v1/keel/enroll-secrets")
	if status != http.StatusOK || strings.Contains(body, keelSecret) || strings.Contains(body, "secret_hash") || !strings.Contains(body, `"fleet"`) {
		t.Fatalf("enroll secrets %d %s", status, body)
	}
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/keel/enroll-secrets", strings.NewReader(`{"name":"ui","secret":"from-the-browser"}`))
	req.Header.Set("Authorization", "Bearer mc_admin")
	if status, _ := h.send(req); status != http.StatusForbidden {
		t.Fatalf("enroll secret write without the terraform header %d", status)
	}
}

func TestKeelReportSignature(t *testing.T) {
	h := newKeelHarness(t)
	pub, priv := newKey(t)
	_, wrong := newKey(t)
	const serial = "DF7XP7HY3N"
	if status, body := h.enroll(keelSecret, serial, pub); status != http.StatusCreated {
		t.Fatalf("enroll %d %s", status, body)
	}
	now := h.clk.Now().Unix()
	body := keelReportBody(serial, "run-1", "apply", 1)

	good := sign(priv, serial, now, body)
	tampered := good
	tampered.body = bytes.Replace(body, []byte(`"failed": 1`), []byte(`"failed": 0`), 1)
	unenrolled := sign(priv, "C02NOTENROLLED", now, keelReportBody("C02NOTENROLLED", "run-x", "apply", 0))
	mismatch := sign(priv, serial, now+1, keelReportBody("C02SOMEONEELSE", "run-m", "apply", 0))
	wrongSchema := sign(priv, serial, now+2, bytes.Replace(body, []byte("keel.report/v1"), []byte("keel.report/v0"), 1))
	nonCanonical := sign(priv, serial, now+3, keelReportBody(serial, "run-nc", "apply", 0))
	nonCanonical.timestamp = "0" + nonCanonical.timestamp
	big := bytes.Repeat([]byte(" "), keel.MaxBody+1)

	cases := []struct {
		name string
		req  signed
		want int
	}{
		{"good signature", good, http.StatusAccepted},
		{"replayed timestamp", good, http.StatusUnauthorized},
		{"tampered body", tampered, http.StatusUnauthorized},
		{"wrong key", sign(wrong, serial, now+10, keelReportBody(serial, "run-w", "apply", 0)), http.StatusUnauthorized},
		{"too old", sign(priv, serial, now-301, keelReportBody(serial, "run-o", "apply", 0)), http.StatusUnauthorized},
		{"too new", sign(priv, serial, now+301, keelReportBody(serial, "run-n", "apply", 0)), http.StatusUnauthorized},
		{"older than the last accepted", sign(priv, serial, now-5, keelReportBody(serial, "run-p", "apply", 0)), http.StatusUnauthorized},
		{"serial has no key", unenrolled, http.StatusUnauthorized},
		{"header serial differs from body", mismatch, http.StatusBadRequest},
		{"wrong schema", wrongSchema, http.StatusBadRequest},
		{"non-canonical timestamp", nonCanonical, http.StatusUnauthorized},
		{"missing signature", signed{serial: serial, timestamp: strconv.FormatInt(now+20, 10), body: body}, http.StatusUnauthorized},
		{"oversize body", sign(priv, serial, now+30, big), http.StatusRequestEntityTooLarge},
		{"next run", sign(priv, serial, now+40, keelReportBody(serial, "run-2", "plan", 0)), http.StatusAccepted},
	}
	for _, tc := range cases {
		status, text := h.report(tc.req)
		if status != tc.want {
			t.Fatalf("%s: %d %s, want %d", tc.name, status, text, tc.want)
		}
	}

	runs, err := h.st.ListKeelRuns(context.Background(), serial)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].RunID != "run-2" || runs[1].RunID != "run-1" || runs[1].Summary.Failed != 1 {
		t.Fatalf("runs %+v", runs)
	}

	// Read APIs: keel:read is enough; no token is 401; a token without keel:read is 403.
	if status, _ := h.get("", "/api/v1/keel/overview"); status != http.StatusUnauthorized {
		t.Fatalf("anonymous overview %d", status)
	}
	if status, _ := h.get("mc_keeladm", "/api/v1/keel/overview"); status != http.StatusForbidden {
		t.Fatalf("keel:admin is not keel:read: %d", status)
	}
	status, detail := h.get("mc_viewer", "/api/v1/keel/devices/"+serial)
	if status != http.StatusOK || !strings.Contains(detail, `"[redacted]"`) || !strings.Contains(detail, "added_in_a_later_keel") {
		t.Fatalf("detail %d %s", status, detail)
	}
	var d model.KeelDeviceDetail
	if err := json.Unmarshal([]byte(detail), &d); err != nil {
		t.Fatal(err)
	}
	if d.LastRun == nil || d.LastRun.RunID != "run-2" || d.LastRun.Mode != "plan" || !d.Enrolled {
		t.Fatalf("detail %+v", d)
	}
	if status, _ := h.get("mc_viewer", "/api/v1/keel/devices/NOPE0000"); status != http.StatusNotFound {
		t.Fatalf("unknown serial %d", status)
	}
	if status, body := h.get("mc_viewer", "/api/v1/keel/devices/"+serial+"/runs"); status != http.StatusOK || !strings.Contains(body, "run-1") {
		t.Fatalf("runs %d %s", status, body)
	}
	if status, body := h.get("mc_viewer", "/api/v1/keel/roles/employee/profiles/netskope"); status != http.StatusOK || !strings.Contains(body, `"devices":1`) {
		t.Fatalf("role settings %d %s", status, body)
	}
	if status, _ := h.get("mc_viewer", "/api/v1/keel/devices?status=bogus"); status != http.StatusBadRequest {
		t.Fatalf("bad status filter %d", status)
	}
}

// Two reports carrying the same timestamp race. The replay floor moves in the
// same transaction as the insert, so exactly one may be accepted.
func TestKeelConcurrentReplayAcceptsOne(t *testing.T) {
	h := newKeelHarness(t)
	pub, priv := newKey(t)
	const serial = "C02RACE0001"
	if status, body := h.enroll(keelSecret, serial, pub); status != http.StatusCreated {
		t.Fatalf("enroll %d %s", status, body)
	}
	for round := 0; round < 5; round++ {
		ts := h.clk.Now().Unix() + int64(round)
		const n = 12
		var wg sync.WaitGroup
		codes := make(chan int, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			// Distinct run ids, so the unique index cannot be what saves us.
			req := sign(priv, serial, ts, keelReportBody(serial, fmt.Sprintf("race-%d-%d", round, i), "apply", 0))
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				httpReq, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/keel/report", bytes.NewReader(req.body))
				httpReq.Header.Set(keel.HeaderSerial, req.serial)
				httpReq.Header.Set(keel.HeaderTimestamp, req.timestamp)
				httpReq.Header.Set(keel.HeaderSignature, req.signature)
				res, err := http.DefaultClient.Do(httpReq)
				if err != nil {
					codes <- 0
					return
				}
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
				codes <- res.StatusCode
			}()
		}
		close(start)
		wg.Wait()
		close(codes)
		accepted, rejected := 0, 0
		for c := range codes {
			switch c {
			case http.StatusAccepted:
				accepted++
			case http.StatusUnauthorized:
				rejected++
			default:
				t.Fatalf("round %d: unexpected status %d", round, c)
			}
		}
		if accepted != 1 || rejected != n-1 {
			t.Fatalf("round %d: accepted=%d rejected=%d", round, accepted, rejected)
		}
	}
	runs, err := h.st.ListKeelRuns(context.Background(), serial)
	if err != nil || len(runs) != 5 {
		t.Fatalf("runs %d %v", len(runs), err)
	}
}
