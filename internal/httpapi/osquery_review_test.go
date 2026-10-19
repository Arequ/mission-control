package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestLoggerGzipAndPayloadLimit(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	var logs bytes.Buffer
	srv := New(Options{Store: st, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	secret := "example-enroll-secret"
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	status, text := apiJSON(t, ts.URL, http.MethodPost, "/api/v1/osquery/enroll-secrets", "mc_admin", true, `{"name":"fleet","secret":"`+secret+`","enabled":true}`)
	if status >= 300 {
		t.Fatalf("secret %d %s", status, text)
	}
	enroll := `{"enroll_secret":"` + secret + `","host_identifier":"mbp","host_details":{"system_info":{"uuid":"UUID-G","hardware_serial":"SER-G","hostname":"mbp"}}}`
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(enroll)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/enroll", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body := readAll(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "node_key") {
		t.Fatalf("gzip enroll %d %s", res.StatusCode, body)
	}
	nodeKey := parseJSON(t, body)["node_key"].(string)
	if strings.Contains(logs.String(), nodeKey) || strings.Contains(logs.String(), secret) {
		t.Fatalf("logs leaked a secret: %s", logs.String())
	}
	var hash string
	if err := st.Pool().QueryRow(ctx, `SELECT node_key_hash FROM devices`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == nodeKey || hash != auth.Hash(nodeKey) {
		t.Fatal("stored node key is not a hash")
	}

	logBody := `{"node_key":"` + nodeKey + `","log_type":"status","data":[{"severity":1,"line":12,"filename":"tls.cpp","message":"compressed","version":"5.19.0"}]}`
	buf.Reset()
	zw = gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(logBody))
	_ = zw.Close()
	req, err = http.NewRequest(http.MethodPost, ts.URL+"/logger", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Encoding", "gzip")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body = readAll(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("gzip logger %d %s", res.StatusCode, body)
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_status_logs WHERE message='compressed'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("status logs %d %v", n, err)
	}

	req, err = http.NewRequest(http.MethodPost, ts.URL+"/logger", strings.NewReader(logBody+" trailing"))
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing data %d", res.StatusCode)
	}

	huge := bytes.Repeat([]byte("a"), osqueryMaxBody+1)
	req, err = http.NewRequest(http.MethodPost, ts.URL+"/logger", bytes.NewReader(huge))
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize %d %s", res.StatusCode, readAll(t, res))
	}

	var bomb bytes.Buffer
	zw = gzip.NewWriter(&bomb)
	if _, err := zw.Write(bytes.Repeat([]byte{0}, osqueryMaxBody+1)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequest(http.MethodPost, ts.URL+"/logger", &bomb)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Encoding", "gzip")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("gzip bomb %d %s", res.StatusCode, readAll(t, res))
	}
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
