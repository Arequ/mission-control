package httpapi

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

// TestOsquerydLive enrolls a real osqueryd over the TLS remote API and runs a live query.
// It skips when the binary is not installed.
func TestOsquerydLive(t *testing.T) {
	bin := osqueryBinary()
	if bin == "" {
		t.Skip("osqueryd is not installed")
	}
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Options{Store: st, Blobs: blobs, OfflineAfter: time.Hour, InventoryInterval: 10 * time.Second})
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	client := ts.Client()

	const secret = "example-enroll-secret"
	status, text := tlsJSON(t, client, ts.URL, http.MethodPost, "/api/v1/osquery/enroll-secrets", "mc_admin", true,
		`{"name":"fleet","secret":"`+secret+`","enabled":true}`)
	if status >= 300 {
		t.Fatalf("enroll secret %d %s", status, text)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "enroll.secret"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("tls test server has no certificate")
	}
	if err := os.WriteFile(filepath.Join(dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(ts.URL, "https://")
	logPath := filepath.Join(dir, "osquery.stderr")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin,
		"--ephemeral",
		"--database_path="+filepath.Join(dir, "osquery.db"),
		"--pidfile="+filepath.Join(dir, "osquery.pid"),
		"--logger_path="+dir,
		"--enroll_secret_path="+filepath.Join(dir, "enroll.secret"),
		"--tls_hostname="+host,
		"--tls_server_certs="+filepath.Join(dir, "server.pem"),
		"--enroll_tls_endpoint=/enroll",
		"--config_tls_endpoint=/config",
		"--logger_tls_endpoint=/logger",
		"--distributed_tls_read_endpoint=/distributed_read",
		"--distributed_tls_write_endpoint=/distributed_write",
		"--config_plugin=tls",
		"--logger_plugin=tls",
		"--distributed_plugin=tls",
		"--logger_tls_compress=true",
		"--extensions_socket="+filepath.Join(dir, "osquery.em"),
		"--logger_tls_period=5",
		"--distributed_interval=5",
		"--config_refresh=10",
		"--host_identifier=hostname",
		"--disable_events",
		"--disable_watchdog",
		"--daemonize=false",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	})

	deadline := time.Now().Add(45 * time.Second)
	var deviceID string
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("osqueryd exited early\n%s", tailFile(logPath))
		default:
		}
		time.Sleep(time.Second)
		body := tlsMap(t, client, ts.URL, http.MethodGet, "/api/v1/devices", "mc_admin", false, "")
		list, _ := body["devices"].([]any)
		if len(list) == 0 {
			continue
		}
		device, _ := list[0].(map[string]any)
		deviceID, _ = device["id"].(string)
		host, _ := device["hostname"].(string)
		if deviceID != "" && host != "" {
			break
		}
	}
	if deviceID == "" {
		t.Fatalf("osqueryd did not enroll\n%s", tailFile(logPath))
	}

	created := tlsMap(t, client, ts.URL, http.MethodPost, "/api/v1/live-queries", "mc_admin", false,
		`{"sql":"SELECT 'ok' AS ready","device_ids":["`+deviceID+`"],"timeout_seconds":30}`)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("live query create: %s", mustJSONRaw(created))
	}
	deadline = time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("osqueryd exited\n%s", tailFile(logPath))
		default:
		}
		time.Sleep(time.Second)
		got := tlsMap(t, client, ts.URL, http.MethodGet, "/api/v1/live-queries/"+id, "mc_admin", false, "")
		rows, _ := got["rows"].([]any)
		for _, row := range rows {
			m, _ := row.(map[string]any)
			if m["ready"] == "ok" {
				goto enrolled
			}
		}
		if got["status"] == "complete" {
			t.Fatalf("live query finished without a row: %s\n%s", mustJSONRaw(got), tailFile(logPath))
		}
	}
	t.Fatalf("timed out waiting for osqueryd results\n%s", tailFile(logPath))

enrolled:
	logDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(logDeadline) {
		var logs int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_status_logs WHERE device_id=$1`, deviceID).Scan(&logs); err != nil {
			t.Fatal(err)
		}
		var results int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_result_logs WHERE device_id=$1`, deviceID).Scan(&results); err != nil {
			t.Fatal(err)
		}
		if logs+results > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	var logs, results int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_status_logs WHERE device_id=$1`, deviceID).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_result_logs WHERE device_id=$1`, deviceID).Scan(&results); err != nil {
		t.Fatal(err)
	}
	if logs+results == 0 {
		t.Fatalf("gzip logger delivered no status or result logs\n%s", tailFile(logPath))
	}

	var enrolledAt time.Time
	if err := st.Pool().QueryRow(ctx, `SELECT last_enrolled_at FROM devices WHERE id=$1`, deviceID).Scan(&enrolledAt); err != nil {
		t.Fatal(err)
	}
	invalidated, invalidBody := tlsJSON(t, client, ts.URL, http.MethodPost, "/api/v1/devices/"+deviceID+"/invalidate", "mc_admin", false, `{}`)
	if invalidated >= 300 {
		t.Fatalf("invalidate %d %s", invalidated, invalidBody)
	}
	deadline = time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("osqueryd exited during re-enroll\n%s", tailFile(logPath))
		default:
		}
		time.Sleep(time.Second)
		var n int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("re-enroll device count = %d\n%s", n, tailFile(logPath))
		}
		var again time.Time
		if err := st.Pool().QueryRow(ctx, `SELECT last_enrolled_at FROM devices WHERE id=$1`, deviceID).Scan(&again); err != nil {
			t.Fatal(err)
		}
		if again.After(enrolledAt) {
			body := tlsMap(t, client, ts.URL, http.MethodGet, "/api/v1/devices/"+deviceID, "mc_admin", false, "")
			if body["node_invalid"] == true || body["hostname"] == "" {
				t.Fatalf("re-enroll left the device invalid: %s", mustJSONRaw(body))
			}
			return
		}
	}
	t.Fatalf("osqueryd did not re-enroll the same device\n%s", tailFile(logPath))
}

func tlsJSON(t *testing.T, client *http.Client, base, method, path, token string, terraform bool, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if terraform {
		req.Header.Set(TerraformClientHeader, "terraform")
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func tlsMap(t *testing.T, client *http.Client, base, method, path, token string, terraform bool, body string) map[string]any {
	t.Helper()
	status, text := tlsJSON(t, client, base, method, path, token, terraform, body)
	if status >= 300 {
		t.Fatalf("%s %s %d %s", method, path, status, text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("json %s: %v", text, err)
	}
	return out
}

func osqueryBinary() string {
	for _, path := range []string{"osqueryd", "/opt/osquery/bin/osqueryd", "/usr/bin/osqueryd", "/usr/local/bin/osqueryd"} {
		if path == "osqueryd" {
			found, err := exec.LookPath(path)
			if err == nil {
				return found
			}
			continue
		}
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return ""
}

func tailFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	if len(b) > 4000 {
		b = b[len(b)-4000:]
	}
	return string(b)
}
