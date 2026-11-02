package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestTokenScopesAndRepoAuth(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureAPIToken(ctx, "jobs", "mc_jobs", []string{"jobs:read", "jobs:write"}); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureBootstrapToken(ctx, "boot", "mc_boot"); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Options{
		Store: st, Blobs: blobs, RepoToken: "mc_repo", DevCORS: true, MaxUpload: 64,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	status, body := do(t, ts, http.MethodPost, "/api/v1/recipes", "mc_jobs", map[string]string{"X-Mission-Control-Client": "terraform"}, `{"identifier":"local.munki.Nope","name":"Nope"}`)
	if status != http.StatusForbidden {
		t.Fatalf("jobs token config write %d %s", status, body)
	}
	status, body = do(t, ts, http.MethodPost, "/api/v1/recipes", "mc_admin", nil, `{"identifier":"local.munki.Nope","name":"Nope","override":"<plist/>"}`)
	if status != http.StatusForbidden || !strings.Contains(body, "Terraform") {
		t.Fatalf("config write without terraform header %d %s", status, body)
	}
	status, body = do(t, ts, http.MethodPost, "/api/v1/recipes", "mc_admin", map[string]string{"X-Mission-Control-Client": "terraform"}, `{"identifier":"local.munki.Nope","name":"Nope","override":"<plist/>","managed_by":"ui"}`)
	if status != http.StatusCreated || !strings.Contains(body, `"managed_by":"terraform"`) {
		t.Fatalf("terraform create %d %s", status, body)
	}
	status, body = do(t, ts, http.MethodPost, "/api/v1/runners/lease?wait=0", "mc_admin", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("api token lease %d %s", status, body)
	}
	status, body = do(t, ts, http.MethodPost, "/api/v1/runners/register", "mc_boot", nil, `{"name":"mini-9","labels":["macos"]}`)
	if status != http.StatusCreated || !strings.Contains(body, `"token"`) {
		t.Fatalf("bootstrap register %d %s", status, body)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/repo/catalogs/testing", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("repo no auth %d", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/catalogs/testing?token=mc_repo", nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query token %d", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/catalogs/testing", nil)
	req.SetBasicAuth("mc_repo", "nope")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("username-as-token %d", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/catalogs/testing", nil)
	req.SetBasicAuth("munki", "mc_repo")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("basic password %d", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/pkgs/../../etc/passwd", nil)
	req.SetBasicAuth("munki", "mc_repo")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusNotFound {
		t.Fatalf("traversal %d", res.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/recipes", nil)
	req.Header.Set("Authorization", "Bearer mc_admin")
	req.Header.Set("Origin", "https://evil.example")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("evil origin reflected %q", res.Header.Get("Access-Control-Allow-Origin"))
	}
	req, _ = http.NewRequest(http.MethodOptions, ts.URL+"/api/v1/recipes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("dev origin %q", res.Header.Get("Access-Control-Allow-Origin"))
	}
	if strings.Contains(logs.String(), "mc_admin") || strings.Contains(logs.String(), "mc_repo") || strings.Contains(logs.String(), "mc_boot") {
		t.Fatalf("token leaked into logs: %s", logs.String())
	}
}

func TestUploadGuards(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	dir := t.TempDir()
	blobs, err := storage.New("local", dir, "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	p := model.Principal{Kind: "test", Name: "test"}
	if _, err := st.UpdatePipelineSettings(ctx, p, model.PipelineSettings{
		MaxConcurrency: 2, PerRunnerParallelism: 1, TimeoutSeconds: 60, MaxRetries: 1, LeaseSeconds: 120, ManagedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.CreateRecipe(ctx, p, model.Recipe{Identifier: "local.munki.Firefox", Name: "Firefox", Enabled: true, Override: "<plist/>", TrustInfo: []byte(`{}`), ManagedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnqueueManual(ctx, p, rec.ID); err != nil {
		t.Fatal(err)
	}
	rn, token, err := st.RegisterRunner(ctx, p, "mini", nil, "", "h", "os", "2")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := st.Lease(ctx, rn.ID)
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	srv := New(Options{Store: st, Blobs: blobs, MaxUpload: 2048})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	status, text := upload(t, ts.URL, token, lease.JobID, lease.Attempt, "Firefox-1.pkg", "Firefox", "1.0", bytes.Repeat([]byte("a"), 8192))
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize %d %s", status, text)
	}
	body := []byte("pkg-bytes-v1")
	status, text = upload(t, ts.URL, token, lease.JobID, lease.Attempt, "..", "Firefox", "1.0", body)
	if status != http.StatusBadRequest {
		t.Fatalf("bad filename %d %s", status, text)
	}
	status, text = upload(t, ts.URL, token, lease.JobID, lease.Attempt, "Firefox-1.0.pkg", "Firefox", "1.0", body)
	if status != http.StatusOK || !strings.Contains(text, `"imported":true`) {
		t.Fatalf("import %d %s", status, text)
	}
	status, text = upload(t, ts.URL, token, lease.JobID, lease.Attempt, "Firefox-1.0.pkg", "Firefox", "1.0", []byte("pkg-bytes-DIFFERENT"))
	if status != http.StatusConflict {
		t.Fatalf("hash mismatch %d %s", status, text)
	}
	got, err := os.ReadFile(filepath.Join(dir, "pkgs", "Firefox-1.0.pkg"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("blob overwritten: %q", got)
	}
	status, text = upload(t, ts.URL, token, lease.JobID, lease.Attempt+9, "Other-1.pkg", "Other", "1", []byte("zzzzzzzz"))
	if status != http.StatusForbidden {
		t.Fatalf("stale upload %d %s", status, text)
	}
}

func TestOpenAPIListsEveryRoute(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	dir := filepath.Dir(file)
	server, err := os.ReadFile(filepath.Join(dir, "server.go"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile(filepath.Join(dir, "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.Handle(?:Func)?\(\s*"(GET|POST|PUT|DELETE) ([^"]+)"`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(server), -1) {
		path := strings.ReplaceAll(m[2], "...", "")
		if path == "/{path}" {
			continue
		}
		seen[path] = true
		if !strings.Contains(string(spec), "\n  "+path+":") {
			t.Errorf("openapi missing %s %s", m[1], path)
		}
	}
	pathRe := regexp.MustCompile(`(?m)^  (/[^:\s]+):`)
	for _, m := range pathRe.FindAllStringSubmatch(string(spec), -1) {
		path := strings.ReplaceAll(m[1], "...", "")
		if !seen[path] {
			t.Errorf("openapi documents %s but the server does not register it", path)
		}
	}
}

func do(t *testing.T, ts *httptest.Server, method, path, token string, headers map[string]string, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func upload(t *testing.T, base, token, jobID string, attempt int, filename, name, version string, pkg []byte) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("attempt", jsonNumber(attempt)); err != nil {
		t.Fatal(err)
	}
	pi, err := w.CreateFormFile("pkginfo", "pkginfo.plist")
	if err != nil {
		t.Fatal(err)
	}
	info, _ := json.Marshal(map[string]string{"name": name, "version": version})
	if _, err := pi.Write(info); err != nil {
		t.Fatal(err)
	}
	part, err := createPackagePart(w, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(pkg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/jobs/"+jobID+"/artifacts", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func createPackagePart(w *multipart.Writer, filename string) (io.Writer, error) {
	if strings.Contains(filename, "/") || strings.Contains(filename, "..") || strings.Contains(filename, "\\") {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf("form-data; name=%q; filename=%q", "package", filename))
		h.Set("Content-Type", "application/octet-stream")
		return w.CreatePart(h)
	}
	return w.CreateFormFile("package", filename)
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
