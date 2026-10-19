package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/store"
)

func TestAPIAuthPlanAndFleet(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.EnsureToken(ctx, "bootstrap", "dev-bootstrap-token", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureToken(ctx, "viewer", "viewer-token", auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	resources, diags, err := config.LoadPath("../../examples/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	srv := New(st, "dev-enroll-secret")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if resp := call(t, ts, http.MethodGet, "/api/v1/devices", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp := call(t, ts, http.MethodPost, "/api/v1/config/apply", "viewer-token", map[string]any{"resources": resources})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer apply status %d body %s", resp.StatusCode, read(t, resp))
	}
	resp = call(t, ts, http.MethodPost, "/api/v1/config/apply", "dev-bootstrap-token", map[string]any{"resources": resources, "prune": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apply %d %s", resp.StatusCode, read(t, resp))
	}
	var plan config.Plan
	if err := json.Unmarshal([]byte(read(t, resp)), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Create == 0 {
		t.Fatalf("plan %+v", plan.Summary)
	}
	resp = call(t, ts, http.MethodPost, "/api/v1/config/apply", "dev-bootstrap-token", map[string]any{"resources": resources, "prune": true})
	if err := json.Unmarshal([]byte(read(t, resp)), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Create != 0 || plan.Summary.Update != 0 || plan.Summary.Unchanged == 0 {
		t.Fatalf("second apply %+v", plan.Summary)
	}

	resp = call(t, ts, http.MethodGet, "/api/v1/fleet/summary", "dev-bootstrap-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("summary %d", resp.StatusCode)
	}
	resp = call(t, ts, http.MethodGet, "/api/v1/munki/catalogs", "dev-bootstrap-token", nil)
	var catalogs struct {
		Catalogs []config.Resource `json:"catalogs"`
	}
	if err := json.Unmarshal([]byte(read(t, resp)), &catalogs); err != nil {
		t.Fatal(err)
	}
	if len(catalogs.Catalogs) < 2 {
		t.Fatalf("catalogs %#v", catalogs.Catalogs)
	}
	resp = call(t, ts, http.MethodGet, "/munki/repo/catalogs/production", "", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("munki client %d", resp.StatusCode)
	}
	resp = call(t, ts, http.MethodGet, "/healthz", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health %d", resp.StatusCode)
	}
}

func call(t *testing.T, ts *httptest.Server, method, path, token string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, ts.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func read(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
