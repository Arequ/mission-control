package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

// TestReleaseReviewPermissions checks the split between the advisor and
// reviewers: the advisor (releases:write) can lease and report but never
// decide; a reviewer (releases:update) decides but cannot pose as the advisor;
// releases:read only looks.
func TestReleaseReviewPermissions(t *testing.T) {
	ctx := t.Context()
	st := testutil.NewStore(t)
	for name, scopes := range map[string][]string{
		"mc_advisor":  {"releases:write"},
		"mc_reviewer": {"releases:update"},
		"mc_reader":   {"releases:read"},
		"mc_rusher":   {"releases:update", "rush:update"},
	} {
		if err := st.EnsureAPIToken(ctx, name, name, scopes); err != nil {
			t.Fatal(err)
		}
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(Options{Store: st, Blobs: blobs}).Handler())
	t.Cleanup(ts.Close)

	info, _ := json.Marshal(map[string]string{"name": "Slack", "version": "4.53.287"})
	if _, _, err := st.InsertPackage(ctx, model.System, model.Package{Name: "Slack", Version: "4.53.287", Filename: "Slack-4.53.287.pkg", Pkginfo: info}); err != nil {
		t.Fatal(err)
	}
	json := map[string]string{"Content-Type": "application/json"}

	status, body := do(t, ts, http.MethodGet, "/api/v1/release-reviews?status=pending", "mc_reader", nil, "")
	if status != http.StatusOK || !strings.Contains(body, `"name":"Slack"`) {
		t.Fatalf("reader list %d %s", status, body)
	}
	var list struct {
		Reviews []model.ReleaseReview `json:"reviews"`
	}
	if err := jsonUnmarshal(body, &list); err != nil || len(list.Reviews) != 1 {
		t.Fatalf("list %v %s", err, body)
	}
	id := list.Reviews[0].ID
	decide := "/api/v1/release-reviews/" + id + "/decide"

	for _, tok := range []string{"mc_reader", "mc_advisor"} {
		if status, _ := do(t, ts, http.MethodPost, decide, tok, json, `{"decision":"rush"}`); status != http.StatusForbidden {
			t.Fatalf("%s decided: %d", tok, status)
		}
	}
	for _, path := range []string{"/api/v1/release-reviews/lease", "/api/v1/release-reviews/" + id + "/notes", "/api/v1/release-reviews/" + id + "/evaluate"} {
		if status, _ := do(t, ts, http.MethodPost, path, "mc_reviewer", json, `{"summary":"fake","recommendation":"high"}`); status != http.StatusForbidden {
			t.Fatalf("reviewer posed as advisor at %s: %d", path, status)
		}
	}
	if status, _ := do(t, ts, http.MethodGet, "/api/v1/release-reviews?status=bogus", "mc_reader", nil, ""); status != http.StatusBadRequest {
		t.Fatalf("bad status filter %d", status)
	}

	status, body = do(t, ts, http.MethodPost, "/api/v1/release-reviews/lease", "mc_advisor", nil, "")
	if status != http.StatusOK || !strings.Contains(body, `"name":"Slack"`) {
		t.Fatalf("lease %d %s", status, body)
	}
	if status, _ := do(t, ts, http.MethodPost, "/api/v1/release-reviews/lease", "mc_advisor", nil, ""); status != http.StatusNoContent {
		t.Fatalf("empty lease %d", status)
	}
	status, body = do(t, ts, http.MethodPost, "/api/v1/release-reviews/"+id+"/notes", "mc_advisor", json,
		`{"summary":"Bug fixes.","recommendation":"low","rationale":"No security content.","cves":[],"sources":["https://slack.com/release-notes/mac"]}`)
	if status != http.StatusOK || !strings.Contains(body, `"status":"done"`) {
		t.Fatalf("notes %d %s", status, body)
	}

	// Slack is LOW: no one can rush it, and releases:update alone never can.
	if status, _ := do(t, ts, http.MethodPost, decide, "mc_reviewer", json, `{"decision":"rush"}`); status != http.StatusForbidden {
		t.Fatalf("rush without rush:update %d", status)
	}
	if status, _ := do(t, ts, http.MethodPost, decide, "mc_rusher", json, `{"decision":"rush"}`); status != http.StatusConflict {
		t.Fatalf("rushed a LOW build %d", status)
	}
	status, body = do(t, ts, http.MethodPost, decide, "mc_reviewer", json, `{"decision":"normal","note":"routine"}`)
	if status != http.StatusOK || !strings.Contains(body, `"status":"normal"`) {
		t.Fatalf("decide %d %s", status, body)
	}
	if status, _ := do(t, ts, http.MethodPost, decide, "mc_rusher", json, `{"decision":"rush"}`); status != http.StatusConflict {
		t.Fatalf("rush after normal %d", status)
	}
}
