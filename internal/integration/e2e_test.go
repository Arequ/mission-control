package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/httpapi"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/Arequ/mission-control/internal/runneragent"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

const override = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Identifier</key>
	<string>local.munki.Firefox</string>
	<key>Input</key>
	<dict>
		<key>NAME</key>
		<string>Firefox</string>
		<key>VERSION</key>
		<string>130.0</string>
	</dict>
</dict>
</plist>
`

func TestRunnerImportsAndPromotes(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	clk := &clock.Manual{}
	clk.Set(time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC))
	st.SetClock(clk)
	p := model.Principal{Kind: "test", ID: "test", Name: "test"}
	if err := st.EnsureAPIToken(ctx, "admin", "mc_test_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureBootstrapToken(ctx, "bootstrap", "mc_test_boot"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdatePipelineSettings(ctx, p, model.PipelineSettings{
		MaxConcurrency: 2, PerRunnerParallelism: 1, TimeoutSeconds: 60, MaxRetries: 1, LeaseSeconds: 30, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	pool, err := st.CreateRunnerPool(ctx, p, model.RunnerPool{Name: "mac-minis", Labels: []string{"macos", "autopkg"}, ManagedBy: "terraform"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := st.CreateRecipeRepo(ctx, p, model.RecipeRepo{Name: "recipes", URL: "https://example.test/recipes.git", Ref: "main", ManagedBy: "terraform"})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := st.CreateRecipe(ctx, p, model.Recipe{
		Identifier: "local.munki.Firefox", Name: "Firefox", RepoID: &repo.ID, Enabled: true,
		Override: override, TrustInfo: []byte(`{"parent_recipes":[{"identifier":"com.github.firefox","sha256":"abc"}]}`),
		RunnerPoolID: &pool.ID, Labels: []string{"macos", "autopkg"}, ManagedBy: "terraform",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSchedule(ctx, p, model.Schedule{Name: "nightly", RecipeID: rec.ID, Cron: "0 2 * * *", Enabled: true, ManagedBy: "terraform"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePromotionRule(ctx, p, model.PromotionRule{
		Name: "testing-to-production", FromCatalog: "testing", ToCatalog: "production", SoakDays: 7, Enabled: true, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateManifest(ctx, p, model.Manifest{
		Name: "site_default", Catalogs: []string{"production"}, ManagedInstalls: []string{"Firefox"}, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnqueueManual(ctx, p, rec.ID); err != nil {
		t.Fatal(err)
	}

	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := httpapi.New(httpapi.Options{Store: st, Blobs: blobs, RepoToken: "mc_test_repo", WebDir: ""})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	bin := build(t, "./cmd/fake-autopkg", "fake-autopkg")
	agent := &runneragent.Agent{Config: runneragent.Config{
		ServerURL: ts.URL, BootstrapToken: "mc_test_boot", Name: "mini-1",
		Labels: []string{"macos", "autopkg"}, Pool: "mac-minis",
		Hostname: "mini-1", OSVersion: "test", AutopkgBin: bin, AutopkgVersion: "fake",
	}}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := agent.RunJobs(runCtx, 1); err != nil {
		t.Fatal(err)
	}

	jobs, _, err := st.ListJobs(ctx, rec.ID, 10, 0)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs %#v %v", jobs, err)
	}
	if jobs[0].Status != "succeeded" || jobs[0].Result != "new_version" {
		t.Fatalf("job %+v", jobs[0])
	}
	full, err := st.GetJob(ctx, jobs[0].ID, true)
	if err != nil || len(full.Logs) == 0 {
		t.Fatalf("logs %#v %v", full.Logs, err)
	}
	pkgs, err := st.ListPackages(ctx, "testing")
	if err != nil || len(pkgs) != 1 || pkgs[0].Name != "Firefox" || pkgs[0].Version != "130.0" {
		t.Fatalf("testing packages %#v %v", pkgs, err)
	}
	apiReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/recipes", nil)
	apiReq.Header.Set("Authorization", "Bearer mc_test_admin")
	res, err := http.DefaultClient.Do(apiReq)
	if err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Recipes []model.Recipe `json:"recipes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(listed.Recipes) != 1 || listed.Recipes[0].ManagedBy != "terraform" || listed.Recipes[0].LastJob == nil || listed.Recipes[0].LastJob.Result != "new_version" {
		t.Fatalf("recipe api last=%+v", listed.Recipes[0].LastJob)
	}

	clk.Advance(7 * 24 * time.Hour)
	if err := srv.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	prod, err := st.ListPackages(ctx, "production")
	if err != nil || len(prod) != 1 || prod[0].SoakStatus != "promoted" {
		t.Fatalf("production %#v %v", prod, err)
	}
	testing, err := st.ListPackages(ctx, "testing")
	if err != nil || len(testing) != 0 {
		t.Fatalf("testing after promote %#v %v", testing, err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/repo/catalogs/production", nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("repo without auth: %d", res.StatusCode)
	}
	req.SetBasicAuth("munki", "mc_test_repo")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("catalog status %d %s", res.StatusCode, body)
	}
	items, err := munki.ParseCatalog(body)
	if err != nil || len(items) != 1 || items[0]["name"] != "Firefox" {
		t.Fatalf("served catalog %#v %v", items, err)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/manifests/site_default", nil)
	req.Header.Set("Authorization", "Bearer mc_test_admin")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "Firefox") {
		t.Fatalf("manifest %d %s", res.StatusCode, body)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/pkgs/"+prod[0].Filename, nil)
	req.SetBasicAuth("munki", "mc_test_repo")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	pkgBody, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(pkgBody), "fake-pkg") {
		t.Fatalf("pkg %d %q", res.StatusCode, pkgBody)
	}

	if _, err := st.EnqueueManual(ctx, p, rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := agent.RunJobs(runCtx, 1); err != nil {
		t.Fatal(err)
	}
	jobs, _, err = st.ListJobs(ctx, rec.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sawNoChange bool
	for _, j := range jobs {
		if j.Result == "no_change" && j.Status == "succeeded" {
			sawNoChange = true
		}
	}
	if !sawNoChange {
		t.Fatalf("expected no_change, jobs %#v", jobs)
	}
}

func build(t *testing.T, pkg, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	_, file, _, _ := runtime.Caller(0)
	cmd.Dir = filepath.Dir(filepath.Dir(filepath.Dir(file)))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return bin
}
