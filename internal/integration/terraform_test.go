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

	"github.com/Arequ/mission-control/internal/httpapi"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestTerraformProviderCRUD(t *testing.T) {
	if _, err := exec.LookPath("terraform"); err != nil {
		t.Skip("terraform not installed")
	}
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_tf_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := httpapi.New(httpapi.Options{Store: st, Blobs: blobs})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	binDir := t.TempDir()
	providerBin := filepath.Join(binDir, "terraform-provider-missioncontrol")
	buildCmd := exec.Command("go", "build", "-o", providerBin, ".")
	buildCmd.Dir = filepath.Join(moduleRoot(t), "terraform-provider-missioncontrol")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build provider: %v %s", err, out)
	}
	tfrc := filepath.Join(t.TempDir(), "dev.tfrc")
	if err := os.WriteFile(tfrc, []byte("provider_installation {\n  dev_overrides {\n    \"arequ/missioncontrol\" = \""+binDir+"\"\n  }\n  direct {}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	cmd := exec.Command("cp", "-a", filepath.Join(moduleRoot(t), "examples", "terraform")+"/.", work)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copy example: %v %s", err, out)
	}

	run := func(args ...string) string {
		t.Helper()
		c := exec.Command("terraform", args...)
		c.Dir = work
		c.Env = append(os.Environ(),
			"TF_CLI_CONFIG_FILE="+tfrc,
			"TF_IN_AUTOMATION=1",
			"TF_INPUT=0",
			"CHECKPOINT_DISABLE=1",
		)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("terraform %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	run("apply", "-auto-approve", "-input=false",
		"-var", "endpoint="+ts.URL,
		"-var", "token=mc_tf_admin",
		"-var", "max_concurrency=2",
		"-var", "soak_days=7",
	)

	recipes := apiGet(t, ts.URL, "/api/v1/recipes")
	if !strings.Contains(recipes, "local.munki.Firefox") || !strings.Contains(recipes, `"managed_by":"terraform"`) && !strings.Contains(recipes, `"managed_by": "terraform"`) {
		t.Fatalf("recipes after apply: %s", recipes)
	}
	if !strings.Contains(apiGet(t, ts.URL, "/api/v1/schedules"), "firefox-morning") {
		t.Fatal(apiGet(t, ts.URL, "/api/v1/schedules"))
	}
	settings := apiGet(t, ts.URL, "/api/v1/pipeline-settings")
	if !strings.Contains(settings, `"max_concurrency":2`) && !strings.Contains(settings, `"max_concurrency": 2`) {
		t.Fatalf("settings: %s", settings)
	}

	run("apply", "-auto-approve", "-input=false",
		"-var", "endpoint="+ts.URL,
		"-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4",
		"-var", "soak_days=3",
	)
	settings = apiGet(t, ts.URL, "/api/v1/pipeline-settings")
	if !strings.Contains(settings, `"max_concurrency":4`) && !strings.Contains(settings, `"max_concurrency": 4`) {
		t.Fatalf("updated settings: %s", settings)
	}
	rules := apiGet(t, ts.URL, "/api/v1/promotion-rules")
	if !strings.Contains(rules, `"soak_days":3`) && !strings.Contains(rules, `"soak_days": 3`) {
		t.Fatalf("rules: %s", rules)
	}
	manifests := apiGet(t, ts.URL, "/api/v1/manifests")
	if !strings.Contains(manifests, "site_default") || !strings.Contains(manifests, "Firefox") {
		t.Fatalf("manifests: %s", manifests)
	}

	plan := exec.Command("terraform", "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	plan.Dir = work
	plan.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+tfrc, "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
	out, err := plan.CombinedOutput()
	if err != nil {
		t.Fatalf("unexpected drift: %v\n%s", err, out)
	}

	run("destroy", "-auto-approve", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	left := apiGet(t, ts.URL, "/api/v1/recipes")
	var body struct {
		Recipes []model.Recipe `json:"recipes"`
	}
	if err := json.Unmarshal([]byte(left), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Recipes) != 0 {
		t.Fatalf("recipes remain: %s", left)
	}
}

func apiGet(t *testing.T, base, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer mc_tf_admin")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("GET %s %d %s", path, res.StatusCode, b)
	}
	return string(b)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}
