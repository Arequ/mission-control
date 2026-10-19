package integration

import (
	"context"
	"encoding/json"
	"errors"
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

	if _, err := st.UpdatePipelineSettings(ctx, model.Principal{Kind: "api", Name: "drift"}, model.PipelineSettings{
		MaxConcurrency: 9, PerRunnerParallelism: 1, TimeoutSeconds: 3600,
		MaxRetries: 2, LeaseSeconds: 300, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	drift := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	driftOut, driftErr := drift.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(driftErr, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("out-of-band pipeline change should plan with exit 2, err=%v\n%s", driftErr, driftOut)
	}

	run("apply", "-auto-approve", "-input=false",
		"-var", "endpoint="+ts.URL,
		"-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4",
		"-var", "soak_days=3",
	)
	plan := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	out, err := plan.CombinedOutput()
	if err != nil {
		t.Fatalf("unexpected drift: %v\n%s", err, out)
	}

	var listed struct {
		Schedules []model.Schedule `json:"schedules"`
	}
	if err := json.Unmarshal([]byte(apiGet(t, ts.URL, "/api/v1/schedules")), &listed); err != nil {
		t.Fatal(err)
	}
	var scheduleID string
	for _, sc := range listed.Schedules {
		if sc.Name == "firefox-morning" {
			scheduleID = sc.ID
		}
	}
	if scheduleID == "" {
		t.Fatal("firefox-morning missing")
	}
	run("state", "rm", "missioncontrol_schedule.firefox_morning")
	run("import", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3",
		"missioncontrol_schedule.firefox_morning", scheduleID)
	imported := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	out, err = imported.CombinedOutput()
	if err != nil {
		t.Fatalf("imported schedule drifted: %v\n%s", err, out)
	}

	queries := apiGet(t, ts.URL, "/api/v1/osquery/queries")
	if !strings.Contains(queries, "launch_daemons") || !strings.Contains(queries, `"managed_by":"terraform"`) && !strings.Contains(queries, `"managed_by": "terraform"`) {
		t.Fatalf("queries: %s", queries)
	}
	if !strings.Contains(apiGet(t, ts.URL, "/api/v1/osquery/packs"), "endpoint") || !strings.Contains(apiGet(t, ts.URL, "/api/v1/osquery/labels"), "apple-silicon") {
		t.Fatal(apiGet(t, ts.URL, "/api/v1/osquery/packs"))
	}
	secrets := apiGet(t, ts.URL, "/api/v1/osquery/enroll-secrets")
	if !strings.Contains(secrets, "fleet") || strings.Contains(secrets, "example-enroll-secret") {
		t.Fatalf("enroll secrets: %s", secrets)
	}
	connectors := apiGet(t, ts.URL, "/api/v1/source-connectors")
	for _, leak := range []string{"example-crowdstrike-client-secret", "example-kolide-api-token", "example-elastic-api-key", "example-enroll-secret"} {
		if strings.Contains(connectors, leak) {
			t.Fatalf("connector response leaked %s: %s", leak, connectors)
		}
	}
	if !strings.Contains(connectors, `"source":"crowdstrike"`) && !strings.Contains(connectors, `"source": "crowdstrike"`) {
		t.Fatalf("connectors: %s", connectors)
	}
	var listedConnectors struct {
		Connectors []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal([]byte(connectors), &listedConnectors); err != nil {
		t.Fatal(err)
	}
	var connectorID string
	for _, c := range listedConnectors.Connectors {
		if c.Source == "crowdstrike" {
			connectorID = c.ID
		}
	}
	if connectorID == "" {
		t.Fatal("crowdstrike connector missing")
	}
	run("state", "rm", "missioncontrol_source_connector.crowdstrike")
	run("import", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3",
		"missioncontrol_source_connector.crowdstrike", connectorID)
	importedConnector := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	connOut, connErr := importedConnector.CombinedOutput()
	if strings.Contains(string(connOut), "example-crowdstrike-client-secret") || strings.Contains(string(connOut), "example-enroll-secret") {
		t.Fatalf("credential leaked in plan:\n%s", connOut)
	}
	if !errors.As(connErr, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(connOut), "credentials_fingerprint") {
		t.Fatalf("imported connector should plan one fingerprint update, err=%v\n%s", connErr, connOut)
	}
	run("apply", "-auto-approve", "-input=false",
		"-var", "endpoint="+ts.URL,
		"-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4",
		"-var", "soak_days=3",
	)
	recorded := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	recordedOut, recordedErr := recorded.CombinedOutput()
	if strings.Contains(string(recordedOut), "example-crowdstrike-client-secret") {
		t.Fatalf("credential leaked in plan:\n%s", recordedOut)
	}
	if recordedErr != nil {
		t.Fatalf("fingerprint apply should leave a clean plan: %v\n%s", recordedErr, recordedOut)
	}
	var listedQ struct {
		Queries []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"queries"`
	}
	if err := json.Unmarshal([]byte(queries), &listedQ); err != nil {
		t.Fatal(err)
	}
	var queryID string
	for _, q := range listedQ.Queries {
		if q.Name == "launch_daemons" {
			queryID = q.ID
		}
	}
	if queryID == "" {
		t.Fatal("launch_daemons missing")
	}
	nodeKey := enrollOsquery(t, ts.URL, "example-enroll-secret", "UUID-TF", "SER-TF")
	postJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"result","data":[{"name":"mc_label_apple-silicon","snapshot":[{"1":"1"}]}]}`)
	cfg := postJSON(t, ts.URL, "/config", `{"node_key":"`+nodeKey+`"}`)
	if !strings.Contains(cfg, "launch_daemons") || !strings.Contains(cfg, `"endpoint"`) {
		t.Fatalf("terraform pack did not reach agent config: %s", cfg)
	}

	run("state", "rm", "missioncontrol_osquery_query.launch_daemons")
	run("import", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3",
		"missioncontrol_osquery_query.launch_daemons", queryID)
	importedQuery := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	out, err = importedQuery.CombinedOutput()
	if err != nil {
		t.Fatalf("imported query drifted: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "example-enroll-secret") {
		t.Fatalf("enroll secret leaked in plan:\n%s", out)
	}

	var listedPacks struct {
		Packs []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"packs"`
	}
	if err := json.Unmarshal([]byte(apiGet(t, ts.URL, "/api/v1/osquery/packs")), &listedPacks); err != nil {
		t.Fatal(err)
	}
	var packID string
	for _, pack := range listedPacks.Packs {
		if pack.Name == "endpoint" {
			packID = pack.ID
		}
	}
	if packID == "" {
		t.Fatal("endpoint pack missing")
	}
	var listedLabels struct {
		Labels []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"labels"`
	}
	if err := json.Unmarshal([]byte(apiGet(t, ts.URL, "/api/v1/osquery/labels")), &listedLabels); err != nil {
		t.Fatal(err)
	}
	var labelID string
	for _, label := range listedLabels.Labels {
		if label.Name == "apple-silicon" {
			labelID = label.ID
		}
	}
	if labelID == "" {
		t.Fatal("apple-silicon label missing")
	}
	var listedSecrets struct {
		Secrets []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"enroll_secrets"`
	}
	if err := json.Unmarshal([]byte(apiGet(t, ts.URL, "/api/v1/osquery/enroll-secrets")), &listedSecrets); err != nil {
		t.Fatal(err)
	}
	var secretID string
	for _, secret := range listedSecrets.Secrets {
		if secret.Name == "fleet" {
			secretID = secret.ID
		}
	}
	if secretID == "" {
		t.Fatal("fleet enroll secret missing")
	}
	run("state", "rm", "missioncontrol_osquery_pack.endpoint")
	run("import", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3",
		"missioncontrol_osquery_pack.endpoint", packID)
	run("state", "rm", "missioncontrol_osquery_label.apple_silicon")
	run("import", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3",
		"missioncontrol_osquery_label.apple_silicon", labelID)
	rotated := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3",
		"-var", "enroll_secret=rotated-enroll-secret-value")
	rotOut, rotErr := rotated.CombinedOutput()
	if strings.Contains(string(rotOut), "example-enroll-secret") || strings.Contains(string(rotOut), "rotated-enroll-secret-value") {
		t.Fatalf("enroll secret leaked in plan:\n%s", rotOut)
	}
	if !errors.As(rotErr, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("enroll secret rotation should plan with exit 2, err=%v\n%s", rotErr, rotOut)
	}
	importedPackLabel := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	out, err = importedPackLabel.CombinedOutput()
	if strings.Contains(string(out), "example-enroll-secret") {
		t.Fatalf("enroll secret leaked in plan:\n%s", out)
	}
	if err != nil {
		t.Fatalf("imported pack or label drifted: %v\n%s", err, out)
	}
	run("state", "rm", "missioncontrol_osquery_enroll_secret.fleet")
	run("import", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3",
		"missioncontrol_osquery_enroll_secret.fleet", secretID)
	importedRest := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	out, err = importedRest.CombinedOutput()
	if strings.Contains(string(out), "example-enroll-secret") {
		t.Fatalf("enroll secret leaked in plan:\n%s", out)
	}
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "secret_fingerprint") {
		t.Fatalf("imported enroll secret should plan one fingerprint update, err=%v\n%s", err, out)
	}
	run("apply", "-auto-approve", "-input=false",
		"-var", "endpoint="+ts.URL,
		"-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4",
		"-var", "soak_days=3",
	)
	cleanSecret := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	out, err = cleanSecret.CombinedOutput()
	if strings.Contains(string(out), "example-enroll-secret") {
		t.Fatalf("enroll secret leaked in plan:\n%s", out)
	}
	if err != nil {
		t.Fatalf("fingerprint apply should leave a clean plan, err=%v\n%s", err, out)
	}
	if strings.Contains(string(out), "example-crowdstrike-client-secret") || strings.Contains(string(out), "example-kolide-api-token") || strings.Contains(string(out), "example-elastic-api-key") {
		t.Fatalf("connector credential leaked in plan:\n%s", out)
	}

	if _, err := st.Pool().Exec(ctx, `UPDATE osquery_queries SET sql='SELECT 1' WHERE name='launch_daemons'`); err != nil {
		t.Fatal(err)
	}
	driftedQuery := terraformCmd(t, work, tfrc, "plan", "-detailed-exitcode", "-input=false",
		"-var", "endpoint="+ts.URL, "-var", "token=mc_tf_admin",
		"-var", "max_concurrency=4", "-var", "soak_days=3")
	driftOut, driftErr = driftedQuery.CombinedOutput()
	if !errors.As(driftErr, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("query drift should plan with exit 2, err=%v\n%s", driftErr, driftOut)
	}
	if strings.Contains(string(driftOut), "example-enroll-secret") {
		t.Fatalf("enroll secret leaked in plan:\n%s", driftOut)
	}

	stateRaw, err := os.ReadFile(filepath.Join(work, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"example-crowdstrike-client-secret", "example-kolide-api-token", "example-elastic-api-key", "example-enroll-secret", "rotated-enroll-secret-value"} {
		if strings.Contains(string(stateRaw), leak) {
			t.Fatalf("terraform state contains %s", leak)
		}
	}
	var audit string
	if err := st.Pool().QueryRow(ctx, `SELECT coalesce(string_agg(detail::text, ''), '') FROM audit_log`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"example-crowdstrike-client-secret", "example-kolide-api-token", "example-elastic-api-key", "example-enroll-secret"} {
		if strings.Contains(audit, leak) {
			t.Fatalf("audit log contains %s", leak)
		}
	}

	views := apiGet(t, ts.URL, "/api/v1/log-views")
	if !strings.Contains(views, "Endpoint logs") || !strings.Contains(views, "AutoPKG run log") || strings.Contains(views, "example-elastic-api-key") {
		t.Fatalf("log views: %s", views)
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
	if strings.Contains(apiGet(t, ts.URL, "/api/v1/osquery/queries"), "launch_daemons") {
		t.Fatal("osquery query survived destroy")
	}
	settings = apiGet(t, ts.URL, "/api/v1/pipeline-settings")
	if !strings.Contains(settings, `"max_concurrency":4`) && !strings.Contains(settings, `"max_concurrency": 4`) {
		t.Fatalf("destroy should reset pipeline concurrency to the default: %s", settings)
	}
	if !strings.Contains(settings, `"lease_seconds":120`) && !strings.Contains(settings, `"lease_seconds": 120`) {
		t.Fatalf("destroy should reset lease_seconds to the default 120: %s", settings)
	}
}

func terraformCmd(t *testing.T, work, tfrc string, args ...string) *exec.Cmd {
	t.Helper()
	c := exec.Command("terraform", args...)
	c.Dir = work
	c.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+tfrc, "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
	return c
}

func enrollOsquery(t *testing.T, base, secret, uuid, serial string) string {
	t.Helper()
	body := postJSON(t, base, "/enroll", `{"enroll_secret":"`+secret+`","host_identifier":"tf-host","host_details":{"system_info":{"uuid":"`+uuid+`","hardware_serial":"`+serial+`","hostname":"tf-host"},"os_version":{"platform":"darwin","version":"26.1"}}}`)
	var out struct {
		NodeKey string `json:"node_key"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.NodeKey == "" {
		t.Fatalf("enroll: %s", body)
	}
	return out.NodeKey
}

func postJSON(t *testing.T, base, path, body string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		t.Fatalf("POST %s %d %s", path, res.StatusCode, b)
	}
	return string(b)
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
