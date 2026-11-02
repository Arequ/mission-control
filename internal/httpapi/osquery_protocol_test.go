package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestOsqueryProtocol(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureAPIToken(ctx, "reader", "mc_read", []string{"osquery:read"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	var forwarded []osquery.ResultEvent
	srv := New(Options{
		Store: st, Blobs: blobs, OfflineAfter: time.Hour, InventoryInterval: time.Minute,
		Forwarder: captureForwarder{fn: func(events []osquery.ResultEvent) { forwarded = append(forwarded, events...) }},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	status, text := apiJSON(t, ts.URL, http.MethodPost, "/api/v1/osquery/queries", "mc_admin", false, `{"name":"nope","sql":"SELECT 1"}`)
	if status != http.StatusForbidden || !strings.Contains(text, "Terraform") {
		t.Fatalf("config write without terraform header: %d %s", status, text)
	}
	status, text = apiJSON(t, ts.URL, http.MethodPost, "/api/v1/live-queries", "mc_read", false, `{"sql":"SELECT 1","device_ids":["x"]}`)
	if status != http.StatusForbidden {
		t.Fatalf("reader live query: %d %s", status, text)
	}

	secret := tf(t, ts.URL, http.MethodPost, "/api/v1/osquery/enroll-secrets", `{"name":"fleet","secret":"example-enroll-secret","enabled":true}`)
	var secretRec struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(secret), &secretRec); err != nil {
		t.Fatal(err)
	}
	if secretRec.Secret != "" {
		t.Fatalf("secret returned: %s", secret)
	}
	_ = tfJSON(t, ts.URL, http.MethodPost, "/api/v1/osquery/labels", `{"name":"always","kind":"dynamic","sql":"SELECT 1"}`)
	query := tfJSON(t, ts.URL, http.MethodPost, "/api/v1/osquery/queries", `{"name":"launch_daemons","sql":"SELECT name FROM launchd","platform":"darwin","interval":3600,"snapshot":false,"removed":true,"scheduled":false}`)
	tf(t, ts.URL, http.MethodPost, "/api/v1/osquery/packs", `{"name":"endpoint","platform":"darwin","labels":["always"],"query_ids":["`+query["id"].(string)+`"],"enabled":true}`)
	_ = tfJSON(t, ts.URL, http.MethodPost, "/api/v1/osquery/labels", `{"name":"canaries","kind":"manual","serials":["SER-CANARY"]}`)

	status, text = osq(t, ts.URL, "/enroll", `{"enroll_secret":"nope","host_identifier":"x"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("bad secret %d %s", status, text)
	}

	enrollBody := `{"enroll_secret":"example-enroll-secret","host_identifier":"mbp.local","host_details":{"system_info":{"uuid":"UUID-1","hardware_serial":"SER-1","hostname":"mbp.local","computer_name":"Ava's MacBook Pro","cpu_brand":"Apple M4","hardware_model":"Mac16,1","physical_memory":"17179869184"},"os_version":{"name":"macOS","version":"26.1","build":"25B78","platform":"darwin"},"osquery_info":{"version":"5.15.0"}}}`
	en := osqJSON(t, ts.URL, "/enroll", enrollBody)
	nodeKey, _ := en["node_key"].(string)
	if nodeKey == "" || en["node_invalid"] == true {
		t.Fatalf("enroll %v", en)
	}
	devs := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices", "mc_admin", false, "")
	list := devs["devices"].([]any)
	if len(list) != 1 {
		t.Fatalf("devices %s", mustJSONRaw(devs))
	}
	device := list[0].(map[string]any)
	deviceID := device["id"].(string)
	if device["hardware_uuid"] != "UUID-1" || device["serial"] != "SER-1" || device["os_version"] != "26.1" || device["model_name"] != "MacBook Pro 14-inch" {
		t.Fatalf("identity %+v", device)
	}
	if !strings.Contains(device["os_display"].(string), "Tahoe") {
		t.Fatalf("display %v", device["os_display"])
	}

	cfg := osqJSON(t, ts.URL, "/config", `{"node_key":"`+nodeKey+`"}`)
	sched := cfg["schedule"].(map[string]any)
	if _, ok := sched["mc_system_info"]; !ok {
		t.Fatalf("missing inventory schedule: %v", sched)
	}
	if _, ok := sched["mc_label_always"]; !ok {
		t.Fatalf("missing label query: %v", sched)
	}
	if packs, ok := cfg["packs"].(map[string]any); ok && len(packs) > 0 {
		t.Fatalf("pack visible before label match: %v", packs)
	}

	osqJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"status","data":[{"severity":"0","filename":"tls.cpp","line":"12","message":"all good","version":"5.15.0"}]}`)
	osqJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"result","data":[{"name":"mc_label_always","unixTime":"100","snapshot":[{"1":"1"}]}]}`)
	cfg = osqJSON(t, ts.URL, "/config", `{"node_key":"`+nodeKey+`"}`)
	packs := cfg["packs"].(map[string]any)
	endpoint, ok := packs["endpoint"].(map[string]any)
	if !ok {
		t.Fatalf("pack missing after label match: %v", packs)
	}
	qs := endpoint["queries"].(map[string]any)
	if _, ok := qs["launch_daemons"]; !ok {
		t.Fatalf("pack queries %v", qs)
	}
	osqJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"result","data":[{"name":"mc_label_always","snapshot":[]}]}`)
	cfg = osqJSON(t, ts.URL, "/config", `{"node_key":"`+nodeKey+`"}`)
	if packs, ok := cfg["packs"].(map[string]any); ok && len(packs) > 0 {
		t.Fatalf("pack still present after empty label: %v", packs)
	}

	osqJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"result","data":[{"name":"mc_apps","snapshot":[{"name":"Chrome","path":"/Applications/Google Chrome.app","bundle_identifier":"com.google.Chrome","bundle_short_version":"130.0"}]}]}`)
	osqJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"result","data":[{"name":"mc_apps","snapshot":[{"name":"Chrome","path":"/Applications/Google Chrome.app","bundle_identifier":"com.google.Chrome","bundle_short_version":"131.0"},{"name":"Slack","path":"/Applications/Slack.app","bundle_identifier":"com.tinyspeck.slackmacgap","bundle_short_version":"4.41"}]}]}`)
	osqJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"result","data":[{"name":"mc_os_version","snapshot":[{"name":"macOS","version":"26.2","build":"25C1","platform":"darwin"}]}]}`)
	detail := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices/"+deviceID, "mc_admin", false, "")
	apps := detail["apps"].([]any)
	if len(apps) != 2 {
		t.Fatalf("apps %+v", apps)
	}
	actions := map[string]bool{}
	for _, raw := range detail["events"].([]any) {
		ev := raw.(map[string]any)
		actions[ev["action"].(string)] = true
	}
	for _, want := range []string{"app_updated", "app_installed", "os_version_changed", "enrolled"} {
		if !actions[want] {
			t.Fatalf("missing %s in %v", want, detail["events"])
		}
	}
	if detail["os_version"] != "26.2" {
		t.Fatalf("os %v", detail["os_version"])
	}
	if len(forwarded) == 0 {
		t.Fatal("forwarder received nothing")
	}

	results := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices/"+deviceID+"/results?limit=1&offset=0", "mc_admin", false, "")
	if results["total"].(float64) < 2 || len(results["results"].([]any)) != 1 {
		t.Fatalf("pagination %+v", results)
	}

	live := apiMap(t, ts.URL, http.MethodPost, "/api/v1/live-queries", "mc_admin", false, `{"sql":"SELECT version FROM osquery_info","device_ids":["`+deviceID+`"],"timeout_seconds":30}`)
	liveID := live["id"].(string)
	dist := osqJSON(t, ts.URL, "/distributed_read", `{"node_key":"`+nodeKey+`"}`)
	gotQueries := dist["queries"].(map[string]any)
	if gotQueries[liveID] != "SELECT version FROM osquery_info" {
		t.Fatalf("distributed read %v", dist)
	}
	osqJSON(t, ts.URL, "/distributed_write", `{"node_key":"`+nodeKey+`","queries":{"`+liveID+`":[{"version":"5.15.0"}]},"statuses":{"`+liveID+`":0}}`)
	done := apiMap(t, ts.URL, http.MethodGet, "/api/v1/live-queries/"+liveID, "mc_admin", false, "")
	if done["status"] != "complete" || len(done["rows"].([]any)) != 1 {
		t.Fatalf("live query %+v", done)
	}

	apiJSON(t, ts.URL, http.MethodPost, "/api/v1/devices/"+deviceID+"/invalidate", "mc_admin", false, `{}`)
	inv := osqJSON(t, ts.URL, "/config", `{"node_key":"`+nodeKey+`"}`)
	if inv["node_invalid"] != true {
		t.Fatalf("expected node_invalid, got %v", inv)
	}
	reen := osqJSON(t, ts.URL, "/enroll", `{"enroll_secret":"example-enroll-secret","host_identifier":"mbp.local","host_details":{"system_info":{"uuid":"UUID-1","hardware_serial":"SER-1","hostname":"mbp.local"}}}`)
	newKey := reen["node_key"].(string)
	if newKey == "" || newKey == nodeKey {
		t.Fatalf("new key %q", newKey)
	}
	again := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices?q=SER-1", "mc_admin", false, "")
	if again["total"].(float64) != 1 || again["devices"].([]any)[0].(map[string]any)["id"] != deviceID {
		t.Fatalf("re-enroll split the device: %v", again)
	}
	old := osqJSON(t, ts.URL, "/logger", `{"node_key":"`+nodeKey+`","log_type":"status","data":[{"message":"stale"}]}`)
	if old["node_invalid"] != true {
		t.Fatalf("old key accepted %v", old)
	}
	cfg = osqJSON(t, ts.URL, "/config", `{"node_key":"`+newKey+`"}`)
	if cfg["node_invalid"] == true {
		t.Fatal("new key invalid")
	}

	serialEnroll := osqJSON(t, ts.URL, "/enroll", `{"enroll_secret":"example-enroll-secret","host_identifier":"mbp.local","host_details":{"system_info":{"uuid":"UUID-2","hardware_serial":"SER-1","hostname":"mbp.local"}}}`)
	if serialEnroll["node_key"] == "" {
		t.Fatal(serialEnroll)
	}
	matched := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices?q=SER-1", "mc_admin", false, "")
	if matched["total"].(float64) != 1 {
		t.Fatalf("serial re-enroll created a second device: %v", matched)
	}
	if matched["devices"].([]any)[0].(map[string]any)["hardware_uuid"] != "UUID-2" {
		t.Fatalf("uuid not updated: %v", matched["devices"].([]any)[0])
	}

	canary := osqJSON(t, ts.URL, "/enroll", `{"enroll_secret":"example-enroll-secret","host_identifier":"canary","host_details":{"system_info":{"uuid":"UUID-C","hardware_serial":"SER-CANARY","hostname":"canary"}}}`)
	canaryKey := canary["node_key"].(string)
	cfg = osqJSON(t, ts.URL, "/config", `{"node_key":"`+canaryKey+`"}`)
	// canaries is manual and does not scope the endpoint pack; always is dynamic and unmatched.
	if packs, ok := cfg["packs"].(map[string]any); ok && packs["endpoint"] != nil {
		t.Fatalf("canary should not get the always pack yet: %v", packs)
	}
	canaryDev := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices?q=SER-CANARY", "mc_admin", false, "")
	labels := canaryDev["devices"].([]any)
	if len(labels) != 1 {
		t.Fatal(canaryDev)
	}
	full := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices/"+labels[0].(map[string]any)["id"].(string), "mc_admin", false, "")
	gotLabels, _ := full["labels"].([]any)
	if len(gotLabels) != 1 || gotLabels[0] != "canaries" {
		t.Fatalf("manual label membership: %v", full["labels"])
	}

	tf(t, ts.URL, http.MethodPut, "/api/v1/osquery/enroll-secrets/"+secretRec.ID, `{"name":"fleet","secret":"rotated-enroll-secret","enabled":true}`)
	status, _ = osq(t, ts.URL, "/enroll", `{"enroll_secret":"example-enroll-secret","host_identifier":"x","host_details":{"system_info":{"uuid":"UUID-X","hardware_serial":"SER-X"}}}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("old secret still works: %d", status)
	}
	rotated := osqJSON(t, ts.URL, "/enroll", `{"enroll_secret":"rotated-enroll-secret","host_identifier":"x","host_details":{"system_info":{"uuid":"UUID-X","hardware_serial":"SER-X"}}}`)
	if rotated["node_key"] == "" {
		t.Fatal(rotated)
	}

	page := apiMap(t, ts.URL, http.MethodGet, "/api/v1/devices?limit=1&offset=0", "mc_admin", false, "")
	if page["total"].(float64) < 2 || len(page["devices"].([]any)) != 1 {
		t.Fatalf("device page %+v", page)
	}

	// A timed-out live query stops being offered.
	st.SetClock(&manualClock{t: time.Now().Add(2 * time.Hour)})
	timed := apiMap(t, ts.URL, http.MethodPost, "/api/v1/live-queries", "mc_admin", false, `{"sql":"SELECT 1 AS n","device_ids":["`+deviceID+`"],"timeout_seconds":30}`)
	st.SetClock(&manualClock{t: time.Now().Add(3 * time.Hour)})
	empty := osqJSON(t, ts.URL, "/distributed_read", `{"node_key":"`+serialEnroll["node_key"].(string)+`"}`)
	if qs, ok := empty["queries"].(map[string]any); ok && qs[timed["id"].(string)] != nil {
		t.Fatalf("expired query still offered: %v", empty)
	}
	view := apiMap(t, ts.URL, http.MethodGet, "/api/v1/live-queries/"+timed["id"].(string), "mc_admin", false, "")
	targets := view["targets"].([]any)
	if len(targets) == 0 || targets[0].(map[string]any)["status"] != "timeout" {
		t.Fatalf("timeout status %+v", view)
	}
}

type captureForwarder struct {
	fn func([]osquery.ResultEvent)
}

func (c captureForwarder) Forward(_ context.Context, events []osquery.ResultEvent) error {
	c.fn(events)
	return nil
}

type manualClock struct{ t time.Time }

func (m *manualClock) Now() time.Time { return m.t }

func tf(t *testing.T, base, method, path, body string) string {
	t.Helper()
	status, text := apiJSON(t, base, method, path, "mc_admin", true, body)
	if status >= 300 {
		t.Fatalf("%s %s %d %s", method, path, status, text)
	}
	return text
}

func tfJSON(t *testing.T, base, method, path, body string) map[string]any {
	t.Helper()
	return parseJSON(t, tf(t, base, method, path, body))
}

func apiJSON(t *testing.T, base, method, path, token string, terraform bool, body string) (int, string) {
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
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func osq(t *testing.T, base, path, body string) (int, string) {
	t.Helper()
	res, err := http.Post(base+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func osqJSON(t *testing.T, base, path, body string) map[string]any {
	t.Helper()
	status, text := osq(t, base, path, body)
	if status >= 300 {
		t.Fatalf("POST %s %d %s", path, status, text)
	}
	return parseJSON(t, text)
}

func apiMap(t *testing.T, base, method, path, token string, terraform bool, body string) map[string]any {
	t.Helper()
	status, text := apiJSON(t, base, method, path, token, terraform, body)
	return mustJSON(t, status, text)
}

func mustJSON(t *testing.T, status int, text string) map[string]any {
	t.Helper()
	if status >= 300 {
		t.Fatalf("status %d %s", status, text)
	}
	return parseJSON(t, text)
}

func parseJSON(t *testing.T, text string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("json %s: %v", text, err)
	}
	return out
}

func mustJSONRaw(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
