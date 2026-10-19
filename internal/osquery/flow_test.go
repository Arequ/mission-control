package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/store"
)

func TestEnrollConfigInventoryAndDistributed(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	resources, diags, err := config.LoadPath("../../examples/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) > 0 {
		t.Fatalf("example config: %+v", diags)
	}
	if _, err := config.Apply(ctx, st, resources, config.ApplyOptions{Prune: true}); err != nil {
		t.Fatal(err)
	}

	h := &Handler{Store: st, EnrollSecret: "dev-enroll-secret"}
	mux := http.NewServeMux()
	h.Register(mux)

	enrollBody := map[string]any{
		"enroll_secret":   "nope",
		"host_identifier": "HOST-1",
	}
	rec := post(t, mux, "/osquery/enroll", enrollBody)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad secret status %d", rec.Code)
	}

	enrollBody["enroll_secret"] = "dev-enroll-secret"
	enrollBody["host_details"] = map[string]any{
		"system_info": map[string]any{
			"hostname":           "ada.local",
			"computer_name":      "Ada's MacBook Pro",
			"uuid":               "UUID-1",
			"hardware_serial":    "C02ADA001",
			"hardware_model":     "MacBookPro18,3",
			"hardware_vendor":    "Apple Inc.",
			"cpu_brand":          "Apple M3 Pro",
			"cpu_physical_cores": "12",
			"physical_memory":    "38654705664",
		},
		"os_version": map[string]any{
			"name": "macOS", "version": "15.1", "major": "15", "minor": "1", "build": "24B83", "platform": "darwin",
		},
		"osquery_info": map[string]any{"version": "5.15.0"},
	}
	rec = post(t, mux, "/osquery/enroll", enrollBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll %d %s", rec.Code, rec.Body.String())
	}
	var enrolled struct {
		NodeKey     string `json:"node_key"`
		NodeInvalid bool   `json:"node_invalid"`
	}
	mustJSON(t, rec, &enrolled)
	if enrolled.NodeKey == "" || enrolled.NodeInvalid {
		t.Fatalf("enroll response %#v", enrolled)
	}

	// Re-enroll keeps the same device.
	rec = post(t, mux, "/osquery/enroll", enrollBody)
	var again struct {
		NodeKey string `json:"node_key"`
	}
	mustJSON(t, rec, &again)
	if again.NodeKey == "" || again.NodeKey == enrolled.NodeKey {
		t.Fatal("expected a rotated node key")
	}
	enrolled.NodeKey = again.NodeKey

	rec = post(t, mux, "/osquery/config", map[string]any{"node_key": "missing"})
	var invalid struct {
		NodeInvalid bool `json:"node_invalid"`
	}
	mustJSON(t, rec, &invalid)
	if !invalid.NodeInvalid {
		t.Fatal("expected node_invalid")
	}

	rec = post(t, mux, "/osquery/config", map[string]any{"node_key": enrolled.NodeKey})
	var cfg map[string]any
	mustJSON(t, rec, &cfg)
	packs := cfg["packs"].(map[string]any)
	if _, ok := packs["macos-security"]; !ok {
		t.Fatalf("missing security pack: %#v", packs)
	}
	if _, ok := packs["macos-inventory"]; !ok {
		t.Fatal("missing inventory pack")
	}
	schedule := cfg["schedule"].(map[string]any)
	if _, ok := schedule["label_macbooks"]; !ok {
		t.Fatal("missing label query")
	}
	if _, ok := schedule["listening-ports"]; !ok {
		t.Fatal("missing top-level query")
	}
	if _, ok := schedule["system_info"]; ok {
		t.Fatal("built-in system_info should be replaced by the inventory pack")
	}

	rec = post(t, mux, "/osquery/log", map[string]any{
		"node_key": enrolled.NodeKey,
		"log_type": "result",
		"data": []any{
			map[string]any{
				"name":     "pack/macos-inventory/system_info",
				"unixTime": 1_700_000_000,
				"snapshot": []any{enrollBody["host_details"].(map[string]any)["system_info"]},
			},
			map[string]any{
				"name":     "pack/macos-inventory/os_version",
				"unixTime": 1_700_000_000,
				"snapshot": []any{enrollBody["host_details"].(map[string]any)["os_version"]},
			},
			map[string]any{
				"name":     "pack/macos-inventory/users",
				"unixTime": 1_700_000_000,
				"snapshot": []any{map[string]any{"uid": "501", "username": "ada"}},
			},
			map[string]any{
				"name":     "pack/macos-inventory/apps",
				"unixTime": 1_700_000_000,
				"snapshot": []any{
					map[string]any{"name": "Safari", "path": "/Applications/Safari.app", "bundle_identifier": "com.apple.Safari", "bundle_short_version": "18.0"},
					map[string]any{"name": "Slack", "path": "/Applications/Slack.app", "bundle_identifier": "com.tinyspeck.slackmacgap", "bundle_short_version": "4.41.0"},
				},
			},
			map[string]any{"name": "label_macbooks", "unixTime": 1_700_000_000, "snapshot": []any{map[string]any{"1": "1"}}},
			map[string]any{"name": "label_sequoia", "unixTime": 1_700_000_000, "snapshot": []any{map[string]any{"1": "1"}}},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("log %d %s", rec.Code, rec.Body.String())
	}

	devices, err := st.ListDevices(ctx, store.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d", len(devices))
	}
	d, err := st.GetDevice(ctx, devices[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.ComputerName != "Ada's MacBook Pro" || d.OSVersion != "15.1" || d.PrimaryUser != "ada" {
		t.Fatalf("device not updated: %#v", d)
	}
	if d.ConfigHash == "" || d.ConfigDrift {
		t.Fatalf("config hash %#v drift %v", d.ConfigHash, d.ConfigDrift)
	}
	found := map[string]bool{}
	for _, label := range d.Labels {
		found[label] = true
	}
	if !found["macbooks"] || !found["sequoia"] {
		t.Fatalf("labels = %#v", d.Labels)
	}
	apps, err := st.ListApps(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 {
		t.Fatalf("apps = %#v", apps)
	}

	live, err := st.CreateLiveQuery(ctx, "SELECT version FROM osquery_info;", "test", []string{d.ID})
	if err != nil {
		t.Fatal(err)
	}
	rec = post(t, mux, "/osquery/distributed/read", map[string]any{"node_key": enrolled.NodeKey})
	var dist struct {
		Queries map[string]string `json:"queries"`
	}
	mustJSON(t, rec, &dist)
	if dist.Queries[live.ID] == "" {
		t.Fatalf("distributed read = %#v", dist.Queries)
	}
	rec = post(t, mux, "/osquery/distributed/write", map[string]any{
		"node_key": enrolled.NodeKey,
		"queries":  map[string]any{live.ID: []any{map[string]any{"version": "5.15.0"}}},
		"statuses": map[string]any{live.ID: "0"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("write %d %s", rec.Code, rec.Body.String())
	}
	got, err := st.GetLiveQuery(ctx, live.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 1 || got.Targets[0].Status != "complete" {
		t.Fatalf("target = %#v", got.Targets)
	}
}

func post(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustJSON(t *testing.T, rec *httptest.ResponseRecorder, dest any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dest); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
}
