package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
)

// fakeCPEDictionary answers keywordSearch with a small, made-up dictionary.
// Vendors and products are shaped like NVD's but are test data.
var fakeCPEDictionary = map[string][][2]string{
	"zoom": {
		{"cpe:2.3:a:zoom:zoom:5.0.0:*:*:*:*:macos:*:*", "Zoom 5.0.0 for macOS"},
		{"cpe:2.3:a:zoom:zoom_client:5.1:*:*:*:*:*:*:*", "Zoom Client 5.1"},
		{"cpe:2.3:a:zoom:workplace_desktop:6.0:*:*:*:*:macos:*:*", "Zoom Workplace Desktop 6.0"},
	},
	"slack": {
		{"cpe:2.3:a:slack:slack:4.41.105:*:*:*:*:macos:*:*", "Slack 4.41.105 for macOS"},
		{"cpe:2.3:a:slack:slack:4.0:*:*:*:*:android:*:*", "Slack 4.0 for Android"},
	},
	"cursor": {
		{"cpe:2.3:a:anysphere:cursor:0.45.0:*:*:*:*:*:*:*", "Anysphere Cursor 0.45.0"},
		{"cpe:2.3:a:wpplugins:cursor_trail:1.0:*:*:*:*:wordpress:*:*", "Cursor Trail for WordPress"},
	},
	"granola": {
		{"cpe:2.3:a:granola:granola:5.1.0:*:*:*:*:macos:*:*", "Granola 5.1.0 for macOS"},
	},
}

type fakeNVD struct {
	mu       sync.Mutex
	keywords []string
	key      string
	fail     bool
}

func (f *fakeNVD) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path != "/cpes/2.0" {
			// The CVE sync: nothing new.
			_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
			return
		}
		if got := r.Header.Get("apiKey"); got != f.key {
			http.NotFound(w, r)
			return
		}
		if f.fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		kw := r.URL.Query().Get("keywordSearch")
		f.keywords = append(f.keywords, kw)
		var products []map[string]any
		for _, it := range fakeCPEDictionary[kw] {
			products = append(products, map[string]any{"cpe": map[string]any{
				"deprecated": false, "cpeName": it[0], "cpeNameId": fmt.Sprintf("id-%d", len(products)),
				"titles": []map[string]string{{"title": it[1], "lang": "en"}},
			}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"resultsPerPage": len(products), "startIndex": 0, "totalResults": len(products), "products": products})
	})
}

func (f *fakeNVD) searched() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keywords...)
}

func importApp(t *testing.T, st *Store, name, version, display, developer, bundle string) {
	t.Helper()
	info := map[string]any{"name": name, "version": version, "display_name": display, "developer": developer}
	if bundle != "" {
		info["installs"] = []map[string]any{{"type": "application", "CFBundleIdentifier": bundle, "path": "/Applications/" + display + ".app"}}
	}
	raw, _ := json.Marshal(info)
	if _, _, err := st.InsertPackage(context.Background(), model.System, model.Package{
		Name: name, Version: version, Catalog: "alpha", Filename: name + "-" + version + ".pkg", Pkginfo: raw,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCPEProposalsFromFakeNVD(t *testing.T) {
	ctx := context.Background()
	st := releaseStore(t)
	clk := &clock.Manual{}
	clk.Set(time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC))
	st.SetClock(clk)
	const key = "test-nvd-key-0001"
	admin := model.Principal{Kind: "api_token", Name: "admin", Scopes: map[string]bool{"*": true}}
	if _, err := st.UpdateVulnerabilitySettings(ctx, admin, model.VulnerabilitySettings{
		NVDEnabled: true, SyncCron: "20 3 * * *", Timezone: "UTC", NVDAPIKey: key,
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}

	// Slack under its curated Munki name is already mapped and must not be
	// looked up. The other items have no mapping.
	importApp(t, st, "Slack", "4.41.105", "Slack", "Slack Technologies, Inc.", "com.tinyspeck.slackmacgap")
	importApp(t, st, "SlackBeta", "4.42.0", "Slack", "Slack Technologies, Inc.", "com.tinyspeck.slackmacgap")
	importApp(t, st, "ZoomUS", "6.2.0", "Zoom", "Zoom Video Communications, Inc.", "us.zoom.xos")
	importApp(t, st, "Cursor", "0.45.0", "Cursor", "Anysphere Inc.", "com.todesktop.230313mzl4w4u92")
	importApp(t, st, "Granola", "5.1.0", "Granola", "Granola Inc", "com.granola.app")
	importApp(t, st, "InternalTool", "1.0", "Internal Tool", "Example Corp", "com.example.internaltool")

	fake := &fakeNVD{key: key}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	st.SetVulnerabilityFeeds(vuln.Feeds{HTTP: srv.Client(), NVDBase: srv.URL, Sleep: func(context.Context, time.Duration) error { return nil }})

	list, err := st.RefreshCPEProposals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]model.CPEProposal{}
	for _, p := range list.Proposals {
		by[p.Name] = p
	}
	if _, ok := by["Slack"]; ok {
		t.Fatal("curated Slack was looked up")
	}
	want := map[string][3]string{
		"SlackBeta": {"high", "slack", "slack"},
		"Cursor":    {"high", "anysphere", "cursor"},
		"Granola":   {"high", "granola", "granola"},
		"ZoomUS":    {"medium", "zoom", "zoom"},
	}
	for name, w := range want {
		p, ok := by[name]
		if !ok {
			t.Fatalf("no proposal for %s: %+v", name, list.Proposals)
		}
		if p.Confidence != w[0] || p.Vendor != w[1] || p.Product != w[2] || p.Status != "proposed" {
			t.Fatalf("%s = %s %s:%s (%s)", name, p.Confidence, p.Vendor, p.Product, p.Status)
		}
		if p.NeedsReview != (w[0] != "high") {
			t.Fatalf("%s needs_review = %v", name, p.NeedsReview)
		}
		if !strings.Contains(p.Terraform, fmt.Sprintf("name    = %q", name)) || !strings.Contains(p.Terraform, "bundle_id = ") {
			t.Fatalf("%s terraform:\n%s", name, p.Terraform)
		}
	}
	var cands []vuln.CPECandidate
	if err := json.Unmarshal(by["ZoomUS"].Candidates, &cands); err != nil || len(cands) < 2 {
		t.Fatalf("zoom candidates = %s", by["ZoomUS"].Candidates)
	}
	if p := by["InternalTool"]; p.Status != "no_match" || p.Confidence != "none" || p.Terraform != "" {
		t.Fatalf("internal tool = %+v", p)
	}
	if list.Proposals[0].Confidence != "high" || list.Waiting != 0 {
		t.Fatalf("order or waiting: first=%s waiting=%d", list.Proposals[0].Name, list.Waiting)
	}

	// A second run inside the recheck window makes no requests.
	before := len(fake.searched())
	if _, err := st.RefreshCPEProposals(ctx); err != nil {
		t.Fatal(err)
	}
	if after := len(fake.searched()); after != before {
		t.Fatalf("refresh re-queried fresh items: %d -> %d", before, after)
	}

	// Once Terraform adds the override, the item leaves the list.
	if _, err := st.UpdateVulnerabilitySettings(ctx, admin, model.VulnerabilitySettings{
		NVDEnabled: true, SyncCron: "20 3 * * *", Timezone: "UTC",
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14, ManagedBy: "terraform",
		Overrides: []model.CPEOverride{{Name: "Cursor", Vendor: "anysphere", Product: "cursor"}},
	}); err != nil {
		t.Fatal(err)
	}
	list, err = st.ListCPEProposals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list.Proposals {
		if p.Name == "Cursor" {
			t.Fatal("mapped item still proposed")
		}
	}
}

func TestCPEProposalsStopOnInvalidKeyAndRespectBudget(t *testing.T) {
	ctx := context.Background()
	st := releaseStore(t)
	admin := model.Principal{Kind: "api_token", Name: "admin", Scopes: map[string]bool{"*": true}}
	if _, err := st.UpdateVulnerabilitySettings(ctx, admin, model.VulnerabilitySettings{
		NVDEnabled: true, SyncCron: "20 3 * * *", Timezone: "UTC", NVDAPIKey: "stale-nvd-key-0002",
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	importApp(t, st, "Cursor", "0.45.0", "Cursor", "Anysphere Inc.", "")
	fake := &fakeNVD{key: "the-real-key-0003"}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	st.SetVulnerabilityFeeds(vuln.Feeds{HTTP: srv.Client(), NVDBase: srv.URL, Sleep: func(context.Context, time.Duration) error { return nil }})

	_, err := st.RefreshCPEProposals(ctx)
	if err == nil || !strings.Contains(err.Error(), "invalid API key") || strings.Contains(err.Error(), "stale-nvd-key") {
		t.Fatalf("err = %v", err)
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM cpe_proposals`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("key error stored against an item: %d %v", n, err)
	}

	// Without a key the manual run stops at its budget; the rest wait.
	if _, err := st.Pool().Exec(ctx, `UPDATE vulnerability_settings SET nvd_api_key='' WHERE id='default'`); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.key = ""
	fake.mu.Unlock()
	for i := 0; i < cpeManualCalls+3; i++ {
		importApp(t, st, fmt.Sprintf("Tool%02d", i), "1.0", "", "", "")
	}
	list, err := st.RefreshCPEProposals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(fake.searched()); got != cpeManualCalls {
		t.Fatalf("searches = %d, want budget %d", got, cpeManualCalls)
	}
	if list.Waiting == 0 || list.LookedUp == 0 {
		t.Fatalf("waiting=%d looked=%d", list.Waiting, list.LookedUp)
	}

	// A server error is stored on the item and retried after an hour.
	fake.mu.Lock()
	fake.fail = true
	fake.mu.Unlock()
	if _, err := st.RefreshCPEProposals(ctx); err == nil {
		t.Fatal("502 not reported")
	}
	var errs int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM cpe_proposals WHERE status='error'`).Scan(&errs); err != nil || errs != 1 {
		t.Fatalf("error rows = %d %v", errs, err)
	}
}
