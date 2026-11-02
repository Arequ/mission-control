package store

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
)

func TestSLAUsesTheTighterClock(t *testing.T) {
	s := model.VulnerabilitySettings{
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14,
	}
	if slaDays(s, "critical", true) != 7 {
		t.Fatalf("critical kev %d", slaDays(s, "critical", true))
	}
	if slaDays(s, "medium", true) != 14 || slaDays(s, "low", false) != 90 || slaDays(s, "high", true) != 14 {
		t.Fatalf("medium %d low %d high %d", slaDays(s, "medium", true), slaDays(s, "low", false), slaDays(s, "high", true))
	}
}

func TestStaleInventoryDoesNotAutoResolve(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	clk := &clock.Manual{}
	clk.Set(time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC))
	st.SetClock(clk)
	old := clk.Now().Add(-48 * time.Hour)
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform, last_seen_at)
		VALUES ('d-stale','h','S','stale','u','15.1','24B83','darwin',$1)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO device_apps (device_id, name, path, bundle_id, version)
		VALUES ('d-stale','Google Chrome','/Applications/Google Chrome.app','com.google.Chrome','127.0.6533.99')`); err != nil {
		t.Fatal(err)
	}
	if err := st.insertFixture(ctx, chromeRecord(t), clk.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	if mustIssue(t, st, "CVE-2024-11395").Status == "" {
		t.Fatal("missing issue")
	}
	if _, err := st.Pool().Exec(ctx, `DELETE FROM device_apps WHERE device_id='d-stale'`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	issue := mustIssue(t, st, "CVE-2024-11395")
	if issue.Status == "fixed" {
		t.Fatal("stale inventory auto-resolved")
	}
	// A fresh mc_apps snapshot beats an old last_seen. Dropping the app then resolves.
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO device_query_results (device_id, query_name, result_rows, updated_at)
		VALUES ('d-stale','mc_apps','[]'::jsonb,$1)`, clk.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	if mustIssue(t, st, "CVE-2024-11395").Status != "fixed" {
		t.Fatal("fresh mc_apps snapshot should resolve a removed app")
	}
}

func TestNVDMacOSRangeAppliesOnTheSameMajor(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for _, m := range []struct{ id, version string }{
		{"d15", "15.0"},
		{"d14", "14.7.1"},
		{"dfixed", "15.1.1"},
	} {
		if _, err := st.Pool().Exec(ctx, `
			INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform)
			VALUES ($1,$2,$3,$4,$5,$6,'24A335','darwin')`,
			m.id, "h-"+m.id, "S-"+m.id, m.id, "u-"+m.id, m.version); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO vuln_cves (cve_id, description, cvss_score, severity, source, updated_at)
		VALUES ('CVE-2024-55555','sequoia', 8.0, 'high', 'nvd', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO vuln_ranges (cve_id, part, vendor, product, end_excl, source)
		VALUES ('CVE-2024-55555','o','apple','macos','15.1.1','nvd')`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	issue := mustIssue(t, st, "CVE-2024-55555")
	devs := deviceSet(t, st, issue.ID)
	if _, ok := devs["d15"]; !ok {
		t.Fatal("15.0 not matched by the same-major NVD range")
	}
	if _, ok := devs["d14"]; ok {
		t.Fatal("14.7 matched a Sequoia range")
	}
	if _, ok := devs["dfixed"]; ok {
		t.Fatal("15.1.1 is the fix")
	}
}

func TestWindowsPlatformDoesNotMatchMac(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform)
		VALUES ('d','h','S','h','u','15.1','24B83','darwin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO device_apps (device_id, name, path, bundle_id, version)
		VALUES ('d','Google Chrome','/Applications/Google Chrome.app','com.google.Chrome','120.0.0.0')`); err != nil {
		t.Fatal(err)
	}
	plat := vuln.EncodePlatform(vuln.Platform{Vendor: "microsoft", Product: "windows"})
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO vuln_cves (cve_id, description, cvss_score, severity, source, updated_at)
		VALUES ('CVE-2024-66666','windows chrome', 8, 'high', 'nvd', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO vuln_ranges (cve_id, part, vendor, product, end_excl, platform, source)
		VALUES ('CVE-2024-66666','a','google','chrome','999.0.0.0',$1,'nvd')`, plat); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListVulnerabilityIssues(ctx, model.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range list.Issues {
		if issue.CVEID == "CVE-2024-66666" {
			t.Fatal("windows-qualified chrome matched a Mac")
		}
	}
}

func TestEmptyFeedsDoNotWipe(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform)
		VALUES ('d','h','SER','host','uuid','15.1','24B83','darwin')`); err != nil {
		t.Fatal(err)
	}
	if err := st.insertFixture(ctx, chromeRecord(t), now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE vuln_cves SET kev=true, kev_name='kept' WHERE cve_id='CVE-2024-11395'`); err != nil {
		t.Fatal(err)
	}
	if err := st.insertRapid7(ctx, "d", "CVE-2024-11395", "Google Chrome", "1.0", now); err != nil {
		t.Fatal(err)
	}
	kev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer kev.Close()
	r7 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"findings":[]}`))
	}))
	defer r7.Close()
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO source_connectors (id, name, source, mode, base_url, enabled)
		VALUES ('r7','Rapid7','rapid7','api',$1,true)`, r7.URL); err != nil {
		t.Fatal(err)
	}
	p := model.Principal{Kind: "api_token", Name: "admin", Scopes: map[string]bool{"*": true}}
	if _, err := st.UpdateVulnerabilitySettings(ctx, p, model.VulnerabilitySettings{
		NVDEnabled: false, KEVEnabled: true, EPSSEnabled: false, AppleEnabled: false, Rapid7Enabled: true,
		SyncCron: "20 3 * * *", Timezone: "UTC",
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14,
		ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	st.SetVulnerabilityFeeds(vuln.Feeds{HTTP: kev.Client(), KEVURL: kev.URL, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err := st.SyncVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	var kevOn bool
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT kev FROM vuln_cves WHERE cve_id='CVE-2024-11395'`).Scan(&kevOn); err != nil {
		t.Fatal(err)
	}
	if !kevOn {
		t.Fatal("empty KEV catalog cleared known exploited")
	}
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM rapid7_findings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("empty rapid7 response deleted findings")
	}
	var ranges int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM vuln_ranges WHERE cve_id='CVE-2024-11395'`).Scan(&ranges); err != nil {
		t.Fatal(err)
	}
	if ranges == 0 {
		t.Fatal("feed sync deleted ranges")
	}
}

func TestNVDBackfillResumesAndRedactsTheKey(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	const secret = "example-nvd-api-key"
	var starts []string
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("apiKey") != "" || r.Header.Get("apiKey") == "" {
			t.Errorf("key placement header %q query %q", r.Header.Get("apiKey"), r.URL.RawQuery)
		}
		starts = append(starts, r.URL.Query().Get("startIndex"))
		_, _ = w.Write([]byte(`{"totalResults":1000,"vulnerabilities":[{"cve":{"id":"CVE-2024-11395","descriptions":[{"lang":"en","value":"x"}]}}]}`))
	}))
	defer nvd.Close()
	p := model.Principal{Kind: "api_token", Name: "admin", Scopes: map[string]bool{"*": true}}
	if _, err := st.UpdateVulnerabilitySettings(ctx, p, model.VulnerabilitySettings{
		NVDEnabled: true, KEVEnabled: false, EPSSEnabled: false, AppleEnabled: false,
		SyncCron: "20 3 * * *", Timezone: "UTC", NVDAPIKey: secret,
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14,
		ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	st.SetVulnerabilityFeeds(vuln.Feeds{
		HTTP: nvd.Client(), NVDBase: nvd.URL,
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err := st.SyncVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	var cursor string
	if err := st.Pool().QueryRow(ctx, `SELECT nvd_cursor FROM vulnerability_settings WHERE id='default'`).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cursor, "backfill|") {
		t.Fatalf("one tick finished or lost the cursor: %s", cursor)
	}
	first := append([]string(nil), starts...)
	if err := st.SyncVulnerabilities(ctx); err != nil {
		t.Fatal(err)
	}
	if len(starts) <= len(first) {
		t.Fatalf("second tick made no request: %v", starts)
	}
	if starts[len(first)] == "0" {
		t.Fatalf("second tick restarted at 0: first %v then %v", first, starts[len(first):])
	}
	// A failing base that echoes the key must not keep it in the stored error.
	st.SetVulnerabilityFeeds(vuln.Feeds{
		HTTP:    vuln.SafeFeedClient(),
		NVDBase: "http://127.0.0.1:1/" + secret,
		Sleep:   func(context.Context, time.Duration) error { return nil },
	})
	err := st.SyncVulnerabilities(ctx)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("sync error leaked the key: %v", err)
	}
	var stored string
	if err := st.Pool().QueryRow(ctx, `SELECT last_sync_error FROM vulnerability_settings WHERE id='default'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, secret) {
		t.Fatalf("stored error leaked the key: %s", stored)
	}
}

func TestRunRecipeRequiresJobsScopeAndAudits(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	clk := &clock.Manual{}
	clk.Set(time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC))
	st.SetClock(clk)
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform)
		VALUES ('d-zoom','h','S','z','u','15.1','24B83','darwin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO device_apps (device_id, name, path, bundle_id, version)
		VALUES ('d-zoom','Zoom Workplace','/Applications/zoom.us.app','us.zoom.xos','6.0.11')`); err != nil {
		t.Fatal(err)
	}
	for _, rec := range vuln.FixtureRecords() {
		if rec.ID == "CVE-2024-42439" {
			if err := st.insertFixture(ctx, rec, clk.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	admin := model.Principal{Kind: "api_token", Name: "admin", Scopes: map[string]bool{"*": true}}
	if _, err := st.CreateRecipe(ctx, admin, model.Recipe{Identifier: "local.munki.Zoom", Name: "Zoom", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	issue := mustIssue(t, st, "CVE-2024-42439")
	reader := model.Principal{Kind: "api_token", Name: "vuln", Scopes: map[string]bool{"vuln:write": true}}
	if _, err := st.RunVulnerabilityRecipe(ctx, reader, issue.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("vuln:write ran a recipe: %v", err)
	}
	job, err := st.RunVulnerabilityRecipe(ctx, admin, issue.ID)
	if err != nil || job.ID == "" {
		t.Fatal(err)
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM audit_log WHERE action='run_recipe' AND resource_type='vulnerability_issue' AND resource_id=$1`, issue.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("audit rows %d", n)
	}
	opened := issue.OpenedAt
	if _, err := st.Pool().Exec(ctx, `DELETE FROM device_apps WHERE device_id='d-zoom'`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	fixed := mustIssue(t, st, "CVE-2024-42439")
	if fixed.Status != "fixed" {
		t.Fatalf("status %s", fixed.Status)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO device_apps (device_id, name, path, bundle_id, version)
		VALUES ('d-zoom','Zoom Workplace','/Applications/zoom.us.app','us.zoom.xos','6.0.11')`); err != nil {
		t.Fatal(err)
	}
	clk.Advance(48 * time.Hour)
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	again := mustIssue(t, st, "CVE-2024-42439")
	if again.Status != "open" || !again.OpenedAt.Equal(clk.Now()) {
		t.Fatalf("reopen did not reset the SLA clock: %s opened %s want %s", again.Status, again.OpenedAt, clk.Now())
	}
	if !again.OpenedAt.After(opened) {
		t.Fatal("opened_at did not move")
	}
	var audits int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE resource_type='vulnerability_issue' AND action='reopened'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits == 0 {
		t.Fatal("scheduler reopen was not audited")
	}
}

func TestListCountUsesActiveIndex(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform)
		VALUES ('d','h','S','h','u','15.1','24B83','darwin')`); err != nil {
		t.Fatal(err)
	}
	if err := st.insertFixture(ctx, chromeRecord(t), now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO device_apps (device_id, name, path, bundle_id, version)
		VALUES ('d','Google Chrome','/Applications/Google Chrome.app','com.google.Chrome','127.0.6533.99')`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `ANALYZE vuln_findings`); err != nil {
		t.Fatal(err)
	}
	tx, err := st.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DROP INDEX vuln_findings_device_idx`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `
		EXPLAIN SELECT count(*) FROM vuln_findings f
		WHERE f.cve_id='CVE-2024-11395' AND f.software_key='a:google:chrome' AND f.active`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "vuln_findings_active_idx") {
		t.Fatalf("count plan %s", plan.String())
	}
}

func chromeRecord(t *testing.T) vuln.Record {
	t.Helper()
	for _, rec := range vuln.FixtureRecords() {
		if rec.ID == "CVE-2024-11395" {
			return rec
		}
	}
	t.Fatal("fixture missing chrome")
	return vuln.Record{}
}
