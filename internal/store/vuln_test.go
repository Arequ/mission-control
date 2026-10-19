package store

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
)

func TestVulnerabilityMatchingWorkflow(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	clk := &clock.Manual{}
	clk.Set(time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC))
	st.SetClock(clk)
	p := model.Principal{Kind: "api_token", ID: "admin", Name: "admin", Scopes: map[string]bool{"*": true}}

	macs := []struct{ id, serial, host, version, build string }{
		{"d-chrome70", "S-70", "chrome70", "15.1", "24B83"},
		{"d-chrome127", "S-127", "chrome127", "14.8", "23J20"},
		{"d-chrome86", "S-86", "chrome86", "26.1", "25B78"},
		{"d-patched", "S-pat", "patched", "15.1.1", "24B91"},
		{"d-bundle", "S-bun", "bundle", "15.1.1", "24B90"},
		{"d-short", "S-short", "short", "15.7.1", "24G231"},
		{"d-ff131", "S-ff131", "ff131", "15.2", "24C101"},
		{"d-ff128", "S-ff128", "ff128", "14.7", "23H124"},
		{"d-ff130", "S-ff130", "ff130", "15.0", "24A335"},
		{"d-zoom", "S-zoom", "zoom", "15.1", "24B83"},
	}
	for _, m := range macs {
		if _, err := st.Pool().Exec(ctx, `
			INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'darwin')`,
			m.id, "hash-"+m.id, m.serial, m.host, "uuid-"+m.id, m.version, m.build); err != nil {
			t.Fatal(err)
		}
	}
	apps := []struct{ device, name, path, bundle, version, bundleVersion string }{
		{"d-chrome70", "Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "131.0.6778.70", "6778.70"},
		{"d-chrome70", "Google Chrome Helper", "/Applications/Google Chrome Helper.app", "com.google.Chrome.helper", "131.0.6778.70", ""},
		{"d-chrome70", "Chromium", "/Applications/Chromium.app", "org.chromium.Chromium", "131.0.6778.70", ""},
		{"d-chrome127", "Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "127.0.6533.99", ""},
		{"d-chrome86", "Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "131.0.6778.86", ""},
		{"d-patched", "Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "131.0.6778.139", ""},
		{"d-bundle", "Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "", "6778.86"},
		{"d-short", "Google Chrome", "/Applications/Google Chrome.app", "com.google.Chrome", "", "130.0.6723.117"},
		{"d-ff131", "Firefox", "/Applications/Firefox.app", "org.mozilla.firefox", "131.0.1", ""},
		{"d-ff128", "Firefox", "/Applications/Firefox.app", "org.mozilla.firefox", "128.3.1", ""},
		{"d-ff130", "Firefox", "/Applications/Firefox.app", "org.mozilla.firefox", "130.0", ""},
		{"d-zoom", "Zoom Workplace", "/Applications/zoom.us.app", "us.zoom.xos", "6.0.11", ""},
	}
	for _, a := range apps {
		if _, err := st.Pool().Exec(ctx, `
			INSERT INTO device_apps (device_id, name, path, bundle_id, version, bundle_version)
			VALUES ($1,$2,$3,$4,$5,$6)`, a.device, a.name, a.path, a.bundle, a.version, a.bundleVersion); err != nil {
			t.Fatal(err)
		}
	}
	for _, rec := range vuln.FixtureRecords() {
		if err := st.insertFixture(ctx, rec, clk.Now()); err != nil {
			t.Fatal(err)
		}
	}
	pkginfo := func(name, version string) json.RawMessage {
		return json.RawMessage(`{"name":"` + name + `","version":"` + version + `"}`)
	}
	if _, _, err := st.InsertPackage(ctx, p, model.Package{Name: "Chrome", Version: "131.0.6778.139", Filename: "Chrome.pkg", Pkginfo: pkginfo("Chrome", "131.0.6778.139")}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE packages SET catalog='testing' WHERE name='Chrome'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.InsertPackage(ctx, p, model.Package{Name: "Firefox", Version: "128.3.1", Filename: "Firefox.pkg", Pkginfo: pkginfo("Firefox", "128.3.1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE packages SET catalog='testing' WHERE name='Firefox'`); err != nil {
		t.Fatal(err)
	}
	zoomPkg, _, err := st.InsertPackage(ctx, p, model.Package{Name: "Zoom", Version: "6.0.2", Filename: "Zoom.pkg", Pkginfo: pkginfo("Zoom", "6.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE packages SET catalog='testing' WHERE id=$1`, zoomPkg.ID); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Chrome", "Firefox", "Zoom"} {
		if _, err := st.CreateRecipe(ctx, p, model.Recipe{Identifier: "local.munki." + name, Name: name, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}

	list, err := st.ListVulnerabilityIssues(ctx, model.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	byCVE := map[string]model.VulnerabilityIssue{}
	for _, issue := range list.Issues {
		byCVE[issue.CVEID+"|"+issue.SoftwareKey] = issue
	}
	chrome := byCVE["CVE-2024-11395|a:google:chrome"]
	if chrome.ID == "" || chrome.Fix.Action != "promote" || !strings.Contains(chrome.Fix.PRURL, "https://github.com/"+vuln.ConfigRepo+"/compare?") {
		t.Fatalf("chrome promote %+v", chrome.Fix)
	}
	if strings.Contains(chrome.Fix.PRURL, "promotePackage") {
		t.Fatal(chrome.Fix.PRURL)
	}
	devs := deviceSet(t, st, chrome.ID)
	for _, id := range []string{"d-chrome70", "d-chrome127", "d-short"} {
		if _, ok := devs[id]; !ok {
			t.Fatalf("missing %s in %+v", id, devs)
		}
	}
	for _, id := range []string{"d-chrome86", "d-patched", "d-bundle"} {
		if _, ok := devs[id]; ok {
			t.Fatalf("false positive %s", id)
		}
	}
	if _, ok := byCVE["CVE-2024-11110|a:google:chrome"]; !ok {
		t.Fatal("11110 missing")
	}
	c11110 := deviceSet(t, st, byCVE["CVE-2024-11110|a:google:chrome"].ID)
	if _, ok := c11110["d-chrome70"]; ok {
		t.Fatal("patched Mac 131.0.6778.70 flagged for 11110")
	}
	kev := byCVE["CVE-2024-7971|a:google:chrome"]
	if !kev.KEV || len(deviceSet(t, st, kev.ID)) != 1 {
		t.Fatalf("kev devices %+v", deviceSet(t, st, kev.ID))
	}
	if _, ok := deviceSet(t, st, kev.ID)["d-chrome127"]; !ok {
		t.Fatal("127 not on KEV")
	}
	zoom := byCVE["CVE-2024-42439|a:zoom:workplace_desktop"]
	if zoom.Fix.Action != "run_recipe" || zoom.Fix.RecipeName != "Zoom" {
		t.Fatalf("zoom %+v", zoom.Fix)
	}
	ff := byCVE["CVE-2024-9680|a:mozilla:firefox"]
	if ff.Fix.Action != "run_recipe" {
		t.Fatalf("ESR package cleared newer trains: %+v", ff.Fix)
	}
	ffDevs := deviceSet(t, st, ff.ID)
	if _, ok := ffDevs["d-ff128"]; ok {
		t.Fatal("patched ESR flagged")
	}
	if _, ok := ffDevs["d-ff131"]; !ok {
		t.Fatal("131.0.1 not flagged")
	}
	if _, ok := ffDevs["d-ff130"]; !ok {
		t.Fatal("130 not flagged")
	}
	mac := byCVE["CVE-2024-44308|o:apple:macos"]
	macDevs := deviceSet(t, st, mac.ID)
	if mac.Fix.Action != "os_update" || mac.Fix.RequiredOS != "15.1.1 (24B91)" {
		t.Fatalf("os %+v", mac.Fix)
	}
	if _, ok := macDevs["d-chrome70"]; !ok {
		t.Fatal("15.1 not flagged")
	}
	if _, ok := macDevs["d-zoom"]; !ok {
		t.Fatal("second 15.1 not flagged")
	}
	for _, id := range []string{"d-chrome127", "d-chrome86", "d-patched", "d-short", "d-ff131"} {
		if _, ok := macDevs[id]; ok {
			t.Fatalf("macOS false positive %s", id)
		}
	}
	if _, ok := macDevs["d-bundle"]; !ok {
		t.Fatal("15.1.1 build 24B90 should still match")
	}

	// Priority: KEV before a higher device count.
	if list.Issues[0].KEV == false {
		t.Fatalf("first issue is not KEV: %s", list.Issues[0].CVEID)
	}

	updated, err := st.UpdateVulnerabilityIssue(ctx, p, zoom.ID, model.IssueUpdate{
		Status: "risk_accepted", Assignee: "Priya Shah", Revision: zoom.Revision, RiskUntil: timePtr(clk.Now().Add(30 * 24 * time.Hour)),
	})
	if err != nil || updated.Status != "risk_accepted" {
		t.Fatalf("risk %v %+v", err, updated.Status)
	}
	if _, err := st.UpdateVulnerabilityIssue(ctx, p, zoom.ID, model.IssueUpdate{Status: "risk_accepted", Revision: zoom.Revision, RiskUntil: timePtr(clk.Now().Add(time.Hour))}); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale revision err %v", err)
	}
	if _, err := st.Pool().Exec(ctx, `DELETE FROM device_apps WHERE device_id='d-zoom'`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	zoom = mustIssue(t, st, "CVE-2024-42439")
	if zoom.Status != "fixed" || !zoom.AutoResolved || zoom.RiskUntil == nil {
		t.Fatalf("auto resolve %+v", zoom.Status)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO device_apps (device_id, name, path, bundle_id, version) VALUES ('d-zoom','Zoom Workplace','/Applications/zoom.us.app','us.zoom.xos','6.0.11')`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	zoom = mustIssue(t, st, "CVE-2024-42439")
	if zoom.Status != "risk_accepted" {
		t.Fatalf("reopen before expiry: %s", zoom.Status)
	}
	clk.Advance(40 * 24 * time.Hour)
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	zoom = mustIssue(t, st, "CVE-2024-42439")
	if zoom.Status != "open" {
		t.Fatalf("expired risk: %s", zoom.Status)
	}

	if _, err := st.Pool().Exec(ctx, `UPDATE device_apps SET version='131.0.6778.139', bundle_version='' WHERE bundle_id='com.google.Chrome'`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	chrome = mustIssue(t, st, "CVE-2024-11395")
	if chrome.Status != "fixed" {
		t.Fatalf("chrome still %s", chrome.Status)
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE device_apps SET version='130.0.6723.117' WHERE device_id='d-chrome70' AND bundle_id='com.google.Chrome'`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	chrome = mustIssue(t, st, "CVE-2024-11395")
	if chrome.Status != "open" {
		t.Fatalf("regression %s", chrome.Status)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- st.CorrelateVulnerabilities(ctx, true)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	var issues int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM vuln_issues WHERE cve_id='CVE-2024-11395'`).Scan(&issues); err != nil {
		t.Fatal(err)
	}
	if issues != 1 {
		t.Fatalf("duplicate issues %d", issues)
	}

	job, err := st.RunVulnerabilityRecipe(ctx, p, zoom.ID)
	if err != nil || job.RecipeID == "" {
		t.Fatalf("run recipe %v %+v", err, job.ID)
	}
	var catalog, version string
	if err := st.Pool().QueryRow(ctx, `SELECT catalog, version FROM packages WHERE id=$1`, zoomPkg.ID).Scan(&catalog, &version); err != nil {
		t.Fatal(err)
	}
	if catalog != "testing" || version != "6.0.2" {
		t.Fatalf("recipe run mutated the catalog: %s %s", catalog, version)
	}

	saved, err := st.UpdateVulnerabilitySettings(ctx, p, model.VulnerabilitySettings{
		NVDEnabled: true, KEVEnabled: true, EPSSEnabled: true, AppleEnabled: true,
		SyncCron: "20 3 * * *", Timezone: "UTC", NVDAPIKey: "example-nvd-api-key",
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14,
		Overrides: []model.CPEOverride{{BundleID: "com.acme.Browser", Vendor: "acme", Product: "browser"}},
		ManagedBy: "terraform",
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.HasNVDAPIKey == false || saved.NVDAPIKey != "" || len(saved.Overrides) != 1 {
		t.Fatalf("settings leaked or dropped the key: %+v", saved)
	}
	again, err := st.GetVulnerabilitySettings(ctx)
	if err != nil || again.NVDAPIKey != "" || !again.HasNVDAPIKey {
		t.Fatalf("get %+v %v", again.NVDAPIKey, err)
	}
	audit, _, err := st.ListAudit(ctx, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range audit {
		if strings.Contains(string(row.Detail), "example-nvd-api-key") {
			t.Fatalf("audit leaked the key: %s", row.Detail)
		}
	}
	kept, err := st.UpdateVulnerabilitySettings(ctx, p, model.VulnerabilitySettings{
		NVDEnabled: true, KEVEnabled: true, EPSSEnabled: true, AppleEnabled: true,
		SyncCron: "20 3 * * *", Timezone: "UTC",
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14,
		Overrides: saved.Overrides, ManagedBy: "terraform",
	})
	if err != nil || !kept.HasNVDAPIKey {
		t.Fatalf("empty key cleared the stored key: %+v %v", kept.HasNVDAPIKey, err)
	}
	if err := st.SyncVulnerabilitiesDue(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIssueTransitionTable(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	cases := []struct {
		status string
		risk   *time.Time
		active int
		next   string
		action string
	}{
		{"open", nil, 2, "open", ""},
		{"in_progress", nil, 0, "fixed", "auto_resolved"},
		{"fixed", nil, 1, "open", "reopened"},
		{"fixed", &future, 1, "risk_accepted", "reopened"},
		{"fixed", &past, 1, "open", "reopened"},
		{"risk_accepted", &future, 0, "fixed", "auto_resolved"},
		{"risk_accepted", &past, 3, "open", "risk_expired"},
		{"risk_accepted", &future, 3, "risk_accepted", ""},
		{"fixed", nil, 0, "fixed", ""},
	}
	for _, tc := range cases {
		next, action := issueTransition(tc.status, tc.risk, tc.active, now)
		if next != tc.next || action != tc.action {
			t.Fatalf("%s active=%d => %s %s, want %s %s", tc.status, tc.active, next, action, tc.next, tc.action)
		}
	}
}

func TestRapid7DoesNotInventOrReplaceInventory(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	for _, m := range []struct{ id, version string }{
		{"d-old", "127.0.6533.99"},
		{"d-new", "131.0.6778.86"},
	} {
		if _, err := st.Pool().Exec(ctx, `
			INSERT INTO devices (id, node_key_hash, serial, hostname, hardware_uuid, os_version, os_build, platform)
			VALUES ($1,$2,$3,$4,$5,'15.1','24B83','darwin')`,
			m.id, "hash-"+m.id, "S-"+m.id, m.id, "uuid-"+m.id); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool().Exec(ctx, `
			INSERT INTO device_apps (device_id, name, path, bundle_id, version)
			VALUES ($1,'Google Chrome','/Applications/Google Chrome.app','com.google.Chrome',$2)`, m.id, m.version); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for _, rec := range vuln.FixtureRecords() {
		if err := st.insertFixture(ctx, rec, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.insertRapid7(ctx, "d-new", "CVE-2024-11395", "Google Chrome", "131.0.6778.86", now); err != nil {
		t.Fatal(err)
	}
	if err := st.insertRapid7(ctx, "d-old", "CVE-2024-11395", "Google Chrome", "127.0.6533.99", now); err != nil {
		t.Fatal(err)
	}
	if err := st.insertRapid7(ctx, "d-new", "CVE-2099-9999", "Google Chrome", "1.0", now); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	issue := mustIssue(t, st, "CVE-2024-11395")
	got := deviceVersions(t, st, issue.ID)
	if _, ok := got["d-new"]; ok {
		t.Fatalf("rapid7 is off, so a patched Mac must not be flagged: %#v", got)
	}
	if got["d-old"].evidence != "inventory" || got["d-old"].version != "127.0.6533.99" {
		t.Fatalf("inventory finding: %#v", got["d-old"])
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE vulnerability_settings SET rapid7_enabled=true WHERE id='default'`); err != nil {
		t.Fatal(err)
	}
	if err := st.CorrelateVulnerabilities(ctx, true); err != nil {
		t.Fatal(err)
	}
	got = deviceVersions(t, st, issue.ID)
	if got["d-new"].evidence != "rapid7" || got["d-new"].version != "131.0.6778.86" {
		t.Fatalf("disagreement should stay visible: %#v", got["d-new"])
	}
	if got["d-old"].evidence != "both" || got["d-old"].version != "127.0.6533.99" {
		t.Fatalf("rapid7 must not replace the inventory version: %#v", got["d-old"])
	}
	list, err := st.ListVulnerabilityIssues(ctx, model.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range list.Issues {
		if item.CVEID == "CVE-2099-9999" {
			t.Fatal("rapid7 invented a CVE")
		}
	}
}

type deviceFact struct{ evidence, version string }

func deviceVersions(t *testing.T, st *Store, id string) map[string]deviceFact {
	t.Helper()
	detail, err := st.GetVulnerabilityIssue(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]deviceFact{}
	for _, d := range detail.Devices {
		out[d.ID] = deviceFact{evidence: d.Evidence, version: d.Version}
	}
	return out
}

func deviceSet(t *testing.T, st *Store, id string) map[string]string {
	t.Helper()
	detail, err := st.GetVulnerabilityIssue(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range detail.Devices {
		out[d.ID] = d.Evidence
	}
	return out
}

func mustIssue(t *testing.T, st *Store, cve string) model.VulnerabilityIssue {
	t.Helper()
	list, err := st.ListVulnerabilityIssues(context.Background(), model.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range list.Issues {
		if issue.CVEID == cve {
			return issue
		}
	}
	t.Fatalf("missing %s", cve)
	return model.VulnerabilityIssue{}
}

func timePtr(t time.Time) *time.Time { return &t }
