package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReviewVersionEdges(t *testing.T) {
	eq := [][2]string{
		{"6.1.0 (12345)", "6.1.0"},
		{"6.1.0(12345)", "6.1.0"},
		{"128.3.1esr", "128.3.1"},
		{"128.3.1 ESR", "128.3.1"},
		{"01.02.003", "1.2.3"},
		{"16.0.14326.20404", "16.0.14326.20404"},
		{"10.0.22631.01", "10.0.22631.1"},
	}
	for _, pair := range eq {
		c, ok := Compare(pair[0], pair[1])
		if !ok || c != 0 {
			t.Errorf("%s vs %s = %d ok=%v, want equal", pair[0], pair[1], c, ok)
		}
	}
	less := [][2]string{
		{"131.0b1", "131.0"},
		{"131.0.0b1", "131.0"},
		{"1.0.0rc1", "1.0.0"},
		{"1.0.0rc.1", "1.0.0"},
		{"1.0beta2", "1.0"},
		{"1.0.0-b1", "1.0.0"},
		{"6.0.11 (99999)", "6.1.0"},
		{"6.1.0 (12345)", "6.1.0 (12346)"},
		{"16.0.14326.20404", "16.0.14326.20405"},
		{"128.3.0esr", "128.3.1"},
	}
	for _, pair := range less {
		c, ok := Compare(pair[0], pair[1])
		if !ok || c >= 0 {
			t.Errorf("%s should be older than %s, got %d ok=%v", pair[0], pair[1], c, ok)
		}
	}
	// OpenSSH patch letters and Apple builds stay newer than the bare number.
	newer := [][2]string{{"9.9p1", "9.9"}, {"24B100", "24B99"}, {"24C50", "24B91"}}
	for _, pair := range newer {
		c, ok := Compare(pair[0], pair[1])
		if !ok || c <= 0 {
			t.Errorf("%s should be newer than %s, got %d ok=%v", pair[0], pair[1], c, ok)
		}
	}
	incl := Bound{EndIncl: "6.1.0"}
	if ok, comp := incl.Affected("6.1.0 (12345)"); !ok || !comp {
		t.Fatalf("zoom build string %v %v should sit on the inclusive fix", ok, comp)
	}
	excl := Bound{EndExcl: "6.1.0"}
	if ok, comp := excl.Affected("6.1.0 (12345)"); ok || !comp {
		t.Fatalf("6.1.0 (12345) inside end-excluding 6.1.0: %v %v", ok, comp)
	}
	if ok, _ := excl.Affected("6.0.2 (51234)"); !ok {
		t.Fatal("zoom build before the fix should match")
	}
}

func TestReviewChooseVersionSource(t *testing.T) {
	bounds := []string{"6778.139"}
	got, ok := ChooseVersion("131.0.6778.70", "6778.70", "bundle", bounds)
	if !ok || got != "6778.70" {
		t.Fatalf("bundle source = %q ok=%v", got, ok)
	}
	got, ok = ChooseVersion("131.0.6778.70", "6778.70", "short", []string{"131.0.6778.85"})
	if !ok || got != "131.0.6778.70" {
		t.Fatalf("short source = %q ok=%v", got, ok)
	}
}

func TestReviewBundleDoesNotInheritName(t *testing.T) {
	if _, ok := MatchSoftware("Google Chrome", "com.other.FakeChrome", nil); ok {
		t.Fatal("different vendor bundle inherited the Chrome name")
	}
	if _, ok := MatchSoftware("Slack", "com.electron.slack-clone", nil); ok {
		t.Fatal("electron app inherited Slack by name")
	}
	if _, ok := MatchSoftware("Chromium", "org.chromium.Chromium", nil); ok {
		t.Fatal("Chromium matched a curated product")
	}
	p, ok := MatchSoftware("1Password", "com.agilebits.onepassword7", nil)
	if !ok || p.Product != "1password" {
		t.Fatalf("legacy 1Password bundle %+v %v", p, ok)
	}
	p, ok = MatchSoftware("Firefox ESR", "org.mozilla.firefox", nil)
	if !ok || p.Product != "firefox" {
		t.Fatalf("firefox esr %+v", p)
	}
	if _, ok := MatchSoftware("Google Chrome", "", nil); !ok {
		t.Fatal("name-only chrome should still match")
	}
}

func TestReviewWindowsNodeDoesNotMatchMac(t *testing.T) {
	body := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-9001","configurations":[
		{"operator":"AND","nodes":[
			{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"120.0.6099.109"}]},
			{"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}
		]},
		{"operator":"AND","nodes":[
			{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"120.0.6099.129"}]},
			{"operator":"OR","cpeMatch":[
				{"vulnerable":false,"criteria":"cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*","versionEndExcluding":"15.0"},
				{"vulnerable":false,"criteria":"cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*","versionEndExcluding":"15.0"}
			]}
		]}
	]}}]}`)
	page, err := ParseNVD(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.CVEs) != 1 {
		t.Fatal(page)
	}
	if !Applies(page.CVEs[0].Ranges, "119.0.0.0", "14.5") {
		t.Fatal("chrome on macOS 14.5 should match the mac-qualified node")
	}
	if Applies(page.CVEs[0].Ranges, "119.0.0.0", "15.1") {
		t.Fatal("macOS 15.1 is outside the macOS platform bound")
	}
	winOnly := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-9003","configurations":[
		{"operator":"AND","nodes":[
			{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"120.0.6099.109"}]},
			{"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}
		]}
	]}}]}`)
	win, err := ParseNVD(winOnly)
	if err != nil {
		t.Fatal(err)
	}
	if Applies(win.CVEs[0].Ranges, "119.0.0.0", "14.5") {
		t.Fatal("windows-only AND node matched macOS")
	}
	target := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-9002","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:windows:*:*","versionEndExcluding":"120.0"}
	]}]}]}}]}`)
	page, err = ParseNVD(target)
	if err != nil {
		t.Fatal(err)
	}
	if Applies(page.CVEs[0].Ranges, "119.0", "14.5") {
		t.Fatal("target_sw=windows matched a Mac")
	}
}

func TestReviewMacOSRangesSameMajor(t *testing.T) {
	same := []ProductBound{{Part: "o", Vendor: "apple", Product: "macos", Bound: Bound{EndExcl: "15.1.1"}}}
	if !AffectedInstall("15.0", "24A335", "15.0", same, nil) {
		t.Fatal("sequoia inside an NVD same-major range should match when no SOFA train exists")
	}
	if AffectedInstall("15.1.1", "24B91", "15.1.1", same, nil) {
		t.Fatal("fixed 15.1.1 matched")
	}
	if AffectedInstall("14.7.1", "23H124", "14.7.1", same, nil) {
		t.Fatal("sonoma matched a sequoia-only NVD range")
	}
	cross := []ProductBound{{Part: "o", Vendor: "apple", Product: "macos", Bound: Bound{StartIncl: "13.0", EndExcl: "15.1.1"}}}
	if AffectedInstall("14.7", "", "14.7", cross, nil) || AffectedInstall("15.0", "", "15.0", cross, nil) {
		t.Fatal("cross-major NVD macOS range was applied")
	}
	trains := []Train{{Part: "o", Vendor: "apple", Product: "macos", Major: 15, FixedVersion: "15.1.1", FixedBuild: "24B91", Mode: "independent"}}
	if AffectedInstall("15.0", "24A335", "15.0", same, trains) != true {
		t.Fatal("train should still flag 15.0")
	}
	if AffectedInstall("14.7", "", "14.7", same, trains) {
		t.Fatal("train leaked into sonoma")
	}
}

func TestReviewRSRBuild(t *testing.T) {
	trains := []Train{{
		Part: "o", Vendor: "apple", Product: "macos", Major: 13,
		FixedVersion: "13.3.1 (a)", FixedBuild: "22E772610a", Mode: "independent",
	}}
	if !AffectedInstall("13.3.1", "22E261", "13.3.1", nil, trains) {
		t.Fatal("base ventura build should be behind the RSR")
	}
	if AffectedInstall("13.3.1", "22E772610a", "13.3.1", nil, trains) {
		t.Fatal("device on the RSR build was still vulnerable")
	}
	if AffectedInstall("13.3.1 (a)", "", "13.3.1 (a)", nil, trains) {
		t.Fatal("version string that already names the RSR was vulnerable")
	}
	if AffectedInstall("13.4", "22F66", "13.4", nil, trains) {
		t.Fatal("later minor on the same major was vulnerable")
	}
	if AffectedInstall("14.0", "23A344", "14.0", nil, trains) {
		t.Fatal("sonoma matched a ventura RSR")
	}
}

func TestReviewNVDBackoffFloorAndWindow(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	var slept []time.Duration
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	client := &NVDClient{
		Base: srv.URL, HTTP: srv.Client(), Retries: 4,
		Now: func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			now = now.Add(d)
			return nil
		},
	}
	if _, err := client.Fetch(context.Background(), NVDQuery{Part: "a", Vendor: "google", Product: "chrome"}); err != nil {
		t.Fatal(err)
	}
	for _, d := range slept {
		if d > 0 && d < 6500*time.Millisecond {
			t.Fatalf("unkeyed retry slept %s, want at least 6.5s", d)
		}
	}
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(400 * 24 * time.Hour)
	for _, w := range SplitWindows(start, end, nvdWindow) {
		if w[1].Sub(w[0]) > 120*24*time.Hour {
			t.Fatalf("window %s exceeds 120 days", w[1].Sub(w[0]))
		}
	}
}

func TestReviewTotalResultsShrinkRestarts(t *testing.T) {
	var calls []int
	totals := []int{500, 80}
	fetch := func(_ context.Context, q NVDQuery) (NVDPage, error) {
		calls = append(calls, q.Start)
		total := 500
		if len(calls) > 1 {
			total = totals[1]
		}
		if q.Start == 0 {
			return NVDPage{Total: total, Start: 0, CVEs: []Record{{ID: "CVE-2024-1"}}}, nil
		}
		return NVDPage{Total: total, Start: q.Start, CVEs: []Record{{ID: "CVE-2024-2"}}}, nil
	}
	got, err := SyncNVD(context.Background(), []Product{{Part: "a", Vendor: "google", Product: "chrome"}}, "", time.Now(), 4, 1, fetch)
	if err != nil {
		t.Fatal(err)
	}
	restarted := false
	for i := 1; i < len(calls); i++ {
		if calls[i] == 0 && calls[i-1] != 0 {
			restarted = true
		}
	}
	if !restarted {
		t.Fatalf("totalResults shrink did not restart the product: starts %v cursor %s done %v", calls, got.Cursor, got.Done)
	}
}
