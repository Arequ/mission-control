package vuln

import "testing"

func TestBounds(t *testing.T) {
	chrome := Bound{EndExcl: "131.0.6778.85"}
	cases := []struct {
		ver  string
		want bool
		comp bool
	}{
		{"131.0.6778.70", true, true},
		{"130.0.6723.117", true, true},
		{"131.0.6778.85", false, true},
		{"131.0.6778.86", false, true},
		{"6778.86", false, false},
		{"", false, false},
		{"*", false, false},
	}
	for _, tc := range cases {
		got, comp := chrome.Affected(tc.ver)
		if got != tc.want || comp != tc.comp {
			t.Errorf("%s affected=%v comparable=%v, want %v %v", tc.ver, got, comp, tc.want, tc.comp)
		}
	}
	incl := Bound{EndIncl: "6.0.11", StartIncl: "6.0.0"}
	if ok, _ := incl.Affected("6.0.11"); !ok {
		t.Fatal("end including should include the bound")
	}
	if ok, _ := incl.Affected("6.0.0"); !ok {
		t.Fatal("start including should include the bound")
	}
	excl := Bound{StartExcl: "6.0.0", EndExcl: "6.1.0"}
	if ok, comp := excl.Affected("6.0.0"); ok || !comp {
		t.Fatalf("start excluding matched 6.0.0 (%v %v)", ok, comp)
	}
	if ok, _ := excl.Affected("6.0.11"); !ok {
		t.Fatal("6.0.11 should be inside")
	}
	if ok, comp := (Bound{}).Affected("1.2.3"); ok || !comp {
		t.Fatalf("unbounded range matched (%v %v)", ok, comp)
	}
	exact := Bound{Exact: "16.90"}
	if ok, _ := exact.Affected("16.90"); !ok {
		t.Fatal("exact")
	}
	if ok, _ := exact.Affected("16.89"); ok {
		t.Fatal("exact should not match a neighbor")
	}
}

func TestTrainsMacOSAndFirefox(t *testing.T) {
	mac := []Train{{
		Part: "o", Vendor: "apple", Product: "macos", Major: 15,
		FixedVersion: "15.1.1", FixedBuild: "24B91", Mode: "independent",
	}}
	assertAffected(t, "15.1", "", mac, true)
	assertAffected(t, "15.0", "24A335", mac, true)
	assertAffected(t, "15.1.1", "24B91", mac, false)
	assertAffected(t, "15.1.1", "24B83", mac, true)
	assertAffected(t, "15.1.1", "24B92", mac, false)
	assertAffected(t, "15.7.1", "24G231", mac, false)
	assertAffected(t, "14.8", "23J20", mac, false)
	assertAffected(t, "26.1", "25B78", mac, false)
	assertAffected(t, "13.7.1", "", mac, false)

	ff := []Train{
		{Vendor: "mozilla", Product: "firefox", Major: 131, FixedVersion: "131.0.2", Mode: "backport"},
		{Vendor: "mozilla", Product: "firefox", Major: 128, FixedVersion: "128.3.1", Mode: "backport"},
		{Vendor: "mozilla", Product: "firefox", Major: 115, FixedVersion: "115.16.1", Mode: "backport"},
	}
	assertAffected(t, "131.0.1", "", ff, true)
	assertAffected(t, "131.0.2", "", ff, false)
	assertAffected(t, "132.0.2", "", ff, false)
	assertAffected(t, "130.0", "", ff, true)
	assertAffected(t, "128.3.0", "", ff, true)
	assertAffected(t, "128.3.1", "", ff, false)
	assertAffected(t, "115.16.0", "", ff, true)
	assertAffected(t, "115.16.1", "", ff, false)
}

func assertAffected(t *testing.T, version, build string, trains []Train, want bool) {
	t.Helper()
	got, comp := TrainsAffected(version, build, trains)
	if !comp || got != want {
		t.Errorf("%s build %s affected=%v comparable=%v, want affected %v", version, build, got, comp, want)
	}
}

func TestMatchSoftwareFalsePositives(t *testing.T) {
	if _, ok := MatchSoftware("Google Chrome Helper", "com.google.Chrome.helper", nil); ok {
		t.Fatal("helper bundle matched Chrome")
	}
	if _, ok := MatchSoftware("Google Chrome Helper", "", nil); ok {
		t.Fatal("helper name matched Chrome")
	}
	if _, ok := MatchSoftware("Google Chrome Canary", "com.google.Chrome.canary", nil); ok {
		t.Fatal("canary matched stable Chrome")
	}
	if _, ok := MatchSoftware("Chromium", "org.chromium.Chromium", nil); ok {
		t.Fatal("Chromium matched Chrome")
	}
	if _, ok := MatchSoftware("Firefox Focus", "org.mozilla.ios.Focus", nil); ok {
		t.Fatal("Firefox Focus matched Firefox")
	}
	if _, ok := MatchSoftware("Slackline", "com.example.slackline", nil); ok {
		t.Fatal("Slackline matched Slack")
	}
	if _, ok := MatchSoftware("Safari Technology Preview", "com.apple.SafariTechnologyPreview", nil); ok {
		t.Fatal("Safari Technology Preview matched Safari")
	}
	if _, ok := MatchSoftware("Microsoft Word", "com.microsoft.Word", nil); ok {
		t.Fatal("Word matched a curated product")
	}
	if _, ok := MatchSoftware("", "", nil); ok {
		t.Fatal("empty install matched")
	}
	if _, ok := MatchSoftware("Code", "com.microsoft.VSCode.helper", nil); ok {
		t.Fatal("generic Code name or helper matched VS Code")
	}
}

func TestMatchSoftwareTruePositives(t *testing.T) {
	p, ok := MatchSoftware("Google Chrome", "com.google.Chrome", nil)
	if !ok || p.Vendor != "google" || p.Product != "chrome" {
		t.Fatalf("chrome %+v %v", p, ok)
	}
	p, ok = MatchSoftware("Google Chrome.app", "", nil)
	if !ok || p.Product != "chrome" {
		t.Fatal("name with .app suffix")
	}
	p, ok = MatchSoftware("", "COM.GOOGLE.CHROME", nil)
	if !ok || p.Product != "chrome" {
		t.Fatal("bundle only")
	}
	p, ok = MatchSoftware("Firefox", "org.mozilla.firefox", nil)
	if !ok || p.Vendor != "mozilla" || p.Product != "firefox" {
		t.Fatalf("firefox %+v", p)
	}
	p, ok = MatchSoftware("Zoom Workplace", "us.zoom.xos", nil)
	if !ok || p.Product != "workplace_desktop" {
		t.Fatalf("zoom %+v", p)
	}
	p, ok = MatchSoftware("Acme Browser", "com.acme.Browser", []Override{{
		BundleID: "com.acme.Browser", Vendor: "google", Product: "chrome",
	}})
	if !ok || p.Product != "chrome" {
		t.Fatal("override did not win")
	}
	// An override may intentionally map a helper. The curated reject does not apply.
	p, ok = MatchSoftware("Google Chrome Helper", "com.google.Chrome.helper", []Override{{
		BundleID: "com.google.Chrome.helper", Vendor: "google", Product: "chrome",
	}})
	if !ok || p.Product != "chrome" {
		t.Fatal("explicit helper override was ignored")
	}
}

func TestChooseVersionPrefersShort(t *testing.T) {
	bounds := []string{"131.0.6778.85"}
	got, ok := ChooseVersion("131.0.6778.70", "6778.70", "short", bounds)
	if !ok || got != "131.0.6778.70" {
		t.Fatalf("short version %q %v", got, ok)
	}
	got, ok = ChooseVersion("", "6778.86", "short", bounds)
	if ok {
		t.Fatalf("bare bundle version was treated as comparable: %q", got)
	}
	got, ok = ChooseVersion("", "130.0.6723.117", "short", bounds)
	if !ok || got != "130.0.6723.117" {
		t.Fatalf("bundle fallback %q %v", got, ok)
	}
}

func TestParseCPE(t *testing.T) {
	part, vendor, product, version, ok := ParseCPE("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*")
	if !ok || part != "a" || vendor != "google" || product != "chrome" || version != "*" {
		t.Fatalf("wildcard cpe %s %s %s %s %v", part, vendor, product, version, ok)
	}
	_, _, _, version, ok = ParseCPE(`cpe:2.3:a:vendor:pro\:duct:1.2:*:*:*:*:*:*:*`)
	if !ok || version != "1.2" {
		t.Fatalf("escaped colon: version %q ok %v", version, ok)
	}
	if _, _, _, _, ok := ParseCPE("not-a-cpe"); ok {
		t.Fatal("accepted garbage")
	}
}
