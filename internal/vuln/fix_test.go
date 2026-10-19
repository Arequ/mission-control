package vuln

import (
	"net/url"
	"strings"
	"testing"
)

func TestDecidePromoteRunAndOS(t *testing.T) {
	chrome := Decide(DecideInput{
		CVE: "CVE-2024-11395", SoftwareKey: "a:google:chrome", SoftwareName: "Google Chrome",
		Ranges:   []ProductBound{{Part: "a", Vendor: "google", Product: "chrome", Bound: Bound{EndExcl: "131.0.6778.85"}}},
		Installs: []Install{{Version: "131.0.6778.70"}},
		Packages: []CatalogPackage{{Name: "Chrome", Version: "131.0.6778.139", Catalog: "testing"}},
		Recipes:  []RecipeState{{ID: "r1", Name: "Chrome", Enabled: true, Status: "succeeded"}},
	})
	if chrome.Action != "promote" || chrome.CatalogVersion != "131.0.6778.139" || !strings.Contains(chrome.PRURL, "quick_pull=1") || !strings.Contains(chrome.PRBody, "munki/promotion.tf") {
		t.Fatalf("%+v", chrome)
	}
	zoom := Decide(DecideInput{
		CVE: "CVE-2024-42439", SoftwareKey: "a:zoom:workplace_desktop", SoftwareName: "Zoom Workplace",
		Ranges:   []ProductBound{{Part: "a", Vendor: "zoom", Product: "workplace_desktop", Bound: Bound{EndExcl: "6.1.0"}}},
		Installs: []Install{{Version: "6.0.11"}, {Version: "6.2.11.43613"}},
		Packages: []CatalogPackage{{Name: "Zoom", Version: "6.0.2", Catalog: "testing"}},
		Recipes:  []RecipeState{{ID: "r2", Name: "Zoom", Enabled: true, Status: "succeeded"}},
	})
	if zoom.Action != "run_recipe" || zoom.RecipeID != "r2" {
		t.Fatalf("catalog below the fix should run the recipe: %+v", zoom)
	}
	pending := Decide(DecideInput{
		CVE: "CVE-2024-42439", SoftwareKey: "a:zoom:workplace_desktop", SoftwareName: "Zoom",
		Ranges:   []ProductBound{{Bound: Bound{EndExcl: "6.1.0"}, Vendor: "zoom", Product: "workplace_desktop"}},
		Installs: []Install{{Version: "6.0.11"}},
		Recipes:  []RecipeState{{ID: "r2", Name: "Zoom", Enabled: true, Status: "running"}},
	})
	if pending.Action != "recipe_pending" {
		t.Fatal(pending.Action)
	}
	prod := Decide(DecideInput{
		CVE: "CVE-2024-11395", SoftwareKey: "a:google:chrome", SoftwareName: "Google Chrome",
		Ranges:   []ProductBound{{Vendor: "google", Product: "chrome", Bound: Bound{EndExcl: "131.0.6778.85"}}},
		Installs: []Install{{Version: "130.0.6723.117"}},
		Packages: []CatalogPackage{{Name: "Chrome", Version: "131.0.6778.139", Catalog: "production"}},
	})
	if prod.Action != "require_install" || !strings.Contains(prod.PRBody, "munki/manifests.tf") || !strings.Contains(prod.PRURL, "quick_pull=1") {
		t.Fatal(prod.Action, prod.PRURL)
	}
	os := Decide(DecideInput{
		CVE: "CVE-2024-44308", SoftwareKey: "o:apple:macos", SoftwareName: "macOS", OS: true,
		Trains:   []Train{{Part: "o", Vendor: "apple", Product: "macos", Major: 15, FixedVersion: "15.1.1", FixedBuild: "24B91", Mode: "independent"}},
		Installs: []Install{{Version: "15.1", Build: "24B83"}},
	})
	if os.Action != "os_update" || os.RequiredOS != "15.1.1 (24B91)" || !strings.Contains(os.PRBody, "munki/os_policy.tf") {
		t.Fatalf("%+v", os)
	}
}

func TestDecideEscapesPackageName(t *testing.T) {
	name := "Chrome & Co\n+100% <script>"
	got := Decide(DecideInput{
		CVE: "CVE-2024-11395", SoftwareKey: "a:google:chrome", SoftwareName: name,
		Ranges:   []ProductBound{{Vendor: "google", Product: "chrome", Bound: Bound{EndExcl: "131.0.6778.85"}}},
		Installs: []Install{{Version: "131.0.6778.70"}},
		Packages: []CatalogPackage{{Name: name, Version: "131.0.6778.139", Catalog: "testing"}},
	})
	if got.Action != "promote" {
		t.Fatal(got.Action)
	}
	u, err := url.Parse(got.PRURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "github.com" || u.Query().Get("quick_pull") != "1" || u.Query().Get("title") != got.PRTitle || u.Query().Get("body") != got.PRBody {
		t.Fatalf("%+v", u)
	}
	if len(u.Query()) != 3 || !strings.Contains(got.PRTitle, name) || !strings.Contains(got.PRBody, "File: munki/promotion.tf") {
		t.Fatalf("title %q\nbody %q", got.PRTitle, got.PRBody)
	}
	if strings.Contains(u.RawQuery, "&title=hacked") || strings.Contains(got.PRURL, "\n") {
		t.Fatal(got.PRURL)
	}
}

func TestESRPackageDoesNotClearNewerTrain(t *testing.T) {
	in := DecideInput{
		CVE: "CVE-2024-9680", SoftwareKey: "a:mozilla:firefox", SoftwareName: "Firefox",
		Trains: []Train{
			{Part: "a", Vendor: "mozilla", Product: "firefox", Major: 131, FixedVersion: "131.0.2", Mode: "backport"},
			{Part: "a", Vendor: "mozilla", Product: "firefox", Major: 128, FixedVersion: "128.3.1", Mode: "backport"},
		},
		Installs: []Install{{Version: "131.0.1"}, {Version: "128.3.0"}},
		Packages: []CatalogPackage{{Name: "Firefox", Version: "128.3.1", Catalog: "testing"}},
		Recipes:  []RecipeState{{ID: "ff", Name: "Firefox", Enabled: true, Status: "succeeded"}},
	}
	got := Decide(in)
	if got.Action != "run_recipe" {
		t.Fatalf("ESR package cleared a 131 install: %+v", got)
	}
	in.Packages = []CatalogPackage{{Name: "Firefox", Version: "132.0.2", Catalog: "testing"}}
	got = Decide(in)
	if got.Action != "promote" {
		t.Fatalf("132 should clear both trains: %+v", got)
	}
}

func TestUnmanagedWithoutRecipe(t *testing.T) {
	got := Decide(DecideInput{
		CVE: "CVE-2024-42439", SoftwareKey: "a:zoom:workplace_desktop", SoftwareName: "Zoom",
		Ranges:   []ProductBound{{Vendor: "zoom", Product: "workplace_desktop", Bound: Bound{EndExcl: "6.1.0"}}},
		Installs: []Install{{Version: "6.0.11"}},
	})
	if got.Action != "unmanaged" || got.PRURL != "" {
		t.Fatalf("%+v", got)
	}
}
