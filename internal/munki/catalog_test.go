package munki

import (
	"fmt"
	"testing"
	"time"

	"howett.net/plist"
)

func TestBuildCatalogRoundTrip(t *testing.T) {
	info := map[string]any{
		"name":                    "Firefox",
		"version":                 "130.0",
		"catalogs":                []any{"testing"},
		"installer_item_location": "Firefox-130.0.pkg",
		"installer_item_size":     int64(2),
		"unattended_install":      true,
	}
	raw, err := MarshalPkginfo(info)
	if err != nil {
		t.Fatal(err)
	}
	body, err := BuildCatalog([][]byte{raw})
	if err != nil {
		t.Fatal(err)
	}
	items, err := ParseCatalog(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items: %d", len(items))
	}
	if items[0]["name"] != "Firefox" || items[0]["version"] != "130.0" {
		t.Fatalf("item: %#v", items[0])
	}
	if fmt.Sprint(items[0]["installer_item_size"]) != "2" {
		t.Fatalf("size %#v", items[0]["installer_item_size"])
	}
	empty, err := BuildCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	items, err = ParseCatalog(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("empty catalog len %d", len(items))
	}
}

func TestParsePkginfoPlistAndHash(t *testing.T) {
	const plistDoc = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>name</key><string>Firefox</string>
<key>version</key><string>130.0</string>
</dict></plist>`
	info, err := ParsePkginfo([]byte(plistDoc))
	if err != nil {
		t.Fatal(err)
	}
	pkg := []byte("fake-pkg")
	ApplyArtifact(info, "Firefox-130.0.pkg", pkg, "testing")
	if info["installer_item_location"] != "Firefox-130.0.pkg" {
		t.Fatal(info["installer_item_location"])
	}
	if info["installer_item_hash"] == "" {
		t.Fatal("missing hash")
	}
	cats := info["catalogs"].([]any)
	if cats[0] != "testing" {
		t.Fatal(cats)
	}
}

func TestSoakDue(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if SoakDue(start, start, 7, false) {
		t.Fatal("7 day soak should not be due immediately")
	}
	if !SoakDue(start.Add(7*24*time.Hour), start, 7, false) {
		t.Fatal("expected due at 7 days")
	}
	if SoakDue(start.Add(30*24*time.Hour), start, 7, true) {
		t.Fatal("manual hold blocks promotion")
	}
	if !SoakDue(start, start, 0, false) {
		t.Fatal("zero soak is due immediately")
	}
}

func TestManifestPlist(t *testing.T) {
	body, err := ManifestPlist([]string{"production"}, nil, []string{"Firefox"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if _, err := plist.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	m := raw.(map[string]any)
	if m["catalogs"].([]any)[0] != "production" {
		t.Fatalf("%#v", m)
	}
}
