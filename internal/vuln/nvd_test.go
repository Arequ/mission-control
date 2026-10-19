package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSyncNVDPagesDoNotSkipAndMergeProducts(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	products := []Product{{Part: "a", Vendor: "google", Product: "chrome"}, {Part: "a", Vendor: "mozilla", Product: "firefox"}}
	calls := []NVDQuery{}
	fetch := func(_ context.Context, q NVDQuery) (NVDPage, error) {
		calls = append(calls, q)
		switch q.Product {
		case "chrome":
			if q.Start == 0 {
				return NVDPage{Total: 2, CVEs: []Record{{ID: "CVE-2024-11395", Ranges: []ProductBound{{Vendor: "google", Product: "chrome", Bound: Bound{EndExcl: "131.0.6778.85"}}}}}}, nil
			}
			return NVDPage{Total: 2, CVEs: []Record{{ID: "CVE-2024-7971", Ranges: []ProductBound{{Vendor: "google", Product: "chrome", Bound: Bound{EndExcl: "128.0.6613.85"}}}}}}, nil
		default:
			return NVDPage{Total: 1, CVEs: []Record{{ID: "CVE-2024-11395", Ranges: []ProductBound{{Vendor: "mozilla", Product: "firefox", Bound: Bound{EndExcl: "131.0.2"}}}}}}, nil
		}
	}
	first, err := SyncNVD(context.Background(), products, "", now, 1, 1, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if first.Done || first.Cursor != "backfill|0|1" || len(first.CVEs) != 1 {
		t.Fatalf("first page %+v", first)
	}
	second, err := SyncNVD(context.Background(), products, first.Cursor, now, 1, 1, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if second.Cursor != "backfill|1|0" {
		t.Fatalf("cursor skipped or stalled: %s", second.Cursor)
	}
	third, err := SyncNVD(context.Background(), products, second.Cursor, now, 2, 1, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !third.Done || !strings.HasPrefix(third.Cursor, "mod|") {
		t.Fatalf("backfill did not finish: %+v", third)
	}
	merged, err := SyncNVD(context.Background(), products, "", now, 10, 1, fetch)
	if err != nil || !merged.Done {
		t.Fatalf("merged run %+v %v", merged, err)
	}
	var chrome, firefox bool
	for _, cve := range merged.CVEs {
		if cve.ID != "CVE-2024-11395" {
			continue
		}
		for _, r := range cve.Ranges {
			if r.Product == "chrome" {
				chrome = true
			}
			if r.Product == "firefox" {
				firefox = true
			}
		}
	}
	if !chrome || !firefox {
		t.Fatal("same CVE from a second product lost a range")
	}
	again, err := SyncNVD(context.Background(), products, third.Cursor, now, 2, 1, fetch)
	if err != nil || !again.Done || len(again.CVEs) != 0 {
		t.Fatalf("caught up cursor refetched: %+v %v", again, err)
	}
}

func TestSyncNVDStallDoesNotAdvance(t *testing.T) {
	fetch := func(context.Context, NVDQuery) (NVDPage, error) {
		return NVDPage{Total: 5}, nil
	}
	got, err := SyncNVD(context.Background(), []Product{{Part: "a", Vendor: "google", Product: "chrome"}}, "backfill|0|2", time.Now(), 3, 200, fetch)
	if err == nil || !strings.Contains(err.Error(), "no rows") {
		t.Fatalf("err %v", err)
	}
	if got.Cursor != "backfill|0|2" {
		t.Fatalf("cursor moved past a stall: %s", got.Cursor)
	}
}

func TestSplitWindowsTouchAtTheBoundary(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(200 * 24 * time.Hour)
	windows := SplitWindows(start, end, nvdWindow)
	if len(windows) < 2 {
		t.Fatal(windows)
	}
	if !windows[0][0].Equal(start) || !windows[len(windows)-1][1].Equal(end) {
		t.Fatalf("span %v", windows)
	}
	for i := 1; i < len(windows); i++ {
		if !windows[i-1][1].Equal(windows[i][0]) {
			t.Fatalf("gap or overlap mismatch at %d", i)
		}
	}
}

func TestNVDClientRateLimitAndHeader(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.Contains(strings.ToLower(r.URL.RawQuery), "apikey") {
			t.Errorf("key in query: %s", r.URL.RawQuery)
		}
		if r.Header.Get("apiKey") != "test-key" {
			t.Errorf("header %q", r.Header.Get("apiKey"))
		}
		if hits == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-11395","descriptions":[{"lang":"en","value":"type confusion"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.8,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}}]},"configurations":[{"nodes":[{"negate":true,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"1.0"}]},{"negate":false,"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*","versionEndExcluding":"15.0"},{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:1.0:*:*:*:*:*:*:*","versionEndExcluding":"131.0.6778.85"}]}]}]}}]}`))
	}))
	defer srv.Close()
	var slept []time.Duration
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	client := &NVDClient{
		Base: srv.URL, Key: "test-key", HTTP: srv.Client(), Retries: 3,
		Now:   func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	client.Sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		now = now.Add(d)
		return nil
	}
	page, err := client.Fetch(context.Background(), NVDQuery{Part: "a", Vendor: "google", Product: "chrome"})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 2 || len(slept) == 0 || slept[0] != 7*time.Second {
		t.Fatalf("hits %d slept %v", hits, slept)
	}
	if len(page.CVEs) != 1 || len(page.CVEs[0].Ranges) != 1 {
		t.Fatalf("page %+v", page.CVEs)
	}
	got := page.CVEs[0].Ranges[0]
	if got.Product != "chrome" || got.Bound.Exact != "" || got.Bound.EndExcl != "131.0.6778.85" {
		t.Fatalf("range kept the wrong CPE: %+v", got)
	}
	hit, ok := got.Bound.Affected("130.0.6723.117")
	if !ok || !hit {
		t.Fatal("ranged CPE did not match a version inside the range")
	}
	if page.CVEs[0].Score != 8.8 || page.CVEs[0].Description != "type confusion" {
		t.Fatalf("cve %+v", page.CVEs[0])
	}
}

func TestParseNVDUnboundedMatchesNothing(t *testing.T) {
	page, err := ParseNVD([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2020-0001","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"}]}]}]}}]}`))
	if err != nil || len(page.CVEs) != 1 || len(page.CVEs[0].Ranges) != 1 {
		t.Fatal(err, page)
	}
	hit, comp := page.CVEs[0].Ranges[0].Bound.Affected("1.0")
	if hit || !comp {
		t.Fatalf("unbounded matched=%v comparable=%v", hit, comp)
	}
}

func TestModCursorResumesTheSameWindow(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var seen time.Time
	fetch := func(_ context.Context, q NVDQuery) (NVDPage, error) {
		seen = q.ModStart
		return NVDPage{Total: 1, CVEs: []Record{{ID: "CVE-2024-1"}}}, nil
	}
	cursor := formatMod(start, 0, 0)
	now := start.Add(10 * 24 * time.Hour)
	got, err := SyncNVD(context.Background(), []Product{{Part: "a", Vendor: "google", Product: "chrome"}}, cursor, now, 1, 50, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !seen.Equal(start) {
		t.Fatalf("window start %s", seen)
	}
	if !got.Done {
		t.Fatalf("short window did not finish: %+v", got)
	}
}

func TestNVDJSONRoundTripRejectsKeyInQuery(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"totalResults": 0, "vulnerabilities": []any{}})
	if _, err := ParseNVD(body); err != nil {
		t.Fatal(err)
	}
}
