package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// cpeBody builds a CPE API 2.0 response from CPE names and titles.
func cpeBody(t *testing.T, items ...[2]string) []byte {
	t.Helper()
	type title struct {
		Title string `json:"title"`
		Lang  string `json:"lang"`
	}
	type cpe struct {
		Deprecated bool    `json:"deprecated"`
		CPEName    string  `json:"cpeName"`
		CPENameID  string  `json:"cpeNameId"`
		Titles     []title `json:"titles"`
	}
	var products []map[string]cpe
	for i, it := range items {
		products = append(products, map[string]cpe{"cpe": {
			CPEName: it[0], CPENameID: "id-" + string(rune('a'+i)),
			Titles: []title{{Title: it[1] + " (fr)", Lang: "fr"}, {Title: it[1], Lang: "en"}},
		}})
	}
	b, err := json.Marshal(map[string]any{
		"resultsPerPage": len(products), "startIndex": 0, "totalResults": len(products),
		"format": "NVD_CPE", "version": "2.0", "products": products,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseCPEDictionary(t *testing.T) {
	body := []byte(`{"resultsPerPage":3,"startIndex":0,"totalResults":40,"products":[
	 {"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:slack:slack:4.41.105:*:*:*:*:macos:*:*","cpeNameId":"A",
	   "titles":[{"title":"Slack 4.41.105 pour macOS","lang":"fr"},{"title":"Slack 4.41.105 for macOS","lang":"en"}]}},
	 {"cpe":{"deprecated":true,"cpeName":"cpe:2.3:a:slack:slack_desktop:1.0:*:*:*:*:*:*:*","cpeNameId":"B","titles":[]}},
	 {"cpe":{"deprecated":false,"cpeName":"not a cpe","cpeNameId":"C","titles":[]}},
	 {"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:acme:a\\:b:1:*:*:*:*:*:*:*","cpeNameId":"D","titles":[{"title":"x","lang":"en"}]}}
	]}`)
	page, err := ParseCPEDictionary(body)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 40 || len(page.Entries) != 3 {
		t.Fatalf("page = %+v", page)
	}
	e := page.Entries[0]
	if e.Vendor != "slack" || e.Product != "slack" || e.Part != "a" || e.TargetSW != "macos" || e.Title != "Slack 4.41.105 for macOS" || e.NameID != "A" {
		t.Fatalf("entry = %+v", e)
	}
	if !page.Entries[1].Deprecated {
		t.Fatal("deprecated flag lost")
	}
	if page.Entries[2].Product != "a:b" {
		t.Fatalf("escaped colon: %+v", page.Entries[2])
	}
	if _, err := ParseCPEDictionary([]byte(`<html>`)); err == nil {
		t.Fatal("html accepted")
	}
}

func entries(t *testing.T, items ...[2]string) []CPEEntry {
	t.Helper()
	page, err := ParseCPEDictionary(cpeBody(t, items...))
	if err != nil {
		t.Fatal(err)
	}
	return page.Entries
}

func TestProposeCPEConfidence(t *testing.T) {
	cases := []struct {
		name    string
		sub     CPESubject
		dict    [][2]string
		want    string
		vendor  string
		product string
	}{
		{
			name: "slack: exact product, developer and bundle agree",
			sub:  CPESubject{Name: "SlackDesktop", DisplayName: "Slack", Developer: "Slack Technologies, Inc.", BundleID: "com.tinyspeck.slackmacgap"},
			dict: [][2]string{
				{"cpe:2.3:a:slack:slack:4.41.105:*:*:*:*:macos:*:*", "Slack 4.41.105 for macOS"},
				{"cpe:2.3:a:slack:slack:4.40.0:*:*:*:*:*:*:*", "Slack 4.40.0"},
				{"cpe:2.3:a:slack:nebula:1.0:*:*:*:*:*:*:*", "Slack Nebula 1.0"},
				{"cpe:2.3:a:slack:slack:4.0:*:*:*:*:android:*:*", "Slack for Android"},
			},
			want: CPEHigh, vendor: "slack", product: "slack",
		},
		{
			name: "cursor: vendor differs from the name, developer confirms it",
			sub:  CPESubject{Name: "Cursor", DisplayName: "Cursor", Developer: "Anysphere Inc.", BundleID: "com.todesktop.230313mzl4w4u92"},
			dict: [][2]string{
				{"cpe:2.3:a:anysphere:cursor:0.45.0:*:*:*:*:*:*:*", "Anysphere Cursor 0.45.0"},
				{"cpe:2.3:a:wpplugins:cursor_trail:1.0:*:*:*:*:wordpress:*:*", "Cursor Trail plugin for WordPress"},
			},
			want: CPEHigh, vendor: "anysphere", product: "cursor",
		},
		{
			name: "granola: single exact match",
			sub:  CPESubject{Name: "Granola", Developer: "Granola Inc", BundleID: "com.granola.app"},
			dict: [][2]string{{"cpe:2.3:a:granola:granola:5.1.0:*:*:*:*:macos:*:*", "Granola 5.1.0 for macOS"}},
			want: CPEHigh, vendor: "granola", product: "granola",
		},
		{
			name: "zoom: one vendor, several products named zoom",
			sub:  CPESubject{Name: "ZoomUS", DisplayName: "Zoom", Developer: "Zoom Video Communications, Inc.", BundleID: "us.zoom.xos"},
			dict: [][2]string{
				{"cpe:2.3:a:zoom:zoom:5.0.0:*:*:*:*:macos:*:*", "Zoom 5.0.0 for macOS"},
				{"cpe:2.3:a:zoom:zoom_client:5.1:*:*:*:*:*:*:*", "Zoom Client 5.1"},
				{"cpe:2.3:a:zoom:workplace_desktop:6.0:*:*:*:*:macos:*:*", "Zoom Workplace Desktop 6.0"},
				{"cpe:2.3:a:zoom:meetings:5.2:*:*:*:*:*:*:*", "Zoom Meetings 5.2"},
			},
			want: CPEMedium, vendor: "zoom", product: "zoom",
		},
		{
			name: "two vendors ship a product with the same name",
			sub:  CPESubject{Name: "Notes"},
			dict: [][2]string{
				{"cpe:2.3:a:alpha:notes:1:*:*:*:*:*:*:*", "Alpha Notes 1"},
				{"cpe:2.3:a:beta:notes:2:*:*:*:*:*:*:*", "Beta Notes 2"},
			},
			want: CPEMedium,
		},
		{
			name: "exact name without corroboration is not high",
			sub:  CPESubject{Name: "Granola"},
			dict: [][2]string{{"cpe:2.3:a:granola:granola:5.1.0:*:*:*:*:*:*:*", "Granola 5.1.0"}},
			want: CPEMedium, vendor: "granola", product: "granola",
		},
		{
			name: "only partial products",
			sub:  CPESubject{Name: "Figma", Developer: "Figma, Inc."},
			dict: [][2]string{{"cpe:2.3:a:figma:figma_desktop:116:*:*:*:*:*:*:*", "Figma Desktop 116"}},
			want: CPELow, vendor: "figma", product: "figma_desktop",
		},
		{
			name: "other platforms and title-only hits are dropped",
			sub:  CPESubject{Name: "Granola"},
			dict: [][2]string{
				{"cpe:2.3:a:granola:granola:1:*:*:*:*:iphone_os:*:*", "Granola for iOS"},
				{"cpe:2.3:a:acme:recipe_box:1:*:*:*:*:*:*:*", "Recipe Box granola edition"},
			},
			want: CPENone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ProposeCPE(tc.sub, entries(t, tc.dict...))
			if got.Confidence != tc.want {
				t.Fatalf("confidence = %s, want %s; %+v", got.Confidence, tc.want, got)
			}
			if tc.vendor != "" && (got.Vendor != tc.vendor || got.Product != tc.product) {
				t.Fatalf("proposal = %s:%s, want %s:%s", got.Vendor, got.Product, tc.vendor, tc.product)
			}
			if tc.want != CPENone && len(got.Evidence) == 0 {
				t.Fatal("no evidence")
			}
			if got.Candidates == nil {
				t.Fatal("candidates must be a list")
			}
		})
	}
}

func TestProposeCPEIgnoresDeprecated(t *testing.T) {
	es := entries(t, [2]string{"cpe:2.3:a:granola:granola:1:*:*:*:*:*:*:*", "Granola 1"})
	es[0].Deprecated = true
	if got := ProposeCPE(CPESubject{Name: "Granola"}, es); got.Confidence != CPENone {
		t.Fatalf("deprecated CPE proposed: %+v", got)
	}
}

func TestCPEKeywords(t *testing.T) {
	got := CPESubject{Name: "GoogleChrome", DisplayName: "Google Chrome"}.Keywords()
	if len(got) != 1 || got[0] != "google chrome" {
		t.Fatalf("keywords = %q", got)
	}
	got = CPESubject{Name: "VSCode", DisplayName: "Visual Studio Code.app"}.Keywords()
	if len(got) != 2 || got[0] != "visual studio code" || got[1] != "vs code" {
		t.Fatalf("keywords = %q", got)
	}
	if got := (CPESubject{Name: "  "}).Keywords(); len(got) != 0 {
		t.Fatalf("blank name keywords = %q", got)
	}
}

func TestOverrideHCLEscapes(t *testing.T) {
	got := OverrideHCL(`Evil"${file("/etc/passwd")}`, "com.acme.app", "acme", "app")
	if strings.Contains(got, `"${`) || !strings.Contains(got, `$${file(\"/etc/passwd\")}`) {
		t.Fatalf("interpolation not escaped:\n%s", got)
	}
	want := "cpe_override {\n  name    = \"Cursor\"\n  vendor  = \"anysphere\"\n  product = \"cursor\"\n}\n"
	if got := OverrideHCL("Cursor", "", "anysphere", "cursor"); got != want {
		t.Fatalf("hcl:\n%s\nwant:\n%s", got, want)
	}
	if got := OverrideHCL("Cursor", "com.todesktop.x", "anysphere", "cursor"); !strings.Contains(got, "bundle_id = \"com.todesktop.x\"") {
		t.Fatalf("bundle block missing:\n%s", got)
	}
}

func TestFetchCPEsPacesAndSendsKeyAsHeader(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		if r.URL.Path != "/cpes/2.0" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("apiKey") != "" && r.Header.Get("apiKey") != "good-key-123" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(cpeBody(t, [2]string{"cpe:2.3:a:anysphere:cursor:1:*:*:*:*:*:*:*", "Cursor 1"}))
	}))
	defer srv.Close()

	var slept []time.Duration
	clock := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	c := &NVDClient{Base: srv.URL, HTTP: srv.Client(), Now: func() time.Time { return clock },
		Sleep: func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			clock = clock.Add(d)
			return nil
		}}
	for _, kw := range []string{"cursor", "granola"} {
		page, err := c.FetchCPEs(context.Background(), CPEQuery{Keyword: kw})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Entries) != 1 {
			t.Fatalf("entries = %+v", page.Entries)
		}
	}
	// No key: the second call waits the full unauthenticated pace (5 per 30 s).
	if len(slept) != 1 || slept[0] < 6*time.Second {
		t.Fatalf("slept = %v", slept)
	}
	if !strings.Contains(queries[0], "keywordSearch=cursor") {
		t.Fatalf("query = %s", queries[0])
	}

	bad := &NVDClient{Base: srv.URL, HTTP: srv.Client(), Key: "wrong-key-456"}
	_, err := bad.FetchCPEs(context.Background(), CPEQuery{Keyword: "cursor"})
	if err == nil || !strings.Contains(err.Error(), "invalid API key") {
		t.Fatalf("invalid key err = %v", err)
	}
	for _, q := range queries {
		if strings.Contains(strings.ToLower(q), "apikey") || strings.Contains(q, "wrong-key") {
			t.Fatalf("api key leaked into query: %s", q)
		}
	}
	if _, err := c.FetchCPEs(context.Background(), CPEQuery{Keyword: strings.Repeat("x", 101)}); err == nil {
		t.Fatal("long keyword accepted")
	}
	meta := &NVDClient{Base: "http://169.254.169.254/rest/json"}
	if _, err := meta.FetchCPEs(context.Background(), CPEQuery{Keyword: "x"}); err == nil {
		t.Fatal("metadata base accepted")
	}
}
