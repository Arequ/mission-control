package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseKEVAndEPSS(t *testing.T) {
	kev, err := ParseKEV([]byte(`{"vulnerabilities":[
		{"cveID":"CVE-2024-7971","vulnerabilityName":"V8","dateAdded":"2024-08-26","dueDate":"2024-09-16"},
		{"cveID":"not-a-cve","vulnerabilityName":"nope","dateAdded":"2024-01-01","dueDate":"2024-01-02"}
	]}`))
	if err != nil || len(kev) != 1 || kev[0].CVE != "CVE-2024-7971" || kev[0].Added.Format("2006-01-02") != "2024-08-26" {
		t.Fatalf("%v %+v", err, kev)
	}
	epss, err := ParseEPSS([]byte(`{"data":[{"cve":"CVE-2024-7971","epss":"0.42","percentile":"0.97"}]}`))
	if err != nil || len(epss) != 1 || epss[0].Score != 0.42 || epss[0].Percentile != 0.97 {
		t.Fatalf("%v %+v", err, epss)
	}
	q, err := EPSSQuery("https://api.first.org/data/v1/epss", []string{"CVE-2024-7971", "nope"})
	if err != nil || !strings.Contains(q, "CVE-2024-7971") || strings.Contains(q, "nope") {
		t.Fatal(q, err)
	}
}

func TestParseSOFAEarliestTrain(t *testing.T) {
	body := []byte(`{"OSVersions":[{"OSVersion":"macOS Sequoia 15","Latest":{"ProductVersion":"15.2","Build":"24C101","CVEs":{"CVE-2024-44308":"https://example.invalid"}},"SecurityReleases":[
		{"ProductVersion":"15.1.1","Build":"24B91","CVEs":{"CVE-2024-44308":"https://example.invalid","CVE-2024-44309":"https://example.invalid"}},
		{"ProductVersion":"15.1","Build":"24B83","CVEs":{}},
		{"ProductVersion":"14.7","Build":"23H124","CVEs":{"CVE-2024-99999":"https://example.invalid"}}
	]}]}`)
	fixes, err := ParseSOFARecords(body, "macos")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]SOFAFix{}
	for _, f := range fixes {
		got[f.CVE+"|"+f.Train.FixedVersion] = f
	}
	seq, ok := got["CVE-2024-44308|15.1.1"]
	if !ok || seq.Train.Major != 15 || seq.Train.FixedBuild != "24B91" || seq.Train.Mode != "independent" {
		t.Fatalf("sequoia fix %+v", got)
	}
	if _, ok := got["CVE-2024-44308|15.2"]; ok {
		t.Fatal("later cumulative release replaced the earliest fix")
	}
	if _, ok := got["CVE-2024-99999|14.7"]; !ok {
		t.Fatal("sonoma cve missing")
	}
	safari, err := ParseSOFARecords([]byte(`{"SafariVersions":[{"SecurityReleases":[{"ProductVersion":"18.1.1","CVEs":["CVE-2024-44308"]},{"ProductVersion":"18.2","CVEs":["CVE-2024-44308"]}]}]}`), "safari")
	if err != nil || len(safari) != 1 || safari[0].Train.Product != "safari" || safari[0].Train.FixedVersion != "18.1.1" {
		t.Fatalf("%v %+v", err, safari)
	}
}

func TestRapid7APIAndElasticPages(t *testing.T) {
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/findings" {
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("auth %s", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"findings":[{"cve":"CVE-2024-11395","software":"Google Chrome","version":"131.0.6778.70","serial":"MCDEV0001"},{"cve":"made-up","software":"Chrome"}]}`))
			return
		}
		pages++
		if pages == 1 {
			_, _ = w.Write([]byte(`{"hits":{"hits":[{"_source":{"cve":{"id":"CVE-2024-7971"},"app":"Google Chrome","serial":"A"},"sort":[1]}]}}`))
			// one hit is a short page
			return
		}
		t.Error("short page continued")
	}))
	defer srv.Close()
	rows, err := FetchRapid7(context.Background(), srv.Client(), Rapid7Source{Mode: "api", BaseURL: srv.URL, Token: "tok"})
	if err != nil || len(rows) != 1 || rows[0].Serial != "MCDEV0001" {
		t.Fatalf("%v %+v", err, rows)
	}
	elastic, err := FetchRapid7(context.Background(), srv.Client(), Rapid7Source{
		Mode: "elastic", ElasticURL: srv.URL, Index: "findings", APIKey: "k",
		FieldMap: map[string]string{"cve": "cve.id", "software": "app", "serial": "serial"},
	})
	if err != nil || len(elastic) != 1 || elastic[0].CVE != "CVE-2024-7971" || elastic[0].Software != "Google Chrome" {
		t.Fatalf("%v %+v", err, elastic)
	}
}

func TestRapid7ElasticFullPageContinues(t *testing.T) {
	var from []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from = append(from, r.URL.Path)
		if len(from) == 1 {
			hits := strings.Repeat(`{"_source":{"cve":"CVE-2024-11395","software":"Chrome","serial":"S"},"sort":[1]},`, 199)
			hits += `{"_source":{"cve":"CVE-2024-11395","software":"Chrome","serial":"S"},"sort":[2]}`
			_, _ = w.Write([]byte(`{"hits":{"hits":[` + hits + `]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_source":{"cve":"CVE-2024-7971","software":"Chrome","serial":"T"},"sort":[3]}]}}`))
	}))
	defer srv.Close()
	rows, err := FetchRapid7(context.Background(), srv.Client(), Rapid7Source{Mode: "elastic", ElasticURL: srv.URL, Index: "findings"})
	if err != nil {
		t.Fatal(err)
	}
	if len(from) != 2 || len(rows) != 201 {
		t.Fatalf("pages %d rows %d", len(from), len(rows))
	}
	if rows[len(rows)-1].CVE != "CVE-2024-7971" {
		t.Fatalf("last %+v", rows[len(rows)-1])
	}
}

func TestFixtureFirefoxAndMacOSTrains(t *testing.T) {
	var firefox, mac Record
	for _, rec := range FixtureRecords() {
		switch rec.ID {
		case "CVE-2024-9680":
			firefox = rec
		case "CVE-2024-44308":
			mac = rec
		}
	}
	if AffectedInstall("128.3.1", "", nil, firefox.Trains) || !AffectedInstall("128.3.0", "", nil, firefox.Trains) {
		t.Fatal("patched ESR")
	}
	if !AffectedInstall("131.0.1", "", nil, firefox.Trains) || AffectedInstall("132.0.2", "", nil, firefox.Trains) || !AffectedInstall("130.0", "", nil, firefox.Trains) {
		t.Fatal("firefox trains")
	}
	if AffectedInstall("14.8", "23J20", nil, mac.Trains) || AffectedInstall("26.1", "25B78", nil, mac.Trains) {
		t.Fatal("other macOS trains flagged")
	}
	if !AffectedInstall("15.1", "24B83", nil, mac.Trains) || AffectedInstall("15.1.1", "24B91", nil, mac.Trains) {
		t.Fatal("sequoia bound")
	}
	if !AffectedInstall("15.1.1", "24B83", nil, mac.Trains) {
		t.Fatal("same version, older build, should still match")
	}
}
