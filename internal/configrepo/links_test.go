package configrepo

import (
	"net/url"
	"strings"
	"testing"
)

func TestKindPaths(t *testing.T) {
	want := map[Kind]Location{
		KindRecipe:                {KindRecipe, "autopkg/recipes.tf", "autopkg"},
		KindSchedule:              {KindSchedule, "autopkg/schedules.tf", "autopkg"},
		KindPipeline:              {KindPipeline, "autopkg/pipeline.tf", "autopkg"},
		KindRunnerPool:            {KindRunnerPool, "autopkg/runners.tf", "autopkg"},
		KindMunkiCatalog:          {KindMunkiCatalog, "munki/catalogs.tf", "munki"},
		KindMunkiManifest:         {KindMunkiManifest, "munki/manifests.tf", "munki"},
		KindMunkiPromotion:        {KindMunkiPromotion, "munki/promotion.tf", "munki"},
		KindOSPolicy:              {KindOSPolicy, "munki/os_policy.tf", "munki"},
		KindOsqueryPack:           {KindOsqueryPack, "osquery/packs.tf", "osquery"},
		KindOsqueryQuery:          {KindOsqueryQuery, "osquery/queries.tf", "osquery"},
		KindOsqueryLabel:          {KindOsqueryLabel, "osquery/labels.tf", "osquery"},
		KindSourceConnector:       {KindSourceConnector, "sources/connectors.tf", "sources"},
		KindLogView:               {KindLogView, "logs/views.tf", "logs"},
		KindVulnerabilitySettings: {KindVulnerabilitySettings, "vulnerabilities/settings.tf", "vulnerabilities"},
		KindCPEOverride:           {KindCPEOverride, "vulnerabilities/settings.tf", "vulnerabilities"},
		KindSLA:                   {KindSLA, "vulnerabilities/settings.tf", "vulnerabilities"},
	}
	if len(Kinds()) != len(want) {
		t.Fatalf("kinds %d want %d", len(Kinds()), len(want))
	}
	repo := Default()
	seen := map[Kind]bool{}
	for _, kind := range Kinds() {
		seen[kind] = true
		loc, ok := Lookup(kind)
		exp, wantOK := want[kind]
		if !ok || !wantOK || loc != exp {
			t.Fatalf("%s lookup %+v ok=%v", kind, loc, ok)
		}
		link, err := ProposeURL(repo, kind)
		if err != nil {
			t.Fatal(kind, err)
		}
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("%s url %s", kind, link)
		}
		if loc.Path != "" {
			wantPath := "/" + repo.Slug + "/edit/" + repo.Branch + "/" + loc.Path
			if u.Path != wantPath {
				t.Fatalf("%s path %s want %s", kind, u.Path, wantPath)
			}
		} else {
			wantPath := "/" + repo.Slug + "/tree/" + repo.Branch + "/" + loc.Dir
			if u.Path != wantPath {
				t.Fatalf("%s tree %s want %s", kind, u.Path, wantPath)
			}
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("missing kinds")
	}
	if _, err := ProposeURL(repo, "not-a-kind"); err == nil {
		t.Fatal("unknown kind produced a link")
	}
}

func TestPullRequestEscapesNames(t *testing.T) {
	repo := Default()
	names := []string{
		`Chrome & "Beta"`,
		"A+B",
		"100%",
		"a&b=c&title=hacked&quick_pull=0",
		"line1\nline2",
		"line1\r\nline2",
		"q?x=1#frag",
		"slash/dot",
		"<script>alert(1)</script>",
		"emoji 🔒",
		" lead space ",
		"null\x00kept",
	}
	for _, name := range names {
		title := "Promote " + name + " 1.2.3"
		body := name + " is in testing.\n\nDo not edit the catalog."
		link, usedTitle, usedBody, err := PullRequestLink(repo, KindMunkiPromotion, title, body)
		if err != nil {
			t.Fatal(name, err)
		}
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
			t.Fatalf("host %s", link)
		}
		if u.Path != "/"+repo.Slug+"/compare/"+repo.Branch+"..."+repo.Branch {
			t.Fatalf("path %s", u.Path)
		}
		q := u.Query()
		if len(q) != 3 || q.Get("quick_pull") != "1" {
			t.Fatalf("query keys %+v", q)
		}
		if q.Get("title") != usedTitle || q.Get("body") != usedBody {
			t.Fatalf("round trip title %q body %q\nlink %s", usedTitle, usedBody, link)
		}
		wantTitle := strings.ReplaceAll(title, "\x00", "")
		if usedTitle != wantTitle {
			t.Fatalf("title %q want %q", usedTitle, wantTitle)
		}
		wantName := strings.ReplaceAll(name, "\x00", "")
		if !strings.Contains(usedBody, wantName) || !strings.Contains(usedBody, "File: munki/promotion.tf") {
			t.Fatalf("body lost the name or file:\n%s", usedBody)
		}
		if !strings.Contains(usedBody, "https://github.com/"+repo.Slug+"/edit/"+repo.Branch+"/munki/promotion.tf") {
			t.Fatalf("body missing edit link:\n%s", usedBody)
		}
		if strings.Contains(link, "\n") || strings.Contains(link, "\r") || strings.Contains(link, " ") {
			t.Fatalf("raw link has whitespace: %s", link)
		}
		// A raw ampersand from the name must not add a query parameter.
		if strings.Contains(name, "&") && strings.Contains(u.RawQuery, "&title=hacked") {
			t.Fatalf("name broke out of the body: %s", u.RawQuery)
		}
	}
}

func TestPullRequestClipsLongNames(t *testing.T) {
	name := strings.Repeat("Chrome & Co\n", 800)
	link, title, body, err := PullRequestLink(Default(), KindMunkiManifest, "Install "+name, name+"\n\ninstall it")
	if err != nil {
		t.Fatal(err)
	}
	if len(link) > 8192 {
		t.Fatalf("link length %d", len(link))
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("title") != title || u.Query().Get("body") != body {
		t.Fatal("clipped values did not round-trip")
	}
	if !strings.HasPrefix(body, "File: munki/manifests.tf\n") {
		t.Fatalf("header clipped: %s", body[:80])
	}
	if !strings.Contains(body, "/edit/main/munki/manifests.tf") {
		t.Fatal(body)
	}
	if len(u.Query()) != 3 {
		t.Fatalf("keys %v", u.Query())
	}
}

func TestCatalogPullRequest(t *testing.T) {
	link, _, body, err := PullRequestLink(Default(), KindMunkiCatalog, "Catalogs", "testing and production")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(link, "/compare/main...main?") || !strings.Contains(body, "File: munki/catalogs.tf") {
		t.Fatalf("%s\n%s", link, body)
	}
	if !strings.Contains(body, "/edit/main/munki/catalogs.tf") {
		t.Fatal(body)
	}
}

// configRepoFiles is the .tf inventory of Arequ/terraform-mission-control.
// A mapped path that is not in this set is a file the config repo does not have.
var configRepoFiles = []string{
	"access/outputs.tf",
	"access/scopes.tf",
	"access/versions.tf",
	"autopkg/outputs.tf",
	"autopkg/pipeline.tf",
	"autopkg/recipes.tf",
	"autopkg/repos.tf",
	"autopkg/runners.tf",
	"autopkg/schedules.tf",
	"autopkg/variables.tf",
	"autopkg/versions.tf",
	"logs/outputs.tf",
	"logs/variables.tf",
	"logs/versions.tf",
	"logs/views.tf",
	"munki/catalogs.tf",
	"munki/manifests.tf",
	"munki/os_policy.tf",
	"munki/outputs.tf",
	"munki/promotion.tf",
	"munki/variables.tf",
	"munki/versions.tf",
	"osquery/enroll.tf",
	"osquery/labels.tf",
	"osquery/outputs.tf",
	"osquery/packs.tf",
	"osquery/queries.tf",
	"osquery/variables.tf",
	"osquery/versions.tf",
	"sources/connectors.tf",
	"sources/locals.tf",
	"sources/outputs.tf",
	"sources/variables.tf",
	"sources/versions.tf",
	"vulnerabilities/outputs.tf",
	"vulnerabilities/settings.tf",
	"vulnerabilities/variables.tf",
	"vulnerabilities/versions.tf",
	"backend.tf",
	"main.tf",
	"outputs.tf",
	"providers.tf",
	"variables.tf",
	"versions.tf",
}

func TestMappedPathsAreRealFiles(t *testing.T) {
	files := map[string]bool{}
	for _, path := range configRepoFiles {
		if files[path] {
			t.Fatalf("duplicate allowlist path %s", path)
		}
		files[path] = true
	}
	if len(files) != 44 {
		t.Fatalf("allowlist has %d files, want 44", len(files))
	}
	used := map[string]bool{}
	for _, kind := range Kinds() {
		loc, ok := Lookup(kind)
		if !ok || loc.Path == "" || !files[loc.Path] {
			t.Fatalf("%s path %q is not in the config repo", kind, loc.Path)
		}
		used[loc.Path] = true
	}
	shared := []Kind{KindVulnerabilitySettings, KindCPEOverride, KindSLA}
	for _, kind := range shared {
		loc, _ := Lookup(kind)
		if loc.Path != "vulnerabilities/settings.tf" {
			t.Fatalf("%s path %s", kind, loc.Path)
		}
	}
	checks := map[Kind]string{
		KindPipeline:     "autopkg/pipeline.tf",
		KindRunnerPool:   "autopkg/runners.tf",
		KindMunkiCatalog: "munki/catalogs.tf",
	}
	for kind, path := range checks {
		loc, _ := Lookup(kind)
		if loc.Path != path {
			t.Fatalf("%s path %s want %s", kind, loc.Path, path)
		}
	}
	// Real files with no propose target: recipe repos and enroll secrets
	// are API and Terraform only, and access/ is not a UI config surface.
	for _, path := range []string{"autopkg/repos.tf", "osquery/enroll.tf", "access/scopes.tf"} {
		if !files[path] {
			t.Fatalf("allowlist dropped %s", path)
		}
		if used[path] {
			t.Fatalf("%s is mapped but has no propose target", path)
		}
	}
}

func TestCustomRepoAndBranch(t *testing.T) {
	repo, err := Parse("Example-Org/config.repo", "release/1")
	if err != nil {
		t.Fatal(err)
	}
	link, err := ProposeURL(repo, KindLogView)
	if err != nil {
		t.Fatal(err)
	}
	if link != "https://github.com/Example-Org/config.repo/edit/release%2F1/logs/views.tf" {
		t.Fatal(link)
	}
	pr, title, body, err := PullRequestLink(repo, KindOSPolicy, "Require macOS", "15.1.1 (24B91)")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(pr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pr, "/compare/release%2F1...release%2F1?") {
		t.Fatal(pr)
	}
	if u.Host != "github.com" || u.Query().Get("title") != title || !strings.Contains(u.Query().Get("body"), "munki/os_policy.tf") || !strings.Contains(body, "release%2F1/munki/os_policy.tf") {
		t.Fatalf("%s\n%s", pr, body)
	}
}

func TestRejectsRepoEscape(t *testing.T) {
	badSlugs := []string{
		"",
		"noslash",
		"owner/name/extra",
		"https://evil.example/phish",
		"evil.example/repo",
		"owner/name?x=1",
		"owner/name#frag",
		"owner/name@evil",
		"../owner/repo",
		"owner/../repo",
		"owner/",
		"/repo",
		"owner/name with space",
		"owner\\name",
		"owner/na\nme",
		"ow\rner/name",
		"javascript:alert(1)/x",
		".",
		"..",
		"./repo",
		"owner/..",
		"a/b?quick_pull=1",
	}
	for _, slug := range badSlugs {
		if _, err := Parse(slug, "main"); err == nil {
			t.Fatalf("accepted slug %q", slug)
		}
		if _, err := ProposeURL(Repo{Slug: slug, Branch: "main"}, KindRecipe); err == nil {
			t.Fatalf("propose accepted slug %q", slug)
		}
	}
	badBranches := []string{
		"",
		"/main",
		"main/",
		"main//x",
		"..",
		"../main",
		"main/../../etc",
		"feature/../main",
		"main?x=1",
		"main#x",
		"mai\nn",
		"mai\rn",
		"-rel",
		".hidden",
		"feature/.hidden",
		"white space",
		"branch@evil",
	}
	for _, branch := range badBranches {
		if _, err := Parse(DefaultSlug, branch); err == nil {
			t.Fatalf("accepted branch %q", branch)
		}
	}
	if _, err := Parse("  "+DefaultSlug+"  ", "  main  "); err != nil {
		t.Fatal(err)
	}
}
