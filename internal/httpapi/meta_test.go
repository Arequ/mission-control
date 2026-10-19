package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/configrepo"
)

func TestMetaConfigLinks(t *testing.T) {
	repo := configrepo.Repo{Slug: "Example-Org/config.repo", Branch: "release/1"}
	srv := New(Options{ConfigRepo: repo})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	res, err := http.Get(ts.URL + "/api/v1/meta?config_repo=evil/phish")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var got struct {
		ConfigRepo   string            `json:"config_repo"`
		ConfigBranch string            `json:"config_branch"`
		ConfigLinks  map[string]string `json:"config_links"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ConfigRepo != repo.Slug || got.ConfigBranch != repo.Branch {
		t.Fatalf("query string changed the repo: %+v", got)
	}
	if strings.Contains(res.Header.Get("Content-Type"), "html") {
		t.Fatal(res.Header.Get("Content-Type"))
	}
	for _, kind := range configrepo.Kinds() {
		link := got.ConfigLinks[string(kind)]
		want, err := configrepo.ProposeURL(repo, kind)
		if err != nil {
			t.Fatal(err)
		}
		if link != want {
			t.Fatalf("%s %s want %s", kind, link, want)
		}
		if !strings.HasPrefix(link, "https://github.com/"+repo.Slug+"/") {
			t.Fatal(link)
		}
		if !strings.Contains(link, "/edit/") && !strings.Contains(link, "/tree/") {
			t.Fatal(link)
		}
	}
	if len(got.ConfigLinks) != len(configrepo.Kinds()) {
		t.Fatalf("links %d", len(got.ConfigLinks))
	}
}

func TestOpenAPIDocumentsConfigLinks(t *testing.T) {
	srv := New(Options{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/api/v1/meta:") || !strings.Contains(body, "ServerMeta:") {
		t.Fatal("meta path missing from OpenAPI")
	}
	for _, kind := range configrepo.Kinds() {
		if !strings.Contains(body, "\n            "+string(kind)+":") {
			t.Fatalf("openapi missing %s", kind)
		}
	}
}

func TestMetaDefaults(t *testing.T) {
	srv := New(Options{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), configrepo.DefaultSlug) || !strings.Contains(rec.Body.String(), "/edit/main/logs/views.tf") {
		t.Fatal(rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "token") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatal(rec.Body.String())
	}
}
