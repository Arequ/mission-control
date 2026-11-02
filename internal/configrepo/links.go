// Package configrepo builds GitHub links into the GitOps config repository.
// Mission Control does not write that repository. The links open GitHub's
// own edit, tree, or pull-request flow.
package configrepo

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	// DefaultSlug is the GitOps repository when MC_CONFIG_REPO is unset.
	DefaultSlug = "Arequ/terraform-mission-control"
	// DefaultBranch is the branch those links target when MC_CONFIG_BRANCH is unset.
	DefaultBranch = "main"

	maxTitleRunes = 180
	maxBodyRunes  = 2000
	// maxQuery is the encoded title plus body. GitHub rejects oversized compare URLs.
	maxQuery = 6000
)

// Kind is one Terraform config surface the UI can propose a change for.
type Kind string

const (
	KindRecipe                Kind = "recipe"
	KindSchedule              Kind = "schedule"
	KindPipeline              Kind = "pipeline"
	KindRunnerPool            Kind = "runner_pool"
	KindMunkiCatalog          Kind = "munki_catalog"
	KindMunkiManifest         Kind = "munki_manifest"
	KindMunkiPromotion        Kind = "munki_promotion"
	KindOSPolicy              Kind = "os_policy"
	KindOsqueryPack           Kind = "osquery_pack"
	KindOsqueryQuery          Kind = "osquery_query"
	KindOsqueryLabel          Kind = "osquery_label"
	KindSourceConnector       Kind = "source_connector"
	KindLogView               Kind = "log_view"
	KindVulnerabilitySettings Kind = "vulnerability_settings"
	KindCPEOverride           Kind = "cpe_override"
	KindSLA                   Kind = "sla"
)

// Location is where a kind lives in the config repo.
// Path is empty when the kind has no single file; Dir is the directory to open.
type Location struct {
	Kind Kind
	Path string
	Dir  string
}

// locations is the file layout of Arequ/terraform-mission-control.
// Every path below is a .tf file in that repo. CPE overrides and SLA are
// blocks in vulnerabilities/settings.tf, next to the other vulnerability
// settings. Runner pools live in autopkg/runners.tf. Catalogs are
// munki/catalogs.tf. access/, autopkg/repos.tf, and osquery/enroll.tf are
// real files with no propose target in the UI.
var locations = []Location{
	{KindRecipe, "autopkg/recipes.tf", "autopkg"},
	{KindSchedule, "autopkg/schedules.tf", "autopkg"},
	{KindPipeline, "autopkg/pipeline.tf", "autopkg"},
	{KindRunnerPool, "autopkg/runners.tf", "autopkg"},
	{KindMunkiCatalog, "munki/catalogs.tf", "munki"},
	{KindMunkiManifest, "munki/manifests.tf", "munki"},
	{KindMunkiPromotion, "munki/promotion.tf", "munki"},
	{KindOSPolicy, "munki/os_policy.tf", "munki"},
	{KindOsqueryPack, "osquery/packs.tf", "osquery"},
	{KindOsqueryQuery, "osquery/queries.tf", "osquery"},
	{KindOsqueryLabel, "osquery/labels.tf", "osquery"},
	{KindSourceConnector, "sources/connectors.tf", "sources"},
	{KindLogView, "logs/views.tf", "logs"},
	{KindVulnerabilitySettings, "vulnerabilities/settings.tf", "vulnerabilities"},
	{KindCPEOverride, "vulnerabilities/settings.tf", "vulnerabilities"},
	{KindSLA, "vulnerabilities/settings.tf", "vulnerabilities"},
}

var byKind map[Kind]Location

func init() {
	byKind = make(map[Kind]Location, len(locations))
	for _, loc := range locations {
		byKind[loc.Kind] = loc
	}
}

// Repo is the GitHub repository links are built against.
type Repo struct {
	Slug   string
	Branch string
}

// Default is the repository used when nothing is configured.
func Default() Repo {
	return Repo{Slug: DefaultSlug, Branch: DefaultBranch}
}

// Parse checks a slug and branch from configuration.
func Parse(slug, branch string) (Repo, error) {
	repo := Repo{Slug: strings.TrimSpace(slug), Branch: strings.TrimSpace(branch)}
	if err := repo.validate(); err != nil {
		return Repo{}, err
	}
	return repo, nil
}

func (r Repo) validate() error {
	owner, name, ok := strings.Cut(r.Slug, "/")
	if !ok || strings.Contains(name, "/") || !validOwner(owner) || !validRepoName(name) {
		return fmt.Errorf("config repo slug must be owner/name")
	}
	if !validBranch(r.Branch) {
		return fmt.Errorf("config repo branch must be a branch name")
	}
	return nil
}

func validOwner(s string) bool {
	if s == "" || len(s) > 39 || strings.Contains(s, "--") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

func validRepoName(s string) bool {
	if s == "" || len(s) > 100 || strings.HasPrefix(s, ".") || strings.HasSuffix(strings.ToLower(s), ".git") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case c == '.', c == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validBranch(branch string) bool {
	if branch == "" || len(branch) > 255 {
		return false
	}
	if strings.HasPrefix(branch, "/") || strings.HasSuffix(branch, "/") || strings.Contains(branch, "//") || strings.Contains(branch, "..") {
		return false
	}
	for _, part := range strings.Split(branch, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			default:
				return false
			}
		}
		if part[0] == '.' || part[0] == '-' {
			return false
		}
	}
	return true
}

// Kinds returns every mapped kind in a stable order.
func Kinds() []Kind {
	out := make([]Kind, len(locations))
	for i, loc := range locations {
		out[i] = loc.Kind
	}
	return out
}

// Lookup returns the file or directory for a kind.
func Lookup(kind Kind) (Location, bool) {
	loc, ok := byKind[kind]
	return loc, ok
}

// ProposeURL is the edit URL for a file, or the tree URL when the kind has no single file.
// GitHub's edit URL starts a branch and pull request for the signed-in user.
func ProposeURL(repo Repo, kind Kind) (string, error) {
	if err := repo.validate(); err != nil {
		return "", err
	}
	loc, ok := Lookup(kind)
	if !ok {
		return "", fmt.Errorf("unknown config kind %q", kind)
	}
	if loc.Path != "" {
		if !validRel(loc.Path) {
			return "", fmt.Errorf("config path for %s is not a relative file", kind)
		}
		return githubURL(repo.Slug, "edit/"+escapeRef(repo.Branch)+"/"+escapePath(loc.Path), ""), nil
	}
	if !validRel(loc.Dir) {
		return "", fmt.Errorf("config path for %s is not a relative directory", kind)
	}
	return githubURL(repo.Slug, "tree/"+escapeRef(repo.Branch)+"/"+escapePath(loc.Dir), ""), nil
}

// PullRequestLink is a compare URL with quick_pull, title, and body.
// The body names the file and includes its edit or tree URL. GitHub compare
// URLs reject unknown query parameters, so the path is carried in the body.
// Names in the title and body are query-encoded; the returned title and body
// are the values that were encoded, after clipping.
func PullRequestLink(repo Repo, kind Kind, title, body string) (link, usedTitle, usedBody string, err error) {
	if err := repo.validate(); err != nil {
		return "", "", "", err
	}
	if _, ok := Lookup(kind); !ok {
		return "", "", "", fmt.Errorf("unknown config kind %q", kind)
	}
	fileURL, err := ProposeURL(repo, kind)
	if err != nil {
		return "", "", "", err
	}
	title = clipRunes(clean(title), maxTitleRunes)
	body = clipRunes(clean(body), maxBodyRunes)
	title, body = fitQuery(title, body, fileURL, kind)
	usedTitle = title
	usedBody = changeBody(kind, fileURL, body)
	v := url.Values{}
	v.Set("quick_pull", "1")
	v.Set("title", usedTitle)
	v.Set("body", usedBody)
	ref := escapeRef(repo.Branch)
	link = githubURL(repo.Slug, "compare/"+ref+"..."+ref, v.Encode())
	return link, usedTitle, usedBody, nil
}

func changeBody(kind Kind, fileURL, body string) string {
	loc, _ := Lookup(kind)
	var b strings.Builder
	if loc.Path != "" {
		b.WriteString("File: ")
		b.WriteString(loc.Path)
	} else {
		b.WriteString("Directory: ")
		b.WriteString(loc.Dir)
		b.WriteString("/")
	}
	b.WriteString("\n")
	b.WriteString(fileURL)
	if body != "" {
		b.WriteString("\n\n")
		b.WriteString(body)
	}
	return b.String()
}

// fitQuery shrinks the caller text until the encoded title and the composed
// body fit. The file header is added after clipping, so it is not cut off.
func fitQuery(title, user, fileURL string, kind Kind) (string, string) {
	composed := func(text string) string {
		return changeBody(kind, fileURL, text)
	}
	for len(url.QueryEscape(title))+len(url.QueryEscape(composed(user))) > maxQuery {
		if user == "" {
			r := []rune(title)
			if len(r) <= 1 {
				break
			}
			title = string(r[:len(r)/2])
			continue
		}
		r := []rune(user)
		cut := len(r) - max(1, len(r)/4)
		if cut < 1 {
			user = ""
		} else {
			user = string(r[:cut])
		}
	}
	return title, user
}

func clean(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func validRel(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, "..") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func escapeRef(branch string) string {
	return url.PathEscape(branch)
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func githubURL(slug, tail, rawQuery string) string {
	u := "https://github.com/" + slug + "/" + tail
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	return u
}
