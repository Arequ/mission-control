package vuln

import (
	"strings"

	"github.com/Arequ/mission-control/internal/configrepo"
)

// ConfigRepo is the default GitOps repository. Promotion and install changes
// are pull requests against it. This process does not write that repository.
const ConfigRepo = configrepo.DefaultSlug

// CatalogPackage is one Munki item already in a catalog.
type CatalogPackage struct {
	Name    string
	Version string
	Catalog string
}

// RecipeState is an AutoPKG recipe and its latest run.
type RecipeState struct {
	ID         string
	Name       string
	Identifier string
	Enabled    bool
	Status     string
	Result     string
}

// Install is one affected copy of the software.
type Install struct {
	Version string
	Build   string
}

// Plan is the next operational or GitOps step for one issue.
type Plan struct {
	Action         string `json:"action"`
	FixedVersion   string `json:"fixed_version,omitempty"`
	FixedBuild     string `json:"fixed_build,omitempty"`
	Catalog        string `json:"catalog,omitempty"`
	CatalogVersion string `json:"catalog_version,omitempty"`
	RecipeID       string `json:"recipe_id,omitempty"`
	RecipeName     string `json:"recipe_name,omitempty"`
	RecipeStatus   string `json:"recipe_status,omitempty"`
	RequiredOS     string `json:"required_os,omitempty"`
	PRURL          string `json:"pr_url,omitempty"`
	PRTitle        string `json:"pr_title,omitempty"`
	PRBody         string `json:"pr_body,omitempty"`
}

// DecideInput is everything the fix decision needs. It does not touch a catalog.
type DecideInput struct {
	CVE          string
	SoftwareKey  string
	SoftwareName string
	OS           bool
	Ranges       []ProductBound
	Trains       []Train
	Installs     []Install
	Packages     []CatalogPackage
	Recipes      []RecipeState
	Repo         configrepo.Repo
}

// Decide chooses the action for one issue.
// A catalog version counts only when it meets every affected install, so an
// ESR fix does not clear a newer train that is still behind.
func Decide(in DecideInput) Plan {
	plan := Plan{FixedVersion: fixedDisplay(in)}
	repo := in.Repo
	if repo.Slug == "" {
		repo = configrepo.Default()
	} else if repo.Branch == "" {
		repo.Branch = configrepo.DefaultBranch
	}
	if in.OS {
		plan.Action = "os_update"
		plan.RequiredOS = plan.FixedVersion
		if b := fixedBuild(in); b != "" {
			plan.FixedBuild = b
			plan.RequiredOS = plan.FixedVersion + " (" + b + ")"
		}
		title := "Require " + in.SoftwareName + " " + plan.RequiredOS
		body := "macOS update for " + in.CVE + ".\n\nRequired version: " + plan.RequiredOS +
			"\n\nMission Control does not change this repository. Put the required version in the OS update policy."
		plan.setPR(repo, configrepo.KindOSPolicy, title, body)
		return plan
	}
	product, _ := productFromKey(in.SoftwareKey)
	var testing, production *CatalogPackage
	for i := range in.Packages {
		pkg := in.Packages[i]
		if !packageMatches(pkg.Name, product, in.SoftwareName) {
			continue
		}
		if !clearsAll(pkg.Version, in) {
			continue
		}
		switch strings.ToLower(pkg.Catalog) {
		case "production":
			if production == nil || versionLess(production.Version, pkg.Version) {
				cp := pkg
				production = &cp
			}
		default:
			if testing == nil || versionLess(testing.Version, pkg.Version) {
				cp := pkg
				testing = &cp
			}
		}
	}
	if production != nil {
		plan.Action = "require_install"
		plan.Catalog = "production"
		plan.CatalogVersion = production.Version
		title := "Install " + production.Name + " " + production.Version + " on affected Macs"
		body := production.Name + " " + production.Version + " is already in the production catalog and clears " + in.CVE +
			" on " + in.SoftwareName + ".\n\nAdd it to managed_installs for the manifests that still have an affected version.\n\nMission Control does not change this repository."
		plan.setPR(repo, configrepo.KindMunkiManifest, title, body)
		return plan
	}
	if testing != nil {
		plan.Action = "promote"
		plan.Catalog = "testing"
		plan.CatalogVersion = testing.Version
		title := "Promote " + testing.Name + " " + testing.Version + " to production"
		body := testing.Name + " " + testing.Version + " is in the testing catalog and clears " + in.CVE +
			" on " + in.SoftwareName + ".\n\nPromote it to production. Do not edit the catalog from the Mission Control UI.\n\nMission Control does not change this repository."
		plan.setPR(repo, configrepo.KindMunkiPromotion, title, body)
		return plan
	}
	if rec := matchRecipe(in.Recipes, product, in.SoftwareName); rec != nil {
		plan.RecipeID = rec.ID
		plan.RecipeName = rec.Name
		plan.RecipeStatus = rec.Status
		switch rec.Status {
		case "queued", "running", "leased":
			plan.Action = "recipe_pending"
		default:
			plan.Action = "run_recipe"
		}
		return plan
	}
	plan.Action = "unmanaged"
	return plan
}

// setPR fills the compare link. A bad repository leaves the link empty so the
// UI does not open an unscoped URL.
func (plan *Plan) setPR(repo configrepo.Repo, kind configrepo.Kind, title, body string) {
	link, usedTitle, usedBody, err := configrepo.PullRequestLink(repo, kind, title, body)
	if err != nil {
		return
	}
	plan.PRTitle = usedTitle
	plan.PRBody = usedBody
	plan.PRURL = link
}

// Applies reports whether any stored range matches version on a Mac running osVersion.
// It is the platform-aware check used before an issue is opened.
func Applies(ranges []ProductBound, version, osVersion string) bool {
	return AffectedInstall(version, "", osVersion, ranges, nil)
}

// AffectedInstall reports whether a copy is inside this CVE's ranges or trains.
// Trains win when any exist, so an NVD range cannot false-positive a backported
// product or a macOS train the range does not understand.
func AffectedInstall(version, build, osVersion string, ranges []ProductBound, trains []Train) bool {
	if strings.TrimSpace(version) == "" {
		return false
	}
	if len(trains) > 0 {
		hit, _ := TrainsAffected(version, build, trains)
		return hit
	}
	for _, r := range ranges {
		if !platformOK(r.Platforms, osVersion) {
			continue
		}
		if AppleOS(r.Vendor, r.Product) && !sameMajorBound(r.Bound, version) {
			// An NVD macOS range that crosses trains (14.x through 15.x) is not
			// a single fix. Same-major bounds are applied when no SOFA train
			// names this CVE.
			continue
		}
		hit, _ := r.Bound.Affected(version)
		if hit {
			return true
		}
	}
	return false
}

// sameMajorBound reports whether every version in the bound is on the same
// macOS major as installed. A bound with no version is not a train.
func sameMajorBound(b Bound, installed string) bool {
	major, ok := Major(installed)
	if !ok {
		return false
	}
	n := 0
	for _, s := range []string{b.StartIncl, b.StartExcl, b.EndIncl, b.EndExcl, b.Exact} {
		if strings.TrimSpace(s) == "" {
			continue
		}
		m, mok := Major(s)
		if !mok || m != major {
			return false
		}
		n++
	}
	return n > 0
}

func clearsAll(pkg string, in DecideInput) bool {
	if len(in.Installs) == 0 || strings.TrimSpace(pkg) == "" {
		return false
	}
	for _, inst := range in.Installs {
		if !meetsInstall(pkg, inst, in) {
			return false
		}
	}
	return true
}

func meetsInstall(pkg string, inst Install, in DecideInput) bool {
	if len(in.Trains) > 0 {
		req, ok := requirement(inst, in.Trains)
		if !ok {
			return false
		}
		c, cok := Compare(pkg, req.FixedVersion)
		if !cok || c < 0 {
			return false
		}
		return true
	}
	if len(in.Ranges) == 0 {
		return false
	}
	for _, r := range in.Ranges {
		if !meetsBound(pkg, r.Bound) {
			return false
		}
	}
	return true
}

func requirement(inst Install, trains []Train) (Train, bool) {
	major, ok := Major(inst.Version)
	if !ok || len(trains) == 0 {
		return Train{}, false
	}
	mode := trains[0].Mode
	byMajor := map[int]Train{}
	var highest Train
	have := false
	for _, t := range trains {
		cur, exists := byMajor[t.Major]
		if !exists || versionLess(t.FixedVersion, cur.FixedVersion) {
			byMajor[t.Major] = t
		}
		if !have || versionLess(highest.FixedVersion, t.FixedVersion) {
			highest = t
			have = true
		}
	}
	if t, exists := byMajor[major]; exists {
		return t, true
	}
	if mode == "independent" || major > highest.Major {
		return Train{}, false
	}
	return highest, true
}

func meetsBound(pkg string, b Bound) bool {
	if b.EndExcl != "" {
		c, ok := Compare(pkg, b.EndExcl)
		return ok && c >= 0
	}
	if b.EndIncl != "" {
		c, ok := Compare(pkg, b.EndIncl)
		return ok && c > 0
	}
	if b.Exact != "" {
		c, ok := Compare(pkg, b.Exact)
		return ok && c > 0
	}
	return false
}

func fixedDisplay(in DecideInput) string {
	if len(in.Trains) > 0 {
		var best string
		for _, inst := range in.Installs {
			req, ok := requirement(inst, in.Trains)
			if !ok {
				continue
			}
			if best == "" || versionLess(best, req.FixedVersion) {
				best = req.FixedVersion
			}
		}
		if best != "" {
			return best
		}
		var highest string
		for _, t := range in.Trains {
			if highest == "" || versionLess(highest, t.FixedVersion) {
				highest = t.FixedVersion
			}
		}
		return highest
	}
	var best string
	for _, r := range in.Ranges {
		end := r.Bound.EndExcl
		if end == "" {
			end = r.Bound.EndIncl
		}
		if end == "" {
			continue
		}
		if best == "" || versionLess(best, end) {
			best = end
		}
	}
	return best
}

func fixedBuild(in DecideInput) string {
	version := fixedDisplay(in)
	for _, t := range in.Trains {
		if t.FixedVersion == version && t.FixedBuild != "" {
			return t.FixedBuild
		}
	}
	return ""
}

func productFromKey(key string) (Product, bool) {
	part, rest, ok := strings.Cut(key, ":")
	if !ok {
		return Product{}, false
	}
	vendor, product, ok := strings.Cut(rest, ":")
	if !ok {
		return Product{}, false
	}
	if p, found := Lookup(vendor, product); found {
		p.Part = part
		return p, true
	}
	return Product{Part: part, Vendor: vendor, Product: product}, true
}

func packageMatches(name string, product Product, softwareName string) bool {
	if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(softwareName)) {
		return true
	}
	for _, alias := range product.Munki {
		if strings.EqualFold(alias, name) {
			return true
		}
	}
	return false
}

func matchRecipe(recipes []RecipeState, product Product, softwareName string) *RecipeState {
	var fallback *RecipeState
	for i := range recipes {
		rec := &recipes[i]
		if !rec.Enabled || rec.ID == "" {
			continue
		}
		if strings.EqualFold(rec.Name, softwareName) || aliasName(rec.Name, product) {
			return rec
		}
		if fallback == nil && (strings.Contains(strings.ToLower(rec.Identifier), product.Product) || aliasName(rec.Name, product)) {
			fallback = rec
		}
	}
	return fallback
}

func aliasName(name string, product Product) bool {
	for _, alias := range product.Munki {
		if strings.EqualFold(alias, name) {
			return true
		}
	}
	return false
}
