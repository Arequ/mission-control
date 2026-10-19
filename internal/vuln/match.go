package vuln

import (
	"sort"
	"strings"
)

// Bound is one NVD-style version interval. An empty bound matches nothing:
// a CPE with no range would otherwise flag every install of the product.
type Bound struct {
	StartIncl string
	StartExcl string
	EndIncl   string
	EndExcl   string
	Exact     string
}

// Affected reports whether version falls inside the bound. The second result
// is false when the version cannot be compared with the bound, which is not
// the same as "patched".
func (b Bound) Affected(version string) (match bool, comparable bool) {
	version = strings.TrimSpace(version)
	if version == "" || version == "*" {
		return false, false
	}
	exact := b.Exact
	if exact == "*" || exact == "-" {
		exact = ""
	}
	var bounds []string
	for _, s := range []string{b.StartIncl, b.StartExcl, b.EndIncl, b.EndExcl, exact} {
		if strings.TrimSpace(s) != "" {
			bounds = append(bounds, s)
		}
	}
	if len(bounds) == 0 {
		return false, true
	}
	if !SameShape(version, bounds...) {
		return false, false
	}
	if exact != "" {
		c, ok := Compare(version, exact)
		return ok && c == 0, ok
	}
	if b.StartIncl != "" {
		c, ok := Compare(version, b.StartIncl)
		if !ok || c < 0 {
			return false, ok
		}
	}
	if b.StartExcl != "" {
		c, ok := Compare(version, b.StartExcl)
		if !ok || c <= 0 {
			return false, ok
		}
	}
	if b.EndIncl != "" {
		c, ok := Compare(version, b.EndIncl)
		if !ok || c > 0 {
			return false, ok
		}
	}
	if b.EndExcl != "" {
		c, ok := Compare(version, b.EndExcl)
		if !ok || c >= 0 {
			return false, ok
		}
	}
	return true, true
}

// Train is a fix that applies only to one major version line.
type Train struct {
	Part         string
	Vendor       string
	Product      string
	Major        int
	FixedVersion string
	FixedBuild   string
	// Mode is "independent" (macOS: a Sonoma install is not Sequoia) or
	// "backport" (Firefox: 130 is still behind a fix that shipped in 131,
	// unless that major has its own fix).
	Mode string
}

// TrainsAffected applies per-train fixes. A major with no independent train
// is not vulnerable. A backport product is vulnerable below the newest fix
// unless its own major already has a fix it meets.
func TrainsAffected(version, build string, trains []Train) (affected bool, comparable bool) {
	if len(trains) == 0 {
		return false, false
	}
	major, ok := Major(version)
	if !ok {
		return false, false
	}
	mode := trains[0].Mode
	if mode != "independent" && mode != "backport" {
		mode = "independent"
	}
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
		return belowFix(version, build, t)
	}
	if mode == "independent" {
		return false, true
	}
	if major > highest.Major {
		return false, true
	}
	c, cok := Compare(version, highest.FixedVersion)
	if !cok {
		return false, false
	}
	return c < 0, true
}

func versionLess(a, b string) bool {
	c, ok := Compare(a, b)
	return ok && c < 0
}

func belowFix(version, build string, t Train) (bool, bool) {
	c, ok := Compare(version, t.FixedVersion)
	if !ok {
		return false, false
	}
	if c < 0 {
		return true, true
	}
	if c > 0 {
		return false, true
	}
	if t.FixedBuild == "" || strings.TrimSpace(build) == "" {
		return false, true
	}
	bc, bok := Compare(build, t.FixedBuild)
	if !bok {
		return false, false
	}
	return bc < 0, true
}

// Product is a CPE vendor/product an install can be tied to.
type Product struct {
	Part          string
	Vendor        string
	Product       string
	VersionSource string
	Names         []string
	Bundles       []string
	Munki         []string
}

// Key is the stable software key stored on an issue.
func (p Product) Key() string {
	return p.Part + ":" + p.Vendor + ":" + p.Product
}

// Override is an operator mapping. It wins over the curated table, including
// when it points a helper bundle at a product on purpose.
type Override struct {
	BundleID      string
	Name          string
	Vendor        string
	Product       string
	Part          string
	VersionSource string
}

func (o Override) product() Product {
	part := o.Part
	if part == "" {
		part = "a"
	}
	src := o.VersionSource
	if src == "" {
		src = "short"
	}
	return Product{
		Part: part, Vendor: strings.ToLower(o.Vendor), Product: strings.ToLower(o.Product),
		VersionSource: src,
	}
}

type curated struct {
	bundles []string
	names   []string
	munki   []string
	part    string
	vendor  string
	product string
	source  string
}

func (c curated) asProduct() Product {
	return Product{
		Part: c.part, Vendor: c.vendor, Product: c.product, VersionSource: c.source,
		Names: append([]string(nil), c.names...), Bundles: append([]string(nil), c.bundles...),
		Munki: append([]string(nil), c.munki...),
	}
}

// Curated products are exact. A name or bundle that merely contains one of
// these strings is not a match. Helper bundles (an extra component after a
// known id) are rejected unless an override names that exact id.
var catalog = []curated{
	{bundles: []string{"com.google.chrome"}, names: []string{"google chrome", "chrome"}, munki: []string{"Chrome", "Google Chrome", "GoogleChrome"}, part: "a", vendor: "google", product: "chrome", source: "short"},
	{bundles: []string{"org.mozilla.firefox"}, names: []string{"firefox", "firefox esr", "mozilla firefox"}, munki: []string{"Firefox", "FirefoxESR"}, part: "a", vendor: "mozilla", product: "firefox", source: "short"},
	{bundles: []string{"us.zoom.xos"}, names: []string{"zoom", "zoom workplace", "zoom.us"}, munki: []string{"Zoom", "zoom.us", "ZoomWorkplace"}, part: "a", vendor: "zoom", product: "workplace_desktop", source: "short"},
	{bundles: []string{"com.tinyspeck.slackmacgap"}, names: []string{"slack"}, munki: []string{"Slack"}, part: "a", vendor: "slack", product: "slack", source: "short"},
	{bundles: []string{"com.microsoft.teams", "com.microsoft.teams2"}, names: []string{"microsoft teams"}, munki: []string{"MicrosoftTeams", "Teams"}, part: "a", vendor: "microsoft", product: "teams", source: "short"},
	{bundles: []string{"com.microsoft.vscode"}, names: []string{"visual studio code"}, munki: []string{"VSCode", "Visual Studio Code"}, part: "a", vendor: "microsoft", product: "visual_studio_code", source: "short"},
	{bundles: []string{"com.docker.docker"}, names: []string{"docker", "docker desktop"}, munki: []string{"Docker", "DockerDesktop"}, part: "a", vendor: "docker", product: "docker_desktop", source: "short"},
	{bundles: []string{"com.1password.1password"}, names: []string{"1password"}, munki: []string{"1Password", "OnePassword"}, part: "a", vendor: "1password", product: "1password", source: "short"},
	{bundles: []string{"com.apple.safari"}, names: []string{"safari"}, munki: []string{"Safari"}, part: "a", vendor: "apple", product: "safari", source: "short"},
}

// Names that look related but are different products. An exact bundle match
// still wins, so renaming Google Chrome does not hide it.
var rejectedNames = map[string]bool{
	"google chrome helper": true, "google chrome canary": true, "google chrome beta": true,
	"chromium": true, "firefox focus": true, "firefox helper": true, "slack helper": true,
	"slackline": true, "microsoft teams helper": true, "safari technology preview": true,
	"python launcher": true,
}

var (
	byBundle  map[string]Product
	byName    map[string]Product
	allBundle []string
)

func init() {
	byBundle = map[string]Product{}
	byName = map[string]Product{}
	for _, c := range catalog {
		p := c.asProduct()
		for _, b := range c.bundles {
			byBundle[b] = p
			allBundle = append(allBundle, b)
		}
		for _, n := range c.names {
			byName[n] = p
		}
	}
}

// NormName folds an app name for an exact comparison.
func NormName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".app")
	return strings.Join(strings.Fields(s), " ")
}

// MatchSoftware maps one install to a product. Overrides are consulted before
// the curated table. Substring matches are not used.
func MatchSoftware(name, bundle string, overrides []Override) (Product, bool) {
	bundle = strings.ToLower(strings.TrimSpace(bundle))
	name = NormName(name)
	if bundle != "" {
		for _, o := range overrides {
			if strings.ToLower(strings.TrimSpace(o.BundleID)) == bundle {
				return o.product(), true
			}
		}
		if p, ok := byBundle[bundle]; ok {
			return p, true
		}
		if helperBundle(bundle) {
			return Product{}, false
		}
	}
	if name != "" {
		for _, o := range overrides {
			if o.BundleID == "" && NormName(o.Name) == name {
				return o.product(), true
			}
		}
		if rejectedNames[name] {
			return Product{}, false
		}
		if p, ok := byName[name]; ok {
			return p, true
		}
	}
	return Product{}, false
}

func helperBundle(bundle string) bool {
	for _, known := range allBundle {
		if strings.HasPrefix(bundle, known+".") {
			return true
		}
	}
	return false
}

// CuratedProducts is the table the NVD backfill walks, plus macOS.
func CuratedProducts() []Product {
	out := make([]Product, 0, len(catalog)+1)
	for _, c := range catalog {
		out = append(out, c.asProduct())
	}
	out = append(out, OSProduct())
	return out
}

// SyncProducts is the NVD product list: curated applications and operator
// overrides. macOS is left out. Apple's own releases name the fixed build
// per train, and a single NVD range crosses those trains.
func SyncProducts(overrides []Override) []Product {
	seen := map[string]bool{}
	var out []Product
	add := func(p Product) {
		if p.Vendor == "" || p.Product == "" || AppleOS(p.Vendor, p.Product) {
			return
		}
		key := p.Part + ":" + p.Vendor + ":" + p.Product
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, p)
	}
	for _, c := range catalog {
		add(c.asProduct())
	}
	for _, o := range overrides {
		add(o.product())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Product < out[j].Product
	})
	return out
}

// OSProduct is the macOS install itself, matched from the device record
// rather than from an app row.
func OSProduct() Product {
	return Product{Part: "o", Vendor: "apple", Product: "macos", VersionSource: "os", Names: []string{"macos"}, Munki: nil}
}

// Lookup returns the curated product for a vendor and product, if we have one.
func Lookup(vendor, product string) (Product, bool) {
	vendor = strings.ToLower(vendor)
	product = strings.ToLower(product)
	for _, c := range catalog {
		if c.vendor == vendor && c.product == product {
			return c.asProduct(), true
		}
	}
	if vendor == "apple" && (product == "macos" || product == "mac_os" || product == "mac_os_x") {
		return OSProduct(), true
	}
	return Product{}, false
}

// AppleOS reports vendor/product pairs whose NVD ranges cross macOS trains.
// Those ranges are stored and are not used for matching. The Apple security
// releases supply one fix per train.
func AppleOS(vendor, product string) bool {
	vendor = strings.ToLower(vendor)
	product = strings.ToLower(product)
	if vendor != "apple" {
		return false
	}
	switch product {
	case "macos", "mac_os", "mac_os_x", "mac_os_x_server":
		return true
	default:
		return false
	}
}

// ChooseVersion picks the version to compare. The short version is the one
// NVD and Apple publish. The bundle version is used only when the short
// version is missing and it has the same shape as the bounds.
func ChooseVersion(short, bundle string, bounds []string) (string, bool) {
	short = strings.TrimSpace(short)
	bundle = strings.TrimSpace(bundle)
	if short != "" {
		if len(bounds) == 0 || SameShape(short, bounds...) {
			return short, true
		}
		return short, false
	}
	if bundle == "" {
		return "", false
	}
	if len(bounds) > 0 && !SameShape(bundle, bounds...) {
		return bundle, false
	}
	return bundle, true
}

// SplitCPE splits a CPE 2.3 string and keeps escaped colons inside a field.
func SplitCPE(s string) []string {
	var parts []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ':' {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	parts = append(parts, b.String())
	return parts
}

// ParseCPE reads part, vendor, product, and version from a CPE 2.3 name.
func ParseCPE(criteria string) (part, vendor, product, version string, ok bool) {
	f := SplitCPE(strings.TrimSpace(criteria))
	if len(f) < 6 || !strings.EqualFold(f[0], "cpe") {
		return "", "", "", "", false
	}
	part = strings.ToLower(f[2])
	vendor = strings.ToLower(f[3])
	product = strings.ToLower(f[4])
	version = f[5]
	if vendor == "" || product == "" || vendor == "*" || product == "*" {
		return "", "", "", "", false
	}
	return part, vendor, product, version, true
}
