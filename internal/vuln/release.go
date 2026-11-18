package vuln

import (
	"fmt"
	"sort"
	"strings"
)

// ReleaseCVE is one CVE a new build fixes or still carries, with the feed
// scores it was judged on. Source is "ranges" when NVD's affected versions
// placed it, or "release_notes" when the vendor's notes named it.
type ReleaseCVE struct {
	CVE       string  `json:"cve"`
	CVSS      float64 `json:"cvss"`
	Severity  string  `json:"severity"`
	KEV       bool    `json:"kev"`
	EPSS      float64 `json:"epss"`
	EPSSKnown bool    `json:"epss_known"`
	Scored    bool    `json:"scored"`
	Source    string  `json:"source"`
}

// Rush thresholds. A fix for any one of these makes a build HIGH.
const (
	RushCVSS     = 9.0
	RushHighCVSS = 7.0
	RushEPSS     = 0.10
)

// Urgent reports whether fixing c justifies skipping the soak: it is known
// exploited, critical, or high with a meaningful chance of exploitation.
func Urgent(c ReleaseCVE) bool {
	return c.KEV || c.CVSS >= RushCVSS || (c.CVSS >= RushHighCVSS && c.EPSSKnown && c.EPSS >= RushEPSS)
}

// ReleaseInput is what the server knows about a new build when it judges it.
type ReleaseInput struct {
	Mapped       bool   // the item maps to an NVD product
	Baseline     string // version in the final catalog, or ""
	Fixed        []ReleaseCVE
	Open         []ReleaseCVE
	Exposed      int  // devices with an active finding on this product
	NotesDone    bool // the advisor finished reading the release notes
	NotesSecFix  bool // the notes say the release has security fixes
	NotesNoScore []string
}

// ReleaseVerdict is the priority and the reasons a reviewer sees. The verdict
// only recommends; it never promotes anything.
type ReleaseVerdict struct {
	Priority string   `json:"priority"`
	Reasons  []string `json:"reasons"`
}

// JudgeRelease turns feed data into HIGH or LOW. The advisor's own opinion is
// not an input: a model reading a vendor page can be wrong or steered, so only
// CVEs scored by NVD, KEV, and EPSS move the priority.
func JudgeRelease(in ReleaseInput) ReleaseVerdict {
	var reasons []string
	urgent := []ReleaseCVE{}
	for _, c := range in.Fixed {
		if Urgent(c) {
			urgent = append(urgent, c)
		}
	}
	sort.Slice(urgent, func(i, j int) bool { return rank(urgent[i]) > rank(urgent[j]) })
	for _, c := range urgent {
		reasons = append(reasons, "Fixes "+describe(c))
	}
	if len(urgent) > 0 && in.Exposed > 0 {
		reasons = append(reasons, fmt.Sprintf("%d device(s) run a vulnerable version now", in.Exposed))
	}
	if len(urgent) > 0 {
		return ReleaseVerdict{Priority: "high", Reasons: reasons}
	}

	switch {
	case len(in.Fixed) > 0:
		reasons = append(reasons, fmt.Sprintf("Fixes %d CVE(s), none known exploited, critical, or likely to be exploited", len(in.Fixed)))
	case !in.Mapped && len(in.NotesNoScore) == 0:
		reasons = append(reasons, "No NVD product mapping for this app, so no CVE data from the feeds")
	case in.Baseline == "":
		reasons = append(reasons, "Nothing in the final catalog to compare against")
	default:
		reasons = append(reasons, "No known CVEs fixed since "+in.Baseline)
	}
	if len(in.NotesNoScore) > 0 {
		reasons = append(reasons, "Release notes name "+strings.Join(in.NotesNoScore, ", ")+", not scored yet by NVD")
	}
	if in.NotesSecFix && len(in.Fixed) == 0 {
		reasons = append(reasons, "Release notes mention security fixes without CVE IDs")
	}
	if !in.NotesDone {
		reasons = append(reasons, "Release notes not read yet")
	}
	if len(in.Open) > 0 {
		reasons = append(reasons, fmt.Sprintf("Still affected by %d known CVE(s)", len(in.Open)))
	}
	return ReleaseVerdict{Priority: "low", Reasons: reasons}
}

func rank(c ReleaseCVE) float64 {
	r := c.CVSS
	if c.KEV {
		r += 100
	}
	return r
}

func describe(c ReleaseCVE) string {
	parts := []string{}
	if c.Scored {
		parts = append(parts, fmt.Sprintf("CVSS %.1f", c.CVSS))
	}
	if c.KEV {
		parts = append(parts, "known exploited")
	}
	if c.EPSSKnown && c.EPSS >= RushEPSS {
		parts = append(parts, fmt.Sprintf("EPSS %.0f%%", c.EPSS*100))
	}
	if len(parts) == 0 {
		return c.CVE
	}
	return c.CVE + " (" + strings.Join(parts, ", ") + ")"
}

// MatchMunkiName maps a Munki item name to a product: operator overrides and
// curated display names first, then the curated Munki aliases (GoogleChrome).
func MatchMunkiName(name string, overrides []Override) (Product, bool) {
	if p, ok := MatchSoftware(name, "", overrides); ok {
		return p, true
	}
	for _, c := range catalog {
		for _, alias := range c.munki {
			if strings.EqualFold(alias, strings.TrimSpace(name)) {
				return c.asProduct(), true
			}
		}
	}
	return Product{}, false
}

// AffectedCVEs lists the CVEs from idx whose bounds include version.
func AffectedCVEs(idx *Index, p Product, version string) map[string]bool {
	out := map[string]bool{}
	if strings.TrimSpace(version) == "" {
		return out
	}
	for _, hit := range idx.MatchProduct(p.Vendor, p.Product, version, "", "") {
		if AffectedInstall(version, "", "", hit.Ranges, hit.Trains) {
			out[hit.CVE] = true
		}
	}
	return out
}
