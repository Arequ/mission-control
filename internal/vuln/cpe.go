package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// CPEEntry is one name from the NVD CPE dictionary.
type CPEEntry struct {
	Name       string
	NameID     string
	Title      string
	Part       string
	Vendor     string
	Product    string
	TargetSW   string
	Deprecated bool
}

// CPEPage is one page of the CPE API 2.0.
type CPEPage struct {
	Entries []CPEEntry
	Total   int
	Start   int
}

type cpeDoc struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	Products     []struct {
		CPE struct {
			Deprecated bool   `json:"deprecated"`
			CPEName    string `json:"cpeName"`
			CPENameID  string `json:"cpeNameId"`
			Titles     []struct {
				Title string `json:"title"`
				Lang  string `json:"lang"`
			} `json:"titles"`
		} `json:"cpe"`
	} `json:"products"`
}

// ParseCPEDictionary reads a CPE API 2.0 response. Names that are not valid
// CPE 2.3 strings are dropped rather than failing the page.
func ParseCPEDictionary(body []byte) (CPEPage, error) {
	var doc cpeDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return CPEPage{}, fmt.Errorf("nvd cpe: %w", err)
	}
	out := CPEPage{Total: doc.TotalResults, Start: doc.StartIndex}
	for _, p := range doc.Products {
		part, vendor, product, _, ok := ParseCPE(p.CPE.CPEName)
		if !ok {
			continue
		}
		f := SplitCPE(p.CPE.CPEName)
		target := ""
		if len(f) > 10 {
			target = strings.ToLower(f[10])
		}
		title := ""
		for _, t := range p.CPE.Titles {
			if title == "" || strings.HasPrefix(strings.ToLower(t.Lang), "en") {
				title = t.Title
				if strings.HasPrefix(strings.ToLower(t.Lang), "en") {
					break
				}
			}
		}
		out.Entries = append(out.Entries, CPEEntry{
			Name: p.CPE.CPEName, NameID: p.CPE.CPENameID, Title: clipString(title, 200),
			Part: part, Vendor: vendor, Product: product, TargetSW: target, Deprecated: p.CPE.Deprecated,
		})
	}
	return out, nil
}

// CPEQuery is one keyword search of the CPE dictionary.
type CPEQuery struct {
	Keyword string
	Start   int
	PerPage int
}

// FetchCPEs searches the CPE dictionary at the same pace and with the same
// retry, redirect, and invalid-key rules as the CVE API.
func (c *NVDClient) FetchCPEs(ctx context.Context, q CPEQuery) (CPEPage, error) {
	kw := strings.TrimSpace(q.Keyword)
	if kw == "" || len(kw) > 100 {
		return CPEPage{}, fmt.Errorf("cpe keyword must be 1-100 characters")
	}
	var page CPEPage
	err := c.paced(ctx, func() (int, time.Duration, error) {
		base := c.Base
		if base == "" {
			base = "https://services.nvd.nist.gov/rest/json"
		}
		u, err := url.Parse(strings.TrimRight(base, "/") + "/cpes/2.0")
		if err != nil {
			return 0, 0, err
		}
		per := q.PerPage
		if per <= 0 || per > 2000 {
			per = 1000
		}
		v := url.Values{}
		v.Set("keywordSearch", kw)
		v.Set("resultsPerPage", strconv.Itoa(per))
		v.Set("startIndex", strconv.Itoa(q.Start))
		u.RawQuery = v.Encode()
		body, status, retry, err := c.get(ctx, u)
		if err != nil {
			return status, retry, err
		}
		page, err = ParseCPEDictionary(body)
		return status, 0, err
	})
	return page, err
}

// CPESubject is what a Munki item says about itself.
type CPESubject struct {
	Name        string
	DisplayName string
	Developer   string
	BundleID    string
}

// Keywords are the CPE searches to try, best first: the display name, then
// the item name with CamelCase split. Duplicates are dropped.
func (s CPESubject) Keywords() []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range []string{s.DisplayName, splitCamel(s.Name)} {
		words := words(raw)
		if len(words) > 4 {
			words = words[:4]
		}
		kw := strings.Join(words, " ")
		if kw == "" || len(kw) > 100 || seen[kw] {
			continue
		}
		seen[kw] = true
		out = append(out, kw)
	}
	return out
}

// CPECandidate is one vendor/product the dictionary offered.
type CPECandidate struct {
	Part     string   `json:"part"`
	Vendor   string   `json:"vendor"`
	Product  string   `json:"product"`
	Title    string   `json:"title"`
	Entries  int      `json:"entries"`
	Score    int      `json:"score"`
	Exact    bool     `json:"exact"`
	Evidence []string `json:"evidence"`
}

// CPEProposal is the mapping the server suggests. Only "high" is a clear
// single match; "medium" and "low" need a person to pick.
type CPEProposal struct {
	Confidence string         `json:"confidence"`
	Part       string         `json:"part"`
	Vendor     string         `json:"vendor"`
	Product    string         `json:"product"`
	Evidence   []string       `json:"evidence"`
	Candidates []CPECandidate `json:"candidates"`
}

// Confidence levels.
const (
	CPEHigh   = "high"
	CPEMedium = "medium"
	CPELow    = "low"
	CPENone   = "none"
)

// macTargets are target_sw values that can describe a Mac install. A product
// whose every CPE names another platform (android, iphone_os, windows) is a
// different build of the app and is not offered.
var macTargets = map[string]bool{"": true, "*": true, "-": true, "macos": true, "mac_os": true, "mac_os_x": true, "macos_x": true, "osx": true}

// Words left out when a developer string is compared with a CPE vendor.
var corpWords = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true, "corporation": true, "co": true,
	"company": true, "gmbh": true, "ag": true, "sa": true, "bv": true, "plc": true, "pty": true,
	"technologies": true, "technology": true, "software": true, "labs": true, "communications": true, "video": true,
	"the": true, "incorporated": true,
}

// ProposeCPE scores dictionary entries against a Munki item.
//
// A candidate is kept when its product names the app or its vendor is
// corroborated by the developer or bundle id. The result is "high" only when
// exactly one product matches the app name, the developer or bundle id
// agrees with its vendor, and no other product of a vendor in play also
// carries the app name (zoom:zoom next to zoom:zoom_client is ambiguous).
func ProposeCPE(sub CPESubject, entries []CPEEntry) CPEProposal {
	names := map[string]bool{}
	var nameTokens [][]string
	for _, raw := range []string{sub.DisplayName, splitCamel(sub.Name), sub.Name} {
		w := words(raw)
		if len(w) == 0 {
			continue
		}
		j := strings.Join(w, " ")
		if !names[j] {
			names[j] = true
			nameTokens = append(nameTokens, w)
		}
	}
	dev := devTokens(sub.Developer)
	bundle := bundleParts(sub.BundleID)

	type agg struct {
		c   CPECandidate
		mac int
	}
	byKey := map[string]*agg{}
	var order []string
	for _, e := range entries {
		if e.Deprecated || e.Part != "a" {
			continue
		}
		k := e.Vendor + ":" + e.Product
		a := byKey[k]
		if a == nil {
			a = &agg{c: CPECandidate{Part: e.Part, Vendor: e.Vendor, Product: e.Product, Title: titleStem(e.Title)}}
			byKey[k] = a
			order = append(order, k)
		}
		a.c.Entries++
		if macTargets[e.TargetSW] {
			a.mac++
		}
	}

	var cands []CPECandidate
	for _, k := range order {
		a := byKey[k]
		if a.mac == 0 {
			continue
		}
		c := a.c
		prod := strings.Join(words(strings.ReplaceAll(c.Product, "_", " ")), " ")
		vend := strings.Join(words(strings.ReplaceAll(c.Vendor, "_", " ")), " ")
		vendFlat := strings.ReplaceAll(vend, " ", "")
		partial := false
		switch {
		case names[prod]:
			c.Exact = true
			c.Score += 4
			c.Evidence = append(c.Evidence, fmt.Sprintf("product %q is the app name", c.Product))
		case names[vend+" "+prod]:
			c.Exact = true
			c.Score += 4
			c.Evidence = append(c.Evidence, fmt.Sprintf("vendor and product %q are the app name", c.Vendor+" "+c.Product))
		default:
			pt := words(prod)
			for _, nt := range nameTokens {
				if containsAll(pt, nt) || containsAll(nt, pt) {
					partial = true
					break
				}
			}
			if partial {
				c.Score++
				c.Evidence = append(c.Evidence, fmt.Sprintf("product %q shares words with the app name", c.Product))
			}
		}
		vendorBacked := false
		if len(dev) > 0 && (vend == strings.Join(dev, " ") || vendFlat == strings.Join(dev, "") || vend == dev[0]) {
			vendorBacked = true
			c.Score += 3
			c.Evidence = append(c.Evidence, fmt.Sprintf("vendor %q matches developer %q", c.Vendor, strings.TrimSpace(sub.Developer)))
		}
		for _, part := range bundle {
			if part == vendFlat {
				vendorBacked = true
				c.Score += 3
				c.Evidence = append(c.Evidence, fmt.Sprintf("vendor %q is in bundle id %s", c.Vendor, sub.BundleID))
				break
			}
			if len(vendFlat) >= 4 && strings.HasPrefix(part, vendFlat) {
				vendorBacked = true
				c.Score += 2
				c.Evidence = append(c.Evidence, fmt.Sprintf("bundle id %s starts with vendor %q", sub.BundleID, c.Vendor))
				break
			}
		}
		if !vendorBacked && names[vend] {
			c.Score++
			c.Evidence = append(c.Evidence, fmt.Sprintf("vendor %q is the app name", c.Vendor))
		}
		if !c.Exact && !partial && !vendorBacked {
			// A keyword hit in the title alone is noise: a plugin or library
			// that mentions the app.
			continue
		}
		if a.mac < c.Entries {
			c.Evidence = append(c.Evidence, fmt.Sprintf("%d of %d CPE names are for other platforms", c.Entries-a.mac, c.Entries))
		}
		cands = append(cands, c)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].Score != cands[j].Score {
			return cands[i].Score > cands[j].Score
		}
		if cands[i].Entries != cands[j].Entries {
			return cands[i].Entries > cands[j].Entries
		}
		if cands[i].Vendor != cands[j].Vendor {
			return cands[i].Vendor < cands[j].Vendor
		}
		return cands[i].Product < cands[j].Product
	})
	if len(cands) == 0 {
		return CPEProposal{Confidence: CPENone, Evidence: []string{"no macOS application in the NVD CPE dictionary matches this name"}, Candidates: []CPECandidate{}}
	}
	if len(cands) > 6 {
		cands = cands[:6]
	}
	top := cands[0]
	out := CPEProposal{Part: top.Part, Vendor: top.Vendor, Product: top.Product, Evidence: append([]string(nil), top.Evidence...), Candidates: cands}

	exact := 0
	for _, c := range cands {
		if c.Exact {
			exact++
		}
	}
	corroborated := top.Score >= 7 // exact name plus developer or bundle id
	rival := ""
	for _, c := range cands[1:] {
		if c.Exact || (c.Vendor == top.Vendor && sharesName(c, nameTokens)) {
			rival = c.Vendor + ":" + c.Product
			break
		}
	}
	switch {
	case top.Exact && exact == 1 && corroborated && rival == "":
		out.Confidence = CPEHigh
	case top.Exact:
		out.Confidence = CPEMedium
		switch {
		case rival != "":
			out.Evidence = append(out.Evidence, "also close: "+rival)
		case !corroborated:
			out.Evidence = append(out.Evidence, "neither the developer nor the bundle id confirms the vendor")
		}
	default:
		out.Confidence = CPELow
		out.Evidence = append(out.Evidence, "no product is named exactly like the app")
	}
	return out
}

func sharesName(c CPECandidate, nameTokens [][]string) bool {
	pt := words(strings.ReplaceAll(c.Product, "_", " "))
	for _, nt := range nameTokens {
		if containsAll(pt, nt) {
			return true
		}
	}
	return false
}

func containsAll(have, want []string) bool {
	if len(want) == 0 || len(have) == 0 {
		return false
	}
	set := map[string]bool{}
	for _, w := range have {
		set[w] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// words lowercases s and splits it on anything that is not a letter or digit.
// A trailing ".app" is dropped.
func words(s string) []string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(strings.ToLower(s), ".app") {
		s = s[:len(s)-4]
	}
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// splitCamel turns a Munki item name like GoogleChrome or VSCode into words.
func splitCamel(s string) string {
	rs := []rune(strings.TrimSpace(s))
	var b strings.Builder
	for i, r := range rs {
		if i > 0 && unicode.IsUpper(r) {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteRune(' ')
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

func devTokens(s string) []string {
	var out []string
	for _, w := range words(s) {
		if !corpWords[w] {
			out = append(out, w)
		}
	}
	return out
}

// bundleParts are the bundle id components after the reverse-DNS prefix.
func bundleParts(s string) []string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(parts) < 2 {
		return nil
	}
	var out []string
	for _, p := range parts[1:] {
		if p = strings.Join(words(p), ""); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// titleStem keeps the words of a CPE title before the first one that starts
// with a digit, so "Slack 4.41.105 for macOS" is shown as "Slack".
func titleStem(t string) string {
	f := strings.Fields(t)
	for i, w := range f {
		if i > 0 && len(w) > 0 && unicode.IsDigit([]rune(w)[0]) {
			return strings.Join(f[:i], " ")
		}
	}
	return t
}

func clipString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// OverrideHCL is the cpe_override block to paste into the config repo. Munki
// items match on name; the bundle id block also maps the installed app in
// device inventory.
func OverrideHCL(name, bundleID, vendor, product string) string {
	var b strings.Builder
	block := func(match, value string) {
		// terraform fmt aligns "=" on the longest key in the block.
		width := len("product")
		if len(match) > width {
			width = len(match)
		}
		b.WriteString("cpe_override {\n")
		for _, kv := range [][2]string{{match, value}, {"vendor", vendor}, {"product", product}} {
			fmt.Fprintf(&b, "  %-*s = %s\n", width, kv[0], hclString(kv[1]))
		}
		b.WriteString("}\n")
	}
	block("name", name)
	if strings.TrimSpace(bundleID) != "" {
		b.WriteString("\n")
		block("bundle_id", bundleID)
	}
	return b.String()
}

// hclString quotes s for HCL, including the template sequences, so a hostile
// pkginfo name cannot inject an interpolation into pasted config.
func hclString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case (r == '$' || r == '%') && i+1 < len(rs) && rs[i+1] == '{':
			b.WriteRune(r)
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
