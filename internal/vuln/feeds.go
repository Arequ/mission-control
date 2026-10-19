package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Feeds is the optional HTTP side of vulnerability sync. A nil HTTP client
// means scheduled sync does nothing, which keeps unit tests off the network.
type Feeds struct {
	HTTP      *http.Client
	NVDBase   string
	KEVURL    string
	EPSSURL   string
	MacOSURL  string
	SafariURL string
	Sleep     func(context.Context, time.Duration) error
	Now       func() time.Time
}

// KEVItem is one CISA known-exploited entry.
type KEVItem struct {
	CVE   string
	Name  string
	Added time.Time
	Due   time.Time
}

// EPSSItem is one FIRST score. The score is unknown until a row is returned.
type EPSSItem struct {
	CVE        string
	Score      float64
	Percentile float64
}

// Rapid7Finding is evidence from a connector. It never creates a CVE.
type Rapid7Finding struct {
	CVE          string
	Software     string
	Version      string
	Serial       string
	HardwareUUID string
	Hostname     string
}

// Rapid7Source is the rapid7 connector, either the API test double or Elastic.
type Rapid7Source struct {
	Mode       string
	BaseURL    string
	Token      string
	ElasticURL string
	APIKey     string
	Index      string
	FieldMap   map[string]string
}

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ValidCVE reports whether id is a CVE name we are willing to store.
func ValidCVE(id string) bool {
	return cveIDPattern.MatchString(strings.ToUpper(strings.TrimSpace(id)))
}

// ParseKEV reads the CISA catalog. Dates are civil days.
func ParseKEV(body []byte) ([]KEVItem, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVE         string `json:"cveID"`
			Name        string `json:"vulnerabilityName"`
			DateAdded   string `json:"dateAdded"`
			DueDate     string `json:"dueDate"`
			Description string `json:"shortDescription"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]KEVItem, 0, len(doc.Vulnerabilities))
	for _, row := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(row.CVE))
		if !ValidCVE(id) {
			continue
		}
		name := row.Name
		if name == "" {
			name = row.Description
		}
		out = append(out, KEVItem{
			CVE: id, Name: name,
			Added: parseCivil(row.DateAdded), Due: parseCivil(row.DueDate),
		})
	}
	return out, nil
}

func parseCivil(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// ParseEPSS reads a FIRST page. Scores are strings in the payload.
func ParseEPSS(body []byte) ([]EPSSItem, error) {
	var doc struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]EPSSItem, 0, len(doc.Data))
	for _, row := range doc.Data {
		id := strings.ToUpper(strings.TrimSpace(row.CVE))
		if !ValidCVE(id) {
			continue
		}
		score, err := strconv.ParseFloat(row.EPSS, 64)
		if err != nil {
			continue
		}
		pct, _ := strconv.ParseFloat(row.Percentile, 64)
		out = append(out, EPSSItem{CVE: id, Score: score, Percentile: pct})
	}
	return out, nil
}

// EPSSQuery is one batched request. FIRST accepts about one hundred ids.
func EPSSQuery(base string, cves []string) (string, error) {
	if base == "" {
		base = "https://api.first.org/data/v1/epss"
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ids := make([]string, 0, len(cves))
	for _, id := range cves {
		id = strings.ToUpper(strings.TrimSpace(id))
		if ValidCVE(id) {
			ids = append(ids, id)
		}
	}
	q := u.Query()
	q.Set("cve", strings.Join(ids, ","))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SOFAFix is one per-train fix parsed from Apple's structured feed.
type SOFAFix struct {
	CVE   string
	Train Train
}

// ParseSOFARecords returns the earliest fix per CVE and major.
func ParseSOFARecords(body []byte, product string) ([]SOFAFix, error) {
	var doc struct {
		OSVersions     []sofaSeries `json:"OSVersions"`
		SafariVersions []sofaSeries `json:"SafariVersions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	series := doc.OSVersions
	part := "o"
	name := "macos"
	if product == "safari" || (product == "" && len(series) == 0 && len(doc.SafariVersions) > 0) {
		series = doc.SafariVersions
		part = "a"
		name = "safari"
	}
	if product == "safari" {
		series = doc.SafariVersions
		part = "a"
		name = "safari"
	}
	type hit struct {
		version, build string
	}
	best := map[string]hit{}
	consider := func(rel sofaRelease) {
		if strings.TrimSpace(rel.ProductVersion) == "" {
			return
		}
		major, ok := Major(rel.ProductVersion)
		if !ok {
			return
		}
		for _, id := range rel.cves() {
			id = strings.ToUpper(id)
			if !ValidCVE(id) {
				continue
			}
			key := id + "|" + strconv.Itoa(major)
			next := hit{version: rel.ProductVersion, build: rel.Build}
			cur, exists := best[key]
			if !exists || versionLess(next.version, cur.version) {
				best[key] = next
				continue
			}
			if next.version == cur.version && next.build != "" && (cur.build == "" || versionLess(next.build, cur.build)) {
				best[key] = next
			}
		}
	}
	for _, s := range series {
		if s.Latest != nil {
			consider(*s.Latest)
		}
		for _, rel := range s.SecurityReleases {
			consider(rel)
		}
	}
	keys := make([]string, 0, len(best))
	for k := range best {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]SOFAFix, 0, len(keys))
	for _, key := range keys {
		id, majorText, _ := strings.Cut(key, "|")
		major, _ := strconv.Atoi(majorText)
		h := best[key]
		out = append(out, SOFAFix{
			CVE: id,
			Train: Train{
				Part: part, Vendor: "apple", Product: name, Major: major,
				FixedVersion: h.version, FixedBuild: h.build, Mode: "independent",
			},
		})
	}
	return out, nil
}

type sofaSeries struct {
	Latest           *sofaRelease  `json:"Latest"`
	SecurityReleases []sofaRelease `json:"SecurityReleases"`
}

type sofaRelease struct {
	ProductVersion string          `json:"ProductVersion"`
	Build          string          `json:"Build"`
	CVEs           json.RawMessage `json:"CVEs"`
}

func (r sofaRelease) cves() []string {
	if len(r.CVEs) == 0 || string(r.CVEs) == "null" {
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(r.CVEs, &obj) == nil && obj != nil {
		ids := make([]string, 0, len(obj))
		for id := range obj {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return ids
	}
	var arr []string
	if json.Unmarshal(r.CVEs, &arr) == nil {
		return arr
	}
	return nil
}

// ParseRapid7API reads the test-double findings body.
func ParseRapid7API(body []byte) ([]Rapid7Finding, error) {
	var doc struct {
		Findings []struct {
			CVE          string `json:"cve"`
			Software     string `json:"software"`
			Version      string `json:"version"`
			Serial       string `json:"serial"`
			HardwareUUID string `json:"hardware_uuid"`
			Hostname     string `json:"hostname"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]Rapid7Finding, 0, len(doc.Findings))
	for _, row := range doc.Findings {
		id := strings.ToUpper(strings.TrimSpace(row.CVE))
		if !ValidCVE(id) {
			continue
		}
		out = append(out, Rapid7Finding{
			CVE: id, Software: row.Software, Version: row.Version,
			Serial: row.Serial, HardwareUUID: row.HardwareUUID, Hostname: row.Hostname,
		})
	}
	return out, nil
}

// FetchRapid7 loads findings. API mode is a test double, the same shape as
// the other Rapid7 connector stub, not the InsightVM API. Elastic mode reads
// the mapped index. A full page is followed by the next page. A short page stops.
func FetchRapid7(ctx context.Context, hc *http.Client, src Rapid7Source) ([]Rapid7Finding, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if src.Mode == "elastic" || (src.Mode == "" && src.ElasticURL != "") {
		return fetchRapid7Elastic(ctx, hc, src)
	}
	base := strings.TrimRight(src.BaseURL, "/")
	if base == "" {
		return nil, fmt.Errorf("rapid7 connector has no base url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/findings", nil)
	if err != nil {
		return nil, err
	}
	if src.Token != "" {
		req.Header.Set("Authorization", "Bearer "+src.Token)
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("rapid7 status %d", res.StatusCode)
	}
	return ParseRapid7API(body)
}

func fetchRapid7Elastic(ctx context.Context, hc *http.Client, src Rapid7Source) ([]Rapid7Finding, error) {
	base := strings.TrimRight(src.ElasticURL, "/")
	index := strings.Trim(strings.TrimSpace(src.Index), "/")
	if base == "" || index == "" {
		return nil, fmt.Errorf("rapid7 elastic connector needs a url and an index")
	}
	if strings.Contains(index, "..") || strings.ContainsAny(index, " ?#") {
		return nil, fmt.Errorf("index pattern is not a single path")
	}
	var out []Rapid7Finding
	var searchAfter []any
	for page := 0; page < 10; page++ {
		body := map[string]any{
			"size":  200,
			"sort":  []any{map[string]any{"_shard_doc": "asc"}},
			"query": map[string]any{"match_all": map[string]any{}},
		}
		if searchAfter != nil {
			body["search_after"] = searchAfter
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/"+index+"/_search", bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if src.APIKey != "" {
			req.Header.Set("Authorization", "ApiKey "+src.APIKey)
		}
		res, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		payload, err := io.ReadAll(io.LimitReader(res.Body, 12<<20))
		res.Body.Close()
		if err != nil {
			return nil, err
		}
		if res.StatusCode >= 300 {
			return nil, fmt.Errorf("elastic status %d", res.StatusCode)
		}
		var doc struct {
			Hits struct {
				Hits []struct {
					Source map[string]any `json:"_source"`
					Sort   []any          `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(payload, &doc); err != nil {
			return nil, err
		}
		hits := doc.Hits.Hits
		if len(hits) == 0 {
			break
		}
		for _, hit := range hits {
			row := rapid7FromSource(hit.Source, src.FieldMap)
			if row.CVE != "" {
				out = append(out, row)
			}
			if len(hit.Sort) > 0 {
				searchAfter = hit.Sort
			}
		}
		if len(hits) < 200 {
			break
		}
	}
	return out, nil
}

func rapid7FromSource(src map[string]any, fieldMap map[string]string) Rapid7Finding {
	get := func(key, fallback string) string {
		path := fieldMap[key]
		if path == "" {
			path = fallback
		}
		return dig(src, path)
	}
	id := strings.ToUpper(get("cve", "cve"))
	if !ValidCVE(id) {
		return Rapid7Finding{}
	}
	return Rapid7Finding{
		CVE: id, Software: get("software", "software"), Version: get("version", "version"),
		Serial: get("serial", "serial"), HardwareUUID: get("hardware_uuid", "hardware_uuid"),
		Hostname: get("hostname", "hostname"),
	}
}

func dig(v any, path string) string {
	cur := v
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[part]
	}
	switch t := cur.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

// GetJSON fetches a feed document.
func GetJSON(ctx context.Context, hc *http.Client, rawURL string) ([]byte, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("feed status %d", res.StatusCode)
	}
	return body, nil
}
