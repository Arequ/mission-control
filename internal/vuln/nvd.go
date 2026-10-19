package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Record is one CVE plus the ranges we are willing to match.
type Record struct {
	ID          string
	Description string
	Score       float64
	Vector      string
	Severity    string
	Published   time.Time
	Modified    time.Time
	Ranges      []ProductBound
	Trains      []Train
	KEV         bool
	KEVAdded    time.Time
	KEVDue      time.Time
	KEVName     string
	Source      string
}

// ProductBound is a version interval for one CPE product.
type ProductBound struct {
	Part, Vendor, Product string
	Bound                 Bound
}

// NVDQuery is one page of the CVE API 2.0.
type NVDQuery struct {
	Part, Vendor, Product string
	Start                 int
	PerPage               int
	ModStart              time.Time
	ModEnd                time.Time
}

// NVDPage is one response page.
type NVDPage struct {
	CVEs  []Record
	Total int
	Start int
}

// SyncResult is the progress of an incremental NVD walk.
type SyncResult struct {
	CVEs   []Record
	Cursor string
	Done   bool
	Calls  int
}

const (
	nvdTimeLayout = "2006-01-02T15:04:05.000"
	nvdWindow     = 119 * 24 * time.Hour
)

// SplitWindows divides a lastModified span into pieces NVD will accept.
// The next window starts where the previous one ended, so a CVE stamped on
// the boundary is fetched twice and a gap is not left between them.
func SplitWindows(start, end time.Time, span time.Duration) [][2]time.Time {
	if span <= 0 {
		span = nvdWindow
	}
	if !start.Before(end) {
		return [][2]time.Time{{start, end}}
	}
	var out [][2]time.Time
	cur := start
	for cur.Before(end) {
		next := cur.Add(span)
		if next.After(end) {
			next = end
		}
		out = append(out, [2]time.Time{cur, next})
		if !next.After(cur) {
			break
		}
		cur = next
	}
	return out
}

// SyncNVD walks products page by page. maxCalls bounds one scheduler run so
// a rate limit or a large product does not have to finish in a single pass.
// The cursor resumes the same page; it does not skip ahead of a short page.
func SyncNVD(ctx context.Context, products []Product, cursor string, now time.Time, maxCalls, pageSize int, fetch func(context.Context, NVDQuery) (NVDPage, error)) (SyncResult, error) {
	if maxCalls <= 0 {
		maxCalls = 8
	}
	if pageSize <= 0 {
		pageSize = 200
	}
	if len(products) == 0 {
		return SyncResult{Cursor: cursor, Done: true}, nil
	}
	mode, modStart, idx, start := parseNVDCursor(cursor)
	if idx < 0 || idx >= len(products) {
		idx, start = 0, 0
	}
	var out SyncResult
	index := map[string]int{}
	appendPage := func(page NVDPage) {
		for _, cve := range page.CVEs {
			if cve.ID == "" {
				continue
			}
			if i, ok := index[cve.ID]; ok {
				out.CVEs[i] = mergeRecord(out.CVEs[i], cve)
				continue
			}
			index[cve.ID] = len(out.CVEs)
			out.CVEs = append(out.CVEs, cve)
		}
	}
	for out.Calls < maxCalls {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if mode == "backfill" {
			p := products[idx]
			page, err := fetch(ctx, NVDQuery{Part: p.Part, Vendor: p.Vendor, Product: p.Product, Start: start, PerPage: pageSize})
			out.Calls++
			if err != nil {
				out.Cursor = formatBackfill(idx, start)
				return out, err
			}
			appendPage(page)
			next, done, stall := advance(start, len(page.CVEs), page.Total)
			if stall {
				out.Cursor = formatBackfill(idx, start)
				return out, fmt.Errorf("nvd page at %d returned no rows before total %d", start, page.Total)
			}
			if !done {
				start = next
				out.Cursor = formatBackfill(idx, start)
				continue
			}
			idx++
			start = 0
			if idx >= len(products) {
				out.Cursor = formatMod(now, -1, 0)
				out.Done = true
				return out, nil
			}
			out.Cursor = formatBackfill(idx, 0)
			continue
		}
		if !modStart.Before(now) {
			out.Cursor = formatMod(now, -1, 0)
			out.Done = true
			return out, nil
		}
		windows := SplitWindows(modStart, now, nvdWindow)
		// The cursor names the window start. A later window is a new cursor.
		window := windows[0]
		p := products[idx]
		page, err := fetch(ctx, NVDQuery{
			Part: p.Part, Vendor: p.Vendor, Product: p.Product,
			Start: start, PerPage: pageSize, ModStart: window[0], ModEnd: window[1],
		})
		out.Calls++
		if err != nil {
			out.Cursor = formatMod(window[0], idx, start)
			return out, err
		}
		appendPage(page)
		next, done, stall := advance(start, len(page.CVEs), page.Total)
		if stall {
			out.Cursor = formatMod(window[0], idx, start)
			return out, fmt.Errorf("nvd page at %d returned no rows before total %d", start, page.Total)
		}
		if !done {
			start = next
			out.Cursor = formatMod(window[0], idx, start)
			continue
		}
		idx++
		start = 0
		if idx < len(products) {
			out.Cursor = formatMod(window[0], idx, 0)
			continue
		}
		if window[1].Before(now) {
			modStart = window[1]
			idx = 0
			out.Cursor = formatMod(modStart, 0, 0)
			continue
		}
		out.Cursor = formatMod(now, -1, 0)
		out.Done = true
		return out, nil
	}
	return out, nil
}

func advance(start, n, total int) (next int, done bool, stall bool) {
	if n == 0 {
		if total > start {
			return start, false, true
		}
		return 0, true, false
	}
	next = start + n
	if total >= 0 && next >= total {
		return 0, true, false
	}
	if total < 0 && n == 0 {
		return 0, true, false
	}
	return next, false, false
}

func parseNVDCursor(c string) (mode string, modStart time.Time, idx, start int) {
	c = strings.TrimSpace(c)
	if c == "" {
		return "backfill", time.Time{}, 0, 0
	}
	parts := strings.Split(c, "|")
	switch parts[0] {
	case "backfill":
		if len(parts) == 3 {
			idx, _ = strconv.Atoi(parts[1])
			start, _ = strconv.Atoi(parts[2])
		}
		return "backfill", time.Time{}, idx, start
	case "mod":
		if len(parts) < 2 {
			return "backfill", time.Time{}, 0, 0
		}
		t, err := time.Parse(time.RFC3339Nano, parts[1])
		if err != nil {
			return "backfill", time.Time{}, 0, 0
		}
		idx, start = 0, 0
		if len(parts) == 4 {
			idx, _ = strconv.Atoi(parts[2])
			start, _ = strconv.Atoi(parts[3])
		} else {
			idx = -1
		}
		if idx < 0 {
			return "mod", t, 0, 0
		}
		return "mod", t, idx, start
	default:
		return "backfill", time.Time{}, 0, 0
	}
}

func formatBackfill(idx, start int) string {
	return fmt.Sprintf("backfill|%d|%d", idx, start)
}

func (b Bound) ranged() bool {
	return b.StartIncl != "" || b.StartExcl != "" || b.EndIncl != "" || b.EndExcl != ""
}

func mergeRecord(dst, src Record) Record {
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if src.Score > dst.Score {
		dst.Score, dst.Vector, dst.Severity = src.Score, src.Vector, src.Severity
	}
	if dst.Published.IsZero() {
		dst.Published = src.Published
	}
	if src.Modified.After(dst.Modified) {
		dst.Modified = src.Modified
	}
	seen := map[string]bool{}
	for _, r := range dst.Ranges {
		seen[boundKey(r)] = true
	}
	for _, r := range src.Ranges {
		k := boundKey(r)
		if seen[k] {
			continue
		}
		seen[k] = true
		dst.Ranges = append(dst.Ranges, r)
	}
	return dst
}

func boundKey(r ProductBound) string {
	b := r.Bound
	return strings.Join([]string{r.Part, r.Vendor, r.Product, b.StartIncl, b.StartExcl, b.EndIncl, b.EndExcl, b.Exact}, "|")
}

func formatMod(t time.Time, idx, start int) string {
	if idx < 0 {
		return "mod|" + t.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("mod|%s|%d|%d", t.UTC().Format(time.RFC3339Nano), idx, start)
}

// NVDClient calls the CVE API. The key is sent as a header and never as a
// query parameter, so it does not land in an access log.
type NVDClient struct {
	Base    string
	Key     string
	HTTP    *http.Client
	Sleep   func(context.Context, time.Duration) error
	Now     func() time.Time
	last    time.Time
	Retries int
}

func (c *NVDClient) pace() time.Duration {
	if strings.TrimSpace(c.Key) != "" {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

func (c *NVDClient) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *NVDClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Fetch downloads one page, honoring Retry-After on 429 and 403.
func (c *NVDClient) Fetch(ctx context.Context, q NVDQuery) (NVDPage, error) {
	if !c.last.IsZero() {
		wait := c.pace() - c.now().Sub(c.last)
		if err := c.sleep(ctx, wait); err != nil {
			return NVDPage{}, err
		}
	}
	retries := c.Retries
	if retries <= 0 {
		retries = 4
	}
	var last error
	for attempt := 0; attempt < retries; attempt++ {
		c.last = c.now()
		page, status, retry, err := c.once(ctx, q)
		if err == nil && status < 300 {
			return page, nil
		}
		if status != http.StatusTooManyRequests && status != http.StatusForbidden && status != http.StatusServiceUnavailable {
			if err != nil {
				return NVDPage{}, err
			}
			return NVDPage{}, fmt.Errorf("nvd status %d", status)
		}
		if retry <= 0 {
			retry = time.Duration(1<<attempt) * time.Second
		}
		last = err
		if last == nil {
			last = fmt.Errorf("nvd status %d", status)
		}
		if err := c.sleep(ctx, retry); err != nil {
			return NVDPage{}, err
		}
	}
	if last == nil {
		last = fmt.Errorf("nvd rate limit")
	}
	return NVDPage{}, last
}

func (c *NVDClient) once(ctx context.Context, q NVDQuery) (NVDPage, int, time.Duration, error) {
	base := c.Base
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json"
	}
	u, err := url.Parse(strings.TrimRight(base, "/") + "/cves/2.0")
	if err != nil {
		return NVDPage{}, 0, 0, err
	}
	per := q.PerPage
	if per <= 0 {
		per = 200
	}
	v := url.Values{}
	v.Set("virtualMatchString", fmt.Sprintf("cpe:2.3:%s:%s:%s:*:*:*:*:*:*:*", q.Part, q.Vendor, q.Product))
	v.Set("resultsPerPage", strconv.Itoa(per))
	v.Set("startIndex", strconv.Itoa(q.Start))
	if !q.ModStart.IsZero() {
		end := q.ModEnd
		if end.IsZero() {
			end = c.now()
		}
		v.Set("lastModStartDate", q.ModStart.UTC().Format(nvdTimeLayout))
		v.Set("lastModEndDate", end.UTC().Format(nvdTimeLayout))
	}
	u.RawQuery = v.Encode()
	if strings.Contains(strings.ToLower(u.RawQuery), "apikey") {
		return NVDPage{}, 0, 0, fmt.Errorf("refusing to put the api key in the query")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return NVDPage{}, 0, 0, err
	}
	if c.Key != "" {
		req.Header.Set("apiKey", c.Key)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return NVDPage{}, 0, 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return NVDPage{}, res.StatusCode, 0, err
	}
	if res.StatusCode >= 300 {
		return NVDPage{}, res.StatusCode, retryAfter(res, c.now()), fmt.Errorf("nvd status %d", res.StatusCode)
	}
	page, err := ParseNVD(body)
	return page, res.StatusCode, 0, err
}

func retryAfter(res *http.Response, now time.Time) time.Duration {
	v := strings.TrimSpace(res.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

type nvdDoc struct {
	TotalResults    int `json:"totalResults"`
	StartIndex      int `json:"startIndex"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        map[string]json.RawMessage `json:"metrics"`
	Configurations []struct {
		Nodes []nvdNode `json:"nodes"`
	} `json:"configurations"`
}

type nvdNode struct {
	Negate   bool `json:"negate"`
	CPEMatch []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"criteria"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionStartExcluding string `json:"versionStartExcluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
		VersionEndExcluding   string `json:"versionEndExcluding"`
	} `json:"cpeMatch"`
	Children []nvdNode `json:"children"`
}

// ParseNVD reads one CVE API 2.0 body. Negated nodes and non-vulnerable CPE
// matches are ignored so a "running on" platform row does not become a range.
func ParseNVD(body []byte) (NVDPage, error) {
	var doc nvdDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return NVDPage{}, err
	}
	page := NVDPage{Total: doc.TotalResults, Start: doc.StartIndex}
	for _, wrap := range doc.Vulnerabilities {
		cve := wrap.CVE
		rec := Record{
			ID: cve.ID, Description: nvdEnglish(cve), Source: "nvd",
			Published: parseNVDTime(cve.Published), Modified: parseNVDTime(cve.LastModified),
		}
		rec.Score, rec.Vector, rec.Severity = cvss(cve.Metrics)
		if rec.Severity == "" {
			rec.Severity = Severity(rec.Score)
		}
		for _, cfg := range cve.Configurations {
			walkNodes(cfg.Nodes, &rec)
		}
		if rec.ID != "" {
			page.CVEs = append(page.CVEs, rec)
		}
	}
	return page, nil
}

func walkNodes(nodes []nvdNode, rec *Record) {
	for _, n := range nodes {
		if n.Negate {
			continue
		}
		for _, m := range n.CPEMatch {
			if !m.Vulnerable {
				continue
			}
			part, vendor, product, version, ok := ParseCPE(m.Criteria)
			if !ok {
				continue
			}
			b := Bound{
				StartIncl: m.VersionStartIncluding, StartExcl: m.VersionStartExcluding,
				EndIncl: m.VersionEndIncluding, EndExcl: m.VersionEndExcluding,
			}
			// A ranged CPE uses "*" in the version field. A concrete version is
			// an exact match only when NVD did not also send a range. Letting
			// the version win would hide every other build in the range.
			if version != "" && version != "*" && version != "-" && !b.ranged() {
				b.Exact = version
			}
			rec.Ranges = append(rec.Ranges, ProductBound{Part: part, Vendor: vendor, Product: product, Bound: b})
		}
		walkNodes(n.Children, rec)
	}
}

func nvdEnglish(cve nvdCVE) string {
	for _, d := range cve.Descriptions {
		if d.Lang == "en" && d.Value != "" {
			return d.Value
		}
	}
	if len(cve.Descriptions) > 0 {
		return cve.Descriptions[0].Value
	}
	return ""
}

func parseNVDTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, nvdTimeLayout, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func cvss(metrics map[string]json.RawMessage) (float64, string, string) {
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		raw, ok := metrics[key]
		if !ok {
			continue
		}
		var rows []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
				VectorString string  `json:"vectorString"`
			} `json:"cvssData"`
		}
		if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 {
			continue
		}
		d := rows[0].CVSSData
		return d.BaseScore, d.VectorString, strings.ToLower(d.BaseSeverity)
	}
	return 0, "", ""
}

// Severity maps a CVSS base score onto the four SLA buckets.
func Severity(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}
