package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const elasticPage = 500

var indexPatternRE = regexp.MustCompile(`^[A-Za-z0-9.][A-Za-z0-9*._?-]{0,200}$`)

// Elastic reads one index pattern with search_after. A point-in-time keeps
// the tiebreaker (_shard_doc) stable across pages. The PIT id is returned
// to the caller and must be sent back on the next page.
type Elastic struct {
	Base   string
	APIKey string
	HTTP   *http.Client
	// caps caches field types per index pattern so an exact term can target a
	// keyword mapping instead of an analyzed text field.
	caps sync.Map
}

// Search implements Reader.
func (e *Elastic) Search(ctx context.Context, req SearchRequest) (Result, error) {
	return e.search(ctx, req, false)
}

func (e *Elastic) search(ctx context.Context, req SearchRequest, renewed bool) (Result, error) {
	if err := checkIndex(req.Source.IndexPattern); err != nil {
		return Result{}, err
	}
	if req.Limit <= 0 {
		return Result{}, nil
	}
	kql, err := Compile(req.KQL, req.Source.MessageField)
	if err != nil {
		return Result{}, err
	}
	if containsTerm(kql) {
		e.rewriteTerms(ctx, req.Source.IndexPattern, kql)
	}
	pit := req.PIT
	if pit == "" {
		opened, err := e.openPIT(ctx, req.Source.IndexPattern)
		if err != nil {
			return Result{}, err
		}
		pit = opened
	}
	var hits []Hit
	if req.Before != nil {
		hits, pit, err = e.searchBefore(ctx, req, kql, pit)
	} else {
		hits, pit, err = e.searchForward(ctx, req, kql, pit, req.Desc)
	}
	if err != nil && !renewed && pitExpired(err) {
		opened, oerr := e.openPIT(ctx, req.Source.IndexPattern)
		if oerr != nil {
			return Result{}, oerr
		}
		// _shard_doc values belong to the expired point-in-time. Resume from
		// the key and let the key filter drop lines already shown.
		req.PIT = opened
		req.AfterSort = nil
		req.BeforeSort = nil
		res, rerr := e.search(ctx, req, true)
		if rerr != nil {
			return Result{}, rerr
		}
		res.Renewed = true
		return res, nil
	}
	if err != nil {
		return Result{}, err
	}
	for i := range hits {
		if hits[i].Pit == "" {
			hits[i].Pit = pit
		}
	}
	return Result{Hits: hits, PIT: pit}, nil
}

// Close releases a point-in-time. Tail opens a fresh one so newly indexed
// lines are visible; the previous id is closed so a poll does not leak contexts.
func (e *Elastic) Close(ctx context.Context, pit string) error {
	pit = strings.TrimSpace(pit)
	if pit == "" {
		return nil
	}
	body, err := json.Marshal(map[string]string{"id": pit})
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(e.Base, "/") + "/_pit"
	_, _, err = e.do(ctx, http.MethodDelete, endpoint, body)
	return err
}

func checkIndex(index string) error {
	if err := ValidIndexPattern(index); err != nil {
		return err
	}
	return nil
}

// ValidIndexPattern allows one Elasticsearch index pattern with a literal
// prefix. Views are Terraform-managed, so `logs-munki-*` is the operator's
// choice. A bare `*`, a leading wildcard, a comma-separated list, or a path
// is rejected: a view cannot name every index on the cluster.
func ValidIndexPattern(index string) error {
	if !indexPatternRE.MatchString(index) || strings.Contains(index, "..") {
		return errf("index pattern %q is not a single pattern", index)
	}
	star := strings.IndexAny(index, "*?")
	if star == 0 {
		return errf("index pattern %q needs a literal prefix", index)
	}
	if star > 0 && strings.Trim(index[:star], ".") == "" {
		return errf("index pattern %q needs a literal prefix", index)
	}
	return nil
}

// ValidateElasticURL checks the origin a log view will call. Credentials in
// the URL, query strings, and link-local metadata addresses are rejected.
// Private and loopback addresses stay allowed: Elasticsearch often runs next
// to the server.
func ValidateElasticURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	u, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return errf("elastic_url must be an http(s) URL")
	}
	if u.URL.Scheme != "http" && u.URL.Scheme != "https" || u.URL.Host == "" {
		return errf("elastic_url must be an http(s) URL")
	}
	if u.URL.User != nil {
		return errf("elastic_url must not include credentials")
	}
	if u.URL.RawQuery != "" || u.URL.Fragment != "" {
		return errf("elastic_url must not include a query or fragment")
	}
	host := u.URL.Hostname()
	if metadataHost(host) {
		return errf("elastic_url must not target the instance metadata service")
	}
	if ip := net.ParseIP(host); ip != nil && deniedIP(ip) {
		return errf("elastic_url must not target a link-local address")
	}
	return nil
}

// SafeClient is the HTTP client used for Elasticsearch. It does not follow
// redirects, does not use the environment proxy, and refuses link-local
// addresses at dial time so a configured URL cannot pivot to the metadata
// service. Loopback and private addresses are allowed.
func SafeClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("elastic search: redirects are not followed")
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           safeDialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          8,
		},
	}
}

func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	if ip := net.ParseIP(host); ip != nil {
		if deniedIP(ip) {
			return nil, fmt.Errorf("elastic search: address %s is not allowed", ip)
		}
		return d.DialContext(ctx, network, addr)
	}
	if metadataHost(host) {
		return nil, fmt.Errorf("elastic search: host %s is not allowed", host)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var dialErr error
	for _, ip := range ips {
		if deniedIP(ip.IP) {
			dialErr = fmt.Errorf("elastic search: address %s is not allowed", ip.IP)
			continue
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = err
	}
	if dialErr == nil {
		dialErr = fmt.Errorf("elastic search: no address for %s", host)
	}
	return nil, dialErr
}

func deniedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 169 && v4[1] == 254 {
		return true
	}
	return false
}

func metadataHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	switch h {
	case "metadata.google.internal", "metadata.internal", "instance-data":
		return true
	default:
		return false
	}
}

func (e *Elastic) searchForward(ctx context.Context, req SearchRequest, kql map[string]any, pit string, desc bool) ([]Hit, string, error) {
	order := "asc"
	if desc {
		order = "desc"
	}
	from := req.From
	// A renewed point-in-time cannot resume on the old _shard_doc. Start at
	// the boundary instant and drop hits that are not strictly after the key.
	filterAfter := !desc && req.After != nil && len(req.AfterSort) == 0
	if filterAfter && req.After.Time.After(from) {
		from = req.After.Time
	}
	query := withRange(kql, req.Source.TimestampField, from, req.To, "lt")
	var after json.RawMessage
	if !desc && len(req.AfterSort) > 0 {
		after = req.AfterSort
	}
	var hits []Hit
	scanned := 0
	for len(hits) < req.Limit && scanned < MaxScan {
		size := req.Limit - len(hits)
		if filterAfter || size > elasticPage {
			size = elasticPage
		}
		if size > elasticPage {
			size = elasticPage
		}
		page, err := e.page(ctx, req, query, order, pit, after, size)
		if err != nil {
			return nil, pit, err
		}
		if page.pitID != "" {
			pit = page.pitID
		}
		if page.raw == 0 {
			break
		}
		scanned += page.raw
		chunk := page.hits
		if filterAfter {
			bound := *req.After
			bound.Ord = ""
			chunk = renewedAfter(chunk, bound, req.Returned)
		} else if req.After != nil {
			chunk = strictlyAfter(chunk, *req.After)
			chunk = dropTies(chunk, req.Returned)
		} else {
			chunk = dropTies(chunk, req.Returned)
		}
		hits = append(hits, chunk...)
		if page.raw < size {
			break
		}
		if len(page.last) == 0 || bytes.Equal(page.last, after) {
			return nil, pit, e.redact(fmt.Errorf("elastic search: page missing sort values"))
		}
		after = page.last
	}
	if scanned >= MaxScan && len(hits) < req.Limit {
		return nil, pit, e.redact(fmt.Errorf("elastic search: stopped after scanning %d hits", MaxScan))
	}
	if len(hits) > req.Limit {
		hits = hits[:req.Limit]
	}
	if desc {
		reverseHits(hits)
	}
	return hits, pit, nil
}

func (e *Elastic) searchBefore(ctx context.Context, req SearchRequest, kql map[string]any, pit string) ([]Hit, string, error) {
	anchor := *req.Before
	// A renewed point-in-time's _shard_doc is not comparable with the cursor.
	if len(req.BeforeSort) == 0 {
		anchor.Ord = ""
	}
	// Walk newest-first until `limit` hits sort strictly before the anchor.
	// One page is not enough: a page full of same-timestamp hits that sort
	// after the anchor used to be filtered down to nothing and the walk stopped.
	upper := "lt"
	end := anchor.Time
	var after json.RawMessage
	if req.Source.Index == anchor.Source && len(req.BeforeSort) > 0 && pit != "" {
		after = req.BeforeSort
		end = req.To
		if !end.After(req.From) {
			end = anchor.Time.Add(time.Nanosecond)
		}
	} else if req.Source.Index <= anchor.Source {
		// This source, and earlier sources, can place a line at the anchor
		// instant before the anchor. Later sources at that instant sort after it.
		upper = "lte"
	}
	query := withRange(kql, req.Source.TimestampField, req.From, end, upper)
	var kept []Hit
	scanned := 0
	for len(kept) < req.Limit && scanned < MaxScan {
		size := req.Limit - len(kept)
		if size > elasticPage {
			size = elasticPage
		}
		page, err := e.page(ctx, req, query, "desc", pit, after, size)
		if err != nil {
			return nil, pit, err
		}
		if page.pitID != "" {
			pit = page.pitID
		}
		if page.raw == 0 {
			break
		}
		scanned += page.raw
		for _, h := range page.hits {
			if tieSkipped(h.Tie, req.Returned) {
				continue
			}
			hk := h.Key()
			if anchor.Ord == "" {
				hk.Ord = ""
			}
			if !hk.Before(anchor) {
				continue
			}
			kept = append(kept, h)
			if len(kept) == req.Limit {
				break
			}
		}
		if page.raw < size {
			break
		}
		if len(page.last) == 0 || bytes.Equal(page.last, after) {
			return nil, pit, e.redact(fmt.Errorf("elastic search: page missing sort values"))
		}
		after = page.last
	}
	if scanned >= MaxScan && len(kept) < req.Limit {
		return nil, pit, e.redact(fmt.Errorf("elastic search: stopped after scanning %d hits", MaxScan))
	}
	// kept is newest-first. Callers merge oldest-first.
	reverseHits(kept)
	return kept, pit, nil
}

type searchPage struct {
	hits  []Hit
	raw   int
	last  json.RawMessage
	pitID string
}

func (e *Elastic) page(ctx context.Context, req SearchRequest, query map[string]any, order, pit string, after json.RawMessage, size int) (searchPage, error) {
	body := map[string]any{
		"size":  size,
		"sort":  sortClause(req.Source, order),
		"query": query,
	}
	if pit != "" {
		body["pit"] = map[string]any{"id": pit, "keep_alive": "5m"}
	}
	payload, err := marshalSearch(body, after)
	if err != nil {
		return searchPage{}, err
	}
	endpoint := strings.TrimRight(e.Base, "/") + "/_search"
	if pit == "" {
		endpoint = strings.TrimRight(e.Base, "/") + "/" + req.Source.IndexPattern + "/_search"
	}
	raw, status, err := e.do(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return searchPage{}, err
	}
	if status >= 300 {
		return searchPage{}, e.redact(fmt.Errorf("elastic search: status %d: %s", status, clip(raw)))
	}
	page, err := decodeHits(raw, req, pit)
	if err != nil {
		return searchPage{}, e.redact(err)
	}
	return page, nil
}

func sortClause(src Source, order string) []any {
	missing := "_last"
	if order == "desc" {
		// Missing sequences sort as the largest value, matching asc _last
		// after the page is reversed.
		missing = "_first"
	}
	sort := []any{
		map[string]any{src.TimestampField: map[string]any{"order": order, "unmapped_type": "date"}},
	}
	if src.SequenceField != "" {
		sort = append(sort, map[string]any{src.SequenceField: map[string]any{"order": order, "unmapped_type": "long", "missing": missing}})
	}
	tie := "_shard_doc"
	sort = append(sort, map[string]any{tie: order})
	return sort
}

func marshalSearch(body map[string]any, after json.RawMessage) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if len(after) == 0 {
		return payload, nil
	}
	if !json.Valid(after) {
		return nil, fmt.Errorf("elastic search: invalid search_after")
	}
	payload = payload[:len(payload)-1]
	payload = append(payload, []byte(`,"search_after":`)...)
	payload = append(payload, after...)
	payload = append(payload, '}')
	return payload, nil
}

func withRange(kql map[string]any, field string, from, to time.Time, upper string) map[string]any {
	if field == "" {
		field = "@timestamp"
	}
	bounds := map[string]any{
		"gte": from.UTC().Format(time.RFC3339Nano),
		upper: to.UTC().Format(time.RFC3339Nano),
	}
	rangeQ := map[string]any{"range": map[string]any{field: bounds}}
	return map[string]any{"bool": map[string]any{"must": []any{kql, rangeQ}}}
}

func (e *Elastic) openPIT(ctx context.Context, index string) (string, error) {
	endpoint := strings.TrimRight(e.Base, "/") + "/" + index + "/_pit?keep_alive=5m"
	raw, status, err := e.do(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	if status >= 300 {
		return "", e.redact(fmt.Errorf("elastic search: pit status %d: %s", status, clip(raw)))
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.ID == "" {
		return "", e.redact(fmt.Errorf("elastic search: point-in-time was not opened"))
	}
	return body.ID, nil
}

// rewriteTerms points an exact term at the keyword mapping. A term on an
// analyzed text field matches any token, so host.name "mbp" would also
// return "mbp-2". Keyword fields are queried as themselves.
func (e *Elastic) rewriteTerms(ctx context.Context, index string, q map[string]any) {
	kinds := e.fieldKinds(ctx, index)
	if len(kinds) == 0 || q == nil {
		return
	}
	rewriteTerms(q, kinds)
}

func containsTerm(q map[string]any) bool {
	if q == nil {
		return false
	}
	if _, ok := q["term"]; ok {
		return true
	}
	b, ok := q["bool"].(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"must", "should", "must_not", "filter"} {
		kids, ok := b[key].([]any)
		if !ok {
			continue
		}
		for _, kid := range kids {
			if child, ok := kid.(map[string]any); ok && containsTerm(child) {
				return true
			}
		}
	}
	return false
}

func rewriteTerms(q map[string]any, kinds map[string]string) {
	b, ok := q["bool"].(map[string]any)
	if !ok {
		return
	}
	if should, ok := b["should"].([]any); ok {
		if next := collapseTerms(should, kinds); next != nil {
			for k := range q {
				delete(q, k)
			}
			for k, v := range next {
				q[k] = v
			}
			rewriteTerms(q, kinds)
			return
		}
	}
	for _, key := range []string{"must", "should", "must_not", "filter"} {
		kids, ok := b[key].([]any)
		if !ok {
			continue
		}
		for _, kid := range kids {
			if child, ok := kid.(map[string]any); ok {
				rewriteTerms(child, kinds)
			}
		}
	}
}

func collapseTerms(should []any, kinds map[string]string) map[string]any {
	type term struct{ field, value string }
	terms := make([]term, 0, len(should))
	for _, c := range should {
		m, ok := c.(map[string]any)
		if !ok {
			return nil
		}
		raw, ok := m["term"].(map[string]any)
		if !ok || len(raw) != 1 {
			return nil
		}
		for field, body := range raw {
			val, ok := termValue(body)
			if !ok {
				return nil
			}
			terms = append(terms, term{field, val})
		}
	}
	keep := make([]term, 0, len(terms))
	for _, tm := range terms {
		base := strings.TrimSuffix(tm.field, ".keyword")
		onKeyword := strings.HasSuffix(tm.field, ".keyword")
		kind := kinds[base]
		if onKeyword {
			if kind == "text" && kinds[base+".keyword"] == "keyword" {
				keep = append(keep, tm)
			}
			continue
		}
		if kind != "text" {
			keep = append(keep, tm)
		}
	}
	if len(keep) == 0 || len(keep) == len(terms) {
		return nil
	}
	if len(keep) == 1 {
		return map[string]any{"term": map[string]any{keep[0].field: map[string]any{"value": keep[0].value}}}
	}
	parts := make([]any, len(keep))
	for i, tm := range keep {
		parts[i] = map[string]any{"term": map[string]any{tm.field: map[string]any{"value": tm.value}}}
	}
	return map[string]any{"bool": map[string]any{"should": parts, "minimum_should_match": 1}}
}

func termValue(body any) (string, bool) {
	switch t := body.(type) {
	case string:
		return t, true
	case map[string]any:
		s, ok := t["value"].(string)
		return s, ok
	default:
		return "", false
	}
}

func (e *Elastic) fieldKinds(ctx context.Context, index string) map[string]string {
	if v, ok := e.caps.Load(index); ok {
		return v.(map[string]string)
	}
	endpoint := strings.TrimRight(e.Base, "/") + "/" + index + "/_field_caps?fields=*"
	raw, status, err := e.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil || status >= 300 {
		return nil
	}
	var body struct {
		Fields map[string]map[string]any `json:"fields"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil
	}
	kinds := make(map[string]string, len(body.Fields))
	for field, types := range body.Fields {
		if _, ok := types["keyword"]; ok && len(types) == 1 {
			kinds[field] = "keyword"
			continue
		}
		if _, ok := types["text"]; ok {
			kinds[field] = "text"
		}
	}
	e.caps.Store(index, kinds)
	return kinds
}

func (e *Elastic) redact(err error) error {
	if err == nil || e.APIKey == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), e.APIKey, "[redacted]")
	if msg == err.Error() {
		return err
	}
	return fmt.Errorf("%s", msg)
}

func pitExpired(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "search_context_missing_exception") || strings.Contains(s, "search_phase_execution_exception") && strings.Contains(s, "No search context")
}

func (e *Elastic) do(ctx context.Context, method, endpoint string, payload []byte) ([]byte, int, error) {
	var r io.Reader
	if payload != nil {
		r = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, r)
	if err != nil {
		return nil, 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if e.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+e.APIKey)
	}
	hc := e.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		// url.Error includes the request URL. A redirect target or a metadata
		// address must not ride along into the audit log.
		var uerr *url.Error
		if errors.As(err, &uerr) && uerr.Err != nil {
			err = uerr.Err
		}
		return nil, 0, e.redact(fmt.Errorf("elastic search: %v", err))
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return raw, res.StatusCode, nil
}

func decodeHits(raw []byte, req SearchRequest, pit string) (searchPage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed struct {
		PitID string `json:"pit_id"`
		Hits  struct {
			Hits []struct {
				ID     string          `json:"_id"`
				Source json.RawMessage `json:"_source"`
				Sort   json.RawMessage `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := dec.Decode(&parsed); err != nil {
		return searchPage{}, fmt.Errorf("elastic search: decode: %w", err)
	}
	if parsed.PitID != "" {
		pit = parsed.PitID
	}
	loc := req.Location
	if loc == nil {
		loc = time.UTC
	}
	out := make([]Hit, 0, len(parsed.Hits.Hits))
	var last json.RawMessage
	for _, hit := range parsed.Hits.Hits {
		if len(hit.Sort) > 0 {
			last = append(json.RawMessage(nil), hit.Sort...)
		}
		var src map[string]any
		if len(hit.Source) > 0 {
			d := json.NewDecoder(bytes.NewReader(hit.Source))
			d.UseNumber()
			if err := d.Decode(&src); err != nil {
				continue
			}
		}
		ts := ParseTime(walk(src, req.Source.TimestampField), loc)
		if ts.IsZero() {
			continue
		}
		msg := stringify(walk(src, req.Source.MessageField))
		if msg == "" {
			msg = "(no message)"
		}
		h := Hit{
			Source: req.Source.Index,
			Time:   ts,
			Seq:    seqOf(src, req.Source.SequenceField),
			Tie:    hit.ID,
			Sort:   hit.Sort,
			File:   stringify(walk(src, req.Source.FileField)),
			Host:   stringify(walk(src, req.Source.HostField)),
			Msg:    msg,
			Pit:    pit,
		}
		out = append(out, h)
	}
	return searchPage{hits: out, raw: len(parsed.Hits.Hits), last: last, pitID: pit}, nil
}

func seqOf(src map[string]any, field string) int64 {
	if field == "" {
		return 0
	}
	v := walk(src, field)
	if v == nil {
		return math.MaxInt64
	}
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			f, ferr := t.Float64()
			if ferr != nil {
				return math.MaxInt64
			}
			return int64(f)
		}
		return n
	case float64:
		return int64(t)
	case string:
		var n int64
		if _, err := fmt.Sscan(t, &n); err == nil {
			return n
		}
	}
	return math.MaxInt64
}

func walk(src map[string]any, path string) any {
	if path == "" || src == nil {
		return nil
	}
	var cur any = src
	for _, part := range strings.Split(path, ".") {
		node, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = node[part]
	}
	return cur
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprint(t)
	}
}

func reverseHits(hits []Hit) {
	for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
		hits[i], hits[j] = hits[j], hits[i]
	}
}

func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}
