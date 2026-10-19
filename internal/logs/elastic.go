package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const elasticPage = 500

var indexPatternRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9*._-]{0,200}$`)

// Elastic reads one index pattern with search_after. A point-in-time keeps
// the tiebreaker (_shard_doc) stable across pages. The PIT id is returned
// to the caller and must be sent back on the next page.
type Elastic struct {
	Base   string
	APIKey string
	HTTP   *http.Client
}

// Search implements Reader.
func (e *Elastic) Search(ctx context.Context, req SearchRequest) (Result, error) {
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
	pit := req.PIT
	if pit == "" {
		opened, err := e.openPIT(ctx, req.Source.IndexPattern)
		if err != nil {
			return Result{}, err
		}
		pit = opened
	}
	if req.Before != nil {
		hits, err := e.searchBefore(ctx, req, kql, pit)
		return Result{Hits: hits, PIT: pit}, err
	}
	desc := req.Desc
	hits, err := e.searchForward(ctx, req, kql, pit, desc)
	return Result{Hits: hits, PIT: pit}, err
}

func checkIndex(index string) error {
	if !indexPatternRE.MatchString(index) || strings.Contains(index, "..") {
		return errf("index pattern %q is not a single pattern", index)
	}
	return nil
}

func (e *Elastic) searchForward(ctx context.Context, req SearchRequest, kql map[string]any, pit string, desc bool) ([]Hit, error) {
	order := "asc"
	if desc {
		order = "desc"
	}
	query := withRange(kql, req.Source.TimestampField, req.From, req.To, "lt")
	var after json.RawMessage
	if !desc && len(req.AfterSort) > 0 {
		after = req.AfterSort
	}
	var hits []Hit
	for len(hits) < req.Limit {
		size := req.Limit - len(hits)
		if size > elasticPage {
			size = elasticPage
		}
		page, err := e.page(ctx, req, query, order, pit, after, size)
		if err != nil {
			return nil, err
		}
		if page.raw == 0 {
			break
		}
		hits = append(hits, page.hits...)
		if page.raw < size {
			break
		}
		if len(page.last) == 0 || bytes.Equal(page.last, after) {
			return nil, fmt.Errorf("elastic search: page missing sort values")
		}
		after = page.last
	}
	if len(hits) > req.Limit {
		hits = hits[:req.Limit]
	}
	if desc {
		reverseHits(hits)
	}
	return hits, nil
}

func (e *Elastic) searchBefore(ctx context.Context, req SearchRequest, kql map[string]any, pit string) ([]Hit, error) {
	anchor := *req.Before
	// The anchor's own source can walk backward with its sort tuple inside the
	// same point-in-time. Other sources use a time bound, because their
	// sequence numbers are not comparable with the anchor.
	if req.Source.Index == anchor.Source && len(req.BeforeSort) > 0 && pit != "" {
		query := withRange(kql, req.Source.TimestampField, req.From, req.To, "lt")
		page, err := e.page(ctx, req, query, "desc", pit, req.BeforeSort, req.Limit)
		if err != nil {
			return nil, err
		}
		reverseHits(page.hits)
		return page.hits, nil
	}
	// An earlier source at the anchor's timestamp sorts before the anchor.
	// The same source does too when its sequence is lower, so the range must
	// include that instant and the key filter drops the anchor itself.
	// A later source at that instant sorts after the anchor.
	upper := "lt"
	if req.Source.Index <= anchor.Source {
		upper = "lte"
	}
	query := withRange(kql, req.Source.TimestampField, req.From, anchor.Time, upper)
	page, err := e.page(ctx, req, query, "desc", pit, nil, req.Limit)
	if err != nil {
		return nil, err
	}
	reverseHits(page.hits)
	if req.Source.Index != anchor.Source {
		return page.hits, nil
	}
	var kept []Hit
	for _, h := range page.hits {
		if h.Key().Before(anchor) {
			kept = append(kept, h)
		}
	}
	return kept, nil
}

type searchPage struct {
	hits []Hit
	raw  int
	last json.RawMessage
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
		return searchPage{}, fmt.Errorf("elastic search: status %d: %s", status, clip(raw))
	}
	return decodeHits(raw, req)
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
		return "", nil
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.ID == "" {
		return "", nil
	}
	return body.ID, nil
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
		return nil, 0, fmt.Errorf("elastic search: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return raw, res.StatusCode, nil
}

func decodeHits(raw []byte, req SearchRequest) (searchPage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed struct {
		Hits struct {
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
			Pit:    req.PIT,
		}
		out = append(out, h)
	}
	return searchPage{hits: out, raw: len(parsed.Hits.Hits), last: last}, nil
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
