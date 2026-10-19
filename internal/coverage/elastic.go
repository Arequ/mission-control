package coverage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const elasticPageSize = 1000

// Elastic reads the latest event per device from an index pattern.
// Pages use a point-in-time and search_after so a fleet larger than the
// result window is not truncated and from/size never walks past 10k.
// The lookback overlaps the previous window by a few minutes; native ids are
// deduped to the latest event. Field paths may land on arrays or nested objects.
type Elastic struct{}

func (Elastic) Poll(ctx context.Context, cfg Config, hc *http.Client) ([]Observation, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	base := trimURL(cfg.ElasticURL)
	index := strings.Trim(strings.TrimSpace(cfg.IndexPattern), "/")
	if base == "" || index == "" {
		return nil, fmt.Errorf("elastic connector needs a url and an index pattern")
	}
	if strings.Contains(index, "..") || strings.ContainsAny(index, " ?#") {
		return nil, fmt.Errorf("index pattern is not a single path")
	}
	timeField := cfg.TimeField
	if timeField == "" {
		timeField = "@timestamp"
	}
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}
	lookback := cfg.Lookback
	if lookback <= 0 {
		lookback = 30 * 24 * time.Hour
	}
	since := now.Add(-lookback)
	if lookback > 0 {
		since = since.Add(-5 * time.Minute)
	}
	query, err := CompileQuery(cfg.QueryLanguage, cfg.Query, timeField, since)
	if err != nil {
		return nil, err
	}
	loc, err := loadLocation(cfg.TimeZone)
	if err != nil {
		return nil, err
	}
	pit, err := openPIT(ctx, hc, base, index, cfg.ElasticAPIKey)
	if err != nil {
		return nil, err
	}
	if pit != "" {
		defer closePIT(ctx, hc, base, pit, cfg.ElasticAPIKey)
	}
	seen := map[string]Observation{}
	var after []any
	for page := 0; page < 500; page++ {
		hits, err := searchPage(ctx, hc, base, index, pit, cfg.ElasticAPIKey, query, timeField, after)
		if err != nil {
			return nil, err
		}
		if len(hits) == 0 {
			break
		}
		for _, hit := range hits {
			obs := observationFromSource(hit.Source, cfg.FieldMap, timeField, loc)
			if obs.NativeID == "" {
				continue
			}
			prev, ok := seen[obs.NativeID]
			if !ok || obs.LastSeen.After(prev.LastSeen) {
				seen[obs.NativeID] = obs
			}
		}
		if len(hits) < elasticPageSize {
			break
		}
		if len(hits[len(hits)-1].Sort) == 0 {
			return nil, fmt.Errorf("elastic search: page missing sort values")
		}
		after = hits[len(hits)-1].Sort
		if page == 499 {
			return nil, fmt.Errorf("elastic search: truncated before the window was exhausted")
		}
	}
	out := make([]Observation, 0, len(seen))
	for _, obs := range seen {
		out = append(out, obs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NativeID < out[j].NativeID })
	return out, nil
}

type elasticHit struct {
	Source map[string]any `json:"_source"`
	Sort   []any          `json:"sort"`
}

func openPIT(ctx context.Context, hc *http.Client, base, index, apiKey string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, base+"/"+index+"/_pit?keep_alive=2m", nil)
	if err != nil {
		return "", err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
	}
	raw, status, err := doJSON(ctx, hc, req)
	if err != nil || status >= 300 {
		return "", nil
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", nil
	}
	return body.ID, nil
}

func closePIT(ctx context.Context, hc *http.Client, base, id, apiKey string) {
	payload, _ := json.Marshal(map[string]string{"id": id})
	req, err := http.NewRequest(http.MethodDelete, base+"/_pit", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
	}
	_, _, _ = doJSON(ctx, hc, req)
}

func searchPage(ctx context.Context, hc *http.Client, base, index, pit, apiKey string, query map[string]any, timeField string, after []any) ([]elasticHit, error) {
	body := map[string]any{
		"size": elasticPageSize,
		"sort": []any{
			map[string]any{timeField: map[string]any{"order": "desc", "unmapped_type": "date"}},
			map[string]any{"_shard_doc": "desc"},
		},
		"query": query,
	}
	endpoint := base + "/" + index + "/_search"
	if pit != "" {
		body["pit"] = map[string]any{"id": pit, "keep_alive": "2m"}
		endpoint = base + "/_search"
	}
	if len(after) > 0 {
		body["search_after"] = after
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
	}
	raw, status, err := doJSON(ctx, hc, req)
	if err != nil {
		return nil, fmt.Errorf("elastic search: %w", err)
	}
	if status >= 300 && pit != "" && len(after) == 0 {
		return searchPage(ctx, hc, base, index, "", apiKey, query, timeField, nil)
	}
	if status >= 300 {
		return nil, statusError("elastic search", status)
	}
	var parsed struct {
		Hits struct {
			Hits []elasticHit `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("elastic search: decode: %w", err)
	}
	return parsed.Hits.Hits, nil
}

func observationFromSource(src map[string]any, fieldMap map[string]string, timeField string, loc *time.Location) Observation {
	get := func(canonical, fallback string) string {
		path := fieldMap[canonical]
		if path == "" {
			path = fallback
		}
		if path == "" {
			return ""
		}
		return stringify(walk(src, path))
	}
	obs := Observation{
		NativeID:     get("native_id", ""),
		OSVersion:    get("os_version", ""),
		IPAddress:    get("ip_address", ""),
		AgentVersion: get("agent_version", ""),
		Keys: Keys{
			Serial:       get("serial", ""),
			HardwareUUID: get("hardware_uuid", ""),
			MAC:          get("mac", ""),
			Hostname:     get("hostname", ""),
			PrimaryUser:  get("primary_user", ""),
		},
	}
	seenPath := fieldMap["last_seen"]
	if seenPath == "" {
		seenPath = timeField
	}
	obs.LastSeen = valueTimeIn(walk(src, seenPath), loc)
	obs.Fields = obs.NormalizedFields()
	return obs
}

func walk(src map[string]any, path string) any {
	var cur any = src
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			cur = node[part]
		case []any:
			var next any
			for _, item := range node {
				if m, ok := item.(map[string]any); ok {
					if v, ok := m[part]; ok && v != nil {
						next = v
						break
					}
				}
			}
			cur = next
		default:
			return nil
		}
	}
	return cur
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []any:
		for _, item := range t {
			if s := stringify(item); s != "" {
				return s
			}
		}
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func loadLocation(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "UTC") {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("time zone %q: %w", name, err)
	}
	return loc, nil
}

func valueTimeIn(v any, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	switch t := v.(type) {
	case string:
		return parseTimeIn(t, loc)
	case float64:
		if t > 1e14 {
			return time.UnixMicro(int64(t)).UTC()
		}
		if t > 1e12 {
			return time.UnixMilli(int64(t)).UTC()
		}
		if t > 1e9 {
			return time.Unix(int64(t), 0).UTC()
		}
	}
	return time.Time{}
}

func parseTime(s string) time.Time {
	return parseTimeIn(s, time.UTC)
}

func parseTimeIn(s string, loc *time.Location) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if loc == nil {
		loc = time.UTC
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02T15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
