package coverage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Elastic reads the latest event per device from an index pattern.
// The query is KQL (a subset) or Elasticsearch DSL. FieldMap translates event
// fields onto normalized device fields and the source's native id.
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
	query, err := CompileQuery(cfg.QueryLanguage, cfg.Query, timeField, now.Add(-lookback))
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"size": 1000,
		"sort": []any{map[string]any{timeField: "desc"}},
		"query": query,
	})
	req, err := http.NewRequest(http.MethodPost, base+"/"+index+"/_search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.ElasticAPIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+cfg.ElasticAPIKey)
	}
	raw, status, err := doJSON(ctx, hc, req)
	if err != nil {
		return nil, fmt.Errorf("elastic search: %w", err)
	}
	if status >= 300 {
		return nil, statusError("elastic search", status)
	}
	var parsed struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("elastic search: decode: %w", err)
	}
	return mapHits(parsed.Hits.Hits, cfg.FieldMap, timeField), nil
}

func mapHits(hits []struct {
	Source map[string]any `json:"_source"`
}, fieldMap map[string]string, timeField string) []Observation {
	seen := map[string]bool{}
	var out []Observation
	for _, hit := range hits {
		obs := observationFromSource(hit.Source, fieldMap, timeField)
		if obs.NativeID == "" {
			continue
		}
		if seen[obs.NativeID] {
			continue
		}
		seen[obs.NativeID] = true
		out = append(out, obs)
	}
	return out
}

func observationFromSource(src map[string]any, fieldMap map[string]string, timeField string) Observation {
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
	obs.LastSeen = valueTime(walk(src, seenPath))
	obs.Fields = obs.NormalizedFields()
	return obs
}

func walk(src map[string]any, path string) any {
	var cur any = src
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
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
	default:
		return fmt.Sprint(t)
	}
}

func valueTime(v any) time.Time {
	switch t := v.(type) {
	case string:
		return parseTime(t)
	case float64:
		if t > 1e12 {
			return time.UnixMilli(int64(t)).UTC()
		}
		if t > 1e9 {
			return time.Unix(int64(t), 0).UTC()
		}
	}
	return time.Time{}
}
