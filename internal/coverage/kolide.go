package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Kolide polls the Kolide K2 device API.
// GET {base}/api/v0/devices?per_page=100 with a bearer token. Pages follow
// pagination.next, then pagination.next_cursor when the server omits the URL.
// Relative next links are resolved against the connector base URL.
type Kolide struct{}

func (Kolide) Poll(ctx context.Context, cfg Config, hc *http.Client) ([]Observation, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("kolide: api token is required")
	}
	base := trimURL(cfg.BaseURL)
	if base == "" {
		base = "https://k2.kolide.com"
	}
	next := base + "/api/v0/devices?per_page=100"
	if strings.HasSuffix(base, "/api/v0") {
		next = base + "/devices?per_page=100"
	}
	seenURL := map[string]struct{}{}
	seenID := map[string]struct{}{}
	var out []Observation
	for page := 0; page < 200 && next != ""; page++ {
		if _, ok := seenURL[next]; ok {
			break
		}
		seenURL[next] = struct{}{}
		req, err := http.NewRequest(http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
		req.Header.Set("Accept", "application/json")
		raw, status, err := doJSON(ctx, hc, req)
		if err != nil {
			return nil, fmt.Errorf("kolide devices: %w", err)
		}
		if status >= 300 {
			return nil, statusError("kolide devices", status)
		}
		var body struct {
			Data []struct {
				ID              json.RawMessage `json:"id"`
				Name            string          `json:"name"`
				Serial          string          `json:"serial"`
				HardwareUUID    string          `json:"hardware_uuid"`
				OperatingSystem string          `json:"operating_system"`
				LastSeenAt      string          `json:"last_seen_at"`
				RemoteIP        string          `json:"remote_ip"`
				PrimaryMAC      string          `json:"primary_mac_address"`
				AssignedOwner   struct {
					Email string `json:"email"`
				} `json:"assigned_owner"`
			} `json:"data"`
			Pagination struct {
				Next       string `json:"next"`
				NextCursor string `json:"next_cursor"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, fmt.Errorf("kolide devices: decode: %w", err)
		}
		for _, d := range body.Data {
			id := strings.Trim(string(d.ID), `"`)
			if id == "" || id == "null" {
				continue
			}
			if _, ok := seenID[id]; ok {
				continue
			}
			seenID[id] = struct{}{}
			obs := Observation{
				NativeID:  id,
				OSVersion: d.OperatingSystem,
				IPAddress: d.RemoteIP,
				LastSeen:  parseTime(d.LastSeenAt),
				Keys: Keys{
					Serial:       d.Serial,
					HardwareUUID: d.HardwareUUID,
					MAC:          d.PrimaryMAC,
					Hostname:     d.Name,
					PrimaryUser:  d.AssignedOwner.Email,
				},
			}
			obs.Fields = obs.NormalizedFields()
			out = append(out, obs)
		}
		next = kolideNext(base, body.Pagination.Next, body.Pagination.NextCursor)
	}
	return out, nil
}

func kolideNext(base, next, cursor string) string {
	next = strings.TrimSpace(next)
	cursor = strings.TrimSpace(cursor)
	if next == "" && cursor != "" {
		next = base + "/api/v0/devices?per_page=100&cursor=" + url.QueryEscape(cursor)
	}
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	if u.Host == "" {
		baseURL, err := url.Parse(base)
		if err != nil {
			return ""
		}
		u.Scheme = baseURL.Scheme
		u.Host = baseURL.Host
	}
	return u.String()
}
