package coverage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Falcon polls the CrowdStrike Falcon hosts API with OAuth2 client credentials.
// List: GET /devices/queries/devices-scroll/v1
// Details: POST /devices/entities/devices/v2 {"ids": [...]}
type Falcon struct{}

func (Falcon) Poll(ctx context.Context, cfg Config, hc *http.Client) ([]Observation, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	base := trimURL(cfg.BaseURL)
	if base == "" {
		base = "https://api.crowdstrike.com"
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("falcon oauth: client id and client secret are required")
	}
	token, err := falconToken(ctx, hc, base, cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		return nil, err
	}
	ids, err := falconIDs(ctx, hc, base, token)
	if err != nil {
		return nil, err
	}
	var out []Observation
	for i := 0; i < len(ids); i += 100 {
		end := i + 100
		if end > len(ids) {
			end = len(ids)
		}
		chunk, err := falconDetails(ctx, hc, base, token, ids[i:end])
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

func falconToken(ctx context.Context, hc *http.Client, base, clientID, clientSecret string) (string, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "client_credentials")
	req, err := http.NewRequest(http.MethodPost, base+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, status, err := doJSON(ctx, hc, req)
	if err != nil {
		return "", fmt.Errorf("falcon oauth: %w", err)
	}
	if status >= 300 {
		return "", statusError("falcon oauth", status)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.AccessToken == "" {
		return "", fmt.Errorf("falcon oauth: token missing")
	}
	return body.AccessToken, nil
}

func falconIDs(ctx context.Context, hc *http.Client, base, token string) ([]string, error) {
	var ids []string
	offset := ""
	for page := 0; page < 40; page++ {
		u := base + "/devices/queries/devices-scroll/v1?limit=5000"
		if offset != "" {
			u += "&offset=" + url.QueryEscape(offset)
		}
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		raw, status, err := doJSON(ctx, hc, req)
		if err != nil {
			return nil, fmt.Errorf("falcon devices: %w", err)
		}
		if status >= 300 {
			return nil, statusError("falcon devices", status)
		}
		var body struct {
			Resources []string `json:"resources"`
			Meta      struct {
				Pagination struct {
					Offset string `json:"offset"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, fmt.Errorf("falcon devices: decode: %w", err)
		}
		if len(body.Resources) == 0 {
			break
		}
		ids = append(ids, body.Resources...)
		next := body.Meta.Pagination.Offset
		if next == "" || next == offset {
			break
		}
		offset = next
	}
	return ids, nil
}

func falconDetails(ctx context.Context, hc *http.Client, base, token string, ids []string) ([]Observation, error) {
	payload, _ := json.Marshal(map[string]any{"ids": ids})
	req, err := http.NewRequest(http.MethodPost, base+"/devices/entities/devices/v2", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	raw, status, err := doJSON(ctx, hc, req)
	if err != nil {
		return nil, fmt.Errorf("falcon device details: %w", err)
	}
	if status >= 300 {
		return nil, statusError("falcon device details", status)
	}
	var body struct {
		Resources []struct {
			DeviceID     string `json:"device_id"`
			SerialNumber string `json:"serial_number"`
			Hostname     string `json:"hostname"`
			MACAddress   string `json:"mac_address"`
			LocalIP      string `json:"local_ip"`
			OSVersion    string `json:"os_version"`
			LastSeen     string `json:"last_seen"`
			AgentVersion string `json:"agent_version"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("falcon device details: decode: %w", err)
	}
	out := make([]Observation, 0, len(body.Resources))
	for _, d := range body.Resources {
		if d.DeviceID == "" {
			continue
		}
		obs := Observation{
			NativeID:     d.DeviceID,
			OSVersion:    d.OSVersion,
			IPAddress:    d.LocalIP,
			AgentVersion: d.AgentVersion,
			LastSeen:     parseTime(d.LastSeen),
			Keys: Keys{
				Serial:   d.SerialNumber,
				MAC:      d.MACAddress,
				Hostname: d.Hostname,
			},
		}
		if obs.LastSeen.IsZero() {
			obs.LastSeen = time.Time{}
		}
		obs.Fields = obs.NormalizedFields()
		out = append(out, obs)
	}
	return out, nil
}
