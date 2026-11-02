package coverage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Falcon polls the CrowdStrike Falcon hosts API with OAuth2 client credentials.
// List: GET /devices/queries/devices-scroll/v1
// Details: POST /devices/entities/devices/v2 {"ids": [...]}
// The base URL is the cloud region (api.crowdstrike.com, api.us-2, api.eu-1, ...).
// Tokens are cached until shortly before expires_in and refreshed once on 401.
type Falcon struct{}

const falconMaxPages = 20

type falconTokenEntry struct {
	token string
	until time.Time
}

var (
	falconTokens sync.Mutex
	falconCache  = map[string]falconTokenEntry{}
)

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
	token, err := falconToken(ctx, hc, base, cfg.ClientID, cfg.ClientSecret, false)
	if err != nil {
		return nil, err
	}
	ids, refreshed, err := falconIDs(ctx, hc, base, cfg.ClientID, cfg.ClientSecret, token)
	if err != nil {
		return nil, err
	}
	if refreshed != "" {
		token = refreshed
	}
	var out []Observation
	seen := map[string]bool{}
	for i := 0; i < len(ids); i += 100 {
		end := i + 100
		if end > len(ids) {
			end = len(ids)
		}
		chunk, next, err := falconDetails(ctx, hc, base, cfg.ClientID, cfg.ClientSecret, token, ids[i:end])
		if err != nil {
			return nil, err
		}
		token = next
		for _, obs := range chunk {
			if seen[obs.NativeID] {
				continue
			}
			seen[obs.NativeID] = true
			out = append(out, obs)
		}
	}
	return out, nil
}

func falconCacheKey(base, clientID, secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base + "\n" + clientID + "\n" + hex.EncodeToString(sum[:8])
}

func falconToken(ctx context.Context, hc *http.Client, base, clientID, clientSecret string, force bool) (string, error) {
	key := falconCacheKey(base, clientID, clientSecret)
	falconTokens.Lock()
	if !force {
		if ent, ok := falconCache[key]; ok && time.Until(ent.until) > 30*time.Second {
			falconTokens.Unlock()
			return ent.token, nil
		}
	} else {
		delete(falconCache, key)
	}
	falconTokens.Unlock()

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
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.AccessToken == "" {
		return "", fmt.Errorf("falcon oauth: token missing")
	}
	if body.ExpiresIn <= 0 {
		body.ExpiresIn = 1800
	}
	falconTokens.Lock()
	falconCache[key] = falconTokenEntry{token: body.AccessToken, until: time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)}
	falconTokens.Unlock()
	return body.AccessToken, nil
}

func falconIDs(ctx context.Context, hc *http.Client, base, clientID, secret, token string) ([]string, string, error) {
	var ids []string
	seen := map[string]struct{}{}
	offset := ""
	refreshed := false
	for page := 0; page < falconMaxPages; page++ {
		u := base + "/devices/queries/devices-scroll/v1?limit=5000"
		if offset != "" {
			u += "&offset=" + url.QueryEscape(offset)
		}
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		raw, status, err := doJSON(ctx, hc, req)
		if err != nil {
			return nil, "", fmt.Errorf("falcon devices: %w", err)
		}
		if status == http.StatusUnauthorized && !refreshed {
			token, err = falconToken(ctx, hc, base, clientID, secret, true)
			if err != nil {
				return nil, "", err
			}
			refreshed = true
			page--
			continue
		}
		if status >= 300 {
			return nil, "", statusError("falcon devices", status)
		}
		var body struct {
			Resources []string `json:"resources"`
			Meta      struct {
				Pagination struct {
					Offset string `json:"offset"`
					Total  int    `json:"total"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, "", fmt.Errorf("falcon devices: decode: %w", err)
		}
		for _, id := range body.Resources {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
		next := body.Meta.Pagination.Offset
		total := body.Meta.Pagination.Total
		if len(body.Resources) == 0 || next == "" || next == offset || (total > 0 && len(ids) >= total) {
			return ids, token, nil
		}
		offset = next
	}
	return nil, "", fmt.Errorf("falcon devices: scroll truncated before the offset was exhausted")
}

func falconDetails(ctx context.Context, hc *http.Client, base, clientID, secret, token string, ids []string) ([]Observation, string, error) {
	payload, _ := json.Marshal(map[string]any{"ids": ids})
	req, err := http.NewRequest(http.MethodPost, base+"/devices/entities/devices/v2", bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	raw, status, err := doJSON(ctx, hc, req)
	if err != nil {
		return nil, "", fmt.Errorf("falcon device details: %w", err)
	}
	if status == http.StatusUnauthorized {
		token, err = falconToken(ctx, hc, base, clientID, secret, true)
		if err != nil {
			return nil, "", err
		}
		req, err = http.NewRequest(http.MethodPost, base+"/devices/entities/devices/v2", bytes.NewReader(payload))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		raw, status, err = doJSON(ctx, hc, req)
		if err != nil {
			return nil, "", fmt.Errorf("falcon device details: %w", err)
		}
	}
	if status >= 300 {
		return nil, "", statusError("falcon device details", status)
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
		return nil, "", fmt.Errorf("falcon device details: decode: %w", err)
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
		obs.Fields = obs.NormalizedFields()
		out = append(out, obs)
	}
	return out, token, nil
}
