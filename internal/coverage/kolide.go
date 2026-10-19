package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Kolide polls the Kolide K2 device API.
// GET {base}/api/v0/devices?per_page=100 with a bearer token, following
// pagination.next until it is empty. Device fields that the public list
// documents (id, name, serial, operating_system, last_seen_at) are always
// read. hardware_uuid, primary_mac_address, remote_ip, and assigned_owner.email
// are read when the payload includes them.
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
	var out []Observation
	for page := 0; page < 200 && next != ""; page++ {
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
				Next string `json:"next"`
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
		next = strings.TrimSpace(body.Pagination.Next)
	}
	return out, nil
}
