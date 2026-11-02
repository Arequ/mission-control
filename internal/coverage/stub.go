package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// APIStub is a placeholder HTTP poller for vendors whose device APIs are not
// stable or public enough to implement here: Rapid7 Insight Agent, Netskope,
// Proofpoint, and BlastShield. The example Terraform stack maps those sources
// through Elastic instead.
//
// The stub speaks a small contract so it can be tested with an httptest server:
// GET {base}/v1/devices, Authorization: Bearer {api token}, body
// {"devices":[{"id","serial","hardware_uuid","mac","hostname","primary_user",
// "os_version","ip_address","agent_version","last_seen"}]}.
// That path is not the vendor's API. A real tenant needs the vendor's own
// credentials and a later connector before this mode returns production data.
type APIStub struct {
	Source string
}

func (s APIStub) Poll(ctx context.Context, cfg Config, hc *http.Client) ([]Observation, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("%s api stub: api token is required", s.Source)
	}
	base := trimURL(cfg.BaseURL)
	if base == "" {
		return nil, fmt.Errorf("%s api stub: base url is required", s.Source)
	}
	req, err := http.NewRequest(http.MethodGet, base+"/v1/devices", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	req.Header.Set("Accept", "application/json")
	raw, status, err := doJSON(ctx, hc, req)
	if err != nil {
		return nil, fmt.Errorf("%s api stub: %w", s.Source, err)
	}
	if status >= 300 {
		return nil, statusError(s.Source+" api stub", status)
	}
	var body struct {
		Devices []struct {
			ID           string `json:"id"`
			Serial       string `json:"serial"`
			HardwareUUID string `json:"hardware_uuid"`
			MAC          string `json:"mac"`
			Hostname     string `json:"hostname"`
			PrimaryUser  string `json:"primary_user"`
			OSVersion    string `json:"os_version"`
			IPAddress    string `json:"ip_address"`
			AgentVersion string `json:"agent_version"`
			LastSeen     string `json:"last_seen"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("%s api stub: decode: %w", s.Source, err)
	}
	out := make([]Observation, 0, len(body.Devices))
	for _, d := range body.Devices {
		if d.ID == "" {
			continue
		}
		obs := Observation{
			NativeID:     d.ID,
			OSVersion:    d.OSVersion,
			IPAddress:    d.IPAddress,
			AgentVersion: d.AgentVersion,
			LastSeen:     parseTime(d.LastSeen),
			Keys: Keys{
				Serial:       d.Serial,
				HardwareUUID: d.HardwareUUID,
				MAC:          d.MAC,
				Hostname:     d.Hostname,
				PrimaryUser:  d.PrimaryUser,
			},
		}
		obs.Fields = obs.NormalizedFields()
		out = append(out, obs)
	}
	return out, nil
}
