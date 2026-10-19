package model

import "time"

// Connector is a Terraform-managed source connector. Secrets are write-only:
// the API accepts them and never returns them.
type Connector struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Source              string            `json:"source"`
	Mode                string            `json:"mode"`
	Enabled             bool              `json:"enabled"`
	IntervalSeconds     int               `json:"interval_seconds"`
	StaleAfterSeconds   int               `json:"stale_after_seconds"`
	BaseURL             string            `json:"base_url"`
	ClientID            string            `json:"client_id"`
	ElasticURL          string            `json:"elastic_url"`
	IndexPattern        string            `json:"index_pattern"`
	Query               string            `json:"query"`
	QueryLanguage       string            `json:"query_language"`
	TimeField           string            `json:"time_field"`
	FieldMap            map[string]string `json:"field_map"`
	ManagedBy           string            `json:"managed_by"`
	HasClientSecret     bool              `json:"has_client_secret"`
	HasAPIToken         bool              `json:"has_api_token"`
	HasElasticAPIKey    bool              `json:"has_elastic_api_key"`
	LastSyncAt          *time.Time        `json:"last_sync_at,omitempty"`
	LastSyncStatus      string            `json:"last_sync_status"`
	LastSyncError       string            `json:"last_sync_error"`
	LastSyncCount       int               `json:"last_sync_count"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
	ClientSecret        string            `json:"client_secret,omitempty"`
	APIToken            string            `json:"api_token,omitempty"`
	ElasticAPIKey       string            `json:"elastic_api_key,omitempty"`
}

// Public returns a copy safe to marshal. Secret fields are cleared.
func (c Connector) Public() Connector {
	c.ClientSecret = ""
	c.APIToken = ""
	c.ElasticAPIKey = ""
	if c.FieldMap == nil {
		c.FieldMap = map[string]string{}
	}
	return c
}

// DeviceCoverage is the small chip on the general device page.
type DeviceCoverage struct {
	Seen  int `json:"seen"`
	Total int `json:"total"`
}

// CoverageMatrix is devices (and ghosts) by source.
type CoverageMatrix struct {
	Sources []CoverageSourceColumn `json:"sources"`
	Rows    []CoverageRow          `json:"rows"`
	Total   int                    `json:"total"`
	Gaps    int                    `json:"gaps"`
	Limit   int                    `json:"limit"`
	Offset  int                    `json:"offset"`
}

// CoverageSourceColumn is one matrix header.
type CoverageSourceColumn struct {
	Key               string  `json:"key"`
	Name              string  `json:"name"`
	Short             string  `json:"short"`
	Percent           float64 `json:"percent"`
	StaleAfterSeconds int     `json:"stale_after_seconds"`
}

// CoverageRow is one device or ghost.
type CoverageRow struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Name      string         `json:"name"`
	Hostname  string         `json:"hostname"`
	Serial    string         `json:"serial"`
	User      string         `json:"user"`
	OSVersion string         `json:"os_version"`
	Seen      int            `json:"seen"`
	Total     int            `json:"total"`
	Cells     []CoverageCell `json:"cells"`
}

// CoverageCell is seen, stale, or missing.
type CoverageCell struct {
	Source   string     `json:"source"`
	State    string     `json:"state"`
	LastSeen *time.Time `json:"last_seen_at,omitempty"`
	NativeID string     `json:"native_id,omitempty"`
}

// CoverageDevice is the per-device pane.
type CoverageDevice struct {
	ID        string               `json:"id"`
	Kind      string               `json:"kind"`
	Name      string               `json:"name"`
	Hostname  string               `json:"hostname"`
	Serial    string               `json:"serial"`
	User      string               `json:"user"`
	OSVersion string               `json:"os_version"`
	Model     string               `json:"model,omitempty"`
	DeviceID  string               `json:"device_id,omitempty"`
	Match     CoverageMatch        `json:"match"`
	Seen      int                  `json:"seen"`
	Total     int                  `json:"total"`
	Sources   []CoverageTile       `json:"sources"`
	Fields    []CoverageField      `json:"fields"`
	Events    []CoverageEvent      `json:"events"`
}

// CoverageMatch explains which keys joined the record to a device.
type CoverageMatch struct {
	Confidence string   `json:"confidence"`
	MatchedOn  []string `json:"matched_on"`
	Note       string   `json:"note"`
}

// CoverageTile is one source on the device pane.
type CoverageTile struct {
	Key        string     `json:"key"`
	Name       string     `json:"name"`
	Short      string     `json:"short"`
	State      string     `json:"state"`
	LastSeen   *time.Time `json:"last_seen_at,omitempty"`
	NativeID   string     `json:"native_id,omitempty"`
	Confidence string     `json:"confidence,omitempty"`
	MatchedOn  []string   `json:"matched_on,omitempty"`
}

// CoverageField is one row of the field comparison.
type CoverageField struct {
	Field   string               `json:"field"`
	Label   string               `json:"label"`
	Unified string               `json:"unified"`
	Values  []CoverageFieldValue `json:"values"`
}

// CoverageFieldValue is one source's value for a field.
type CoverageFieldValue struct {
	Source    string `json:"source"`
	Value     string `json:"value"`
	Disagrees bool   `json:"disagrees"`
}

// CoverageEvent is a source sighting, loss, disagreement, or rematch.
type CoverageEvent struct {
	ID     int64          `json:"id"`
	At     time.Time      `json:"at"`
	Source string         `json:"source"`
	Kind   string         `json:"kind"`
	Detail map[string]any `json:"detail"`
}
