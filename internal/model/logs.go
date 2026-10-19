package model

import "time"

// LogSource is one index inside a log view.
type LogSource struct {
	ID             string `json:"id,omitempty"`
	Label          string `json:"label"`
	Color          string `json:"color"`
	IndexPattern   string `json:"index_pattern"`
	KQL            string `json:"kql"`
	MessageField   string `json:"message_field"`
	TimestampField string `json:"timestamp_field"`
	FileField      string `json:"file_field"`
	HostField      string `json:"host_field"`
	SequenceField  string `json:"sequence_field"`
}

// LogView is a named query over one or more Elastic indexes.
// ElasticAPIKey is write-only: the API accepts it and never returns it.
type LogView struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	DefaultWindow    string      `json:"default_window"`
	MaxLines         int         `json:"max_lines"`
	DeviceScoped     bool        `json:"device_scoped"`
	TimeZone         string      `json:"time_zone"`
	ElasticURL       string      `json:"elastic_url"`
	ConnectorID      string      `json:"connector_id"`
	ManagedBy        string      `json:"managed_by"`
	HasElasticAPIKey bool        `json:"has_elastic_api_key"`
	Sources          []LogSource `json:"sources"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	ElasticAPIKey    string      `json:"elastic_api_key,omitempty"`
	Reader           string      `json:"-"`
}

// Public clears the write-only credential.
func (v LogView) Public() LogView {
	v.ElasticAPIKey = ""
	v.Reader = ""
	if v.Sources == nil {
		v.Sources = []LogSource{}
	}
	return v
}

// LogRun is a request to read a view.
type LogRun struct {
	From     time.Time
	To       time.Time
	DeviceID string
	Limit    int
	Cursor   string
	Dir      string
	Align    string
	Extend   bool
}
