package provider

import (
	"context"
	"net/http"
)

type connectorAPI struct {
	ID                string            `json:"id,omitempty"`
	Name              string            `json:"name"`
	Source            string            `json:"source"`
	Mode              string            `json:"mode"`
	Enabled           bool              `json:"enabled"`
	IntervalSeconds   int               `json:"interval_seconds"`
	StaleAfterSeconds int               `json:"stale_after_seconds"`
	BaseURL           string            `json:"base_url"`
	ClientID          string            `json:"client_id"`
	ClientSecret      string            `json:"client_secret,omitempty"`
	APIToken          string            `json:"api_token,omitempty"`
	ElasticURL        string            `json:"elastic_url"`
	ElasticAPIKey     string            `json:"elastic_api_key,omitempty"`
	IndexPattern      string            `json:"index_pattern"`
	Query             string            `json:"query"`
	QueryLanguage     string            `json:"query_language"`
	TimeField         string            `json:"time_field"`
	TimeZone          string            `json:"time_zone"`
	FieldMap          map[string]string `json:"field_map"`
	ManagedBy         string            `json:"managed_by,omitempty"`
}

func (c *Client) CreateConnector(ctx context.Context, in connectorAPI) (connectorAPI, error) {
	var out connectorAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/source-connectors", in, &out)
	return out, err
}

func (c *Client) GetConnector(ctx context.Context, id string) (connectorAPI, error) {
	var out connectorAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/source-connectors/"+id, nil, &out)
	return out, err
}

func (c *Client) UpdateConnector(ctx context.Context, id string, in connectorAPI) (connectorAPI, error) {
	var out connectorAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/source-connectors/"+id, in, &out)
	return out, err
}

func (c *Client) DeleteConnector(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/source-connectors/"+id, nil, nil)
}
