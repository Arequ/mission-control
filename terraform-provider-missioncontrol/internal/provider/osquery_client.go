package provider

import (
	"context"
	"net/http"
)

type osqueryQueryAPI struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SQL         string `json:"sql"`
	Platform    string `json:"platform"`
	Interval    int    `json:"interval"`
	Snapshot    bool   `json:"snapshot"`
	Removed     bool   `json:"removed"`
	Scheduled   bool   `json:"scheduled"`
	ManagedBy   string `json:"managed_by,omitempty"`
}

func (c *Client) CreateOsqueryQuery(ctx context.Context, in osqueryQueryAPI) (osqueryQueryAPI, error) {
	var out osqueryQueryAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/osquery/queries", in, &out)
	return out, err
}
func (c *Client) GetOsqueryQuery(ctx context.Context, id string) (osqueryQueryAPI, error) {
	var out osqueryQueryAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/osquery/queries/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateOsqueryQuery(ctx context.Context, id string, in osqueryQueryAPI) (osqueryQueryAPI, error) {
	var out osqueryQueryAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/osquery/queries/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteOsqueryQuery(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/osquery/queries/"+id, nil, nil)
}

type osqueryPackAPI struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Platform    string   `json:"platform"`
	Interval    *int     `json:"interval,omitempty"`
	Shard       *int     `json:"shard,omitempty"`
	Discovery   []string `json:"discovery"`
	Labels      []string `json:"labels"`
	QueryIDs    []string `json:"query_ids"`
	Enabled     bool     `json:"enabled"`
	ManagedBy   string   `json:"managed_by,omitempty"`
}

func (c *Client) CreateOsqueryPack(ctx context.Context, in osqueryPackAPI) (osqueryPackAPI, error) {
	var out osqueryPackAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/osquery/packs", in, &out)
	return out, err
}
func (c *Client) GetOsqueryPack(ctx context.Context, id string) (osqueryPackAPI, error) {
	var out osqueryPackAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/osquery/packs/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateOsqueryPack(ctx context.Context, id string, in osqueryPackAPI) (osqueryPackAPI, error) {
	var out osqueryPackAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/osquery/packs/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteOsqueryPack(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/osquery/packs/"+id, nil, nil)
}

type osqueryLabelAPI struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Kind        string   `json:"kind"`
	SQL         string   `json:"sql"`
	Platform    string   `json:"platform"`
	Serials     []string `json:"serials"`
	DeviceIDs   []string `json:"device_ids"`
	ManagedBy   string   `json:"managed_by,omitempty"`
}

func (c *Client) CreateOsqueryLabel(ctx context.Context, in osqueryLabelAPI) (osqueryLabelAPI, error) {
	var out osqueryLabelAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/osquery/labels", in, &out)
	return out, err
}
func (c *Client) GetOsqueryLabel(ctx context.Context, id string) (osqueryLabelAPI, error) {
	var out osqueryLabelAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/osquery/labels/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateOsqueryLabel(ctx context.Context, id string, in osqueryLabelAPI) (osqueryLabelAPI, error) {
	var out osqueryLabelAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/osquery/labels/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteOsqueryLabel(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/osquery/labels/"+id, nil, nil)
}

type enrollSecretAPI struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Secret    string `json:"secret,omitempty"`
	Enabled   bool   `json:"enabled"`
	ManagedBy string `json:"managed_by,omitempty"`
}

func (c *Client) CreateEnrollSecret(ctx context.Context, in enrollSecretAPI) (enrollSecretAPI, error) {
	var out enrollSecretAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/osquery/enroll-secrets", in, &out)
	return out, err
}
func (c *Client) GetEnrollSecret(ctx context.Context, id string) (enrollSecretAPI, error) {
	var out enrollSecretAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/osquery/enroll-secrets/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateEnrollSecret(ctx context.Context, id string, in enrollSecretAPI) (enrollSecretAPI, error) {
	var out enrollSecretAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/osquery/enroll-secrets/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteEnrollSecret(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/osquery/enroll-secrets/"+id, nil, nil)
}
