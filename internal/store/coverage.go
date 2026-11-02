package store

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/Arequ/mission-control/internal/model"
)

var fieldMapKeys = map[string]bool{
	"native_id": true, "serial": true, "hardware_uuid": true, "mac": true,
	"hostname": true, "primary_user": true, "os_version": true, "ip_address": true,
	"agent_version": true, "last_seen": true,
}

type storedConnector struct {
	model.Connector
	clientSecret  string
	apiToken      string
	elasticAPIKey string
}

func (c storedConnector) public() model.Connector {
	out := c.Connector
	out.ClientSecret = ""
	out.APIToken = ""
	out.ElasticAPIKey = ""
	out.HasClientSecret = c.clientSecret != ""
	out.HasAPIToken = c.apiToken != ""
	out.HasElasticAPIKey = c.elasticAPIKey != ""
	if out.FieldMap == nil {
		out.FieldMap = map[string]string{}
	}
	return out
}

func (s *Store) CreateConnector(ctx context.Context, p model.Principal, in model.Connector) (model.Connector, error) {
	in.ID = ""
	if err := normalizeConnector(&in); err != nil {
		return model.Connector{}, err
	}
	now := s.now()
	id := newID()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Connector{}, err
	}
	defer tx.Rollback(ctx)
	fieldRaw, err := json.Marshal(in.FieldMap)
	if err != nil {
		return model.Connector{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO source_connectors (
			id, name, source, mode, enabled, interval_seconds, stale_after_seconds,
			base_url, client_id, client_secret, api_token, elastic_url, elastic_api_key,
			index_pattern, query_text, query_language, time_field, time_zone, field_map, managed_by,
			created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20,$21,$21)`,
		id, in.Name, in.Source, in.Mode, in.Enabled, in.IntervalSeconds, in.StaleAfterSeconds,
		in.BaseURL, in.ClientID, in.ClientSecret, in.APIToken, in.ElasticURL, in.ElasticAPIKey,
		in.IndexPattern, in.Query, in.QueryLanguage, in.TimeField, in.TimeZone, string(fieldRaw), managedBy(in.ManagedBy), now)
	if err != nil {
		return model.Connector{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "source_connector", id, connectorAudit(in)); err != nil {
		return model.Connector{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Connector{}, err
	}
	return s.GetConnector(ctx, id)
}

func (s *Store) UpdateConnector(ctx context.Context, p model.Principal, id string, in model.Connector) (model.Connector, error) {
	cur, err := s.loadConnector(ctx, id)
	if err != nil {
		return model.Connector{}, err
	}
	if strings.TrimSpace(in.ClientSecret) == "" {
		in.ClientSecret = cur.clientSecret
	}
	if strings.TrimSpace(in.APIToken) == "" {
		in.APIToken = cur.apiToken
	}
	if strings.TrimSpace(in.ElasticAPIKey) == "" {
		in.ElasticAPIKey = cur.elasticAPIKey
	}
	in.ID = id
	in.Source = cur.Source
	if err := normalizeConnector(&in); err != nil {
		return model.Connector{}, err
	}
	// Source is immutable so a rename cannot retarget another tool's snapshots.
	in.Source = cur.Source
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Connector{}, err
	}
	defer tx.Rollback(ctx)
	fieldRaw, err := json.Marshal(in.FieldMap)
	if err != nil {
		return model.Connector{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE source_connectors SET
			name=$2, mode=$3, enabled=$4, interval_seconds=$5, stale_after_seconds=$6,
			base_url=$7, client_id=$8, client_secret=$9, api_token=$10, elastic_url=$11, elastic_api_key=$12,
			index_pattern=$13, query_text=$14, query_language=$15, time_field=$16, time_zone=$17, field_map=$18::jsonb,
			managed_by=$19, updated_at=$20
		WHERE id=$1`,
		id, in.Name, in.Mode, in.Enabled, in.IntervalSeconds, in.StaleAfterSeconds,
		in.BaseURL, in.ClientID, in.ClientSecret, in.APIToken, in.ElasticURL, in.ElasticAPIKey,
		in.IndexPattern, in.Query, in.QueryLanguage, in.TimeField, in.TimeZone, string(fieldRaw), managedBy(in.ManagedBy), now)
	if err != nil {
		return model.Connector{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return model.Connector{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "source_connector", id, connectorAudit(in)); err != nil {
		return model.Connector{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Connector{}, err
	}
	return s.GetConnector(ctx, id)
}

func (s *Store) GetConnector(ctx context.Context, id string) (model.Connector, error) {
	c, err := s.loadConnector(ctx, id)
	if err != nil {
		return model.Connector{}, err
	}
	return c.public(), nil
}

func (s *Store) ListConnectors(ctx context.Context) ([]model.Connector, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+connectorCols+` FROM source_connectors ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Connector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c.public())
	}
	if out == nil {
		out = []model.Connector{}
	}
	return out, rows.Err()
}

func (s *Store) DeleteConnector(ctx context.Context, p model.Principal, id string) error {
	cur, err := s.loadConnector(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM source_connectors WHERE id=$1`, id); err != nil {
		return err
	}
	if err := s.audit(ctx, tx, p, "delete", "source_connector", id, map[string]any{"name": cur.Name, "source": cur.Source}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func connectorAudit(in model.Connector) map[string]any {
	return map[string]any{
		"name": in.Name, "source": in.Source, "mode": in.Mode, "enabled": in.Enabled,
		"interval_seconds": in.IntervalSeconds, "stale_after_seconds": in.StaleAfterSeconds,
		"has_client_secret": in.ClientSecret != "", "has_api_token": in.APIToken != "",
		"has_elastic_api_key": in.ElasticAPIKey != "",
	}
}

func normalizeConnector(in *model.Connector) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Source = strings.TrimSpace(in.Source)
	in.Mode = strings.TrimSpace(in.Mode)
	if err := checkName("name", in.Name); err != nil {
		return err
	}
	if !coverage.KnownSource(in.Source) {
		return invalid("source must be one of the eight coverage tools")
	}
	switch in.Mode {
	case "api", "elastic", "native":
	default:
		return invalid("mode must be api, elastic, or native")
	}
	native := in.Source == "osquery" || in.Source == "munki"
	if in.Mode == "native" && !native {
		return invalid("native mode is only for osquery and munki")
	}
	if in.Mode != "native" && native {
		return invalid("osquery and munki are projected by Mission Control")
	}
	if in.IntervalSeconds == 0 {
		in.IntervalSeconds = 900
	}
	if in.IntervalSeconds < 60 || in.IntervalSeconds > 604800 {
		return invalid("interval_seconds must be between 60 and 604800")
	}
	if in.StaleAfterSeconds == 0 {
		in.StaleAfterSeconds = 86400
	}
	if in.StaleAfterSeconds < 60 || in.StaleAfterSeconds > 31536000 {
		return invalid("stale_after_seconds must be between 60 and 31536000")
	}
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	in.ElasticURL = strings.TrimSpace(in.ElasticURL)
	if err := checkHTTPURL("base_url", in.BaseURL); err != nil {
		return err
	}
	if err := checkHTTPURL("elastic_url", in.ElasticURL); err != nil {
		return err
	}
	if in.Mode == "api" && in.BaseURL == "" {
		return invalid("api mode requires base_url")
	}
	if in.Mode == "elastic" {
		if in.ElasticURL == "" || strings.TrimSpace(in.IndexPattern) == "" {
			return invalid("elastic mode requires elastic_url and index_pattern")
		}
	}
	if in.QueryLanguage == "" {
		in.QueryLanguage = "kql"
	}
	if in.QueryLanguage != "kql" && in.QueryLanguage != "dsl" {
		return invalid("query_language must be kql or dsl")
	}
	if in.TimeField == "" {
		in.TimeField = "@timestamp"
	}
	if in.TimeZone == "" {
		in.TimeZone = "UTC"
	}
	if _, err := time.LoadLocation(in.TimeZone); err != nil {
		return invalid("time_zone must be an IANA name such as UTC")
	}
	if in.FieldMap == nil {
		in.FieldMap = map[string]string{}
	}
	for k, v := range in.FieldMap {
		if !fieldMapKeys[k] {
			return invalid("field_map key " + k + " is not a normalized device field")
		}
		if strings.TrimSpace(v) == "" || strings.Contains(v, " ") {
			return invalid("field_map values are dotted event paths")
		}
	}
	in.ClientSecret = strings.TrimSpace(in.ClientSecret)
	in.APIToken = strings.TrimSpace(in.APIToken)
	in.ElasticAPIKey = strings.TrimSpace(in.ElasticAPIKey)
	if len(in.ClientSecret) > 4000 || len(in.APIToken) > 4000 || len(in.ElasticAPIKey) > 4000 {
		return invalid("credential is too long")
	}
	return nil
}

func checkHTTPURL(field, v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return invalid(field + " must be an http(s) URL")
	}
	if u.User != nil {
		return invalid(field + " must not include credentials")
	}
	return nil
}

const connectorCols = `id, name, source, mode, enabled, interval_seconds, stale_after_seconds,
	base_url, client_id, client_secret, api_token, elastic_url, elastic_api_key,
	index_pattern, query_text, query_language, time_field, time_zone, field_map, managed_by,
	last_sync_at, last_sync_status, last_sync_error, last_sync_count, created_at, updated_at`

func (s *Store) loadConnector(ctx context.Context, id string) (storedConnector, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+connectorCols+` FROM source_connectors WHERE id=$1`, id)
	c, err := scanConnector(row)
	if err != nil {
		return storedConnector{}, notFound(err)
	}
	return c, nil
}

func (s *Store) loadConnectors(ctx context.Context) ([]storedConnector, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+connectorCols+` FROM source_connectors ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedConnector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type scannable interface {
	Scan(dest ...any) error
}

func scanConnector(row scannable) (storedConnector, error) {
	var c storedConnector
	var fieldRaw []byte
	var last *time.Time
	err := row.Scan(
		&c.ID, &c.Name, &c.Source, &c.Mode, &c.Enabled, &c.IntervalSeconds, &c.StaleAfterSeconds,
		&c.BaseURL, &c.ClientID, &c.clientSecret, &c.apiToken, &c.ElasticURL, &c.elasticAPIKey,
		&c.IndexPattern, &c.Query, &c.QueryLanguage, &c.TimeField, &c.TimeZone, &fieldRaw, &c.ManagedBy,
		&last, &c.LastSyncStatus, &c.LastSyncError, &c.LastSyncCount, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return storedConnector{}, err
	}
	c.LastSyncAt = last
	c.FieldMap = map[string]string{}
	if len(fieldRaw) > 0 {
		_ = json.Unmarshal(fieldRaw, &c.FieldMap)
	}
	return c, nil
}

func (s *Store) thresholds(ctx context.Context) (map[string]time.Duration, error) {
	rows, err := s.pool.Query(ctx, `SELECT source, stale_after_seconds FROM source_connectors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Duration{}
	for _, src := range coverage.Sources {
		out[src.Key] = 24 * time.Hour
	}
	for rows.Next() {
		var source string
		var seconds int
		if err := rows.Scan(&source, &seconds); err != nil {
			return nil, err
		}
		if seconds > 0 {
			out[source] = time.Duration(seconds) * time.Second
		}
	}
	return out, rows.Err()
}
