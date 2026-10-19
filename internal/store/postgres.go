package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/config"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the production Store.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres wraps a connection pool.
func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

func (s *Postgres) withTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Postgres) EnsureToken(ctx context.Context, name, token, role string) error {
	if !auth.ValidRole(role) {
		return ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO api_tokens (id, name, token_hash, role)
		VALUES ($1::uuid, $2, $3, $4)
		ON CONFLICT (name) DO UPDATE SET token_hash = EXCLUDED.token_hash, role = EXCLUDED.role
	`, uuid.NewString(), name, auth.Hash(token), role)
	return err
}

func (s *Postgres) AuthenticateToken(ctx context.Context, token string) (auth.Principal, error) {
	var p auth.Principal
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, name, role FROM api_tokens WHERE token_hash = $1
	`, auth.Hash(token)).Scan(&p.ID, &p.Name, &p.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Principal{}, ErrUnauthorized
	}
	if err != nil {
		return auth.Principal{}, err
	}
	_, _ = s.pool.Exec(ctx, `
		UPDATE api_tokens SET last_used_at = now()
		WHERE id = $1::uuid AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')
	`, p.ID)
	return p, nil
}

func (s *Postgres) CreateToken(ctx context.Context, name, role string) (string, auth.Principal, error) {
	if !auth.ValidRole(role) || strings.TrimSpace(name) == "" {
		return "", auth.Principal{}, ErrInvalid
	}
	token, err := auth.NewSecret("mc_")
	if err != nil {
		return "", auth.Principal{}, err
	}
	p := auth.Principal{ID: uuid.NewString(), Name: name, Role: role}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO api_tokens (id, name, token_hash, role) VALUES ($1::uuid, $2, $3, $4)
	`, p.ID, name, auth.Hash(token), role)
	if isUnique(err) {
		return "", auth.Principal{}, ErrConflict
	}
	if err != nil {
		return "", auth.Principal{}, err
	}
	return token, p, nil
}

const deviceCols = `id::text, node_key_hash, host_identifier, hostname, computer_name, uuid,
	hardware_serial, hardware_model, hardware_vendor, cpu_brand, cpu_physical_cores,
	physical_memory, platform, os_name, os_version, os_build, osquery_version,
	primary_user, config_hash, labels, last_seen_at, enrolled_at, updated_at`

func scanDevice(row pgx.Row, inv *[]byte) (Device, error) {
	var d Device
	var labels []string
	var last *time.Time
	dest := []any{
		&d.ID, &d.NodeKeyHash, &d.HostIdentifier, &d.Hostname, &d.ComputerName, &d.UUID,
		&d.HardwareSerial, &d.HardwareModel, &d.HardwareVendor, &d.CPUBrand, &d.CPUPhysicalCores,
		&d.PhysicalMemory, &d.Platform, &d.OSName, &d.OSVersion, &d.OSBuild, &d.OSQueryVersion,
		&d.PrimaryUser, &d.ConfigHash, &labels, &last, &d.EnrolledAt, &d.UpdatedAt,
	}
	if inv != nil {
		dest = append(dest, inv)
	}
	if err := row.Scan(dest...); err != nil {
		return Device{}, err
	}
	if labels == nil {
		labels = []string{}
	}
	d.Labels = labels
	if last != nil {
		t := last.UTC()
		d.LastSeenAt = &t
	}
	d.EnrolledAt = d.EnrolledAt.UTC()
	d.UpdatedAt = d.UpdatedAt.UTC()
	if inv != nil && len(*inv) > 0 && string(*inv) != "null" {
		if err := json.Unmarshal(*inv, &d.Inventory); err != nil {
			return Device{}, err
		}
	}
	return d, nil
}

func (s *Postgres) EnrollDevice(ctx context.Context, nodeKey string, incoming Device) (Device, error) {
	var saved Device
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		id, found, err := findDeviceID(ctx, tx, incoming)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		hash := auth.Hash(nodeKey)
		var d Device
		if !found {
			d = incoming
			d.ID = uuid.NewString()
			d.EnrolledAt = now
			if d.Labels == nil {
				d.Labels = []string{}
			}
			if d.Hostname == "" {
				d.Hostname = incoming.HostIdentifier
			}
		} else {
			var inv []byte
			d, err = scanDevice(tx.QueryRow(ctx, `SELECT `+deviceCols+`, inventory FROM devices WHERE id = $1::uuid FOR UPDATE`, id), &inv)
			if err != nil {
				return err
			}
			MergeIdentity(&d, incoming)
		}
		d.NodeKeyHash = hash
		d.UpdatedAt = now
		d.LastSeenAt = &now
		if err := upsertDevice(ctx, tx, d, !found); err != nil {
			return err
		}
		saved = publicDevice(d)
		return nil
	})
	return saved, err
}

func findDeviceID(ctx context.Context, tx pgx.Tx, in Device) (string, bool, error) {
	var id string
	if in.HardwareSerial != "" {
		err := tx.QueryRow(ctx, `SELECT id::text FROM devices WHERE hardware_serial = $1 FOR UPDATE`, in.HardwareSerial).Scan(&id)
		if err == nil {
			return id, true, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", false, err
		}
	}
	if in.HostIdentifier != "" {
		err := tx.QueryRow(ctx, `
			SELECT id::text FROM devices WHERE host_identifier = $1
			ORDER BY enrolled_at LIMIT 1 FOR UPDATE
		`, in.HostIdentifier).Scan(&id)
		if err == nil {
			return id, true, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", false, err
		}
	}
	return "", false, nil
}

func upsertDevice(ctx context.Context, tx pgx.Tx, d Device, insert bool) error {
	inv, err := inventoryArg(d)
	if err != nil {
		return err
	}
	labels := d.Labels
	if labels == nil {
		labels = []string{}
	}
	if insert {
		_, err = tx.Exec(ctx, `
			INSERT INTO devices (
				id, node_key_hash, host_identifier, hostname, computer_name, uuid,
				hardware_serial, hardware_model, hardware_vendor, cpu_brand, cpu_physical_cores,
				physical_memory, platform, os_name, os_version, os_build, osquery_version,
				primary_user, config_hash, labels, inventory, last_seen_at, enrolled_at, updated_at
			) VALUES (
				$1::uuid, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11,
				$12, $13, $14, $15, $16, $17,
				$18, $19, $20, $21::jsonb, $22, $23, $24
			)
		`, d.ID, d.NodeKeyHash, d.HostIdentifier, d.Hostname, d.ComputerName, d.UUID,
			d.HardwareSerial, d.HardwareModel, d.HardwareVendor, d.CPUBrand, d.CPUPhysicalCores,
			d.PhysicalMemory, d.Platform, d.OSName, d.OSVersion, d.OSBuild, d.OSQueryVersion,
			d.PrimaryUser, d.ConfigHash, labels, inv, d.LastSeenAt, d.EnrolledAt, d.UpdatedAt)
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE devices SET
			node_key_hash = $2,
			host_identifier = $3,
			hostname = $4,
			computer_name = $5,
			uuid = $6,
			hardware_serial = $7,
			hardware_model = $8,
			hardware_vendor = $9,
			cpu_brand = $10,
			cpu_physical_cores = $11,
			physical_memory = $12,
			platform = $13,
			os_name = $14,
			os_version = $15,
			os_build = $16,
			osquery_version = $17,
			primary_user = $18,
			config_hash = $19,
			labels = $20,
			inventory = $21::jsonb,
			last_seen_at = $22,
			updated_at = $23
		WHERE id = $1::uuid
	`, d.ID, d.NodeKeyHash, d.HostIdentifier, d.Hostname, d.ComputerName, d.UUID,
		d.HardwareSerial, d.HardwareModel, d.HardwareVendor, d.CPUBrand, d.CPUPhysicalCores,
		d.PhysicalMemory, d.Platform, d.OSName, d.OSVersion, d.OSBuild, d.OSQueryVersion,
		d.PrimaryUser, d.ConfigHash, labels, inv, d.LastSeenAt, d.UpdatedAt)
	return err
}

func inventoryArg(d Device) (string, error) {
	if len(d.Inventory) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(d.Inventory)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *Postgres) DeviceByNodeKey(ctx context.Context, nodeKey string) (Device, bool, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE node_key_hash = $1`, auth.Hash(nodeKey)), nil)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, false, nil
	}
	if err != nil {
		return Device{}, false, err
	}
	return publicDevice(d), true, nil
}

func (s *Postgres) TouchDevice(ctx context.Context, id, configHash string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices SET
			last_seen_at = now(),
			updated_at = now(),
			config_hash = CASE WHEN $2 <> '' THEN $2 ELSE config_hash END
		WHERE id = $1::uuid
	`, id, configHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Postgres) ApplyInventory(ctx context.Context, id string, patch Device, snapshots map[string]json.RawMessage, apps *[]App, labels []LabelUpdate) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		var inv []byte
		d, err := scanDevice(tx.QueryRow(ctx, `SELECT `+deviceCols+`, inventory FROM devices WHERE id = $1::uuid FOR UPDATE`, id), &inv)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		MergeIdentity(&d, patch)
		if len(snapshots) > 0 {
			if d.Inventory == nil {
				d.Inventory = map[string]json.RawMessage{}
			}
			for k, v := range snapshots {
				d.Inventory[k] = append(json.RawMessage(nil), v...)
			}
		}
		for _, label := range labels {
			d.Labels = ApplyLabel(d.Labels, label)
		}
		now := time.Now().UTC()
		d.LastSeenAt = &now
		d.UpdatedAt = now
		if err := upsertDevice(ctx, tx, d, false); err != nil {
			return err
		}
		if apps == nil {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_apps WHERE device_id = $1::uuid`, id); err != nil {
			return err
		}
		for _, app := range *apps {
			if _, err := tx.Exec(ctx, `
				INSERT INTO device_apps (device_id, name, bundle_id, path, version, last_seen_at)
				VALUES ($1::uuid, $2, $3, $4, $5, now())
			`, id, app.Name, app.BundleID, app.Path, app.Version); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Postgres) ListDevices(ctx context.Context, filter DeviceFilter) ([]Device, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+deviceCols+`
		FROM devices
		WHERE ($1 = '' OR hostname ILIKE $1 ESCAPE '\'
			OR computer_name ILIKE $1 ESCAPE '\'
			OR hardware_serial ILIKE $1 ESCAPE '\'
			OR primary_user ILIKE $1 ESCAPE '\'
			OR hardware_model ILIKE $1 ESCAPE '\')
		ORDER BY last_seen_at DESC NULLS LAST, hostname
		LIMIT $2 OFFSET $3
	`, likePattern(filter.Query), limit, filter.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDevices(rows)
}

func (s *Postgres) listAllDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deviceCols+` FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDevices(rows)
}

func collectDevices(rows pgx.Rows) ([]Device, error) {
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, publicDevice(d))
	}
	if out == nil {
		out = []Device{}
	}
	return out, rows.Err()
}

func likePattern(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return ""
	}
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + replacer.Replace(q) + "%"
}

func (s *Postgres) GetDevice(ctx context.Context, id string) (Device, error) {
	var inv []byte
	d, err := scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+`, inventory FROM devices WHERE id = $1::uuid`, id), &inv)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	return publicDevice(d), nil
}

func (s *Postgres) ListApps(ctx context.Context, deviceID string) ([]App, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT name, bundle_id, path, version FROM device_apps
		WHERE device_id = $1::uuid ORDER BY name, version
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []App
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.Name, &a.BundleID, &a.Path, &a.Version); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	if apps == nil {
		apps = []App{}
	}
	return apps, rows.Err()
}

func (s *Postgres) AddResult(ctx context.Context, deviceID string, result QueryResult) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO query_results (device_id, name, collected_at, snapshot, added, removed)
		VALUES ($1::uuid, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb)
	`, deviceID, result.Name, result.CollectedAt, rawArg(result.Snapshot), rawArg(result.Added), rawArg(result.Removed))
	return err
}

func rawArg(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func (s *Postgres) ListResults(ctx context.Context, deviceID string, limit int) ([]QueryResult, error) {
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT name, collected_at, snapshot, added, removed
		FROM query_results WHERE device_id = $1::uuid
		ORDER BY collected_at DESC LIMIT $2
	`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueryResult
	for rows.Next() {
		var r QueryResult
		var snap, added, removed []byte
		if err := rows.Scan(&r.Name, &r.CollectedAt, &snap, &added, &removed); err != nil {
			return nil, err
		}
		r.CollectedAt = r.CollectedAt.UTC()
		r.Snapshot = nullRaw(snap)
		r.Added = nullRaw(added)
		r.Removed = nullRaw(removed)
		out = append(out, r)
	}
	if out == nil {
		out = []QueryResult{}
	}
	return out, rows.Err()
}

func nullRaw(b []byte) json.RawMessage {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return json.RawMessage(b)
}

func (s *Postgres) AppCounts(ctx context.Context, limit int) ([]AppCount, error) {
	if limit <= 0 {
		limit = 8
	}
	rows, err := s.pool.Query(ctx, `
		SELECT name, COUNT(DISTINCT device_id)
		FROM device_apps
		WHERE name <> ''
		GROUP BY name
		ORDER BY COUNT(DISTINCT device_id) DESC, name
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppCount
	for rows.Next() {
		var a AppCount
		if err := rows.Scan(&a.Name, &a.Devices); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if out == nil {
		out = []AppCount{}
	}
	return out, rows.Err()
}

func (s *Postgres) FleetSummary(ctx context.Context, expected map[string]string) (FleetSummary, error) {
	devices, err := s.listAllDevices(ctx)
	if err != nil {
		return FleetSummary{}, err
	}
	apps, err := s.AppCounts(ctx, 8)
	if err != nil {
		return FleetSummary{}, err
	}
	return Summarize(devices, apps, expected, time.Now().UTC()), nil
}

func (s *Postgres) ListResources(ctx context.Context) ([]config.Resource, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT api_version, kind, namespace, name, labels, annotations, spec, spec_hash,
			managed_by, source_path, generation, applied_at
		FROM resources
		ORDER BY kind, namespace, name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []config.Resource{}
	}
	return out, rows.Err()
}

func scanResource(row pgx.Row) (config.Resource, error) {
	var r config.Resource
	var labels, annotations, spec []byte
	var hash, managed, source string
	var gen int64
	var applied time.Time
	if err := row.Scan(&r.APIVersion, &r.Kind, &r.Metadata.Namespace, &r.Metadata.Name, &labels, &annotations, &spec, &hash, &managed, &source, &gen, &applied); err != nil {
		return config.Resource{}, err
	}
	if len(labels) > 0 {
		_ = json.Unmarshal(labels, &r.Metadata.Labels)
	}
	if len(annotations) > 0 {
		_ = json.Unmarshal(annotations, &r.Metadata.Annotations)
	}
	if err := json.Unmarshal(spec, &r.Spec); err != nil {
		return config.Resource{}, err
	}
	if canon, ok := config.Canonicalize(r.Spec).(map[string]any); ok {
		r.Spec = canon
	}
	applied = applied.UTC()
	r.SourcePath = source
	r.Status = &config.Status{
		ManagedBy:  managed,
		Generation: gen,
		SpecHash:   hash,
		SourcePath: source,
		AppliedAt:  &applied,
	}
	return r, nil
}

func (s *Postgres) ApplyChanges(ctx context.Context, changes []config.Change) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		for _, c := range changes {
			switch c.Op {
			case config.OpDelete:
				if _, err := tx.Exec(ctx, `
					DELETE FROM resources
					WHERE kind = $1 AND namespace = $2 AND name = $3 AND managed_by = 'config'
				`, c.Kind, c.Namespace, c.Name); err != nil {
					return err
				}
			case config.OpCreate, config.OpUpdate:
				if c.Resource == nil {
					return ErrInvalid
				}
				if err := upsertResource(ctx, tx, *c.Resource); err != nil {
					return err
				}
			default:
				return fmt.Errorf("%w: change %s", ErrInvalid, c.Op)
			}
		}
		return nil
	})
}

func upsertResource(ctx context.Context, tx pgx.Tx, r config.Resource) error {
	id := r.ID()
	hash := ""
	managed := config.ManagedByConfig
	if r.Status != nil {
		hash = r.Status.SpecHash
		if r.Status.ManagedBy != "" {
			managed = r.Status.ManagedBy
		}
	}
	if hash == "" {
		var err error
		hash, err = config.SpecHash(r)
		if err != nil {
			return err
		}
	}
	labels, err := json.Marshal(emptyStringMap(r.Metadata.Labels))
	if err != nil {
		return err
	}
	annotations, err := json.Marshal(emptyStringMap(r.Metadata.Annotations))
	if err != nil {
		return err
	}
	spec, err := json.Marshal(r.Spec)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO resources (
			id, api_version, kind, namespace, name, labels, annotations, spec, spec_hash, managed_by, source_path, generation
		) VALUES (
			$1::uuid, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10, $11, 1
		)
		ON CONFLICT (kind, namespace, name) DO UPDATE SET
			api_version = EXCLUDED.api_version,
			labels = EXCLUDED.labels,
			annotations = EXCLUDED.annotations,
			spec = EXCLUDED.spec,
			spec_hash = EXCLUDED.spec_hash,
			managed_by = EXCLUDED.managed_by,
			source_path = EXCLUDED.source_path,
			generation = resources.generation + 1,
			applied_at = now(),
			updated_at = now()
	`, uuid.NewString(), r.APIVersion, id.Kind, id.Namespace, id.Name, string(labels), string(annotations), string(spec), hash, managed, r.SourcePath)
	return err
}

func emptyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
