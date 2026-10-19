package store

import (
	"context"
	"strings"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
	"github.com/jackc/pgx/v5"
	"github.com/robfig/cron/v3"
)

func defaultVulnerabilitySettings() model.VulnerabilitySettings {
	return model.VulnerabilitySettings{
		ID: "default", NVDEnabled: true, KEVEnabled: true, EPSSEnabled: true, AppleEnabled: true,
		SyncCron: "20 3 * * *", Timezone: "UTC",
		SLACriticalDays: 7, SLAHighDays: 14, SLAMediumDays: 30, SLALowDays: 90, SLAKEVDays: 14,
		ManagedBy: "system", Overrides: []model.CPEOverride{},
	}
}

func (s *Store) GetVulnerabilitySettings(ctx context.Context) (model.VulnerabilitySettings, error) {
	out, _, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return model.VulnerabilitySettings{}, err
	}
	return out.Public(), nil
}

func (s *Store) loadVulnerabilitySettings(ctx context.Context, tx pgx.Tx) (model.VulnerabilitySettings, string, error) {
	q := `
		SELECT id, nvd_enabled, kev_enabled, epss_enabled, apple_enabled, rapid7_enabled,
			sync_cron, timezone, nvd_api_key <> '', nvd_api_key,
			sla_critical_days, sla_high_days, sla_medium_days, sla_low_days, sla_kev_days,
			managed_by, last_sync_at, last_sync_status, last_sync_error, nvd_cursor, updated_at
		FROM vulnerability_settings WHERE id='default'`
	var row pgx.Row
	if tx != nil {
		row = tx.QueryRow(ctx, q)
	} else {
		row = s.pool.QueryRow(ctx, q)
	}
	var out model.VulnerabilitySettings
	var key string
	err := row.Scan(
		&out.ID, &out.NVDEnabled, &out.KEVEnabled, &out.EPSSEnabled, &out.AppleEnabled, &out.Rapid7Enabled,
		&out.SyncCron, &out.Timezone, &out.HasNVDAPIKey, &key,
		&out.SLACriticalDays, &out.SLAHighDays, &out.SLAMediumDays, &out.SLALowDays, &out.SLAKEVDays,
		&out.ManagedBy, &out.LastSyncAt, &out.LastSyncStatus, &out.LastSyncError, &out.NVDCursor, &out.UpdatedAt,
	)
	if err != nil {
		return model.VulnerabilitySettings{}, "", notFound(err)
	}
	out.NVDAPIKey = key
	overrides, err := s.loadOverrides(ctx, tx)
	if err != nil {
		return model.VulnerabilitySettings{}, "", err
	}
	out.Overrides = overrides
	return out, key, nil
}

func (s *Store) loadOverrides(ctx context.Context, tx pgx.Tx) ([]model.CPEOverride, error) {
	q := `SELECT bundle_id, name, vendor, product, part, version_source FROM cpe_overrides ORDER BY position, vendor, product, bundle_id, name`
	var rows pgx.Rows
	var err error
	if tx != nil {
		rows, err = tx.Query(ctx, q)
	} else {
		rows, err = s.pool.Query(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.CPEOverride{}
	for rows.Next() {
		var o model.CPEOverride
		if err := rows.Scan(&o.BundleID, &o.Name, &o.Vendor, &o.Product, &o.Part, &o.VersionSource); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func validateVulnerabilitySettings(in model.VulnerabilitySettings) (model.VulnerabilitySettings, error) {
	in.SyncCron = strings.TrimSpace(in.SyncCron)
	if _, err := cron.ParseStandard(in.SyncCron); err != nil {
		return model.VulnerabilitySettings{}, invalid("sync_cron must be a five-field cron expression")
	}
	if _, err := loadLocation(in.Timezone); err != nil {
		return model.VulnerabilitySettings{}, err
	}
	for _, pair := range []struct {
		name string
		n    int
	}{
		{"sla_critical_days", in.SLACriticalDays},
		{"sla_high_days", in.SLAHighDays},
		{"sla_medium_days", in.SLAMediumDays},
		{"sla_low_days", in.SLALowDays},
		{"sla_kev_days", in.SLAKEVDays},
	} {
		if pair.n < 1 || pair.n > 3660 {
			return model.VulnerabilitySettings{}, invalid(pair.name + " must be between 1 and 3660")
		}
	}
	if len(in.NVDAPIKey) > 4000 {
		return model.VulnerabilitySettings{}, invalid("nvd_api_key is too long")
	}
	seen := map[string]bool{}
	clean := make([]model.CPEOverride, 0, len(in.Overrides))
	for _, o := range in.Overrides {
		o.BundleID = strings.TrimSpace(o.BundleID)
		o.Name = strings.TrimSpace(o.Name)
		o.Vendor = strings.ToLower(strings.TrimSpace(o.Vendor))
		o.Product = strings.ToLower(strings.TrimSpace(o.Product))
		o.Part = strings.ToLower(strings.TrimSpace(o.Part))
		o.VersionSource = strings.ToLower(strings.TrimSpace(o.VersionSource))
		if o.Part == "" {
			o.Part = "a"
		}
		if o.VersionSource == "" {
			o.VersionSource = "short"
		}
		if o.BundleID == "" && o.Name == "" {
			return model.VulnerabilitySettings{}, invalid("cpe override needs a bundle_id or a name")
		}
		if !cpeToken(o.Vendor) || !cpeToken(o.Product) {
			return model.VulnerabilitySettings{}, invalid("cpe vendor and product must be lowercase tokens")
		}
		switch o.Part {
		case "a", "o", "h":
		default:
			return model.VulnerabilitySettings{}, invalid("cpe part must be a, o, or h")
		}
		switch o.VersionSource {
		case "short", "bundle":
		default:
			return model.VulnerabilitySettings{}, invalid("version_source must be short or bundle")
		}
		key := strings.ToLower(o.BundleID) + "|" + vuln.NormName(o.Name) + "|" + o.Vendor + "|" + o.Product
		if seen[key] {
			return model.VulnerabilitySettings{}, invalid("duplicate cpe override")
		}
		seen[key] = true
		clean = append(clean, o)
	}
	in.Overrides = clean
	in.ManagedBy = managedBy(in.ManagedBy)
	in.ID = "default"
	return in, nil
}

func cpeToken(s string) bool {
	if s == "" || len(s) > 80 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '_' || r == '-' || r == '.' || r == '+'):
		default:
			return false
		}
	}
	return true
}

// UpdateVulnerabilitySettings replaces the singleton. An empty NVD key keeps
// the stored key. The audit row is the public struct, without the key.
func (s *Store) UpdateVulnerabilitySettings(ctx context.Context, p model.Principal, in model.VulnerabilitySettings) (model.VulnerabilitySettings, error) {
	in, err := validateVulnerabilitySettings(in)
	if err != nil {
		return model.VulnerabilitySettings{}, err
	}
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.VulnerabilitySettings{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE vulnerability_settings SET
			nvd_enabled=$1, kev_enabled=$2, epss_enabled=$3, apple_enabled=$4, rapid7_enabled=$5,
			sync_cron=$6, timezone=$7,
			nvd_api_key=CASE WHEN $8 = '' THEN nvd_api_key ELSE $8 END,
			sla_critical_days=$9, sla_high_days=$10, sla_medium_days=$11, sla_low_days=$12, sla_kev_days=$13,
			managed_by=$14, last_sync_at=$15, inventory_watermark='', updated_at=$15
		WHERE id='default'`,
		in.NVDEnabled, in.KEVEnabled, in.EPSSEnabled, in.AppleEnabled, in.Rapid7Enabled,
		in.SyncCron, in.Timezone, in.NVDAPIKey,
		in.SLACriticalDays, in.SLAHighDays, in.SLAMediumDays, in.SLALowDays, in.SLAKEVDays,
		in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.VulnerabilitySettings{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return model.VulnerabilitySettings{}, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cpe_overrides`); err != nil {
		_ = tx.Rollback(ctx)
		return model.VulnerabilitySettings{}, err
	}
	for i, o := range in.Overrides {
		if _, err := tx.Exec(ctx, `
			INSERT INTO cpe_overrides (id, position, bundle_id, name, vendor, product, part, version_source)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			newID(), i, o.BundleID, o.Name, o.Vendor, o.Product, o.Part, o.VersionSource); err != nil {
			_ = tx.Rollback(ctx)
			return model.VulnerabilitySettings{}, mapWriteErr(err)
		}
	}
	saved, _, err := s.loadVulnerabilitySettings(ctx, tx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.VulnerabilitySettings{}, err
	}
	if err := s.audit(ctx, tx, p, "update", "vulnerability_settings", "default", saved.Public()); err != nil {
		_ = tx.Rollback(ctx)
		return model.VulnerabilitySettings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.VulnerabilitySettings{}, err
	}
	if err := s.CorrelateVulnerabilities(ctx, true); err != nil {
		return model.VulnerabilitySettings{}, err
	}
	return saved.Public(), nil
}

// ResetVulnerabilitySettings restores defaults and drops the key and overrides.
func (s *Store) ResetVulnerabilitySettings(ctx context.Context, p model.Principal) (model.VulnerabilitySettings, error) {
	in := defaultVulnerabilitySettings()
	in.NVDAPIKey = ""
	// An empty key would keep the stored secret. Clear it explicitly first.
	if _, err := s.pool.Exec(ctx, `UPDATE vulnerability_settings SET nvd_api_key='' WHERE id='default'`); err != nil {
		return model.VulnerabilitySettings{}, err
	}
	return s.UpdateVulnerabilitySettings(ctx, p, in)
}
