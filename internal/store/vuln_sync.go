package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
)

// SyncVulnerabilitiesDue runs one incremental sync when the cron is due and a
// feed client is configured. A second tick while a sync is in progress returns
// without starting another. Tests that never call SetVulnerabilityFeeds do
// not touch the network.
func (s *Store) SyncVulnerabilitiesDue(ctx context.Context) error {
	feeds := s.vulnerabilityFeeds()
	if feeds.HTTP == nil {
		return nil
	}
	settings, _, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return err
	}
	due, err := cronDue(settings.SyncCron, settings.Timezone, &settings.LastSyncAt, s.now())
	if err != nil || !due {
		return err
	}
	if !s.vulnSyncMu.TryLock() {
		return nil
	}
	defer s.vulnSyncMu.Unlock()
	return s.syncVulnerabilities(ctx, feeds)
}

// SyncVulnerabilities runs one sync now, ignoring the cron.
func (s *Store) SyncVulnerabilities(ctx context.Context) error {
	feeds := s.vulnerabilityFeeds()
	if feeds.HTTP == nil {
		return invalid("vulnerability feeds are not configured")
	}
	s.vulnSyncMu.Lock()
	defer s.vulnSyncMu.Unlock()
	return s.syncVulnerabilities(ctx, feeds)
}

func (s *Store) syncVulnerabilities(ctx context.Context, feeds vuln.Feeds) error {
	settings, key, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return err
	}
	now := s.now()
	var errs []string
	cursor := settings.NVDCursor
	if settings.NVDEnabled {
		next, nerr := s.syncNVD(ctx, feeds, settings, key, now)
		if next != "" {
			cursor = next
		}
		if nerr != nil {
			errs = append(errs, nerr.Error())
		}
	}
	if settings.KEVEnabled {
		if kerr := s.syncKEV(ctx, feeds, now); kerr != nil {
			errs = append(errs, kerr.Error())
		}
	}
	if settings.EPSSEnabled {
		if eerr := s.syncEPSS(ctx, feeds); eerr != nil {
			errs = append(errs, eerr.Error())
		}
	}
	if settings.AppleEnabled {
		if aerr := s.syncApple(ctx, feeds, now); aerr != nil {
			errs = append(errs, aerr.Error())
		}
	}
	if settings.Rapid7Enabled {
		if rerr := s.syncRapid7(ctx, feeds, now); rerr != nil {
			errs = append(errs, rerr.Error())
		}
	}
	status, msg := "ok", ""
	if len(errs) > 0 {
		status = "error"
		msg = vuln.RedactSecret(strings.Join(errs, "; "), key)
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE vulnerability_settings
		SET last_sync_at=$2, last_sync_status=$3, last_sync_error=$4, nvd_cursor=$5, updated_at=$2
		WHERE id=$1`, "default", now, status, msg, cursor); err != nil {
		return err
	}
	if err := s.CorrelateVulnerabilities(ctx, true); err != nil {
		return err
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (s *Store) syncNVD(ctx context.Context, feeds vuln.Feeds, settings model.VulnerabilitySettings, key string, now time.Time) (string, error) {
	products := vuln.SyncProducts(overridesToVuln(settings.Overrides))
	client := &vuln.NVDClient{Base: feeds.NVDBase, Key: key, HTTP: feeds.HTTP, Sleep: feeds.Sleep, Now: feeds.Now}
	if client.Now == nil {
		client.Now = func() time.Time { return s.now() }
	}
	res, err := vuln.SyncNVD(ctx, products, settings.NVDCursor, now, 3, 200, client.Fetch)
	for _, rec := range res.CVEs {
		if saveErr := s.saveNVDRecord(ctx, rec, now); saveErr != nil {
			if err == nil {
				err = saveErr
			}
			break
		}
	}
	return res.Cursor, err
}

func (s *Store) saveNVDRecord(ctx context.Context, rec vuln.Record, now time.Time) error {
	if !vuln.ValidCVE(rec.ID) {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	sev := rec.Severity
	if sev == "" {
		sev = vuln.Severity(rec.Score)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vuln_cves (cve_id, description, cvss_score, cvss_vector, severity, published, last_modified, source, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'nvd',$8)
		ON CONFLICT (cve_id) DO UPDATE SET
			description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE vuln_cves.description END,
			cvss_score = CASE WHEN EXCLUDED.cvss_score > 0 THEN EXCLUDED.cvss_score ELSE vuln_cves.cvss_score END,
			cvss_vector = CASE WHEN EXCLUDED.cvss_vector <> '' THEN EXCLUDED.cvss_vector ELSE vuln_cves.cvss_vector END,
			severity = CASE WHEN EXCLUDED.cvss_score > 0 THEN EXCLUDED.severity ELSE vuln_cves.severity END,
			published = COALESCE(vuln_cves.published, EXCLUDED.published),
			last_modified = EXCLUDED.last_modified,
			source = 'nvd',
			updated_at = EXCLUDED.updated_at`,
		rec.ID, rec.Description, rec.Score, rec.Vector, sev, nullTime(rec.Published), nullTime(rec.Modified), now); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vuln_ranges WHERE cve_id=$1 AND source IN ('nvd','fixture')`, rec.ID); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	for _, r := range rec.Ranges {
		if _, err := tx.Exec(ctx, `
			INSERT INTO vuln_ranges (cve_id, part, vendor, product, start_incl, start_excl, end_incl, end_excl, exact, platform, source)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'nvd')
			ON CONFLICT (cve_id, part, vendor, product, start_incl, start_excl, end_incl, end_excl, exact, platform)
			DO UPDATE SET source='nvd'`,
			rec.ID, r.Part, r.Vendor, r.Product, r.Bound.StartIncl, r.Bound.StartExcl, r.Bound.EndIncl, r.Bound.EndExcl, r.Bound.Exact, vuln.EncodePlatforms(r.Platforms)); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) syncKEV(ctx context.Context, feeds vuln.Feeds, now time.Time) error {
	body, err := vuln.GetJSON(ctx, feeds.HTTP, feedsKEV(feeds))
	if err != nil {
		return err
	}
	items, err := vuln.ParseKEV(body)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.CVE)
		if _, err := s.pool.Exec(ctx, `
			UPDATE vuln_cves SET kev=true, kev_date=$2, kev_due=$3, kev_name=$4, updated_at=$5
			WHERE cve_id=$1`, item.CVE, nullTime(item.Added), nullTime(item.Due), item.Name, now); err != nil {
			return err
		}
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE vuln_cves SET kev=false, kev_name='', kev_date=NULL, kev_due=NULL, updated_at=$2
		WHERE kev AND NOT (cve_id = ANY($1::text[]))`, ids, now)
	return err
}

func (s *Store) syncEPSS(ctx context.Context, feeds vuln.Feeds) error {
	rows, err := s.pool.Query(ctx, `SELECT cve_id FROM vuln_cves ORDER BY cve_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := 0; i < len(ids); i += 100 {
		end := i + 100
		if end > len(ids) {
			end = len(ids)
		}
		rawURL, err := vuln.EPSSQuery(feeds.EPSSURL, ids[i:end])
		if err != nil {
			return err
		}
		body, err := vuln.GetJSON(ctx, feeds.HTTP, rawURL)
		if err != nil {
			return err
		}
		items, err := vuln.ParseEPSS(body)
		if err != nil {
			return err
		}
		for _, item := range items {
			if _, err := s.pool.Exec(ctx, `
				UPDATE vuln_cves SET epss=$2, epss_percentile=$3, epss_known=true, updated_at=$4
				WHERE cve_id=$1`, item.CVE, item.Score, item.Percentile, s.now()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) syncApple(ctx context.Context, feeds vuln.Feeds, now time.Time) error {
	var all []vuln.SOFAFix
	for _, spec := range []struct{ url, product string }{
		{feeds.MacOSURL, "macos"},
		{feeds.SafariURL, "safari"},
	} {
		raw := spec.url
		if raw == "" {
			if spec.product == "safari" {
				raw = "https://sofa.macadmins.io/v1/safari_data_feed.json"
			} else {
				raw = "https://sofa.macadmins.io/v1/macos_data_feed.json"
			}
		}
		body, err := vuln.GetJSON(ctx, feeds.HTTP, raw)
		if err != nil {
			return err
		}
		fixes, err := vuln.ParseSOFARecords(body, spec.product)
		if err != nil {
			return err
		}
		all = append(all, fixes...)
	}
	for _, fix := range all {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO vuln_cves (cve_id, description, severity, source, updated_at)
			VALUES ($1,'','none','apple',$2)
			ON CONFLICT (cve_id) DO NOTHING`, fix.CVE, now); err != nil {
			return err
		}
		t := fix.Train
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO vuln_trains (cve_id, part, vendor, product, major, fixed_version, fixed_build, train_mode, source)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'apple')
			ON CONFLICT (cve_id, part, vendor, product, major, fixed_version, fixed_build, train_mode)
			DO UPDATE SET source='apple'`,
			fix.CVE, t.Part, t.Vendor, t.Product, t.Major, t.FixedVersion, t.FixedBuild, t.Mode); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) syncRapid7(ctx context.Context, feeds vuln.Feeds, now time.Time) error {
	var mode, base, token, elasticURL, apiKey, index string
	var fieldRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT mode, base_url, api_token, elastic_url, elastic_api_key, index_pattern, field_map
		FROM source_connectors WHERE source='rapid7' AND enabled`).Scan(&mode, &base, &token, &elasticURL, &apiKey, &index, &fieldRaw)
	if err != nil {
		return nil
	}
	fieldMap := map[string]string{}
	if len(fieldRaw) > 0 {
		_ = json.Unmarshal(fieldRaw, &fieldMap)
	}
	rows, err := vuln.FetchRapid7(ctx, feeds.HTTP, vuln.Rapid7Source{
		Mode: mode, BaseURL: base, Token: token, ElasticURL: elasticURL, APIKey: apiKey, Index: index, FieldMap: fieldMap,
	})
	if err != nil {
		return err
	}
	// An empty page is not "the fleet is clean". A failed or truncated fetch
	// must not delete the findings that the last good sync stored, because
	// correlation would then auto-resolve Rapid7-only issues.
	if len(rows) == 0 {
		return nil
	}
	devices, err := s.rapid7Devices(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	cveRows, err := s.pool.Query(ctx, `SELECT cve_id FROM vuln_cves`)
	if err != nil {
		return err
	}
	defer cveRows.Close()
	for cveRows.Next() {
		var id string
		if err := cveRows.Scan(&id); err != nil {
			return err
		}
		known[id] = true
	}
	if err := cveRows.Err(); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM rapid7_findings`); err != nil {
		return err
	}
	for _, row := range rows {
		if !known[row.CVE] {
			continue
		}
		deviceID := matchRapid7Device(devices, row)
		if deviceID == "" {
			continue
		}
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO rapid7_findings (id, device_id, cve_id, software_name, version, seen_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (device_id, cve_id, software_name) DO UPDATE SET version=EXCLUDED.version, seen_at=EXCLUDED.seen_at`,
			newID(), deviceID, row.CVE, row.Software, row.Version, now); err != nil {
			return err
		}
	}
	return nil
}

type rapid7Device struct {
	id, serial, uuid, host string
}

func (s *Store) rapid7Devices(ctx context.Context) ([]rapid7Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, serial, hardware_uuid, hostname FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rapid7Device
	for rows.Next() {
		var d rapid7Device
		if err := rows.Scan(&d.id, &d.serial, &d.uuid, &d.host); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func matchRapid7Device(devices []rapid7Device, row vuln.Rapid7Finding) string {
	if id, ok := uniqueField(devices, func(d rapid7Device) string { return d.serial }, row.Serial); ok {
		return id
	}
	if id, ok := uniqueField(devices, func(d rapid7Device) string { return d.uuid }, row.HardwareUUID); ok {
		return id
	}
	if id, ok := uniqueField(devices, func(d rapid7Device) string { return strings.ToLower(d.host) }, strings.ToLower(row.Hostname)); ok {
		return id
	}
	return ""
}

func uniqueField(devices []rapid7Device, field func(rapid7Device) string, want string) (string, bool) {
	want = strings.TrimSpace(want)
	if want == "" {
		return "", false
	}
	var id string
	n := 0
	for _, d := range devices {
		if strings.EqualFold(strings.TrimSpace(field(d)), want) {
			n++
			id = d.id
		}
	}
	return id, n == 1
}

func feedsKEV(f vuln.Feeds) string {
	if f.KEVURL != "" {
		return f.KEVURL
	}
	return "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func overridesToVuln(in []model.CPEOverride) []vuln.Override {
	out := make([]vuln.Override, len(in))
	for i, o := range in {
		out[i] = vuln.Override{
			BundleID: o.BundleID, Name: o.Name, Vendor: o.Vendor, Product: o.Product,
			Part: o.Part, VersionSource: o.VersionSource,
		}
	}
	return out
}
