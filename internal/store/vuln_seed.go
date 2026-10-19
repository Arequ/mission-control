package store

import (
	"context"
	"time"

	"github.com/Arequ/mission-control/internal/vuln"
)

// seedVulnerabilities loads the fixture CVE catalog once and correlates it
// with the seeded fleet. A later boot does not rewrite issues an operator changed.
func (s *Store) seedVulnerabilities(ctx context.Context) error {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM vuln_cves`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return s.CorrelateVulnerabilities(ctx, false)
	}
	now := s.now()
	for _, rec := range vuln.FixtureRecords() {
		if err := s.insertFixture(ctx, rec, now); err != nil {
			return err
		}
	}
	if err := s.seedRapid7Evidence(ctx, now); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE vulnerability_settings
		SET rapid7_enabled=true, last_sync_at=$1, last_sync_status='fixture', last_sync_error='', updated_at=$1
		WHERE id='default'`, now); err != nil {
		return err
	}
	if err := s.CorrelateVulnerabilities(ctx, true); err != nil {
		return err
	}
	return s.seedIssueWorkflow(ctx, now)
}

func (s *Store) insertFixture(ctx context.Context, rec vuln.Record, now time.Time) error {
	sev := rec.Severity
	if sev == "" {
		sev = vuln.Severity(rec.Score)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO vuln_cves (
			cve_id, description, cvss_score, cvss_vector, severity, published, last_modified,
			kev, kev_date, kev_due, kev_name, epss, epss_percentile, epss_known, source, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$6,$7,$8,$9,$10,0,0,false,$11,$12)
		ON CONFLICT (cve_id) DO NOTHING`,
		rec.ID, rec.Description, rec.Score, rec.Vector, sev, nullTime(rec.Published),
		rec.KEV, nullTime(rec.KEVAdded), nullTime(rec.KEVDue), rec.KEVName, rec.Source, now); err != nil {
		return err
	}
	for _, r := range rec.Ranges {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO vuln_ranges (cve_id, part, vendor, product, start_incl, start_excl, end_incl, end_excl, exact, source)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'fixture')
			ON CONFLICT (cve_id, part, vendor, product, start_incl, start_excl, end_incl, end_excl, exact) DO NOTHING`,
			rec.ID, r.Part, r.Vendor, r.Product, r.Bound.StartIncl, r.Bound.StartExcl, r.Bound.EndIncl, r.Bound.EndExcl, r.Bound.Exact); err != nil {
			return err
		}
	}
	for _, t := range rec.Trains {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO vuln_trains (cve_id, part, vendor, product, major, fixed_version, fixed_build, train_mode, source)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'fixture')
			ON CONFLICT (cve_id, part, vendor, product, major, fixed_version, fixed_build, train_mode) DO NOTHING`,
			rec.ID, t.Part, t.Vendor, t.Product, t.Major, t.FixedVersion, t.FixedBuild, t.Mode); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) seedRapid7Evidence(ctx context.Context, now time.Time) error {
	rows, err := s.pool.Query(ctx, `
		SELECT device_id, version FROM device_apps WHERE lower(bundle_id)='com.google.chrome'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct{ id, version string }
	var apps []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.version); err != nil {
			return err
		}
		apps = append(apps, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	disagreement := false
	for _, app := range apps {
		c, ok := vuln.Compare(app.version, "131.0.6778.85")
		agree := ok && c < 0
		if agree {
			if err := s.insertRapid7(ctx, app.id, "CVE-2024-11395", "Google Chrome", app.version, now); err != nil {
				return err
			}
		}
		if !disagreement && app.version == "131.0.6778.86" {
			disagreement = true
			if err := s.insertRapid7(ctx, app.id, "CVE-2024-11395", "Google Chrome", app.version, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) insertRapid7(ctx context.Context, deviceID, cve, name, version string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rapid7_findings (id, device_id, cve_id, software_name, version, seen_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (device_id, cve_id, software_name) DO NOTHING`,
		newID(), deviceID, cve, name, version, now)
	return err
}

func (s *Store) seedIssueWorkflow(ctx context.Context, now time.Time) error {
	type tweak struct {
		cve, key, status, assignee, notes string
		opened                            time.Time
		risk                              *time.Time
	}
	until := now.Add(30 * 24 * time.Hour)
	tweaks := []tweak{
		{cve: "CVE-2024-11395", key: "a:google:chrome", status: "in_progress", assignee: "Priya Shah", notes: "Fix is in the testing catalog.", opened: now.Add(-2 * 24 * time.Hour)},
		{cve: "CVE-2024-42439", key: "a:zoom:workplace_desktop", status: "risk_accepted", assignee: "Priya Shah", notes: "Waiting on the next Zoom recipe. Acceptance expires in 30 days.", opened: now.Add(-3 * 24 * time.Hour), risk: &until},
		{cve: "CVE-2024-7971", key: "a:google:chrome", status: "open", opened: now.Add(-16 * 24 * time.Hour)},
		{cve: "CVE-2024-9680", key: "a:mozilla:firefox", status: "open", opened: now.Add(-10 * 24 * time.Hour)},
	}
	for _, tw := range tweaks {
		var id string
		var revision int
		err := s.pool.QueryRow(ctx, `SELECT id, revision FROM vuln_issues WHERE cve_id=$1 AND software_key=$2`, tw.cve, tw.key).Scan(&id, &revision)
		if err != nil {
			continue
		}
		if _, err := s.pool.Exec(ctx, `
			UPDATE vuln_issues
			SET status=$2, assignee=$3, notes=$4, opened_at=$5, risk_until=$6, updated_at=$7, revision=revision+1
			WHERE id=$1`, id, tw.status, tw.assignee, tw.notes, tw.opened, tw.risk, now); err != nil {
			return err
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		action := "updated"
		if tw.status == "risk_accepted" {
			action = "risk_accepted"
		}
		if err := insertIssueEvent(ctx, tx, id, now, "seed", action, map[string]any{"status": tw.status, "assignee": tw.assignee}); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
