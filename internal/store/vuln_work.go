package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
	"github.com/jackc/pgx/v5"
)

// CorrelateVulnerabilities rebuilds active findings from inventory and open
// issues. force is set after a feed sync or a settings change. A quiet tick
// returns when the inventory watermark is unchanged. The settings row is
// locked so two passes cannot create two issues for one CVE.
func (s *Store) CorrelateVulnerabilities(ctx context.Context, force bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var watermark string
	var rapid7On bool
	if err := tx.QueryRow(ctx, `
		SELECT inventory_watermark, rapid7_enabled FROM vulnerability_settings WHERE id='default' FOR UPDATE`).Scan(&watermark, &rapid7On); err != nil {
		return err
	}
	next, err := vulnWatermark(ctx, tx)
	if err != nil {
		return err
	}
	if !force && watermark != "" && watermark == next {
		return tx.Commit(ctx)
	}
	now := s.now()
	overrides, err := s.loadOverrides(ctx, tx)
	if err != nil {
		return err
	}
	ov := overridesToVuln(overrides)
	catalog, err := loadVulnRules(ctx, tx)
	if err != nil {
		return err
	}
	want, err := desiredFindings(ctx, tx, ov, catalog, rapid7On, now)
	if err != nil {
		return err
	}
	if err := replaceFindings(ctx, tx, want, now); err != nil {
		return err
	}
	if err := s.syncIssues(ctx, tx, want, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE vulnerability_settings SET inventory_watermark=$1 WHERE id='default'`, next); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func vulnWatermark(ctx context.Context, tx pgx.Tx) (string, error) {
	var mark string
	err := tx.QueryRow(ctx, `
		SELECT md5(coalesce(string_agg(line, E'\n' ORDER BY line), '')) FROM (
			SELECT device_id || '|' || path || '|' || bundle_id || '|' || version || '|' || bundle_version AS line FROM device_apps
			UNION ALL
			SELECT 'os|' || id || '|' || os_version || '|' || os_build FROM devices
			UNION ALL
			SELECT 'r7|' || device_id || '|' || cve_id || '|' || software_name || '|' || version FROM rapid7_findings
			UNION ALL
			SELECT 'ov|' || bundle_id || '|' || name || '|' || vendor || '|' || product || '|' || part FROM cpe_overrides
			UNION ALL
			SELECT 'cve|' || cve_id || '|' || source || '|' || kev::text || '|' || epss::text || '|' || updated_at::text FROM vuln_cves
			UNION ALL
			SELECT 'rg|' || cve_id || '|' || vendor || '|' || product || '|' || end_excl || '|' || end_incl || '|' || exact || '|' || platform FROM vuln_ranges
			UNION ALL
			SELECT 'tr|' || cve_id || '|' || product || '|' || major::text || '|' || fixed_version || '|' || fixed_build || '|' || train_mode FROM vuln_trains
			UNION ALL
			SELECT 'cfg|' || rapid7_enabled::text FROM vulnerability_settings WHERE id='default'
		) q`).Scan(&mark)
	return mark, err
}

type vulnRules struct {
	ranges map[string][]vuln.ProductBound
	trains map[string][]vuln.Train
}

type rowQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadVulnRules(ctx context.Context, q rowQuery) (vulnRules, error) {
	out := vulnRules{ranges: map[string][]vuln.ProductBound{}, trains: map[string][]vuln.Train{}}
	rows, err := q.Query(ctx, `
		SELECT cve_id, part, vendor, product, start_incl, start_excl, end_incl, end_excl, exact, platform FROM vuln_ranges`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, platform string
		var b vuln.ProductBound
		if err := rows.Scan(&id, &b.Part, &b.Vendor, &b.Product, &b.Bound.StartIncl, &b.Bound.StartExcl, &b.Bound.EndIncl, &b.Bound.EndExcl, &b.Bound.Exact, &platform); err != nil {
			return out, err
		}
		b.Platforms = vuln.DecodePlatforms(platform)
		out.ranges[id] = append(out.ranges[id], b)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	trows, err := q.Query(ctx, `
		SELECT cve_id, part, vendor, product, major, fixed_version, fixed_build, train_mode FROM vuln_trains`)
	if err != nil {
		return out, err
	}
	defer trows.Close()
	for trows.Next() {
		var id string
		var t vuln.Train
		if err := trows.Scan(&id, &t.Part, &t.Vendor, &t.Product, &t.Major, &t.FixedVersion, &t.FixedBuild, &t.Mode); err != nil {
			return out, err
		}
		out.trains[id] = append(out.trains[id], t)
	}
	return out, trows.Err()
}

type wantFinding struct {
	deviceID, cve, key, name, version, build, evidence string
}

func desiredFindings(ctx context.Context, tx pgx.Tx, overrides []vuln.Override, rules vulnRules, rapid7On bool, now time.Time) (map[string]wantFinding, error) {
	want := map[string]wantFinding{}
	add := func(f wantFinding) {
		if f.deviceID == "" || f.cve == "" || f.key == "" {
			return
		}
		k := f.deviceID + "\x00" + f.cve + "\x00" + f.key
		if prev, ok := want[k]; ok {
			if prev.evidence != f.evidence {
				prev.evidence = "both"
			}
			if f.evidence == "inventory" || prev.version == "" {
				prev.version = f.version
				prev.build = f.build
				if f.name != "" {
					prev.name = f.name
				}
			}
			want[k] = prev
			return
		}
		want[k] = f
	}
	cves := map[string]bool{}
	for id := range rules.ranges {
		cves[id] = true
	}
	for id := range rules.trains {
		cves[id] = true
	}
	idx := vuln.NewIndex(rules.ranges, rules.trains)
	stale, err := staleAppDevices(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	apps, err := tx.Query(ctx, `
		SELECT a.device_id, a.name, a.bundle_id, a.version, a.bundle_version, COALESCE(d.os_version, '')
		FROM device_apps a
		LEFT JOIN devices d ON d.id = a.device_id`)
	if err != nil {
		return nil, err
	}
	defer apps.Close()
	present := map[string]bool{}
	for apps.Next() {
		var deviceID, name, bundle, version, bundleVersion, osVersion string
		if err := apps.Scan(&deviceID, &name, &bundle, &version, &bundleVersion, &osVersion); err != nil {
			return nil, err
		}
		product, ok := vuln.MatchSoftware(name, bundle, overrides)
		if !ok {
			continue
		}
		present[deviceID+"\x00"+product.Key()] = true
		consider := func(probe string) {
			if probe == "" {
				return
			}
			for _, hit := range idx.MatchProduct(product.Vendor, product.Product, probe, "", osVersion) {
				ver, comparable := vuln.ChooseVersion(version, bundleVersion, product.VersionSource, boundHints(hit.Ranges, hit.Trains))
				if !comparable || !vuln.AffectedInstall(ver, "", osVersion, hit.Ranges, hit.Trains) {
					continue
				}
				add(wantFinding{deviceID: deviceID, cve: hit.CVE, key: product.Key(), name: name, version: ver, evidence: "inventory"})
			}
		}
		consider(version)
		if strings.EqualFold(product.VersionSource, "bundle") && bundleVersion != "" && bundleVersion != version {
			consider(bundleVersion)
		}
		if version == "" && bundleVersion != "" {
			consider(bundleVersion)
		}
	}
	if err := apps.Err(); err != nil {
		return nil, err
	}
	if err := carryStaleFindings(ctx, tx, stale, present, add); err != nil {
		return nil, err
	}
	devs, err := tx.Query(ctx, `SELECT id, os_version, os_build FROM devices`)
	if err != nil {
		return nil, err
	}
	defer devs.Close()
	osProduct := vuln.OSProduct()
	for devs.Next() {
		var id, version, build string
		if err := devs.Scan(&id, &version, &build); err != nil {
			return nil, err
		}
		for _, hit := range idx.MatchProduct(osProduct.Vendor, osProduct.Product, version, build, version) {
			if !vuln.AffectedInstall(version, build, version, hit.Ranges, hit.Trains) {
				continue
			}
			add(wantFinding{deviceID: id, cve: hit.CVE, key: osProduct.Key(), name: "macOS", version: version, build: build, evidence: "inventory"})
		}
	}
	if err := devs.Err(); err != nil {
		return nil, err
	}
	if !rapid7On {
		return want, nil
	}
	r7, err := tx.Query(ctx, `SELECT device_id, cve_id, software_name, version FROM rapid7_findings`)
	if err != nil {
		return nil, err
	}
	defer r7.Close()
	for r7.Next() {
		var deviceID, cve, name, version string
		if err := r7.Scan(&deviceID, &cve, &name, &version); err != nil {
			return nil, err
		}
		if !cves[cve] {
			continue
		}
		product, ok := vuln.MatchSoftware(name, "", overrides)
		if !ok {
			product, ok = soleProduct(rules, cve)
		}
		if !ok {
			continue
		}
		add(wantFinding{deviceID: deviceID, cve: cve, key: product.Key(), name: name, version: version, evidence: "rapid7"})
	}
	return want, r7.Err()
}

func rulesFor(rules vulnRules, cve string, product vuln.Product) ([]vuln.ProductBound, []vuln.Train) {
	var trains []vuln.Train
	for _, t := range rules.trains[cve] {
		if t.Vendor == product.Vendor && t.Product == product.Product {
			trains = append(trains, t)
		}
	}
	// A train names the fix for this product. NVD ranges for the same CVE are
	// ignored, including cross-train macOS ranges. When no train exists, a
	// same-major macOS range is applied by AffectedInstall.
	if len(trains) > 0 {
		return nil, trains
	}
	var ranges []vuln.ProductBound
	for _, r := range rules.ranges[cve] {
		if r.Vendor == product.Vendor && r.Product == product.Product {
			ranges = append(ranges, r)
		}
	}
	return ranges, nil
}

// staleAppDevices reports devices whose mc_apps inventory is older than the
// osquery stale window. A missing timestamp is fresh: a device row inserted
// without a check-in still reflects the apps stored beside it. The window
// comes from the osquery source connector, or 24 hours when that connector
// is not configured.
func staleAppDevices(ctx context.Context, tx pgx.Tx, now time.Time) (map[string]bool, error) {
	var seconds int
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT stale_after_seconds FROM source_connectors WHERE source='osquery' LIMIT 1), 86400)`).Scan(&seconds); err != nil {
		return nil, err
	}
	if seconds < 60 {
		seconds = 86400
	}
	rows, err := tx.Query(ctx, `
		SELECT d.id,
			COALESCE(
				(SELECT r.updated_at FROM device_query_results r WHERE r.device_id = d.id AND r.query_name = 'mc_apps'),
				d.last_seen_at
			)
		FROM devices d`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	window := time.Duration(seconds) * time.Second
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var seen *time.Time
		if err := rows.Scan(&id, &seen); err != nil {
			return nil, err
		}
		if seen == nil {
			continue
		}
		if now.Sub(seen.UTC()) > window {
			out[id] = true
		}
	}
	return out, rows.Err()
}

// carryStaleFindings keeps the previous active app findings for a device whose
// inventory is stale when that product is no longer in device_apps. A Mac that
// stopped reporting must not close an issue. A fresh inventory that dropped
// the app is a real uninstall.
func carryStaleFindings(ctx context.Context, tx pgx.Tx, stale, present map[string]bool, add func(wantFinding)) error {
	if len(stale) == 0 {
		return nil
	}
	ids := make([]string, 0, len(stale))
	for id := range stale {
		ids = append(ids, id)
	}
	rows, err := tx.Query(ctx, `
		SELECT device_id, cve_id, software_key, software_name, installed_version, installed_build, evidence
		FROM vuln_findings
		WHERE active AND software_key NOT LIKE 'o:%' AND device_id = ANY($1::text[])`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var f wantFinding
		if err := rows.Scan(&f.deviceID, &f.cve, &f.key, &f.name, &f.version, &f.build, &f.evidence); err != nil {
			return err
		}
		if present[f.deviceID+"\x00"+f.key] {
			continue
		}
		if f.evidence == "" {
			f.evidence = "inventory"
		}
		add(f)
	}
	return rows.Err()
}

func soleProduct(rules vulnRules, cve string) (vuln.Product, bool) {
	seen := map[string]vuln.Product{}
	consider := func(vendor, product string) {
		if vuln.AppleOS(vendor, product) {
			return
		}
		p, ok := vuln.Lookup(vendor, product)
		if !ok {
			return
		}
		seen[p.Key()] = p
	}
	for _, r := range rules.ranges[cve] {
		consider(r.Vendor, r.Product)
	}
	for _, t := range rules.trains[cve] {
		consider(t.Vendor, t.Product)
	}
	if len(seen) != 1 {
		return vuln.Product{}, false
	}
	for _, p := range seen {
		return p, true
	}
	return vuln.Product{}, false
}

func boundHints(ranges []vuln.ProductBound, trains []vuln.Train) []string {
	var out []string
	for _, r := range ranges {
		for _, s := range []string{r.Bound.StartIncl, r.Bound.StartExcl, r.Bound.EndIncl, r.Bound.EndExcl, r.Bound.Exact} {
			if strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	}
	for _, t := range trains {
		if t.FixedVersion != "" {
			out = append(out, t.FixedVersion)
		}
	}
	return out
}

func replaceFindings(ctx context.Context, tx pgx.Tx, want map[string]wantFinding, now time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE vuln_findings SET active=false, resolved_at=COALESCE(resolved_at, $1) WHERE active`, now); err != nil {
		return err
	}
	if len(want) == 0 {
		return nil
	}
	const chunk = 400
	batch := make([]wantFinding, 0, chunk)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		ids := make([]string, len(batch))
		devs := make([]string, len(batch))
		cves := make([]string, len(batch))
		keys := make([]string, len(batch))
		names := make([]string, len(batch))
		vers := make([]string, len(batch))
		builds := make([]string, len(batch))
		ev := make([]string, len(batch))
		for i, f := range batch {
			ids[i] = newID()
			devs[i], cves[i], keys[i], names[i] = f.deviceID, f.cve, f.key, f.name
			vers[i], builds[i], ev[i] = f.version, f.build, f.evidence
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO vuln_findings (
				id, device_id, cve_id, software_key, software_name, installed_version, installed_build, evidence, active, first_seen, last_seen)
			SELECT id, device_id, cve_id, software_key, software_name, installed_version, installed_build, evidence, true, $9, $9
			FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[])
				AS u(id, device_id, cve_id, software_key, software_name, installed_version, installed_build, evidence)
			ON CONFLICT (device_id, cve_id, software_key) DO UPDATE SET
				software_name=EXCLUDED.software_name,
				installed_version=EXCLUDED.installed_version,
				installed_build=EXCLUDED.installed_build,
				evidence=EXCLUDED.evidence,
				active=true,
				last_seen=EXCLUDED.last_seen,
				resolved_at=NULL`,
			ids, devs, cves, keys, names, vers, builds, ev, now)
		batch = batch[:0]
		return err
	}
	for _, f := range want {
		batch = append(batch, f)
		if len(batch) >= chunk {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

type issueGroup struct {
	cve, key, name string
	n              int
}

func (s *Store) syncIssues(ctx context.Context, tx pgx.Tx, want map[string]wantFinding, now time.Time) error {
	groups := map[string]*issueGroup{}
	for _, f := range want {
		k := f.cve + "\x00" + f.key
		g := groups[k]
		if g == nil {
			g = &issueGroup{cve: f.cve, key: f.key, name: f.name}
			groups[k] = g
		}
		g.n++
		if g.name == "" {
			g.name = f.name
		}
	}
	rows, err := tx.Query(ctx, `
		SELECT id, cve_id, software_key, status, risk_until, revision
		FROM vuln_issues ORDER BY cve_id, software_key FOR UPDATE`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var existing []lockedIssue
	for rows.Next() {
		var row lockedIssue
		if err := rows.Scan(&row.id, &row.cve, &row.key, &row.status, &row.risk, &row.revision); err != nil {
			return err
		}
		existing = append(existing, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	seen := map[string]bool{}
	byKey := map[string]lockedIssue{}
	for _, row := range existing {
		byKey[row.cve+"\x00"+row.key] = row
	}
	for k, g := range groups {
		seen[k] = true
		cur, ok := byKey[k]
		if !ok {
			id := newID()
			if _, err := tx.Exec(ctx, `
				INSERT INTO vuln_issues (id, cve_id, software_key, software_name, status, opened_at, updated_at, revision)
				VALUES ($1,$2,$3,$4,'open',$5,$5,1)`, id, g.cve, g.key, g.name, now); err != nil {
				return err
			}
			if err := insertIssueEvent(ctx, tx, id, now, "scheduler", "opened", map[string]any{"devices": g.n}); err != nil {
				return err
			}
			continue
		}
		next, action := issueTransition(cur.status, cur.risk, g.n, now)
		if action == "" {
			continue
		}
		if err := s.applyIssueTransition(ctx, tx, cur, next, action, g.n, now); err != nil {
			return err
		}
	}
	for _, cur := range existing {
		if seen[cur.cve+"\x00"+cur.key] {
			continue
		}
		next, action := issueTransition(cur.status, cur.risk, 0, now)
		if action == "" {
			continue
		}
		if err := s.applyIssueTransition(ctx, tx, cur, next, action, 0, now); err != nil {
			return err
		}
	}
	return nil
}

func issueTransition(status string, risk *time.Time, active int, now time.Time) (string, string) {
	if active > 0 {
		switch status {
		case "fixed":
			if risk != nil && risk.After(now) {
				return "risk_accepted", "reopened"
			}
			return "open", "reopened"
		case "risk_accepted":
			if risk == nil || !risk.After(now) {
				return "open", "risk_expired"
			}
		}
		return status, ""
	}
	if status == "fixed" {
		return status, ""
	}
	return "fixed", "auto_resolved"
}

type lockedIssue struct {
	id, cve, key, status string
	risk                 *time.Time
	revision             int
}

func (s *Store) applyIssueTransition(ctx context.Context, tx pgx.Tx, cur lockedIssue, next, action string, devices int, now time.Time) error {
	// Only the transition into fixed is automatic. A later regression clears the flag.
	auto := next == "fixed" && cur.status != "fixed"
	reopen := action == "reopened"
	var resolved any
	var risk any
	if next == "fixed" {
		resolved = now
		risk = cur.risk
	} else if next == "risk_accepted" {
		risk = cur.risk
	}
	// revision matches the row we locked. A user update that committed first
	// changes the revision and this statement touches nothing.
	tag, err := tx.Exec(ctx, `
		UPDATE vuln_issues
		SET status=$2, updated_at=$3, resolved_at=$4, auto_resolved=$5, risk_until=$6,
			opened_at=CASE WHEN $8 THEN $3 ELSE opened_at END,
			revision=revision+1
		WHERE id=$1 AND revision=$7`, cur.id, next, now, resolved, auto, risk, cur.revision, reopen)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if err := insertIssueEvent(ctx, tx, cur.id, now, "scheduler", action, map[string]any{"from": cur.status, "to": next, "devices": devices}); err != nil {
		return err
	}
	return s.audit(ctx, tx, model.System, action, "vulnerability_issue", cur.id, map[string]any{"from": cur.status, "to": next, "devices": devices})
}

func insertIssueEvent(ctx context.Context, tx pgx.Tx, issueID string, at time.Time, actor, action string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO vuln_issue_events (id, issue_id, at, actor, action, detail)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb)`, newID(), issueID, at, actor, action, string(raw))
	return err
}
