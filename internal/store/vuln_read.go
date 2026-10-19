package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
)

// ListVulnerabilityIssues returns a prioritized page and the headline counts.
// Priority is KEV, then EPSS, then CVSS, then the number of affected devices.
func (s *Store) ListVulnerabilityIssues(ctx context.Context, f model.IssueFilter) (model.VulnerabilityList, error) {
	all, err := s.queryIssues(ctx, model.IssueFilter{})
	if err != nil {
		return model.VulnerabilityList{}, err
	}
	decorated, err := s.decorateIssues(ctx, all)
	if err != nil {
		return model.VulnerabilityList{}, err
	}
	summary := summarizeIssues(decorated, s.now())
	filtered := filterIssues(decorated, f)
	limit, offset := pageWindow(f.Limit, f.Offset)
	page := filtered
	if offset > len(page) {
		page = []model.VulnerabilityIssue{}
	} else {
		page = page[offset:]
	}
	if len(page) > limit {
		page = page[:limit]
	}
	if page == nil {
		page = []model.VulnerabilityIssue{}
	}
	return model.VulnerabilityList{Issues: page, Summary: summary, Total: len(filtered), Limit: limit, Offset: offset}, nil
}

// DeviceVulnerabilities lists active issues on one device.
func (s *Store) DeviceVulnerabilities(ctx context.Context, deviceID string) ([]model.VulnerabilityIssue, error) {
	if _, err := s.GetDevice(ctx, deviceID, 0); err != nil {
		return nil, err
	}
	rows, err := s.queryIssues(ctx, model.IssueFilter{DeviceID: deviceID, Active: true})
	if err != nil {
		return nil, err
	}
	out, err := s.decorateIssues(ctx, rows)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []model.VulnerabilityIssue{}
	}
	return out, nil
}

// GetVulnerabilityIssue loads one issue, its devices, and its timeline.
func (s *Store) GetVulnerabilityIssue(ctx context.Context, id string) (model.VulnerabilityDetail, error) {
	rows, err := s.queryIssues(ctx, model.IssueFilter{})
	if err != nil {
		return model.VulnerabilityDetail{}, err
	}
	var found *model.VulnerabilityIssue
	for i := range rows {
		if rows[i].ID == id {
			found = &rows[i]
			break
		}
	}
	if found == nil {
		return model.VulnerabilityDetail{}, ErrNotFound
	}
	decorated, err := s.decorateIssues(ctx, []model.VulnerabilityIssue{*found})
	if err != nil || len(decorated) != 1 {
		if err == nil {
			err = ErrNotFound
		}
		return model.VulnerabilityDetail{}, err
	}
	detail := model.VulnerabilityDetail{VulnerabilityIssue: decorated[0]}
	devs, err := s.pool.Query(ctx, `
		SELECT d.id, d.hostname, d.computer_name, d.serial, d.username, f.installed_version, f.installed_build, f.evidence
		FROM vuln_findings f
		JOIN devices d ON d.id = f.device_id
		WHERE f.cve_id=$1 AND f.software_key=$2 AND f.active
		ORDER BY d.hostname`, detail.CVEID, detail.SoftwareKey)
	if err != nil {
		return model.VulnerabilityDetail{}, err
	}
	defer devs.Close()
	detail.Devices = []model.AffectedDevice{}
	for devs.Next() {
		var d model.AffectedDevice
		if err := devs.Scan(&d.ID, &d.Hostname, &d.ComputerName, &d.Serial, &d.Username, &d.Version, &d.Build, &d.Evidence); err != nil {
			return model.VulnerabilityDetail{}, err
		}
		detail.Devices = append(detail.Devices, d)
	}
	if err := devs.Err(); err != nil {
		return model.VulnerabilityDetail{}, err
	}
	detail.Affected = len(detail.Devices)
	installs, err := s.countInstalls(ctx, detail.SoftwareKey)
	if err != nil {
		return model.VulnerabilityDetail{}, err
	}
	detail.Installs = installs
	ev, err := s.pool.Query(ctx, `
		SELECT id, at, actor, action, detail FROM vuln_issue_events WHERE issue_id=$1 ORDER BY at, id`, id)
	if err != nil {
		return model.VulnerabilityDetail{}, err
	}
	defer ev.Close()
	detail.Events = []model.IssueEvent{}
	for ev.Next() {
		var e model.IssueEvent
		if err := ev.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Detail); err != nil {
			return model.VulnerabilityDetail{}, err
		}
		detail.Events = append(detail.Events, e)
	}
	return detail, ev.Err()
}

// UpdateVulnerabilityIssue changes status, assignee, or notes.
// A stale revision is a conflict. Fixed is rejected while a device still matches.
// Risk acceptance requires an expiry and at least one affected device.
func (s *Store) UpdateVulnerabilityIssue(ctx context.Context, p model.Principal, id string, in model.IssueUpdate) (model.VulnerabilityIssue, error) {
	if len(in.Notes) > 4000 || len(in.Assignee) > 200 {
		return model.VulnerabilityIssue{}, invalid("assignee or notes is too long")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.VulnerabilityIssue{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status, assignee, notes, cve, key string
	var revision int
	var risk *time.Time
	err = tx.QueryRow(ctx, `
		SELECT status, assignee, notes, revision, risk_until, cve_id, software_key
		FROM vuln_issues WHERE id=$1 FOR UPDATE`, id).Scan(&status, &assignee, &notes, &revision, &risk, &cve, &key)
	if err != nil {
		return model.VulnerabilityIssue{}, notFound(err)
	}
	if in.Revision != revision {
		return model.VulnerabilityIssue{}, fmt.Errorf("%w: stale revision", ErrConflict)
	}
	next := strings.TrimSpace(in.Status)
	if next == "" {
		next = status
	}
	switch next {
	case "open", "in_progress", "risk_accepted", "fixed":
	default:
		return model.VulnerabilityIssue{}, invalid("status must be open, in_progress, risk_accepted, or fixed")
	}
	var active int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM vuln_findings WHERE cve_id=$1 AND software_key=$2 AND active`, cve, key).Scan(&active); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	now := s.now()
	var riskOut any
	switch next {
	case "risk_accepted":
		if in.RiskUntil == nil || !in.RiskUntil.After(now) {
			return model.VulnerabilityIssue{}, invalid("risk acceptance needs an expiry in the future")
		}
		if active == 0 {
			return model.VulnerabilityIssue{}, invalid("nothing is affected")
		}
		riskOut = *in.RiskUntil
	case "fixed":
		if active > 0 {
			return model.VulnerabilityIssue{}, invalid("devices still match this vulnerability")
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE vuln_issues
		SET status=$2, assignee=$3, notes=$4, risk_until=$5, updated_at=$6,
			resolved_at=CASE WHEN $2='fixed' THEN COALESCE(resolved_at, $6) ELSE NULL END,
			auto_resolved=CASE WHEN $2='fixed' THEN auto_resolved ELSE false END,
			revision=revision+1
		WHERE id=$1`, id, next, strings.TrimSpace(in.Assignee), in.Notes, riskOut, now); err != nil {
		_ = tx.Rollback(ctx)
		return model.VulnerabilityIssue{}, err
	}
	if err := insertIssueEvent(ctx, tx, id, now, actorName(p), "updated", map[string]any{
		"from": status, "to": next, "assignee": strings.TrimSpace(in.Assignee),
	}); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	if err := s.audit(ctx, tx, p, "update", "vulnerability_issue", id, map[string]any{"from": status, "to": next}); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	detail, err := s.GetVulnerabilityIssue(ctx, id)
	if err != nil {
		return model.VulnerabilityIssue{}, err
	}
	return detail.VulnerabilityIssue, nil
}

// AddVulnerabilityNote records a note and refreshes the notes field.
func (s *Store) AddVulnerabilityNote(ctx context.Context, p model.Principal, id string, in model.IssueNote) (model.VulnerabilityIssue, error) {
	note := strings.TrimSpace(in.Note)
	if note == "" || len(note) > 4000 {
		return model.VulnerabilityIssue{}, invalid("note must be 1–4000 characters")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.VulnerabilityIssue{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var revision int
	var status, assignee, notes string
	err = tx.QueryRow(ctx, `SELECT revision, status, assignee, notes FROM vuln_issues WHERE id=$1 FOR UPDATE`, id).Scan(&revision, &status, &assignee, &notes)
	if err != nil {
		return model.VulnerabilityIssue{}, notFound(err)
	}
	if in.Revision != revision {
		return model.VulnerabilityIssue{}, fmt.Errorf("%w: stale revision", ErrConflict)
	}
	now := s.now()
	if _, err := tx.Exec(ctx, `
		UPDATE vuln_issues SET notes=$2, updated_at=$3, revision=revision+1 WHERE id=$1`, id, note, now); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	if err := insertIssueEvent(ctx, tx, id, now, actorName(p), "note", map[string]any{"note": note}); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	if err := s.audit(ctx, tx, p, "note", "vulnerability_issue", id, map[string]any{"revision": revision}); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.VulnerabilityIssue{}, err
	}
	detail, err := s.GetVulnerabilityIssue(ctx, id)
	if err != nil {
		return model.VulnerabilityIssue{}, err
	}
	return detail.VulnerabilityIssue, nil
}

// RunVulnerabilityRecipe enqueues the recipe Decide linked to this issue.
// It does not promote a package and it does not edit Terraform. The caller
// must hold jobs:write as well as vuln:write; the HTTP handler checks both.
func (s *Store) RunVulnerabilityRecipe(ctx context.Context, p model.Principal, id string) (model.Job, error) {
	if !p.Allows("jobs:write") {
		return model.Job{}, fmt.Errorf("%w: jobs:write is required to run a recipe", ErrForbidden)
	}
	detail, err := s.GetVulnerabilityIssue(ctx, id)
	if err != nil {
		return model.Job{}, err
	}
	if detail.Fix.Action != "run_recipe" || detail.Fix.RecipeID == "" {
		return model.Job{}, invalid("this issue has no recipe to run")
	}
	if vuln.GitOpsBoundary == "" {
		return model.Job{}, invalid("gitops boundary")
	}
	rec, err := s.GetRecipe(ctx, detail.Fix.RecipeID)
	if err != nil {
		return model.Job{}, err
	}
	if !rec.Enabled {
		return model.Job{}, invalid("recipe is disabled")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Job{}, err
	}
	job, err := s.insertJob(ctx, tx, p, detail.Fix.RecipeID, nil, "manual")
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Job{}, err
	}
	if err := s.audit(ctx, tx, p, "run_recipe", "vulnerability_issue", id, map[string]any{
		"recipe_id": detail.Fix.RecipeID, "job_id": job.ID, "cve_id": detail.CVEID,
	}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Job{}, err
	}
	return s.GetJob(ctx, job.ID, false)
}

func (s *Store) queryIssues(ctx context.Context, f model.IssueFilter) ([]model.VulnerabilityIssue, error) {
	where := []string{"TRUE"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.KEV != nil {
		add("c.kev = $%d", *f.KEV)
	}
	if f.Severity != "" {
		add("c.severity = $%d", f.Severity)
	}
	if f.Status != "" {
		add("i.status = $%d", f.Status)
	}
	if f.Active {
		where = append(where, "i.status <> 'fixed'")
	}
	if f.DeviceID != "" {
		add(`EXISTS (SELECT 1 FROM vuln_findings f WHERE f.cve_id=i.cve_id AND f.software_key=i.software_key AND f.device_id=$%d AND f.active)`, f.DeviceID)
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		add(`(i.cve_id ILIKE $%d ESCAPE '\' OR i.software_name ILIKE $%d ESCAPE '\' OR c.description ILIKE $%d ESCAPE '\')`, likeContains(q))
		// The same placeholder must be reused. Rebuild this clause.
		where = where[:len(where)-1]
		args = args[:len(args)-1]
		args = append(args, likeContains(q))
		n := len(args)
		where = append(where, fmt.Sprintf(`(i.cve_id ILIKE $%d ESCAPE '\' OR i.software_name ILIKE $%d ESCAPE '\' OR c.description ILIKE $%d ESCAPE '\')`, n, n, n))
	}
	q := `
		SELECT i.id, i.cve_id, i.software_key, i.software_name, i.status, i.assignee, i.notes,
			i.risk_until, i.opened_at, i.updated_at, i.resolved_at, i.auto_resolved, i.revision,
			c.description, c.cvss_score, c.cvss_vector, c.severity, c.kev, c.kev_name, c.kev_date, c.kev_due,
			c.epss, c.epss_percentile, c.epss_known, c.source,
			(SELECT count(*) FROM vuln_findings f WHERE f.cve_id=i.cve_id AND f.software_key=i.software_key AND f.active)
		FROM vuln_issues i
		JOIN vuln_cves c ON c.cve_id = i.cve_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY c.kev DESC, c.epss DESC, c.cvss_score DESC,
			(SELECT count(*) FROM vuln_findings f WHERE f.cve_id=i.cve_id AND f.software_key=i.software_key AND f.active) DESC,
			i.cve_id
		LIMIT 2000`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.VulnerabilityIssue
	for rows.Next() {
		var issue model.VulnerabilityIssue
		if err := rows.Scan(
			&issue.ID, &issue.CVEID, &issue.SoftwareKey, &issue.SoftwareName, &issue.Status, &issue.Assignee, &issue.Notes,
			&issue.RiskUntil, &issue.OpenedAt, &issue.UpdatedAt, &issue.ResolvedAt, &issue.AutoResolved, &issue.Revision,
			&issue.Description, &issue.Score, &issue.Vector, &issue.Severity, &issue.KEV, &issue.KEVName, &issue.KEVAdded, &issue.KEVDue,
			&issue.EPSS, &issue.EPSSPercentile, &issue.EPSSKnown, &issue.Source, &issue.DeviceCount,
		); err != nil {
			return nil, err
		}
		out = append(out, issue)
	}
	return out, rows.Err()
}

func (s *Store) decorateIssues(ctx context.Context, issues []model.VulnerabilityIssue) ([]model.VulnerabilityIssue, error) {
	if len(issues) == 0 {
		return []model.VulnerabilityIssue{}, nil
	}
	settings, _, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return nil, err
	}
	pkgs, recipes, err := s.fixInputs(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT cve_id, software_key, installed_version, installed_build FROM vuln_findings WHERE active`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	installs := map[string][]vuln.Install{}
	for rows.Next() {
		var cve, key, version, build string
		if err := rows.Scan(&cve, &key, &version, &build); err != nil {
			return nil, err
		}
		k := cve + "\x00" + key
		installs[k] = append(installs[k], vuln.Install{Version: version, Build: build})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rules, err := loadVulnRules(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	now := s.now()
	for i := range issues {
		issue := &issues[i]
		vendor, product := splitSoftware(issue.SoftwareKey)
		p := vuln.Product{Vendor: vendor, Product: product}
		if known, ok := vuln.Lookup(vendor, product); ok {
			p = known
		}
		rs, ts := rulesFor(rules, issue.CVEID, p)
		plan := vuln.Decide(vuln.DecideInput{
			CVE: issue.CVEID, SoftwareKey: issue.SoftwareKey, SoftwareName: issue.SoftwareName,
			OS: strings.HasPrefix(issue.SoftwareKey, "o:"), Ranges: rs, Trains: ts,
			Installs: installs[issue.CVEID+"\x00"+issue.SoftwareKey], Packages: pkgs, Recipes: recipes,
		})
		issue.Fix = model.IssueFix{
			Action: plan.Action, FixedVersion: plan.FixedVersion, FixedBuild: plan.FixedBuild,
			Catalog: plan.Catalog, CatalogVersion: plan.CatalogVersion, RecipeID: plan.RecipeID,
			RecipeName: plan.RecipeName, RecipeStatus: plan.RecipeStatus, RequiredOS: plan.RequiredOS,
			PRURL: plan.PRURL, PRTitle: plan.PRTitle, PRBody: plan.PRBody,
		}
		issue.SLADays = slaDays(settings, issue.Severity, issue.KEV)
		issue.SLADue = issue.OpenedAt.Add(time.Duration(issue.SLADays) * 24 * time.Hour)
		issue.WithinSLA = issue.Status == "fixed" || !now.After(issue.SLADue)
	}
	return issues, nil
}

func (s *Store) fixInputs(ctx context.Context) ([]vuln.CatalogPackage, []vuln.RecipeState, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, version, catalog FROM packages`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var pkgs []vuln.CatalogPackage
	for rows.Next() {
		var p vuln.CatalogPackage
		if err := rows.Scan(&p.Name, &p.Version, &p.Catalog); err != nil {
			return nil, nil, err
		}
		pkgs = append(pkgs, p)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rrows, err := s.pool.Query(ctx, `
		SELECT r.id, r.name, r.identifier, r.enabled,
			COALESCE((SELECT status FROM jobs WHERE recipe_id=r.id ORDER BY created_at DESC LIMIT 1), ''),
			COALESCE((SELECT result FROM jobs WHERE recipe_id=r.id ORDER BY created_at DESC LIMIT 1), '')
		FROM recipes r`)
	if err != nil {
		return nil, nil, err
	}
	defer rrows.Close()
	var recipes []vuln.RecipeState
	for rrows.Next() {
		var r vuln.RecipeState
		if err := rrows.Scan(&r.ID, &r.Name, &r.Identifier, &r.Enabled, &r.Status, &r.Result); err != nil {
			return nil, nil, err
		}
		recipes = append(recipes, r)
	}
	return pkgs, recipes, rrows.Err()
}

func (s *Store) countInstalls(ctx context.Context, softwareKey string) (int, error) {
	if strings.HasPrefix(softwareKey, "o:") {
		var n int
		err := s.pool.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n)
		return n, err
	}
	vendor, product := splitSoftware(softwareKey)
	target := vuln.Product{Vendor: vendor, Product: product}
	if known, ok := vuln.Lookup(vendor, product); ok {
		target = known
	}
	overrides, err := s.loadOverrides(ctx, nil)
	if err != nil {
		return 0, err
	}
	rows, err := s.pool.Query(ctx, `SELECT name, bundle_id FROM device_apps`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name, bundle string
		if err := rows.Scan(&name, &bundle); err != nil {
			return 0, err
		}
		got, ok := vuln.MatchSoftware(name, bundle, overridesToVuln(overrides))
		if ok && got.Key() == target.Key() {
			n++
		}
	}
	return n, rows.Err()
}

func filterIssues(in []model.VulnerabilityIssue, f model.IssueFilter) []model.VulnerabilityIssue {
	var out []model.VulnerabilityIssue
	q := strings.ToLower(strings.TrimSpace(f.Q))
	for _, issue := range in {
		if f.KEV != nil && issue.KEV != *f.KEV {
			continue
		}
		if f.Severity != "" && issue.Severity != f.Severity {
			continue
		}
		if f.Status != "" && issue.Status != f.Status {
			continue
		}
		if f.Active && issue.Status == "fixed" {
			continue
		}
		if f.HasFix != nil && hasCatalogFix(issue.Fix.Action) != *f.HasFix {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(issue.CVEID+" "+issue.SoftwareName+" "+issue.Description), q) {
			continue
		}
		out = append(out, issue)
	}
	return out
}

func summarizeIssues(in []model.VulnerabilityIssue, now time.Time) model.VulnerabilitySummary {
	var sum model.VulnerabilitySummary
	week := now.Add(7 * 24 * time.Hour)
	for _, issue := range in {
		if issue.Status == "fixed" {
			continue
		}
		sum.Open++
		if issue.KEV {
			sum.KEV++
			sum.KEVDevices += issue.DeviceCount
		}
		if hasCatalogFix(issue.Fix.Action) {
			sum.WithFix++
		}
		if issue.WithinSLA {
			sum.WithinSLA++
		}
		if issue.SLADue.After(now) && !issue.SLADue.After(week) {
			sum.DueThisWeek++
		}
		if !issue.OpenedAt.Before(now.Add(-7 * 24 * time.Hour)) {
			sum.OpenedThisWeek++
		}
	}
	return sum
}

func hasCatalogFix(action string) bool {
	return action == "promote" || action == "require_install"
}

func slaDays(s model.VulnerabilitySettings, severity string, kev bool) int {
	days := s.SLALowDays
	switch severity {
	case "critical":
		days = s.SLACriticalDays
	case "high":
		days = s.SLAHighDays
	case "medium":
		days = s.SLAMediumDays
	}
	if days <= 0 {
		days = 90
	}
	// A KEV issue uses the tighter of the severity clock and the CISA clock.
	if kev && s.SLAKEVDays > 0 && s.SLAKEVDays < days {
		days = s.SLAKEVDays
	}
	return days
}

func splitSoftware(key string) (string, string) {
	_, rest, ok := strings.Cut(key, ":")
	if !ok {
		return "", ""
	}
	vendor, product, _ := strings.Cut(rest, ":")
	return vendor, product
}

func likeContains(q string) string {
	q = strings.ReplaceAll(q, `\`, `\\`)
	q = strings.ReplaceAll(q, `%`, `\%`)
	q = strings.ReplaceAll(q, `_`, `\_`)
	return "%" + q + "%"
}

func actorName(p model.Principal) string {
	if p.Name != "" {
		return p.Name
	}
	if p.ID != "" {
		return p.ID
	}
	return "api"
}
