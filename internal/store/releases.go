package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
	"github.com/jackc/pgx/v5"
)

// RejectedCatalog holds builds a reviewer rejected. No rule promotes out of it
// and no manifest should list it, so clients stop seeing the build.
const RejectedCatalog = "rejected"

const notesLease = 10 * time.Minute
const notesMaxAttempts = 3

const reviewCols = `r.id, r.package_id, r.name, r.version, r.baseline_version, p.catalog, r.final_catalog,
	r.software_key, r.priority, r.reasons, r.fixed, r.still_open, r.exposed_devices, r.status,
	r.decided_by, r.decided_at, r.decision_note, r.notes_status, r.notes_summary, r.notes_recommendation,
	r.notes_rationale, r.notes_security_fixes, r.notes_cves, r.notes_sources, r.notes_model, r.notes_error,
	r.notes_attempts, r.notes_at, r.created_at, r.evaluated_at, COALESCE(p.pkginfo->>'display_name', '')`

func scanReview(row pgx.Row) (model.ReleaseReview, error) {
	var r model.ReleaseReview
	var reasons []byte
	err := row.Scan(&r.ID, &r.PackageID, &r.Name, &r.Version, &r.BaselineVersion, &r.Catalog, &r.FinalCatalog,
		&r.SoftwareKey, &r.Priority, &reasons, &r.Fixed, &r.StillOpen, &r.ExposedDevices, &r.Status,
		&r.DecidedBy, &r.DecidedAt, &r.DecisionNote, &r.Notes.Status, &r.Notes.Summary, &r.Notes.Recommendation,
		&r.Notes.Rationale, &r.Notes.SecurityFixes, &r.Notes.CVEs, &r.Notes.Sources, &r.Notes.Model, &r.Notes.Error,
		&r.Notes.Attempts, &r.Notes.At, &r.CreatedAt, &r.EvaluatedAt, &r.DisplayName)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal(reasons, &r.Reasons)
	if r.Reasons == nil {
		r.Reasons = []string{}
	}
	if r.Notes.CVEs == nil {
		r.Notes.CVEs = []string{}
	}
	if r.Notes.Sources == nil {
		r.Notes.Sources = []string{}
	}
	if r.DisplayName == "" {
		r.DisplayName = r.Name
	}
	return r, nil
}

// ListReleaseReviews returns reviews, newest first. status "" means every status.
func (s *Store) ListReleaseReviews(ctx context.Context, status string) ([]model.ReleaseReview, error) {
	q := `SELECT ` + reviewCols + ` FROM release_reviews r JOIN packages p ON p.id = r.package_id`
	args := []any{}
	if status != "" {
		q += ` WHERE r.status = $1`
		args = append(args, status)
	}
	q += ` ORDER BY (r.status = 'pending') DESC, (r.priority = 'high') DESC, r.created_at DESC LIMIT 500`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ReleaseReview{}
	for rows.Next() {
		r, err := scanReview(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetReleaseReview loads one review.
func (s *Store) GetReleaseReview(ctx context.Context, id string) (model.ReleaseReview, error) {
	r, err := scanReview(s.pool.QueryRow(ctx, `SELECT `+reviewCols+` FROM release_reviews r JOIN packages p ON p.id = r.package_id WHERE r.id=$1`, id))
	if err != nil {
		return model.ReleaseReview{}, notFound(err)
	}
	return r, nil
}

// finalCatalog is where a build ends up: a rule's destination that no
// enabled rule promotes out of. "production" wins a tie; with no rules it is
// "production".
func finalCatalog(rules []model.PromotionRule) string {
	from := map[string]bool{}
	for _, r := range rules {
		if r.Enabled {
			from[r.FromCatalog] = true
		}
	}
	var ends []string
	for _, r := range rules {
		if r.Enabled && !from[r.ToCatalog] {
			ends = append(ends, r.ToCatalog)
		}
	}
	if len(ends) == 0 {
		return "production"
	}
	sort.Strings(ends)
	for _, e := range ends {
		if e == "production" {
			return e
		}
	}
	return ends[0]
}

// releaseAfterImport opens a review for a newly imported build. It never fails
// the import: a review that cannot be scored still shows up, as LOW, pending.
func (s *Store) releaseAfterImport(ctx context.Context, pkg model.Package) {
	if err := s.openReleaseReview(ctx, pkg); err != nil {
		slog.Error("release review", "package", pkg.ID, "name", pkg.Name, "version", pkg.Version, "err", err.Error())
	}
}

func (s *Store) openReleaseReview(ctx context.Context, pkg model.Package) error {
	now := s.now()
	id := newID()
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO release_reviews (id, package_id, name, version, created_at, evaluated_at)
		VALUES ($1,$2,$3,$4,$5,$5) ON CONFLICT (package_id) DO NOTHING`,
		id, pkg.ID, pkg.Name, pkg.Version, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	// An older pending build of the same app is moot once a newer one lands.
	rows, err := s.pool.Query(ctx, `SELECT id, version FROM release_reviews WHERE name=$1 AND status='pending' AND id<>$2`, pkg.Name, id)
	if err != nil {
		return err
	}
	var older []string
	for rows.Next() {
		var rid, ver string
		if err := rows.Scan(&rid, &ver); err != nil {
			rows.Close()
			return err
		}
		if c, ok := vuln.Compare(ver, pkg.Version); ok && c < 0 {
			older = append(older, rid)
		}
	}
	rows.Close()
	for _, rid := range older {
		if _, err := s.pool.Exec(ctx, `UPDATE release_reviews SET status='superseded', decided_by='system', decided_at=$2,
			decision_note=$3 WHERE id=$1 AND status='pending'`, rid, now, "superseded by "+pkg.Version); err != nil {
			return err
		}
	}
	return s.EvaluateRelease(ctx, id)
}

// EvaluateRelease recomputes a pending review from the current feeds: which
// CVEs the build fixes relative to the final catalog, which it still carries,
// and HIGH or LOW. Decided reviews keep the evaluation they were decided on.
func (s *Store) EvaluateRelease(ctx context.Context, id string) error {
	var pkgID, name, version, status string
	var notesStatus string
	var notesCVEs []string
	var notesSec bool
	err := s.pool.QueryRow(ctx, `SELECT package_id, name, version, status, notes_status, notes_cves, notes_security_fixes
		FROM release_reviews WHERE id=$1`, id).Scan(&pkgID, &name, &version, &status, &notesStatus, &notesCVEs, &notesSec)
	if err != nil {
		return notFound(err)
	}
	if status != "pending" {
		return nil
	}
	rules, err := s.ListPromotionRules(ctx)
	if err != nil {
		return err
	}
	final := finalCatalog(rules)
	baseline, err := s.baselineVersion(ctx, name, final, pkgID, version)
	if err != nil {
		return err
	}
	settings, _, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return err
	}
	product, mapped := vuln.MatchMunkiName(name, overridesToVuln(settings.Overrides))

	fixedIDs, openIDs := map[string]string{}, map[string]bool{}
	if mapped {
		vr, err := loadVulnRules(ctx, s.pool)
		if err != nil {
			return err
		}
		idx := vuln.NewIndex(vr.ranges, vr.trains)
		open := vuln.AffectedCVEs(idx, product, version)
		if baseline != "" {
			for cve := range vuln.AffectedCVEs(idx, product, baseline) {
				if !open[cve] {
					fixedIDs[cve] = "ranges"
				}
			}
		}
		openIDs = open
	}
	for _, cve := range notesCVEs {
		if _, ok := fixedIDs[cve]; !ok && !openIDs[cve] {
			fixedIDs[cve] = "release_notes"
		}
	}
	ids := make([]string, 0, len(fixedIDs)+len(openIDs))
	for c := range fixedIDs {
		ids = append(ids, c)
	}
	for c := range openIDs {
		ids = append(ids, c)
	}
	scores, err := s.cveScores(ctx, ids)
	if err != nil {
		return err
	}
	var fixed, open []vuln.ReleaseCVE
	var unscored []string
	for c, src := range fixedIDs {
		sc := scores[c]
		sc.CVE, sc.Source = c, src
		if !sc.Scored && src == "release_notes" {
			unscored = append(unscored, c)
		}
		fixed = append(fixed, sc)
	}
	for c := range openIDs {
		sc := scores[c]
		sc.CVE, sc.Source = c, "ranges"
		open = append(open, sc)
	}
	sortCVEs(fixed)
	sortCVEs(open)
	sort.Strings(unscored)

	exposed := 0
	if mapped {
		if err := s.pool.QueryRow(ctx, `SELECT count(DISTINCT device_id) FROM vuln_findings WHERE active AND software_key=$1`, product.Key()).Scan(&exposed); err != nil {
			return err
		}
	}
	verdict := vuln.JudgeRelease(vuln.ReleaseInput{
		Mapped: mapped, Baseline: baseline, Fixed: fixed, Open: open, Exposed: exposed,
		NotesDone: notesStatus == "done", NotesSecFix: notesSec, NotesNoScore: unscored,
	})
	reasons, _ := json.Marshal(verdict.Reasons)
	fixedJSON, _ := json.Marshal(nonNil(fixed))
	openJSON, _ := json.Marshal(nonNil(open))
	key := ""
	if mapped {
		key = product.Key()
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE release_reviews SET baseline_version=$2, final_catalog=$3, software_key=$4, priority=$5,
			reasons=$6::jsonb, fixed=$7::jsonb, still_open=$8::jsonb, exposed_devices=$9, evaluated_at=$10
		WHERE id=$1 AND status='pending'`,
		id, baseline, final, key, verdict.Priority, string(reasons), string(fixedJSON), string(openJSON), exposed, s.now())
	return err
}

func nonNil(in []vuln.ReleaseCVE) []vuln.ReleaseCVE {
	if in == nil {
		return []vuln.ReleaseCVE{}
	}
	return in
}

func sortCVEs(list []vuln.ReleaseCVE) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].KEV != list[j].KEV {
			return list[i].KEV
		}
		if list[i].CVSS != list[j].CVSS {
			return list[i].CVSS > list[j].CVSS
		}
		return list[i].CVE < list[j].CVE
	})
}

// baselineVersion is the highest version of name in the final catalog, other
// than this build. With nothing there, it is the highest older build anywhere,
// so a first rush still shows what it fixes.
func (s *Store) baselineVersion(ctx context.Context, name, final, pkgID, version string) (string, error) {
	rows, err := s.pool.Query(ctx, `SELECT version, catalog FROM packages WHERE name=$1 AND id<>$2 AND catalog<>$3`, name, pkgID, RejectedCatalog)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	bestFinal, bestOlder := "", ""
	higher := func(a, b string) bool {
		if b == "" {
			return true
		}
		c, ok := vuln.Compare(a, b)
		return ok && c > 0
	}
	for rows.Next() {
		var v, cat string
		if err := rows.Scan(&v, &cat); err != nil {
			return "", err
		}
		if cat == final && higher(v, bestFinal) {
			bestFinal = v
		}
		if c, ok := vuln.Compare(v, version); ok && c < 0 && higher(v, bestOlder) {
			bestOlder = v
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if bestFinal != "" {
		return bestFinal, nil
	}
	return bestOlder, nil
}

func (s *Store) cveScores(ctx context.Context, ids []string) (map[string]vuln.ReleaseCVE, error) {
	out := map[string]vuln.ReleaseCVE{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT cve_id, cvss_score, severity, kev, epss, epss_known FROM vuln_cves WHERE cve_id = ANY($1::text[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c vuln.ReleaseCVE
		if err := rows.Scan(&c.CVE, &c.CVSS, &c.Severity, &c.KEV, &c.EPSS, &c.EPSSKnown); err != nil {
			return nil, err
		}
		c.Scored = c.CVSS > 0
		out[c.CVE] = c
	}
	return out, rows.Err()
}

// DecideRelease records a reviewer's decision. Only a person decides: the
// advisor's token has releases:write, not releases:update.
func (s *Store) DecideRelease(ctx context.Context, p model.Principal, id string, in model.ReleaseDecision) (model.ReleaseReview, error) {
	decision := strings.TrimSpace(in.Decision)
	status := map[string]string{"rush": "rushed", "normal": "normal", "reject": "rejected"}[decision]
	if status == "" {
		return model.ReleaseReview{}, invalid("decision must be rush, normal, or reject")
	}
	note := strings.TrimSpace(in.Note)
	if len(note) > 2000 || strings.ContainsRune(note, 0) {
		return model.ReleaseReview{}, invalid("note is too long")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.ReleaseReview{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var pkgID, cur, final, priority string
	err = tx.QueryRow(ctx, `SELECT r.package_id, r.status, r.final_catalog, r.priority FROM release_reviews r WHERE r.id=$1 FOR UPDATE`, id).
		Scan(&pkgID, &cur, &final, &priority)
	if err != nil {
		return model.ReleaseReview{}, notFound(err)
	}
	// Rush and normal decide a pending build. Reject is always available until
	// the build is already rejected or superseded, including after it shipped.
	allowed := cur == "pending" || (decision == "reject" && (cur == "rushed" || cur == "normal"))
	if !allowed {
		return model.ReleaseReview{}, fmt.Errorf("%w: review is %s", ErrConflict, cur)
	}
	var catalog string
	if err := tx.QueryRow(ctx, `SELECT catalog FROM packages WHERE id=$1 FOR UPDATE`, pkgID).Scan(&catalog); err != nil {
		return model.ReleaseReview{}, notFound(err)
	}
	dest := ""
	switch decision {
	case "rush":
		if final == "" {
			rules, err := s.ListPromotionRules(ctx)
			if err != nil {
				return model.ReleaseReview{}, err
			}
			final = finalCatalog(rules)
		}
		if catalog != final {
			dest = final
		}
	case "reject":
		if catalog != RejectedCatalog {
			dest = RejectedCatalog
		}
	}
	now := s.now()
	if dest != "" {
		if err := movePackageTx(ctx, tx, id, pkgID, catalog, dest, now); err != nil {
			return model.ReleaseReview{}, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE release_reviews SET status=$2, decided_by=$3, decided_at=$4, decision_note=$5 WHERE id=$1`,
		id, status, actorName(p), now, note); err != nil {
		return model.ReleaseReview{}, err
	}
	if err := s.audit(ctx, tx, p, "release_"+decision, "package", pkgID, map[string]any{
		"review": id, "from": catalog, "to": dest, "priority": priority, "note": note,
	}); err != nil {
		return model.ReleaseReview{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.ReleaseReview{}, err
	}
	if dest != "" {
		if err := s.RegenerateCatalogs(ctx); err != nil {
			return model.ReleaseReview{}, err
		}
	}
	return s.GetReleaseReview(ctx, id)
}

// movePackageTx moves a locked package between catalogs inside the caller's
// transaction, so a decision and its move commit together.
func movePackageTx(ctx context.Context, tx pgx.Tx, reviewID, pkgID, from, dest string, now time.Time) error {
	var info []byte
	if err := tx.QueryRow(ctx, `SELECT pkginfo FROM packages WHERE id=$1`, pkgID).Scan(&info); err != nil {
		return err
	}
	var m map[string]any
	if len(info) > 0 {
		_ = json.Unmarshal(info, &m)
	}
	if m == nil {
		m = map[string]any{}
	}
	m["catalogs"] = []any{dest}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE packages SET catalog=$2, pkginfo=$3::jsonb, soak_started_at=$4, promoted_at=$4 WHERE id=$1 AND catalog=$5`,
		pkgID, dest, string(raw), now, from)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: package %s moved while review %s was decided", ErrConflict, pkgID, reviewID)
	}
	return nil
}

// LeaseReleaseNotes hands the advisor the oldest pending review whose notes
// are unread, or whose lease ran out, or that failed fewer than three times.
// It returns ErrNotFound when there is nothing to do.
func (s *Store) LeaseReleaseNotes(ctx context.Context, p model.Principal) (model.ReleaseNotesTask, error) {
	now := s.now()
	var t model.ReleaseNotesTask
	var pkgID string
	err := s.pool.QueryRow(ctx, `
		UPDATE release_reviews SET notes_status='leased', notes_lease_until=$1, notes_attempts=notes_attempts+1
		WHERE id = (
			SELECT id FROM release_reviews
			WHERE status='pending' AND notes_attempts < $3 AND (
				notes_status IN ('pending', 'failed') OR (notes_status='leased' AND notes_lease_until < $2))
			ORDER BY (priority='high') DESC, created_at
			LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING id, package_id, name, version, baseline_version`,
		now.Add(notesLease), now, notesMaxAttempts).Scan(&t.ID, &pkgID, &t.Name, &t.Version, &t.BaselineVersion)
	if err != nil {
		return model.ReleaseNotesTask{}, notFound(err)
	}
	var info []byte
	_ = s.pool.QueryRow(ctx, `SELECT pkginfo, COALESCE(recipe_identifier, '') FROM packages WHERE id=$1`, pkgID).Scan(&info, &t.RecipeIdentifier)
	var m map[string]any
	_ = json.Unmarshal(info, &m)
	str := func(k string) string {
		v, _ := m[k].(string)
		return clip(v, 500)
	}
	t.DisplayName, t.Developer, t.Description = str("display_name"), str("developer"), str("description")
	if t.DisplayName == "" {
		t.DisplayName = t.Name
	}
	t.LeaseSeconds = int(notesLease / time.Second)
	_ = s.auditNow(ctx, p, "notes_lease", "release_review", t.ID, map[string]any{"name": t.Name, "version": t.Version})
	return t, nil
}

// SubmitReleaseNotes stores what the advisor found, looks up any CVE it named
// in NVD, KEV, and EPSS, and re-scores the review. Every field is untrusted:
// it came from a model that read vendor web pages.
func (s *Store) SubmitReleaseNotes(ctx context.Context, p model.Principal, id string, in model.ReleaseNotesInput) (model.ReleaseReview, error) {
	clean, err := cleanNotes(in)
	if err != nil {
		return model.ReleaseReview{}, err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE release_reviews SET notes_status='done', notes_lease_until=NULL, notes_summary=$2,
			notes_recommendation=$3, notes_rationale=$4, notes_security_fixes=$5, notes_cves=$6,
			notes_sources=$7, notes_model=$8, notes_error='', notes_at=$9
		WHERE id=$1 AND status='pending' AND notes_status='leased'`,
		id, clean.Summary, clean.Recommendation, clean.Rationale, clean.SecurityFixes, clean.CVEs, clean.Sources, clean.Model, s.now())
	if err != nil {
		return model.ReleaseReview{}, err
	}
	if tag.RowsAffected() == 0 {
		return model.ReleaseReview{}, fmt.Errorf("%w: review is not leased for notes", ErrConflict)
	}
	_ = s.auditNow(ctx, p, "notes_submit", "release_review", id, map[string]any{"cves": clean.CVEs, "recommendation": clean.Recommendation})
	if err := s.enrichCVEs(ctx, clean.CVEs); err != nil {
		slog.Warn("release notes cve lookup", "review", id, "err", err.Error())
	}
	if err := s.EvaluateRelease(ctx, id); err != nil {
		return model.ReleaseReview{}, err
	}
	return s.GetReleaseReview(ctx, id)
}

// FailReleaseNotes records an advisor failure. The review is retried until it
// has failed three times; the CVE scoring stands either way.
func (s *Store) FailReleaseNotes(ctx context.Context, p model.Principal, id, msg string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE release_reviews SET notes_status='failed', notes_lease_until=NULL, notes_error=$2
		WHERE id=$1 AND notes_status='leased'`, id, clip(strings.TrimSpace(msg), 1000))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: review is not leased for notes", ErrConflict)
	}
	return s.auditNow(ctx, p, "notes_fail", "release_review", id, map[string]any{"error": clip(msg, 200)})
}

// ReevaluatePendingReleases re-scores every pending review after a feed sync.
func (s *Store) ReevaluatePendingReleases(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT id FROM release_reviews WHERE status='pending'`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := s.EvaluateRelease(ctx, id); err != nil {
			return err
		}
	}
	return rows.Err()
}

func cleanNotes(in model.ReleaseNotesInput) (model.ReleaseNotesInput, error) {
	out := model.ReleaseNotesInput{SecurityFixes: in.SecurityFixes}
	out.Summary = clip(strings.TrimSpace(in.Summary), 4000)
	out.Rationale = clip(strings.TrimSpace(in.Rationale), 2000)
	out.Model = clip(strings.TrimSpace(in.Model), 100)
	switch strings.ToLower(strings.TrimSpace(in.Recommendation)) {
	case "high":
		out.Recommendation = "high"
	case "low":
		out.Recommendation = "low"
	default:
		return out, invalid("recommendation must be high or low")
	}
	if out.Summary == "" {
		return out, invalid("summary is required")
	}
	seen := map[string]bool{}
	out.CVEs = []string{}
	for _, c := range in.CVEs {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !vuln.ValidCVE(c) {
			continue
		}
		if !seen[c] && len(out.CVEs) < 50 {
			seen[c] = true
			out.CVEs = append(out.CVEs, c)
		}
	}
	sort.Strings(out.CVEs)
	out.Sources = []string{}
	for _, raw := range in.Sources {
		raw = strings.TrimSpace(raw)
		u, err := url.Parse(raw)
		// Only https links are shown to reviewers; anything else is dropped.
		if err != nil || u.Scheme != "https" || u.Host == "" || len(raw) > 500 || u.User != nil {
			continue
		}
		if len(out.Sources) < 10 {
			out.Sources = append(out.Sources, u.String())
		}
	}
	return out, nil
}

// enrichCVEs fetches NVD records for named CVEs the database has not seen,
// then refreshes KEV and EPSS so the scores the review uses are current.
func (s *Store) enrichCVEs(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	feeds := s.vulnerabilityFeeds()
	if feeds.HTTP == nil {
		return nil
	}
	settings, key, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return err
	}
	known, err := s.cveScores(ctx, ids)
	if err != nil {
		return err
	}
	var errs []string
	if settings.NVDEnabled {
		client := &vuln.NVDClient{Base: feeds.NVDBase, Key: key, HTTP: feeds.HTTP, Sleep: feeds.Sleep, Now: feeds.Now}
		for _, id := range ids {
			if known[id].Scored {
				continue
			}
			page, err := client.Fetch(ctx, vuln.NVDQuery{CVEID: id})
			if err != nil {
				errs = append(errs, vuln.RedactSecret(err.Error(), key))
				continue
			}
			for _, rec := range page.CVEs {
				if err := s.saveNVDRecord(ctx, rec, s.now()); err != nil {
					return err
				}
			}
		}
	}
	if settings.KEVEnabled {
		if err := s.syncKEV(ctx, feeds, s.now()); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if settings.EPSSEnabled {
		if err := s.epssFor(ctx, feeds, ids); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *Store) epssFor(ctx context.Context, feeds vuln.Feeds, ids []string) error {
	rawURL, err := vuln.EPSSQuery(feeds.EPSSURL, ids)
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
		if _, err := s.pool.Exec(ctx, `UPDATE vuln_cves SET epss=$2, epss_percentile=$3, epss_known=true, updated_at=$4 WHERE cve_id=$1`,
			item.CVE, item.Score, item.Percentile, s.now()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) auditNow(ctx context.Context, p model.Principal, action, kind, id string, detail map[string]any) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.audit(ctx, tx, p, action, kind, id, detail); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
