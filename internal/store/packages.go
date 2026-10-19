package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/jackc/pgx/v5"
)

var filenameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,180}$`)

func scanPackage(row pgx.Row) (model.Package, error) {
	var p model.Package
	var info []byte
	err := row.Scan(&p.ID, &p.Name, &p.Version, &p.Catalog, &p.Filename, &p.RecipeIdentifier, &p.JobID, &p.SoakStartedAt, &p.PromotedAt, &p.CreatedAt, &info)
	p.Pkginfo = info
	return p, err
}

const pkgCols = `id, name, version, catalog, filename, recipe_identifier, job_id, soak_started_at, promoted_at, created_at, pkginfo`

// ImportCatalog is the catalog new builds land in: the oldest enabled promotion rule's source, or "testing".
func (s *Store) ImportCatalog(ctx context.Context) (string, error) {
	var name string
	err := s.pool.QueryRow(ctx, `
		SELECT from_catalog FROM promotion_rules WHERE enabled ORDER BY created_at LIMIT 1`).Scan(&name)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return "testing", nil
		}
		return "", err
	}
	return name, nil
}

func validateFilename(name string) error {
	if name == "" || strings.ContainsAny(name, "/\\\x00") || strings.Contains(name, "..") || !filenameRE.MatchString(name) {
		return invalid("invalid package filename")
	}
	return nil
}

func hashesDiffer(existing, incoming []byte) bool {
	oldHash, newHash := installerHash(existing), installerHash(incoming)
	return oldHash != "" && newHash != "" && oldHash != newHash
}

func installerHash(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	s, _ := m["installer_item_hash"].(string)
	return strings.ToLower(s)
}

type leaseOwner struct {
	runnerID string
	jobID    string
	attempt  int
}

// InsertPackage records a new pkginfo. A duplicate name+version with the same bytes is not imported again.
// A duplicate name+version with different bytes is a conflict and does not replace the stored object.
func (s *Store) InsertPackage(ctx context.Context, p model.Principal, pkg model.Package) (model.Package, bool, error) {
	return s.insertPackage(ctx, p, pkg, nil)
}

// InsertOwnedPackage is InsertPackage that also checks the runner still holds the job attempt.
// The check and the insert share a transaction so a reclaimed lease cannot import.
func (s *Store) InsertOwnedPackage(ctx context.Context, p model.Principal, runnerID, jobID string, attempt int, pkg model.Package) (model.Package, bool, error) {
	return s.insertPackage(ctx, p, pkg, &leaseOwner{runnerID: runnerID, jobID: jobID, attempt: attempt})
}

func (s *Store) insertPackage(ctx context.Context, p model.Principal, pkg model.Package, owner *leaseOwner) (model.Package, bool, error) {
	if pkg.Name == "" || pkg.Version == "" {
		return model.Package{}, false, invalid("package name and version are required")
	}
	if err := validateFilename(pkg.Filename); err != nil {
		return model.Package{}, false, err
	}
	if pkg.Catalog == "" {
		cat, err := s.ImportCatalog(ctx)
		if err != nil {
			return model.Package{}, false, err
		}
		pkg.Catalog = cat
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Package{}, false, err
	}
	defer tx.Rollback(ctx)
	if owner != nil {
		var status string
		var attempt int
		err = tx.QueryRow(ctx, `
			SELECT status, attempt FROM jobs WHERE id=$1 AND runner_id=$2 AND attempt=$3 FOR UPDATE`,
			owner.jobID, owner.runnerID, owner.attempt).Scan(&status, &attempt)
		if err != nil {
			if notFound(err) == ErrNotFound {
				return model.Package{}, false, ErrForbidden
			}
			return model.Package{}, false, err
		}
		if status != "leased" && status != "running" {
			return model.Package{}, false, ErrForbidden
		}
	}
	var existingID string
	var existingInfo []byte
	err = tx.QueryRow(ctx, `SELECT id, pkginfo FROM packages WHERE name=$1 AND version=$2 FOR UPDATE`, pkg.Name, pkg.Version).Scan(&existingID, &existingInfo)
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return model.Package{}, false, err
		}
		got, gerr := s.GetPackage(ctx, existingID)
		if gerr != nil {
			return model.Package{}, false, gerr
		}
		if hashesDiffer(existingInfo, pkg.Pkginfo) {
			return got, false, fmt.Errorf("%w: package bytes differ", ErrConflict)
		}
		return got, false, nil
	}
	if notFound(err) != ErrNotFound {
		return model.Package{}, false, err
	}
	now := s.now()
	pkg.ID = newID()
	pkg.SoakStartedAt = now
	pkg.CreatedAt = now
	_, err = tx.Exec(ctx, `
		INSERT INTO packages (id, name, version, catalog, pkginfo, pkg_key, filename, job_id, recipe_identifier, soak_started_at, created_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$10)`,
		pkg.ID, pkg.Name, pkg.Version, pkg.Catalog, string(pkg.Pkginfo), "pkgs/"+pkg.Filename, pkg.Filename, optUUID(pkg.JobID), pkg.RecipeIdentifier, now)
	if err != nil {
		mapped := mapWriteErr(err)
		if errors.Is(mapped, ErrConflict) {
			_ = tx.Rollback(ctx)
			var existing string
			var info []byte
			if qerr := s.pool.QueryRow(ctx, `SELECT id, pkginfo FROM packages WHERE name=$1 AND version=$2`, pkg.Name, pkg.Version).Scan(&existing, &info); qerr == nil {
				got, gerr := s.GetPackage(ctx, existing)
				if gerr != nil {
					return model.Package{}, false, gerr
				}
				if hashesDiffer(info, pkg.Pkginfo) {
					return got, false, fmt.Errorf("%w: package bytes differ", ErrConflict)
				}
				return got, false, nil
			}
		}
		return model.Package{}, false, mapped
	}
	if err := s.audit(ctx, tx, p, "import", "package", pkg.ID, map[string]any{"name": pkg.Name, "version": pkg.Version, "catalog": pkg.Catalog}); err != nil {
		return model.Package{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Package{}, false, err
	}
	if err := s.RegenerateCatalogs(ctx); err != nil {
		return model.Package{}, false, err
	}
	got, err := s.GetPackage(ctx, pkg.ID)
	return got, true, err
}

// DeletePackage removes a package row and rebuilds catalogs. Used when blob storage fails after insert.
func (s *Store) DeletePackage(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM packages WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return s.RegenerateCatalogs(ctx)
}

// GetPackage loads one package and computes soak status.
func (s *Store) GetPackage(ctx context.Context, id string) (model.Package, error) {
	p, err := scanPackage(s.pool.QueryRow(ctx, `SELECT `+pkgCols+` FROM packages WHERE id=$1`, id))
	if err != nil {
		return model.Package{}, notFound(err)
	}
	rules, err := s.ListPromotionRules(ctx)
	if err != nil {
		return model.Package{}, err
	}
	annotateSoak(&p, rules, s.now())
	return p, nil
}

// ListPackages returns packages, optionally filtered by catalog.
func (s *Store) ListPackages(ctx context.Context, catalog string) ([]model.Package, error) {
	q := `SELECT ` + pkgCols + ` FROM packages`
	args := []any{}
	if catalog != "" {
		q += ` WHERE catalog=$1`
		args = append(args, catalog)
	}
	q += ` ORDER BY name, version`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Package{}
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rules, err := s.ListPromotionRules(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	for i := range out {
		annotateSoak(&out[i], rules, now)
	}
	return out, nil
}

func matchingRule(rules []model.PromotionRule, catalog string) *model.PromotionRule {
	var best *model.PromotionRule
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.FromCatalog != catalog {
			continue
		}
		if best == nil || r.CreatedAt.Before(best.CreatedAt) {
			best = r
		}
	}
	return best
}

func annotateSoak(p *model.Package, rules []model.PromotionRule, now time.Time) {
	match := matchingRule(rules, p.Catalog)
	if match != nil {
		if d, ok := munki.SoakDuration(match.SoakDays); ok {
			ends := p.SoakStartedAt.Add(d)
			p.SoakEndsAt = &ends
		}
		switch {
		case match.ManualHold:
			p.SoakStatus = "held"
		case munki.SoakDue(now, p.SoakStartedAt, match.SoakDays, false):
			p.SoakStatus = "ready"
		default:
			p.SoakStatus = "soaking"
		}
		return
	}
	if p.PromotedAt != nil {
		p.SoakStatus = "promoted"
		return
	}
	p.SoakStatus = "stable"
}

// PromoteDue moves packages whose soak has elapsed. Each package moves at most once per call per rule evaluation.
func (s *Store) PromoteDue(ctx context.Context) (int, error) {
	rules, err := s.ListPromotionRules(ctx)
	if err != nil {
		return 0, err
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].CreatedAt.Before(rules[j].CreatedAt) })
	now := s.now()
	n := 0
	for _, rule := range rules {
		if !rule.Enabled || rule.ManualHold {
			continue
		}
		d, ok := munki.SoakDuration(rule.SoakDays)
		if !ok {
			continue
		}
		deadline := now.Add(-d)
		rows, err := s.pool.Query(ctx, `SELECT id FROM packages WHERE catalog=$1 AND soak_started_at <= $2`, rule.FromCatalog, deadline)
		if err != nil {
			return n, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return n, err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return n, err
		}
		for _, id := range ids {
			moved, err := s.movePackage(ctx, model.System, id, rule.FromCatalog, rule.ToCatalog, "promote")
			if err != nil {
				return n, err
			}
			if moved {
				n++
			}
		}
	}
	if n > 0 {
		if err := s.RegenerateCatalogs(ctx); err != nil {
			return n, err
		}
	}
	return n, nil
}

// PromotePackage forces a package along the matching rule, including through a manual hold.
func (s *Store) PromotePackage(ctx context.Context, p model.Principal, id string) (model.Package, error) {
	pkg, err := s.GetPackage(ctx, id)
	if err != nil {
		return model.Package{}, err
	}
	rules, err := s.ListPromotionRules(ctx)
	if err != nil {
		return model.Package{}, err
	}
	match := matchingRule(rules, pkg.Catalog)
	if match == nil {
		for _, rule := range rules {
			if rule.ToCatalog == pkg.Catalog {
				return pkg, nil
			}
		}
		return model.Package{}, invalid("no promotion rule matches catalog " + pkg.Catalog)
	}
	if _, err := s.movePackage(ctx, p, id, pkg.Catalog, match.ToCatalog, "promote_manual"); err != nil {
		return model.Package{}, err
	}
	if err := s.RegenerateCatalogs(ctx); err != nil {
		return model.Package{}, err
	}
	return s.GetPackage(ctx, id)
}

func (s *Store) movePackage(ctx context.Context, p model.Principal, id, from, dest, action string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var cur string
	var info []byte
	err = tx.QueryRow(ctx, `SELECT catalog, pkginfo FROM packages WHERE id=$1 FOR UPDATE`, id).Scan(&cur, &info)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return false, ErrNotFound
		}
		return false, err
	}
	if cur != from {
		return false, tx.Commit(ctx)
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
		return false, err
	}
	now := s.now()
	tag, err := tx.Exec(ctx, `
		UPDATE packages SET catalog=$2, pkginfo=$3::jsonb, soak_started_at=$4, promoted_at=$4 WHERE id=$1 AND catalog=$5`,
		id, dest, string(raw), now, from)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, tx.Commit(ctx)
	}
	if err := s.audit(ctx, tx, p, action, "package", id, map[string]any{"catalog": dest}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// RegenerateCatalogs rewrites every known catalog plist from current pkginfo.
// testing, production, and all always exist. all contains every item, which is what makecatalogs writes
// and what munkiimport reads. An item is also listed in the catalog named by its row.
func (s *Store) RegenerateCatalogs(ctx context.Context) error {
	names := map[string][][]byte{"testing": nil, "production": nil, "all": nil}
	rrows, err := s.pool.Query(ctx, `SELECT from_catalog, to_catalog FROM promotion_rules`)
	if err != nil {
		return err
	}
	for rrows.Next() {
		var a, b string
		if err := rrows.Scan(&a, &b); err != nil {
			rrows.Close()
			return err
		}
		if _, ok := names[a]; !ok {
			names[a] = nil
		}
		if _, ok := names[b]; !ok {
			names[b] = nil
		}
	}
	rrows.Close()
	if err := rrows.Err(); err != nil {
		return err
	}
	prows, err := s.pool.Query(ctx, `SELECT catalog, pkginfo FROM packages ORDER BY name, version`)
	if err != nil {
		return err
	}
	for prows.Next() {
		var catalog string
		var raw []byte
		if err := prows.Scan(&catalog, &raw); err != nil {
			prows.Close()
			return err
		}
		item, err := munki.ForCatalog(raw, catalog)
		if err != nil {
			prows.Close()
			return err
		}
		names[catalog] = append(names[catalog], item)
		if catalog != "all" {
			names["all"] = append(names["all"], item)
		}
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return err
	}
	now := s.now()
	for name, items := range names {
		body, err := munki.BuildCatalog(items)
		if err != nil {
			return err
		}
		_, err = s.pool.Exec(ctx, `
			INSERT INTO catalogs (name, item_count, generated_at, body) VALUES ($1,$2,$3,$4)
			ON CONFLICT (name) DO UPDATE SET item_count=EXCLUDED.item_count, generated_at=EXCLUDED.generated_at, body=EXCLUDED.body`,
			name, len(items), now, body)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListCatalogs returns generated catalogs and live item counts.
func (s *Store) ListCatalogs(ctx context.Context) ([]model.Catalog, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.name, c.generated_at, (SELECT count(*) FROM packages p WHERE p.catalog=c.name)
		FROM catalogs c ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Catalog{}
	for rows.Next() {
		var c model.Catalog
		if err := rows.Scan(&c.Name, &c.GeneratedAt, &c.ItemCount); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CatalogBody returns the plist for a catalog.
func (s *Store) CatalogBody(ctx context.Context, name string) ([]byte, error) {
	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT body FROM catalogs WHERE name=$1`, name).Scan(&body)
	if err != nil {
		return nil, notFound(err)
	}
	return body, nil
}
