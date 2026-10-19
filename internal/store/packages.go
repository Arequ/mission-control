package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/jackc/pgx/v5"
)

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

// InsertPackage records a new pkginfo. A duplicate name+version is not imported again.
func (s *Store) InsertPackage(ctx context.Context, p model.Principal, pkg model.Package) (model.Package, bool, error) {
	if pkg.Name == "" || pkg.Version == "" {
		return model.Package{}, false, invalid("package name and version are required")
	}
	if pkg.Catalog == "" {
		cat, err := s.ImportCatalog(ctx)
		if err != nil {
			return model.Package{}, false, err
		}
		pkg.Catalog = cat
	}
	var existing string
	err := s.pool.QueryRow(ctx, `SELECT id FROM packages WHERE name=$1 AND version=$2`, pkg.Name, pkg.Version).Scan(&existing)
	if err == nil {
		got, gerr := s.GetPackage(ctx, existing)
		return got, false, gerr
	}
	if notFound(err) != ErrNotFound {
		return model.Package{}, false, err
	}
	now := s.now()
	pkg.ID = newID()
	pkg.SoakStartedAt = now
	pkg.CreatedAt = now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Package{}, false, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO packages (id, name, version, catalog, pkginfo, pkg_key, filename, job_id, recipe_identifier, soak_started_at, created_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$10)`,
		pkg.ID, pkg.Name, pkg.Version, pkg.Catalog, string(pkg.Pkginfo), "pkgs/"+pkg.Filename, pkg.Filename, optUUID(pkg.JobID), pkg.RecipeIdentifier, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		mapped := mapWriteErr(err)
		if errors.Is(mapped, ErrConflict) {
			var existing string
			if qerr := s.pool.QueryRow(ctx, `SELECT id FROM packages WHERE name=$1 AND version=$2`, pkg.Name, pkg.Version).Scan(&existing); qerr == nil {
				got, gerr := s.GetPackage(ctx, existing)
				return got, false, gerr
			}
		}
		return model.Package{}, false, mapped
	}
	if err := s.audit(ctx, tx, p, "import", "package", pkg.ID, map[string]any{"name": pkg.Name, "version": pkg.Version, "catalog": pkg.Catalog}); err != nil {
		_ = tx.Rollback(ctx)
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

func annotateSoak(p *model.Package, rules []model.PromotionRule, now time.Time) {
	var match *model.PromotionRule
	for i := range rules {
		if rules[i].Enabled && rules[i].FromCatalog == p.Catalog {
			match = &rules[i]
			break
		}
	}
	if match != nil {
		ends := p.SoakStartedAt.Add(time.Duration(match.SoakDays) * 24 * time.Hour)
		p.SoakEndsAt = &ends
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
	now := s.now()
	n := 0
	for _, rule := range rules {
		if !rule.Enabled || rule.ManualHold {
			continue
		}
		deadline := now.Add(-time.Duration(rule.SoakDays) * 24 * time.Hour)
		rows, err := s.pool.Query(ctx, `SELECT id, pkginfo FROM packages WHERE catalog=$1 AND soak_started_at <= $2`, rule.FromCatalog, deadline)
		if err != nil {
			return n, err
		}
		type item struct {
			id   string
			info []byte
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.info); err != nil {
				rows.Close()
				return n, err
			}
			items = append(items, it)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return n, err
		}
		for _, it := range items {
			if err := s.movePackage(ctx, model.System, it.id, it.info, rule.ToCatalog, "promote"); err != nil {
				return n, err
			}
			n++
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
	var dest string
	for _, rule := range rules {
		if rule.Enabled && rule.FromCatalog == pkg.Catalog {
			dest = rule.ToCatalog
			break
		}
	}
	if dest == "" {
		return model.Package{}, invalid("no promotion rule matches catalog " + pkg.Catalog)
	}
	if err := s.movePackage(ctx, p, id, pkg.Pkginfo, dest, "promote_manual"); err != nil {
		return model.Package{}, err
	}
	if err := s.RegenerateCatalogs(ctx); err != nil {
		return model.Package{}, err
	}
	return s.GetPackage(ctx, id)
}

func (s *Store) movePackage(ctx context.Context, p model.Principal, id string, info []byte, dest, action string) error {
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
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE packages SET catalog=$2, pkginfo=$3::jsonb, soak_started_at=$4, promoted_at=$4 WHERE id=$1`,
		id, dest, string(raw), now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, action, "package", id, map[string]any{"catalog": dest}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// RegenerateCatalogs rewrites every known catalog plist from current pkginfo.
func (s *Store) RegenerateCatalogs(ctx context.Context) error {
	names := map[string]bool{"testing": true, "production": true}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT catalog FROM packages`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
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
		names[a] = true
		names[b] = true
	}
	rrows.Close()
	now := s.now()
	for name := range names {
		prows, err := s.pool.Query(ctx, `SELECT pkginfo FROM packages WHERE catalog=$1 ORDER BY name, version`, name)
		if err != nil {
			return err
		}
		var items [][]byte
		for prows.Next() {
			var b []byte
			if err := prows.Scan(&b); err != nil {
				prows.Close()
				return err
			}
			items = append(items, b)
		}
		prows.Close()
		if err := prows.Err(); err != nil {
			return err
		}
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
