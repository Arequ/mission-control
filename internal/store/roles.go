package store

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/sso"
	"github.com/jackc/pgx/v5"
)

// Role names are what bindings refer to, so they are short, lowercase, and stable.
var roleNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

const roleCols = `id, name, description, permissions, managed_by, created_at, updated_at`

func scanRole(row pgx.Row) (model.Role, error) {
	var r model.Role
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Permissions, &r.ManagedBy, &r.CreatedAt, &r.UpdatedAt)
	if r.Permissions == nil {
		r.Permissions = []string{}
	}
	return r, err
}

func normalizeRole(in model.Role) (model.Role, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !roleNameRE.MatchString(in.Name) {
		return model.Role{}, invalid("name must be 1–63 lowercase letters, numbers, '_' or '-', starting with a letter")
	}
	if sso.BuiltinRole(in.Name) {
		return model.Role{}, invalid(fmt.Sprintf("%s is a built-in role", in.Name))
	}
	in.Description = strings.TrimSpace(in.Description)
	if len(in.Description) > 500 || strings.ContainsAny(in.Description, "\x00") {
		return model.Role{}, invalid("description is too long")
	}
	seen := map[string]bool{}
	perms := []string{}
	for _, p := range in.Permissions {
		p = strings.TrimSpace(p)
		if err := sso.CheckCustomPermission(p); err != nil {
			return model.Role{}, invalid(err.Error())
		}
		if !seen[p] {
			seen[p] = true
			perms = append(perms, p)
		}
	}
	if len(perms) == 0 {
		return model.Role{}, invalid("permissions are required")
	}
	sort.Strings(perms)
	in.Permissions = perms
	return in, nil
}

// CreateRole stores a custom role.
func (s *Store) CreateRole(ctx context.Context, p model.Principal, in model.Role) (model.Role, error) {
	out, err := normalizeRole(in)
	if err != nil {
		return model.Role{}, err
	}
	now := s.now()
	out.ID = newID()
	out.ManagedBy = managedBy(out.ManagedBy)
	out.CreatedAt, out.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Role{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO roles (id, name, description, permissions, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$6)`,
		out.ID, out.Name, out.Description, out.Permissions, out.ManagedBy, now); err != nil {
		return model.Role{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "role", out.ID, map[string]any{"name": out.Name, "permissions": out.Permissions}); err != nil {
		return model.Role{}, err
	}
	return out, tx.Commit(ctx)
}

// ListRoles returns every custom role by name.
func (s *Store) ListRoles(ctx context.Context) ([]model.Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+roleCols+` FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRole loads one custom role.
func (s *Store) GetRole(ctx context.Context, id string) (model.Role, error) {
	r, err := scanRole(s.pool.QueryRow(ctx, `SELECT `+roleCols+` FROM roles WHERE id=$1`, id))
	if err != nil {
		return model.Role{}, notFound(err)
	}
	return r, nil
}

// UpdateRole changes a role's description and permissions. The name is fixed:
// bindings refer to it, so a rename is a replace.
func (s *Store) UpdateRole(ctx context.Context, p model.Principal, id string, in model.Role) (model.Role, error) {
	cur, err := s.GetRole(ctx, id)
	if err != nil {
		return model.Role{}, err
	}
	out, err := normalizeRole(in)
	if err != nil {
		return model.Role{}, err
	}
	if out.Name != cur.Name {
		return model.Role{}, invalid("name cannot change; create a new role and move the bindings")
	}
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Role{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE roles SET description=$2, permissions=$3, managed_by=$4, updated_at=$5 WHERE id=$1`,
		id, out.Description, out.Permissions, managedBy(out.ManagedBy), now); err != nil {
		return model.Role{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "role", id, map[string]any{"name": cur.Name, "from": cur.Permissions, "to": out.Permissions}); err != nil {
		return model.Role{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Role{}, err
	}
	return s.GetRole(ctx, id)
}

// DeleteRole removes a role no binding uses. Deleting one in use would leave
// those groups silently without access, so the bindings must go first.
func (s *Store) DeleteRole(ctx context.Context, p model.Principal, id string) error {
	cur, err := s.GetRole(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var used int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sso_role_bindings WHERE role=$1`, cur.Name).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("%w: role %s is used by %d binding(s)", ErrConflict, cur.Name, used)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM roles WHERE id=$1`, id); err != nil {
		return err
	}
	if err := s.audit(ctx, tx, p, "delete", "role", id, map[string]any{"name": cur.Name}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// roleExists reports whether name is built in or a stored custom role.
func (s *Store) roleExists(ctx context.Context, name string) (bool, error) {
	if sso.BuiltinRole(name) {
		return true, nil
	}
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE name=$1`, name).Scan(&n)
	return n > 0, err
}

// customRoles loads every custom role's permissions by name.
func (s *Store) customRoles(ctx context.Context) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, permissions FROM roles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var name string
		var perms []string
		if err := rows.Scan(&name, &perms); err != nil {
			return nil, err
		}
		out[name] = perms
	}
	return out, rows.Err()
}
