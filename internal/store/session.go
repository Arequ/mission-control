package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/sso"
	"github.com/jackc/pgx/v5"
)

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
var groupClaimRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// CreateSSOProvider stores an OIDC provider. The client secret is not returned.
func (s *Store) CreateSSOProvider(ctx context.Context, p model.Principal, in model.SSOProvider) (model.SSOProvider, error) {
	out, secret, err := normalizeProvider(in, true)
	if err != nil {
		return model.SSOProvider{}, err
	}
	now := s.now()
	out.ID = newID()
	out.ManagedBy = managedBy(out.ManagedBy)
	out.CreatedAt, out.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.SSOProvider{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO sso_providers (
			id, name, issuer, client_id, client_secret, allowed_domains, group_claim, enabled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`,
		out.ID, out.Name, out.Issuer, out.ClientID, secret, out.AllowedDomains, out.GroupClaim, out.Enabled, out.ManagedBy, now)
	if err != nil {
		return model.SSOProvider{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "sso_provider", out.ID, map[string]any{"name": out.Name, "issuer": out.Issuer}); err != nil {
		return model.SSOProvider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.SSOProvider{}, err
	}
	out.ClientSecret = ""
	return out, nil
}

const ssoCols = `id, name, issuer, client_id, allowed_domains, group_claim, enabled, managed_by, created_at, updated_at`

func scanSSO(row pgx.Row) (model.SSOProvider, error) {
	var p model.SSOProvider
	err := row.Scan(&p.ID, &p.Name, &p.Issuer, &p.ClientID, &p.AllowedDomains, &p.GroupClaim, &p.Enabled, &p.ManagedBy, &p.CreatedAt, &p.UpdatedAt)
	if p.AllowedDomains == nil {
		p.AllowedDomains = []string{}
	}
	return p, err
}

// ListSSOProviders returns providers without secrets.
func (s *Store) ListSSOProviders(ctx context.Context) ([]model.SSOProvider, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ssoCols+` FROM sso_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SSOProvider{}
	for rows.Next() {
		p, err := scanSSO(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListEnabledSSOProviders is the public sign-in list.
func (s *Store) ListEnabledSSOProviders(ctx context.Context) ([]model.SSOProviderPublic, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, issuer FROM sso_providers WHERE enabled ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SSOProviderPublic{}
	for rows.Next() {
		var p model.SSOProviderPublic
		if err := rows.Scan(&p.ID, &p.Name, &p.Issuer); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetSSOProvider loads one provider without the secret.
func (s *Store) GetSSOProvider(ctx context.Context, id string) (model.SSOProvider, error) {
	p, err := scanSSO(s.pool.QueryRow(ctx, `SELECT `+ssoCols+` FROM sso_providers WHERE id=$1`, id))
	if err != nil {
		return model.SSOProvider{}, notFound(err)
	}
	return p, nil
}

// SSOProviderForLogin loads an enabled provider including the client secret.
// Callers must not write the secret to a response or a log.
func (s *Store) SSOProviderForLogin(ctx context.Context, id string) (model.SSOProvider, error) {
	var p model.SSOProvider
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, issuer, client_id, client_secret, allowed_domains, group_claim, enabled, managed_by, created_at, updated_at
		FROM sso_providers WHERE id=$1 AND enabled`, id).Scan(
		&p.ID, &p.Name, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.AllowedDomains, &p.GroupClaim, &p.Enabled, &p.ManagedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return model.SSOProvider{}, notFound(err)
	}
	if p.AllowedDomains == nil {
		p.AllowedDomains = []string{}
	}
	return p, nil
}

// UpdateSSOProvider edits a provider. An empty client secret keeps the stored value.
func (s *Store) UpdateSSOProvider(ctx context.Context, p model.Principal, id string, in model.SSOProvider) (model.SSOProvider, error) {
	cur, err := s.GetSSOProvider(ctx, id)
	if err != nil {
		return model.SSOProvider{}, err
	}
	out, secret, err := normalizeProvider(in, false)
	if err != nil {
		return model.SSOProvider{}, err
	}
	now := s.now()
	out.ID = cur.ID
	out.ManagedBy = managedBy(out.ManagedBy)
	out.CreatedAt, out.UpdatedAt = cur.CreatedAt, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.SSOProvider{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if secret == "" {
		_, err = tx.Exec(ctx, `
			UPDATE sso_providers SET name=$2, issuer=$3, client_id=$4, allowed_domains=$5, group_claim=$6, enabled=$7, managed_by=$8, updated_at=$9
			WHERE id=$1`,
			id, out.Name, out.Issuer, out.ClientID, out.AllowedDomains, out.GroupClaim, out.Enabled, out.ManagedBy, now)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE sso_providers SET name=$2, issuer=$3, client_id=$4, client_secret=$5, allowed_domains=$6, group_claim=$7, enabled=$8, managed_by=$9, updated_at=$10
			WHERE id=$1`,
			id, out.Name, out.Issuer, out.ClientID, secret, out.AllowedDomains, out.GroupClaim, out.Enabled, out.ManagedBy, now)
	}
	if err != nil {
		return model.SSOProvider{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "sso_provider", id, map[string]any{"name": out.Name, "issuer": out.Issuer, "secret_rotated": secret != ""}); err != nil {
		return model.SSOProvider{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.SSOProvider{}, err
	}
	out.ClientSecret = ""
	return out, nil
}

// DeleteSSOProvider removes a provider, its bindings, and revokes its sessions.
func (s *Store) DeleteSSOProvider(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=$2 WHERE provider_id=$1 AND revoked_at IS NULL`, id, s.now()); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM sso_providers WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "sso_provider", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func normalizeProvider(in model.SSOProvider, creating bool) (model.SSOProvider, string, error) {
	if err := checkName("name", in.Name); err != nil {
		return model.SSOProvider{}, "", err
	}
	issuer, err := sso.NormalizeIssuer(in.Issuer)
	if err != nil {
		return model.SSOProvider{}, "", invalid(err.Error())
	}
	clientID := strings.TrimSpace(in.ClientID)
	if clientID == "" || len(clientID) > 200 || strings.ContainsAny(clientID, " \r\n\x00") {
		return model.SSOProvider{}, "", invalid("client_id is invalid")
	}
	secret := strings.TrimSpace(in.ClientSecret)
	if creating && len(secret) < 8 {
		return model.SSOProvider{}, "", invalid("client_secret must be at least 8 characters")
	}
	if secret != "" && len(secret) < 8 {
		return model.SSOProvider{}, "", invalid("client_secret must be at least 8 characters")
	}
	domains, err := normalizeDomains(in.AllowedDomains)
	if err != nil {
		return model.SSOProvider{}, "", err
	}
	claim := strings.TrimSpace(in.GroupClaim)
	if claim == "" {
		claim = "groups"
	}
	if !groupClaimRE.MatchString(claim) {
		return model.SSOProvider{}, "", invalid("group_claim must be a short claim name")
	}
	in.Issuer = issuer
	in.ClientID = clientID
	in.ClientSecret = ""
	in.AllowedDomains = domains
	in.GroupClaim = claim
	return in, secret, nil
}

func normalizeDomains(in []string) ([]string, error) {
	if len(in) > 50 {
		return nil, invalid("too many allowed domains")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !domainRE.MatchString(d) {
			return nil, invalid("allowed domain is invalid")
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// CreateRoleBinding maps an IdP group to a role.
func (s *Store) CreateRoleBinding(ctx context.Context, p model.Principal, in model.RoleBinding) (model.RoleBinding, error) {
	out, err := s.normalizeBinding(ctx, in)
	if err != nil {
		return model.RoleBinding{}, err
	}
	now := s.now()
	out.ID = newID()
	out.ManagedBy = managedBy(out.ManagedBy)
	out.CreatedAt, out.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.RoleBinding{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO sso_role_bindings (id, provider_id, idp_group, role, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$6)`,
		out.ID, out.ProviderID, out.Group, out.Role, out.ManagedBy, now)
	if err != nil {
		return model.RoleBinding{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "role_binding", out.ID, map[string]any{"provider_id": out.ProviderID, "group": out.Group, "role": out.Role}); err != nil {
		return model.RoleBinding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.RoleBinding{}, err
	}
	return out, nil
}

const bindingCols = `id, provider_id, idp_group, role, managed_by, created_at, updated_at`

func scanBinding(row pgx.Row) (model.RoleBinding, error) {
	var b model.RoleBinding
	err := row.Scan(&b.ID, &b.ProviderID, &b.Group, &b.Role, &b.ManagedBy, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

// ListRoleBindings returns every binding.
func (s *Store) ListRoleBindings(ctx context.Context) ([]model.RoleBinding, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+bindingCols+` FROM sso_role_bindings ORDER BY provider_id, idp_group`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RoleBinding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetRoleBinding loads one binding.
func (s *Store) GetRoleBinding(ctx context.Context, id string) (model.RoleBinding, error) {
	b, err := scanBinding(s.pool.QueryRow(ctx, `SELECT `+bindingCols+` FROM sso_role_bindings WHERE id=$1`, id))
	if err != nil {
		return model.RoleBinding{}, notFound(err)
	}
	return b, nil
}

// UpdateRoleBinding changes the group or role.
func (s *Store) UpdateRoleBinding(ctx context.Context, p model.Principal, id string, in model.RoleBinding) (model.RoleBinding, error) {
	cur, err := s.GetRoleBinding(ctx, id)
	if err != nil {
		return model.RoleBinding{}, err
	}
	out, err := s.normalizeBinding(ctx, in)
	if err != nil {
		return model.RoleBinding{}, err
	}
	now := s.now()
	out.ID = cur.ID
	out.ManagedBy = managedBy(out.ManagedBy)
	out.CreatedAt, out.UpdatedAt = cur.CreatedAt, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.RoleBinding{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE sso_role_bindings SET provider_id=$2, idp_group=$3, role=$4, managed_by=$5, updated_at=$6 WHERE id=$1`,
		id, out.ProviderID, out.Group, out.Role, out.ManagedBy, now)
	if err != nil {
		return model.RoleBinding{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return model.RoleBinding{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "role_binding", id, map[string]any{"group": out.Group, "role": out.Role}); err != nil {
		return model.RoleBinding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.RoleBinding{}, err
	}
	return out, nil
}

// DeleteRoleBinding removes a mapping. Existing sessions keep their groups and
// are re-resolved on the next request, so the change applies immediately.
func (s *Store) DeleteRoleBinding(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM sso_role_bindings WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "role_binding", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) normalizeBinding(ctx context.Context, in model.RoleBinding) (model.RoleBinding, error) {
	if _, err := s.GetSSOProvider(ctx, in.ProviderID); err != nil {
		return model.RoleBinding{}, err
	}
	group := strings.TrimSpace(in.Group)
	if group == "" || len(group) > 200 || strings.ContainsAny(group, "\r\n\x00") {
		return model.RoleBinding{}, invalid("group is invalid")
	}
	if !sso.ValidRole(in.Role) {
		return model.RoleBinding{}, invalid("role must be viewer, operator, or admin")
	}
	in.Group = group
	return in, nil
}

// ResolveRole maps snapshotted groups through the provider's current bindings.
func (s *Store) ResolveRole(ctx context.Context, providerID string, groups []string) (string, bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT idp_group, role FROM sso_role_bindings WHERE provider_id=$1`, providerID)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	var bindings []sso.Binding
	for rows.Next() {
		var b sso.Binding
		if err := rows.Scan(&b.Group, &b.Role); err != nil {
			return "", false, err
		}
		bindings = append(bindings, b)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	role, ok := sso.MapRole(groups, bindings)
	return role, ok, nil
}

// LoginState is a one-time OIDC transaction.
type LoginState struct {
	ID         string
	ProviderID string
	Nonce      string
	Verifier   string
	ReturnTo   string
}

// SaveLoginState stores state, nonce, and the PKCE verifier.
func (s *Store) SaveLoginState(ctx context.Context, st LoginState, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = sso.LoginTTL
	}
	now := s.now()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sso_login_states (id, provider_id, nonce, verifier, return_to, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		st.ID, st.ProviderID, st.Nonce, st.Verifier, st.ReturnTo, now.Add(ttl), now)
	return err
}

// ConsumeLoginState deletes a login state and returns it. A second use fails.
func (s *Store) ConsumeLoginState(ctx context.Context, id string) (LoginState, error) {
	if id == "" {
		return LoginState{}, ErrNotFound
	}
	var st LoginState
	var exp time.Time
	err := s.pool.QueryRow(ctx, `
		DELETE FROM sso_login_states WHERE id=$1
		RETURNING id, provider_id, nonce, verifier, return_to, expires_at`, id).Scan(
		&st.ID, &st.ProviderID, &st.Nonce, &st.Verifier, &st.ReturnTo, &exp)
	if err != nil {
		return LoginState{}, notFound(err)
	}
	if !exp.After(s.now()) {
		return LoginState{}, ErrNotFound
	}
	return st, nil
}

// SessionRecord is a server-side session. IDToken is for RP-initiated logout only.
type SessionRecord struct {
	ProviderID string
	Subject    string
	Email      string
	Name       string
	Role       string
	Groups     []string
	CSRF       string
	IDToken    string
	BreakGlass bool
}

// CreateSession inserts a session and returns the raw cookie value.
func (s *Store) CreateSession(ctx context.Context, rec SessionRecord, absolute, idle time.Duration) (raw string, user model.SessionUser, err error) {
	raw, err = randomToken()
	if err != nil {
		return "", model.SessionUser{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", model.SessionUser{}, err
	}
	if absolute <= 0 {
		absolute = 12 * time.Hour
	}
	if idle <= 0 || idle > absolute {
		idle = 30 * time.Minute
	}
	now := s.now()
	role := rec.Role
	if rec.ProviderID != "" {
		resolved, ok, err := s.ResolveRole(ctx, rec.ProviderID, rec.Groups)
		if err != nil {
			return "", model.SessionUser{}, err
		}
		if !ok {
			return "", model.SessionUser{}, invalid("no role binding matches this user")
		}
		role = resolved
	}
	if !sso.ValidRole(role) {
		return "", model.SessionUser{}, invalid("role is invalid")
	}
	if rec.Groups == nil {
		rec.Groups = []string{}
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO sessions (
			id_hash, csrf_token, provider_id, subject, email, display_name, role, groups, id_token,
			created_at, last_seen_at, rotated_at, expires_at, idle_expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$10,$11,$12)`,
		auth.Hash(raw), csrf, rec.ProviderID, rec.Subject, rec.Email, rec.Name, role, rec.Groups, rec.IDToken,
		now, now.Add(absolute), now.Add(idle))
	if err != nil {
		return "", model.SessionUser{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", model.SessionUser{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.audit(ctx, tx, model.Principal{Kind: "session", ID: auth.Hash(raw), Name: rec.Email}, "login", "session", auth.Hash(raw), map[string]any{
		"email": rec.Email, "role": role, "provider_id": rec.ProviderID, "break_glass": rec.BreakGlass,
	}); err != nil {
		return "", model.SessionUser{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", model.SessionUser{}, err
	}
	return raw, model.SessionUser{Email: rec.Email, Name: rec.Name, Role: role, CSRFToken: csrf}, nil
}

// LookupSession loads a session, enforces idle and absolute timeouts, and slides the idle deadline.
func (s *Store) LookupSession(ctx context.Context, raw string, idle time.Duration) (SessionRecord, error) {
	if strings.TrimSpace(raw) == "" {
		return SessionRecord{}, ErrNotFound
	}
	if idle <= 0 {
		idle = 30 * time.Minute
	}
	var rec SessionRecord
	var role string
	var expires, idleExp time.Time
	var revoked *time.Time
	var last time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT provider_id, subject, email, display_name, role, groups, csrf_token, id_token, expires_at, idle_expires_at, revoked_at, last_seen_at
		FROM sessions WHERE id_hash=$1`, auth.Hash(raw)).Scan(
		&rec.ProviderID, &rec.Subject, &rec.Email, &rec.Name, &role, &rec.Groups, &rec.CSRF, &rec.IDToken, &expires, &idleExp, &revoked, &last)
	if err != nil {
		return SessionRecord{}, notFound(err)
	}
	now := s.now()
	if revoked != nil || !expires.After(now) || !idleExp.After(now) {
		return SessionRecord{}, ErrNotFound
	}
	if rec.Groups == nil {
		rec.Groups = []string{}
	}
	rec.BreakGlass = rec.ProviderID == ""
	if rec.BreakGlass {
		rec.Role = role
	} else {
		resolved, ok, err := s.ResolveRole(ctx, rec.ProviderID, rec.Groups)
		if err != nil {
			return SessionRecord{}, err
		}
		if !ok {
			return SessionRecord{}, ErrNotFound
		}
		rec.Role = resolved
	}
	if now.Sub(last) > 30*time.Second {
		nextIdle := now.Add(idle)
		if nextIdle.After(expires) {
			nextIdle = expires
		}
		_, _ = s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=$2, idle_expires_at=$3, role=$4 WHERE id_hash=$1 AND revoked_at IS NULL`,
			auth.Hash(raw), now, nextIdle, rec.Role)
	}
	return rec, nil
}

// RevokeSession marks a session revoked. The raw cookie value is not logged.
func (s *Store) RevokeSession(ctx context.Context, raw string) (SessionRecord, error) {
	rec, err := s.LookupSession(ctx, raw, 24*time.Hour)
	// Lookup enforces idle. Logout of an already-idle session still clears the cookie.
	if err != nil && !isNoRows(err) && err != ErrNotFound {
		return SessionRecord{}, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=$2 WHERE id_hash=$1 AND revoked_at IS NULL`, auth.Hash(raw), s.now())
	if err != nil {
		return SessionRecord{}, err
	}
	if tag.RowsAffected() > 0 {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return rec, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		name := rec.Email
		if name == "" {
			name = "session"
		}
		if err := s.audit(ctx, tx, model.Principal{Kind: "session", Name: name}, "logout", "session", auth.Hash(raw), map[string]any{"email": rec.Email}); err != nil {
			return rec, err
		}
		if err := tx.Commit(ctx); err != nil {
			return rec, err
		}
	}
	return rec, nil
}

// RotateSession revokes the current session and inserts a new one with the same identity.
func (s *Store) RotateSession(ctx context.Context, raw string, absolute, idle time.Duration) (string, model.SessionUser, error) {
	rec, err := s.LookupSession(ctx, raw, idle)
	if err != nil {
		return "", model.SessionUser{}, err
	}
	if _, err := s.pool.Exec(ctx, `UPDATE sessions SET revoked_at=$2 WHERE id_hash=$1 AND revoked_at IS NULL`, auth.Hash(raw), s.now()); err != nil {
		return "", model.SessionUser{}, err
	}
	return s.CreateSession(ctx, rec, absolute, idle)
}

// PurgeSessions deletes expired login states and old sessions.
func (s *Store) PurgeSessions(ctx context.Context) error {
	now := s.now()
	if _, err := s.pool.Exec(ctx, `DELETE FROM sso_login_states WHERE expires_at < $1`, now); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $2)`, now, now.Add(-24*time.Hour))
	return err
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// LoopbackHost reports whether host is localhost or a loopback IP, with an optional port.
func LoopbackHost(host string) bool {
	h := host
	if strings.Contains(h, ":") {
		if name, _, err := net.SplitHostPort(h); err == nil {
			h = name
		}
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
