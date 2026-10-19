package store

import (
	"context"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
)

// EnsureAPIToken creates or rotates a named API token.
func (s *Store) EnsureAPIToken(ctx context.Context, name, raw string, scopes []string) error {
	if name == "" || raw == "" {
		return invalid("token name and value are required")
	}
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO api_tokens (id, name, token_hash, scopes, created_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (name) DO UPDATE
		SET token_hash = EXCLUDED.token_hash, scopes = EXCLUDED.scopes, revoked_at = NULL`,
		newID(), name, auth.Hash(raw), scopes, s.now())
	return err
}

// EnsureBootstrapToken creates or rotates a named runner bootstrap token.
func (s *Store) EnsureBootstrapToken(ctx context.Context, name, raw string) error {
	if name == "" || raw == "" {
		return invalid("bootstrap token name and value are required")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO bootstrap_tokens (id, name, token_hash, created_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (name) DO UPDATE
		SET token_hash = EXCLUDED.token_hash, revoked_at = NULL`,
		newID(), name, auth.Hash(raw), s.now())
	return err
}

// LookupAPIToken resolves a raw bearer token.
func (s *Store) LookupAPIToken(ctx context.Context, raw string) (model.Principal, error) {
	if raw == "" {
		return model.Principal{}, ErrNotFound
	}
	var id, name string
	var scopes []string
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, scopes FROM api_tokens
		WHERE token_hash=$1 AND revoked_at IS NULL`, auth.Hash(raw)).Scan(&id, &name, &scopes)
	if err != nil {
		return model.Principal{}, notFound(err)
	}
	_, _ = s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at=$2 WHERE id=$1`, id, s.now())
	set := map[string]bool{}
	for _, sc := range scopes {
		set[sc] = true
	}
	return model.Principal{Kind: "api_token", ID: id, Name: name, Scopes: set}, nil
}

// LookupBootstrapToken resolves a bootstrap token.
func (s *Store) LookupBootstrapToken(ctx context.Context, raw string) (model.Principal, error) {
	if raw == "" {
		return model.Principal{}, ErrNotFound
	}
	var id, name string
	var expires, revoked *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, expires_at, revoked_at FROM bootstrap_tokens WHERE token_hash=$1`, auth.Hash(raw)).
		Scan(&id, &name, &expires, &revoked)
	if err != nil {
		return model.Principal{}, notFound(err)
	}
	if revoked != nil {
		return model.Principal{}, ErrNotFound
	}
	if expires != nil && !s.now().Before(*expires) {
		return model.Principal{}, ErrNotFound
	}
	return model.Principal{Kind: "bootstrap", ID: id, Name: name}, nil
}

// CreateAPIToken issues a new token and returns the raw secret once.
func (s *Store) CreateAPIToken(ctx context.Context, p model.Principal, name string, scopes []string) (model.Token, error) {
	if err := checkName("name", name); err != nil {
		return model.Token{}, err
	}
	if len(scopes) == 0 {
		return model.Token{}, invalid("scopes are required")
	}
	raw, err := auth.NewToken("mc_")
	if err != nil {
		return model.Token{}, err
	}
	tok := model.Token{
		ID: newID(), Name: name, Scopes: scopes, CreatedAt: s.now(), Token: raw,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Token{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO api_tokens (id, name, token_hash, scopes, created_at) VALUES ($1,$2,$3,$4,$5)`,
		tok.ID, tok.Name, auth.Hash(raw), scopes, tok.CreatedAt)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Token{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "api_token", tok.ID, map[string]any{"name": name, "scopes": scopes}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Token{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Token{}, err
	}
	return tok, nil
}

// ListAPITokens returns tokens without secrets.
func (s *Store) ListAPITokens(ctx context.Context) ([]model.Token, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, scopes, created_at, last_used_at, revoked_at
		FROM api_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Token{}
	for rows.Next() {
		var t model.Token
		if err := rows.Scan(&t.ID, &t.Name, &t.Scopes, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		if t.Scopes == nil {
			t.Scopes = []string{}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`, id, s.now())
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "api_token", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
