// Package store is the Postgres persistence layer for Mission Control.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/db"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,200}$`)
var refRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./+\-]{0,200}$`)

// Store talks to Postgres.
type Store struct {
	pool *pgxpool.Pool
	mu   sync.RWMutex
	clk  clock.Clock
}

// Open connects, pings, and migrates.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool, clk: clock.System{}}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the connection pool for tests.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// SetClock replaces the time source. Tests use a manual clock.
func (s *Store) SetClock(c clock.Clock) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clk = c
}

func (s *Store) now() time.Time {
	s.mu.RLock()
	c := s.clk
	s.mu.RUnlock()
	if c == nil {
		return time.Now().UTC()
	}
	return c.Now().UTC()
}

// Now returns the store clock, including any test override.
func (s *Store) Now() time.Time { return s.now() }

func (s *Store) audit(ctx context.Context, tx pgx.Tx, p model.Principal, action, resourceType, resourceID string, detail any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	kind := p.Kind
	if kind == "" {
		kind = "api_token"
	}
	name := p.Name
	if name == "" {
		name = p.ID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_log (at, actor, actor_kind, action, resource_type, resource_id, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
		s.now(), name, kind, action, resourceType, resourceID, string(b))
	return err
}

func newID() string { return uuid.NewString() }

func managedBy(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "api"
	}
	return v
}

func checkName(field, v string) error {
	if !nameRE.MatchString(v) {
		return invalid(field + " must be 1–201 characters of letters, numbers, '.', '_', '+', or '-'")
	}
	return nil
}

func checkRef(v string) error {
	if !refRE.MatchString(v) {
		return invalid("ref must be a git branch or tag")
	}
	return nil
}

func optUUID(v *string) any {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(*v)
	if s == "" {
		return nil
	}
	return s
}

func strPtr(v any) *string {
	if v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}

func labelsOrEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, 0, len(in))
	for _, l := range in {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !nameRE.MatchString(l) {
			return []string{"__invalid__" + l}
		}
		out = append(out, l)
	}
	return out
}

func validateLabels(in []string) ([]string, error) {
	if in == nil {
		return []string{}, nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, l := range in {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !nameRE.MatchString(l) {
			return nil, invalid("invalid label " + l)
		}
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out, nil
}

func trustString(raw json.RawMessage) (string, error) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return "{}", nil
	}
	if !json.Valid(raw) {
		return "", invalid("trust_info must be json")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", invalid("trust_info must be json")
	}
	if _, ok := v.(map[string]any); !ok {
		return "", invalid("trust_info must be a json object")
	}
	return string(raw), nil
}

func parseCron(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return invalid("cron is required")
	}
	if _, err := cron.ParseStandard(expr); err != nil {
		return invalid("invalid cron: " + err.Error())
	}
	return nil
}

func cronDue(expr string, last *time.Time, now time.Time) (bool, error) {
	if last == nil {
		return false, nil
	}
	sched, err := cron.ParseStandard(strings.TrimSpace(expr))
	if err != nil {
		return false, err
	}
	next := sched.Next(last.UTC())
	return !next.After(now.UTC()), nil
}

// ListAudit returns recent audit entries, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, actor, actor_kind, action, resource_type, resource_id, detail
		FROM audit_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var e model.AuditEntry
		var detail []byte
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.ActorKind, &e.Action, &e.ResourceType, &e.ResourceID, &detail); err != nil {
			return nil, err
		}
		e.Detail = detail
		out = append(out, e)
	}
	return out, rows.Err()
}

func notFound(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func commit(ctx context.Context, tx pgx.Tx, err error) error {
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
