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
	"github.com/Arequ/mission-control/internal/vuln"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron/v3"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,200}$`)
var refRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./+\-]{0,200}$`)

// Store talks to Postgres.
type Store struct {
	pool       *pgxpool.Pool
	mu         sync.RWMutex
	clk        clock.Clock
	feeds      vuln.Feeds
	vulnSyncMu sync.Mutex
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

// SetVulnerabilityFeeds enables scheduled feed sync. Tests leave it unset so
// a tick never calls NVD, CISA, FIRST, or Apple.
func (s *Store) SetVulnerabilityFeeds(f vuln.Feeds) {
	s.mu.Lock()
	s.feeds = f
	s.mu.Unlock()
}

func (s *Store) vulnerabilityFeeds() vuln.Feeds {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.feeds
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

func checkRepoURL(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return invalid("url is required")
	}
	if strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \t\r\n") {
		return invalid("invalid repo url")
	}
	switch {
	case strings.HasPrefix(v, "https://"), strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "git://"), strings.HasPrefix(v, "ssh://"):
		return nil
	case strings.HasPrefix(v, "git@") && strings.Contains(v, ":"):
		return nil
	default:
		return invalid("repo url must be https, ssh, or git@host:path")
	}
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

func parseCron(expr, timezone string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return invalid("cron is required")
	}
	loc, err := loadLocation(timezone)
	if err != nil {
		return err
	}
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return invalid("invalid cron: " + err.Error())
	}
	// A schedule that never matches (31 Feb) makes Next return the zero time.
	// Treating that as due would enqueue on every tick.
	if sched.Next(time.Date(2026, 1, 1, 0, 0, 0, 0, loc)).IsZero() {
		return invalid("cron never fires")
	}
	return nil
}

func loadLocation(timezone string) (*time.Location, error) {
	if strings.TrimSpace(timezone) == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, invalid("invalid timezone " + timezone)
	}
	return loc, nil
}

// cronDue reports whether a schedule should enqueue one run at now.
// Missed ticks collapse to a single due window. A civil time that repeats
// on a DST fall-back fires once. A time that does not exist on a spring-forward is skipped.
// A cron that never matches is not due.
func cronDue(expr, timezone string, last *time.Time, now time.Time) (bool, error) {
	if last == nil {
		return false, nil
	}
	loc, err := loadLocation(timezone)
	if err != nil {
		return false, err
	}
	sched, err := cron.ParseStandard(strings.TrimSpace(expr))
	if err != nil {
		return false, err
	}
	next := sched.Next(last.In(loc))
	if next.IsZero() || next.After(now) {
		return false, nil
	}
	// Fall back repeats a civil hour. The later absolute instant has an earlier wall clock
	// than a fire that already happened in the first occurrence, so it is not a new slot.
	if civilStamp(next.In(loc)) <= civilStamp(last.In(loc)) {
		return false, nil
	}
	return true, nil
}

func civilStamp(t time.Time) string {
	return t.Format("2006-01-02 15:04:05.000000000")
}

// ListAudit returns recent audit entries, newest first, plus the total row count.
func (s *Store) ListAudit(ctx context.Context, limit, offset int) ([]model.AuditEntry, int, error) {
	limit, offset = pageWindow(limit, offset)
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, actor, actor_kind, action, resource_type, resource_id, detail
		FROM audit_log ORDER BY id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var e model.AuditEntry
		var detail []byte
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.ActorKind, &e.Action, &e.ResourceType, &e.ResourceID, &detail); err != nil {
			return nil, 0, err
		}
		e.Detail = detail
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func pageWindow(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
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
