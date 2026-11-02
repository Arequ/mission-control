package store

import (
	"context"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
)

func scanRunner(row pgx.Row, offlineAfter time.Duration, now time.Time) (model.Runner, error) {
	var r model.Runner
	err := row.Scan(&r.ID, &r.Name, &r.PoolID, &r.PoolName, &r.Labels, &r.Hostname, &r.OSVersion, &r.AutopkgVersion, &r.LastHeartbeatAt, &r.RegisteredAt, &r.ActiveJobs)
	if r.Labels == nil {
		r.Labels = []string{}
	}
	r.Status = "offline"
	if r.LastHeartbeatAt != nil && now.Sub(r.LastHeartbeatAt.UTC()) <= offlineAfter {
		r.Status = "online"
	}
	return r, err
}

const runnerCols = `rn.id, rn.name, rn.pool_id, COALESCE(p.name, ''), rn.labels, rn.hostname, rn.os_version, rn.autopkg_version,
	rn.last_heartbeat_at, rn.registered_at, (SELECT count(*) FROM jobs j WHERE j.runner_id=rn.id AND j.status IN ('leased','running'))`

// RegisterRunner creates a runner and returns a raw token once.
func (s *Store) RegisterRunner(ctx context.Context, p model.Principal, name string, labels []string, poolName, hostname, osVersion, autopkgVersion string) (model.Runner, string, error) {
	if err := checkName("name", name); err != nil {
		return model.Runner{}, "", err
	}
	labs, err := validateLabels(labels)
	if err != nil {
		return model.Runner{}, "", err
	}
	var poolID *string
	if poolName != "" {
		pool, err := s.GetRunnerPoolByName(ctx, poolName)
		if err != nil {
			return model.Runner{}, "", err
		}
		poolID = &pool.ID
	}
	raw, err := auth.NewToken("mcr_")
	if err != nil {
		return model.Runner{}, "", err
	}
	now := s.now()
	id := newID()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Runner{}, "", err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO runners (id, name, pool_id, labels, token_hash, hostname, os_version, autopkg_version, last_heartbeat_at, registered_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
		id, name, optUUID(poolID), labs, auth.Hash(raw), hostname, osVersion, autopkgVersion, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Runner{}, "", mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "register", "runner", id, map[string]any{"name": name, "pool": poolName, "labels": labs}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Runner{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Runner{}, "", err
	}
	rn, err := s.GetRunner(ctx, id, 45*time.Second)
	return rn, raw, err
}

// LookupRunner resolves a runner token.
func (s *Store) LookupRunner(ctx context.Context, raw string) (model.Principal, error) {
	if raw == "" {
		return model.Principal{}, ErrNotFound
	}
	var id, name string
	err := s.pool.QueryRow(ctx, `SELECT id, name FROM runners WHERE token_hash=$1`, auth.Hash(raw)).Scan(&id, &name)
	if err != nil {
		return model.Principal{}, notFound(err)
	}
	return model.Principal{Kind: "runner", ID: id, Name: name}, nil
}

// Heartbeat updates liveness and reported host facts.
func (s *Store) Heartbeat(ctx context.Context, id, hostname, osVersion, autopkgVersion string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE runners SET last_heartbeat_at=$2,
			hostname=CASE WHEN $3 <> '' THEN $3 ELSE hostname END,
			os_version=CASE WHEN $4 <> '' THEN $4 ELSE os_version END,
			autopkg_version=CASE WHEN $5 <> '' THEN $5 ELSE autopkg_version END
		WHERE id=$1`, id, s.now(), hostname, osVersion, autopkgVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListRunners returns runners with online/offline derived from heartbeats.
func (s *Store) ListRunners(ctx context.Context, offlineAfter time.Duration) ([]model.Runner, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+runnerCols+` FROM runners rn LEFT JOIN runner_pools p ON p.id=rn.pool_id ORDER BY rn.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := s.now()
	out := []model.Runner{}
	for rows.Next() {
		r, err := scanRunner(rows, offlineAfter, now)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRunner loads one runner.
func (s *Store) GetRunner(ctx context.Context, id string, offlineAfter time.Duration) (model.Runner, error) {
	r, err := scanRunner(s.pool.QueryRow(ctx, `SELECT `+runnerCols+` FROM runners rn LEFT JOIN runner_pools p ON p.id=rn.pool_id WHERE rn.id=$1`, id), offlineAfter, s.now())
	if err != nil {
		return model.Runner{}, notFound(err)
	}
	return r, nil
}

// DeleteRunner removes a runner. In-flight jobs are requeued by lease expiry.
func (s *Store) DeleteRunner(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM runners WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "runner", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
