package store

import (
	"context"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
)

const (
	jobQueued    = "queued"
	jobLeased    = "leased"
	jobRunning   = "running"
	jobSucceeded = "succeeded"
	jobFailed    = "failed"
)

const (
	resultNoChange    = "no_change"
	resultNewVersion  = "new_version"
	resultTrustFailed = "trust_failed"
	resultError       = "error"
)

func scanJob(row pgx.Row) (model.Job, error) {
	var j model.Job
	err := row.Scan(
		&j.ID, &j.RecipeID, &j.RecipeIdentifier, &j.RecipeName, &j.ScheduleID, &j.Trigger,
		&j.Status, &j.Result, &j.Attempt, &j.MaxAttempts, &j.RunnerID, &j.RunnerName,
		&j.LeaseExpiresAt, &j.TimeoutSeconds, &j.StartedAt, &j.FinishedAt, &j.Error,
		&j.CreatedAt, &j.UpdatedAt,
	)
	return j, err
}

const jobCols = `j.id, j.recipe_id, r.identifier, r.name, j.schedule_id, j.trigger, j.status, j.result,
	j.attempt, j.max_attempts, j.runner_id, COALESCE(rn.name, ''), j.lease_expires_at, j.timeout_seconds,
	j.started_at, j.finished_at, j.error, j.created_at, j.updated_at`

const jobFrom = `FROM jobs j
	JOIN recipes r ON r.id = j.recipe_id
	LEFT JOIN runners rn ON rn.id = j.runner_id`

// EnqueueManual queues an on-demand run.
func (s *Store) EnqueueManual(ctx context.Context, p model.Principal, recipeID string) (model.Job, error) {
	rec, err := s.GetRecipe(ctx, recipeID)
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
	job, err := s.insertJob(ctx, tx, p, recipeID, nil, "manual")
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Job{}, err
	}
	return s.GetJob(ctx, job.ID, false)
}

func (s *Store) insertJob(ctx context.Context, tx pgx.Tx, p model.Principal, recipeID string, scheduleID *string, trigger string) (model.Job, error) {
	settings, err := scanSettings(tx.QueryRow(ctx, `
		SELECT id, max_concurrency, per_runner_parallelism, timeout_seconds, max_retries, lease_seconds, managed_by, updated_at
		FROM pipeline_settings WHERE id='default'`))
	if err != nil {
		return model.Job{}, err
	}
	now := s.now()
	job := model.Job{
		ID:             newID(),
		RecipeID:       recipeID,
		ScheduleID:     scheduleID,
		Trigger:        trigger,
		Status:         jobQueued,
		Attempt:        0,
		MaxAttempts:    settings.MaxRetries + 1,
		TimeoutSeconds: settings.TimeoutSeconds,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO jobs (id, recipe_id, schedule_id, trigger, status, attempt, max_attempts, timeout_seconds, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,0,$6,$7,$8,$8)`,
		job.ID, job.RecipeID, optUUID(scheduleID), trigger, jobQueued, job.MaxAttempts, job.TimeoutSeconds, now)
	if err != nil {
		return model.Job{}, err
	}
	if err := s.audit(ctx, tx, p, "create", "job", job.ID, map[string]any{"recipe_id": recipeID, "trigger": trigger}); err != nil {
		return model.Job{}, err
	}
	return job, nil
}

// EnqueueDue creates a job for every schedule whose cron has fired since the last enqueue.
// A recipe that already has a queued or in-flight scheduled job is skipped so missed windows collapse into one run.
func (s *Store) EnqueueDue(ctx context.Context) (int, error) {
	now := s.now()
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.recipe_id, s.cron, s.last_enqueued_at
		FROM schedules s
		JOIN recipes r ON r.id = s.recipe_id
		WHERE s.enabled AND r.enabled`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type due struct {
		id, recipe, cron string
	}
	var dues []due
	for rows.Next() {
		var id, recipe, expr string
		var last *time.Time
		if err := rows.Scan(&id, &recipe, &expr, &last); err != nil {
			return 0, err
		}
		ok, err := cronDue(expr, last, now)
		if err != nil {
			continue
		}
		if ok {
			dues = append(dues, due{id, recipe, expr})
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, d := range dues {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return n, err
		}
		var active int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM jobs
			WHERE recipe_id=$1 AND trigger='schedule' AND status IN ('queued','leased','running')`, d.recipe).Scan(&active); err != nil {
			_ = tx.Rollback(ctx)
			return n, err
		}
		if active == 0 {
			if _, err := s.insertJob(ctx, tx, model.System, d.recipe, &d.id, "schedule"); err != nil {
				_ = tx.Rollback(ctx)
				return n, err
			}
			n++
		}
		if _, err := tx.Exec(ctx, `UPDATE schedules SET last_enqueued_at=$2, updated_at=$2 WHERE id=$1`, d.id, now); err != nil {
			_ = tx.Rollback(ctx)
			return n, err
		}
		if err := tx.Commit(ctx); err != nil {
			return n, err
		}
	}
	return n, nil
}

// ReclaimExpired requeues leased jobs whose lease has lapsed, or fails them when retries are exhausted.
func (s *Store) ReclaimExpired(ctx context.Context) (requeued, failed int, err error) {
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, attempt, max_attempts FROM jobs
		WHERE status IN ('leased','running') AND lease_expires_at IS NOT NULL AND lease_expires_at < $1
		FOR UPDATE`, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return 0, 0, err
	}
	type item struct {
		id           string
		attempt, max int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.attempt, &it.max); err != nil {
			rows.Close()
			_ = tx.Rollback(ctx)
			return 0, 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		_ = tx.Rollback(ctx)
		return 0, 0, err
	}
	for _, it := range items {
		if it.attempt >= it.max {
			_, err = tx.Exec(ctx, `
				UPDATE jobs SET status=$2, result=$3, error=$4, finished_at=$5, updated_at=$5, lease_expires_at=NULL
				WHERE id=$1`, it.id, jobFailed, resultError, "lease expired", now)
			if err != nil {
				_ = tx.Rollback(ctx)
				return 0, 0, err
			}
			if err := s.audit(ctx, tx, model.System, "fail", "job", it.id, map[string]any{"reason": "lease expired"}); err != nil {
				_ = tx.Rollback(ctx)
				return 0, 0, err
			}
			failed++
			continue
		}
		_, err = tx.Exec(ctx, `
			UPDATE jobs SET status=$2, runner_id=NULL, lease_expires_at=NULL, updated_at=$3 WHERE id=$1`,
			it.id, jobQueued, now)
		if err != nil {
			_ = tx.Rollback(ctx)
			return 0, 0, err
		}
		if err := s.audit(ctx, tx, model.System, "requeue", "job", it.id, map[string]any{"reason": "lease expired", "attempt": it.attempt}); err != nil {
			_ = tx.Rollback(ctx)
			return 0, 0, err
		}
		requeued++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return requeued, failed, nil
}

// Lease assigns the oldest eligible queued job to a runner, respecting fleet and per-runner limits.
// A nil lease means nothing is available right now.
func (s *Store) Lease(ctx context.Context, runnerID string) (*model.Lease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	settings, err := scanSettings(tx.QueryRow(ctx, `
		SELECT id, max_concurrency, per_runner_parallelism, timeout_seconds, max_retries, lease_seconds, managed_by, updated_at
		FROM pipeline_settings WHERE id='default' FOR UPDATE`))
	if err != nil {
		return nil, err
	}
	var inflight int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE status IN ('leased','running')`).Scan(&inflight); err != nil {
		return nil, err
	}
	if inflight >= settings.MaxConcurrency {
		return nil, tx.Commit(ctx)
	}
	var poolID *string
	var labels []string
	err = tx.QueryRow(ctx, `SELECT pool_id, labels FROM runners WHERE id=$1`, runnerID).Scan(&poolID, &labels)
	if err != nil {
		return nil, notFound(err)
	}
	if labels == nil {
		labels = []string{}
	}
	var mine int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE runner_id=$1 AND status IN ('leased','running')`, runnerID).Scan(&mine); err != nil {
		return nil, err
	}
	if mine >= settings.PerRunnerParallelism {
		return nil, tx.Commit(ctx)
	}
	var jobID string
	err = tx.QueryRow(ctx, `
		SELECT j.id
		FROM jobs j
		JOIN recipes r ON r.id = j.recipe_id
		WHERE j.status = 'queued' AND r.enabled
		  AND (r.runner_pool_id IS NULL OR r.runner_pool_id = $1)
		  AND r.labels <@ $2
		ORDER BY j.created_at
		FOR UPDATE OF j SKIP LOCKED
		LIMIT 1`, poolID, labels).Scan(&jobID)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return nil, tx.Commit(ctx)
		}
		return nil, err
	}
	now := s.now()
	exp := now.Add(time.Duration(settings.LeaseSeconds) * time.Second)
	var attempt int
	if err := tx.QueryRow(ctx, `
		UPDATE jobs SET status=$2, runner_id=$3, lease_expires_at=$4, attempt=attempt+1,
			started_at=COALESCE(started_at, $5), updated_at=$5, timeout_seconds=$6
		WHERE id=$1 RETURNING attempt`,
		jobID, jobLeased, runnerID, exp, now, settings.TimeoutSeconds).Scan(&attempt); err != nil {
		return nil, err
	}
	rec, err := scanRecipe(tx.QueryRow(ctx, `SELECT `+recipeCols+` FROM recipes WHERE id=(SELECT recipe_id FROM jobs WHERE id=$1)`, jobID))
	if err != nil {
		return nil, err
	}
	repos, err := s.listReposTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, tx, model.Principal{Kind: "runner", ID: runnerID, Name: runnerID}, "lease", "job", jobID, map[string]any{"attempt": attempt}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &model.Lease{
		JobID:          jobID,
		Attempt:        attempt,
		LeaseExpiresAt: exp,
		LeaseSeconds:   settings.LeaseSeconds,
		TimeoutSeconds: settings.TimeoutSeconds,
		Recipe: model.LeaseRecipe{
			ID: rec.ID, Identifier: rec.Identifier, Name: rec.Name,
			Override: rec.Override, TrustInfo: rec.TrustInfo,
		},
		Repos: repos,
	}, nil
}

func (s *Store) listReposTx(ctx context.Context, tx pgx.Tx) ([]model.RecipeRepo, error) {
	rows, err := tx.Query(ctx, `SELECT `+repoCols+` FROM recipe_repos ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RecipeRepo{}
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RenewLease extends a lease the runner still owns and marks the job running.
func (s *Store) RenewLease(ctx context.Context, jobID, runnerID string) (time.Time, error) {
	settings, err := s.GetPipelineSettings(ctx)
	if err != nil {
		return time.Time{}, err
	}
	now := s.now()
	exp := now.Add(time.Duration(settings.LeaseSeconds) * time.Second)
	tag, err := s.pool.Exec(ctx, `
		UPDATE jobs SET lease_expires_at=$3, status=$4, updated_at=$5
		WHERE id=$1 AND runner_id=$2 AND status IN ('leased','running')`,
		jobID, runnerID, exp, jobRunning, now)
	if err != nil {
		return time.Time{}, err
	}
	if tag.RowsAffected() == 0 {
		return time.Time{}, ErrForbidden
	}
	return exp, nil
}

// AppendLogs stores runner output and moves the job to running.
func (s *Store) AppendLogs(ctx context.Context, jobID, runnerID string, lines []model.LogLine) error {
	if len(lines) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	var ok bool
	err = tx.QueryRow(ctx, `
		SELECT true FROM jobs WHERE id=$1 AND runner_id=$2 AND status IN ('leased','running')`, jobID, runnerID).Scan(&ok)
	if err != nil {
		_ = tx.Rollback(ctx)
		if notFound(err) == ErrNotFound {
			return ErrForbidden
		}
		return err
	}
	now := s.now()
	for _, ln := range lines {
		stream := ln.Stream
		if stream == "" {
			stream = "stdout"
		}
		if stream != "stdout" && stream != "stderr" {
			_ = tx.Rollback(ctx)
			return invalid("stream must be stdout or stderr")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO job_logs (job_id, stream, line, at) VALUES ($1,$2,$3,$4)`, jobID, stream, ln.Line, now); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, updated_at=$3 WHERE id=$1 AND status='leased'`, jobID, jobRunning, now); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// CompleteJob records the runner's result. Retryable errors go back on the queue until max attempts.
func (s *Store) CompleteJob(ctx context.Context, jobID, runnerID, result, errMsg string) (model.Job, error) {
	switch result {
	case resultNoChange, resultNewVersion, resultTrustFailed, resultError:
	default:
		return model.Job{}, invalid("result must be no_change, new_version, trust_failed, or error")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Job{}, err
	}
	var status string
	var attempt, max int
	err = tx.QueryRow(ctx, `
		SELECT status, attempt, max_attempts FROM jobs WHERE id=$1 AND runner_id=$2 FOR UPDATE`, jobID, runnerID).
		Scan(&status, &attempt, &max)
	if err != nil {
		_ = tx.Rollback(ctx)
		if notFound(err) == ErrNotFound {
			return model.Job{}, ErrForbidden
		}
		return model.Job{}, err
	}
	if status != jobLeased && status != jobRunning {
		_ = tx.Rollback(ctx)
		return model.Job{}, invalid("job is not active")
	}
	now := s.now()
	newStatus := jobSucceeded
	requeue := false
	switch result {
	case resultTrustFailed:
		newStatus = jobFailed
	case resultError:
		if attempt < max {
			requeue = true
			newStatus = jobQueued
		} else {
			newStatus = jobFailed
		}
	}
	if requeue {
		_, err = tx.Exec(ctx, `
			UPDATE jobs SET status=$2, result='', error=$3, runner_id=NULL, lease_expires_at=NULL, updated_at=$4
			WHERE id=$1`, jobID, jobQueued, errMsg, now)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE jobs SET status=$2, result=$3, error=$4, finished_at=$5, updated_at=$5, lease_expires_at=NULL
			WHERE id=$1`, jobID, newStatus, result, errMsg, now)
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Job{}, err
	}
	if err := s.audit(ctx, tx, model.Principal{Kind: "runner", ID: runnerID, Name: runnerID}, "complete", "job", jobID, map[string]any{"result": result, "requeued": requeue, "error": errMsg}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Job{}, err
	}
	return s.GetJob(ctx, jobID, false)
}

// GetJob loads a job. includeLogs attaches the log tail.
func (s *Store) GetJob(ctx context.Context, id string, includeLogs bool) (model.Job, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, `SELECT `+jobCols+` `+jobFrom+` WHERE j.id=$1`, id))
	if err != nil {
		return model.Job{}, notFound(err)
	}
	if includeLogs {
		logs, err := s.jobLogs(ctx, id)
		if err != nil {
			return model.Job{}, err
		}
		j.Logs = logs
	}
	return j, nil
}

func (s *Store) jobLogs(ctx context.Context, id string) ([]model.LogLine, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, stream, line, at FROM job_logs WHERE job_id=$1 ORDER BY id LIMIT 10000`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.LogLine{}
	for rows.Next() {
		var ln model.LogLine
		if err := rows.Scan(&ln.ID, &ln.Stream, &ln.Line, &ln.At); err != nil {
			return nil, err
		}
		out = append(out, ln)
	}
	return out, rows.Err()
}

// ListJobs returns recent jobs, optionally filtered by recipe.
func (s *Store) ListJobs(ctx context.Context, recipeID string, limit int) ([]model.Job, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + jobCols + ` ` + jobFrom
	args := []any{}
	if recipeID != "" {
		q += ` WHERE j.recipe_id=$1`
		args = append(args, recipeID)
	}
	q += ` ORDER BY j.created_at DESC LIMIT `
	if recipeID != "" {
		q += `$2`
	} else {
		q += `$1`
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// RunnerOwnsJob reports whether the runner currently holds the job.
func (s *Store) RunnerOwnsJob(ctx context.Context, jobID, runnerID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT true FROM jobs WHERE id=$1 AND runner_id=$2 AND status IN ('leased','running')`, jobID, runnerID).Scan(&ok)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
