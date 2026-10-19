package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Postgres) CreateLiveQuery(ctx context.Context, sql, createdBy string, deviceIDs []string) (LiveQuery, error) {
	var created LiveQuery
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		ids := append([]string{}, deviceIDs...)
		if len(ids) == 0 {
			rows, err := tx.Query(ctx, `SELECT id::text FROM devices`)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, id)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		for _, id := range ids {
			var one int
			err := tx.QueryRow(ctx, `SELECT 1 FROM devices WHERE id = $1::uuid`, id).Scan(&one)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
		}
		created = LiveQuery{
			ID:        uuid.NewString(),
			SQL:       sql,
			CreatedBy: createdBy,
			CreatedAt: time.Now().UTC(),
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO distributed_queries (id, sql, created_by, created_at) VALUES ($1::uuid, $2, $3, $4)
		`, created.ID, sql, createdBy, created.CreatedAt); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.Exec(ctx, `
				INSERT INTO distributed_targets (query_id, device_id, status) VALUES ($1::uuid, $2::uuid, 'pending')
			`, created.ID, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return LiveQuery{}, err
	}
	return s.GetLiveQuery(ctx, created.ID)
}

func (s *Postgres) ListLiveQueries(ctx context.Context) ([]LiveQuery, error) {
	rows, err := s.pool.Query(ctx, liveQuerySQL+` GROUP BY q.id ORDER BY q.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LiveQuery
	for rows.Next() {
		q, err := scanLiveQuery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	if out == nil {
		out = []LiveQuery{}
	}
	return out, rows.Err()
}

func (s *Postgres) GetLiveQuery(ctx context.Context, id string) (LiveQuery, error) {
	q, err := scanLiveQuery(s.pool.QueryRow(ctx, liveQuerySQL+` WHERE q.id = $1::uuid GROUP BY q.id`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return LiveQuery{}, ErrNotFound
	}
	return q, err
}

const liveQuerySQL = `
	SELECT q.id::text, q.sql, q.created_by, q.created_at,
		COALESCE(json_agg(json_build_object(
			'deviceId', t.device_id::text,
			'hostname', COALESCE(d.hostname, ''),
			'status', t.status,
			'results', t.results,
			'osqueryStatus', t.osquery_status
		) ORDER BY d.hostname) FILTER (WHERE t.device_id IS NOT NULL), '[]'::json)
	FROM distributed_queries q
	LEFT JOIN distributed_targets t ON t.query_id = q.id
	LEFT JOIN devices d ON d.id = t.device_id
`

func scanLiveQuery(row pgx.Row) (LiveQuery, error) {
	var q LiveQuery
	var targets []byte
	if err := row.Scan(&q.ID, &q.SQL, &q.CreatedBy, &q.CreatedAt, &targets); err != nil {
		return LiveQuery{}, err
	}
	q.CreatedAt = q.CreatedAt.UTC()
	if len(targets) > 0 {
		if err := json.Unmarshal(targets, &q.Targets); err != nil {
			return LiveQuery{}, err
		}
	}
	if q.Targets == nil {
		q.Targets = []LiveTarget{}
	}
	for i := range q.Targets {
		if string(q.Targets[i].Results) == "null" {
			q.Targets[i].Results = nil
		}
	}
	return q, nil
}

func (s *Postgres) PendingQueries(ctx context.Context, deviceID string) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT q.id::text, q.sql
		FROM distributed_targets t
		JOIN distributed_queries q ON q.id = t.query_id
		WHERE t.device_id = $1::uuid AND t.status = 'pending'
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, sql string
		if err := rows.Scan(&id, &sql); err != nil {
			return nil, err
		}
		out[id] = sql
	}
	return out, rows.Err()
}

func (s *Postgres) WriteQueryResults(ctx context.Context, deviceID string, results map[string]json.RawMessage, statuses map[string]int) error {
	ids := map[string]struct{}{}
	for id := range results {
		ids[id] = struct{}{}
	}
	for id := range statuses {
		ids[id] = struct{}{}
	}
	for id := range ids {
		code := statuses[id]
		state := "complete"
		if code != 0 {
			state = "error"
		}
		var raw any
		if r, ok := results[id]; ok && len(r) > 0 {
			raw = string(r)
		}
		if _, err := s.pool.Exec(ctx, `
			UPDATE distributed_targets
			SET status = $3, results = COALESCE($4::jsonb, results), osquery_status = $5, updated_at = now()
			WHERE query_id = $1::uuid AND device_id = $2::uuid
		`, id, deviceID, state, raw, code); err != nil {
			return err
		}
	}
	return nil
}

func (s *Postgres) CreateRunner(ctx context.Context, name string, labels map[string]string) (Runner, error) {
	token, err := auth.NewSecret("mcr_")
	if err != nil {
		return Runner{}, err
	}
	runner := Runner{
		ID:        uuid.NewString(),
		Name:      name,
		Labels:    labels,
		CreatedAt: time.Now().UTC(),
		Token:     token,
	}
	body, err := json.Marshal(emptyStringMap(labels))
	if err != nil {
		return Runner{}, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO runners (id, name, token_hash, labels, created_at) VALUES ($1::uuid, $2, $3, $4::jsonb, $5)
	`, runner.ID, name, auth.Hash(token), string(body), runner.CreatedAt)
	if isUnique(err) {
		return Runner{}, ErrConflict
	}
	if err != nil {
		return Runner{}, err
	}
	return runner, nil
}

func (s *Postgres) AuthenticateRunner(ctx context.Context, token string) (Runner, error) {
	runner, err := scanRunner(s.pool.QueryRow(ctx, `
		SELECT id::text, name, labels, autopkg_version, os_version, last_seen_at, created_at
		FROM runners WHERE token_hash = $1
	`, auth.Hash(token)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Runner{}, ErrUnauthorized
	}
	return runner, err
}

func (s *Postgres) HeartbeatRunner(ctx context.Context, id string, hb RunnerHeartbeat) error {
	labels := hb.Labels
	body, err := json.Marshal(emptyStringMap(labels))
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE runners SET
			last_seen_at = now(),
			autopkg_version = CASE WHEN $2 <> '' THEN $2 ELSE autopkg_version END,
			os_version = CASE WHEN $3 <> '' THEN $3 ELSE os_version END,
			labels = CASE WHEN $4::jsonb <> '{}'::jsonb THEN $4::jsonb ELSE labels END
		WHERE id = $1::uuid
	`, id, hb.AutoPkgVersion, hb.OSVersion, string(body))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Postgres) ListRunners(ctx context.Context) ([]Runner, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, name, labels, autopkg_version, os_version, last_seen_at, created_at
		FROM runners ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Runner
	for rows.Next() {
		r, err := scanRunner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []Runner{}
	}
	return out, rows.Err()
}

func scanRunner(row pgx.Row) (Runner, error) {
	var r Runner
	var labels []byte
	var last *time.Time
	if err := row.Scan(&r.ID, &r.Name, &labels, &r.AutoPkgVersion, &r.OSVersion, &last, &r.CreatedAt); err != nil {
		return Runner{}, err
	}
	if len(labels) > 0 {
		_ = json.Unmarshal(labels, &r.Labels)
	}
	if last != nil {
		t := last.UTC()
		r.LastSeenAt = &t
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}

func (s *Postgres) CreateJob(ctx context.Context, pipeline string, spec map[string]any) (Job, error) {
	if spec == nil {
		spec = map[string]any{}
	}
	body, err := json.Marshal(spec)
	if err != nil {
		return Job{}, err
	}
	job := Job{
		ID:           uuid.NewString(),
		PipelineName: pipeline,
		Status:       "queued",
		Spec:         spec,
		CreatedAt:    time.Now().UTC(),
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO autopkg_jobs (id, pipeline_name, status, spec, created_at)
		VALUES ($1::uuid, $2, 'queued', $3::jsonb, $4)
	`, job.ID, pipeline, string(body), job.CreatedAt)
	return job, err
}

func (s *Postgres) ListJobs(ctx context.Context) ([]Job, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, pipeline_name, status, COALESCE(runner_id::text, ''), spec, logs, result,
			created_at, started_at, finished_at
		FROM autopkg_jobs ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	if out == nil {
		out = []Job{}
	}
	return out, rows.Err()
}

func (s *Postgres) GetJob(ctx context.Context, id string) (Job, error) {
	job, err := scanJob(s.pool.QueryRow(ctx, `
		SELECT id::text, pipeline_name, status, COALESCE(runner_id::text, ''), spec, logs, result,
			created_at, started_at, finished_at
		FROM autopkg_jobs WHERE id = $1::uuid
	`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return job, err
}

func scanJob(row pgx.Row) (Job, error) {
	var job Job
	var spec, result []byte
	var started, finished *time.Time
	if err := row.Scan(&job.ID, &job.PipelineName, &job.Status, &job.RunnerID, &spec, &job.Logs, &result, &job.CreatedAt, &started, &finished); err != nil {
		return Job{}, err
	}
	if len(spec) > 0 {
		_ = json.Unmarshal(spec, &job.Spec)
	}
	if len(result) > 0 && string(result) != "null" {
		_ = json.Unmarshal(result, &job.Result)
	}
	job.CreatedAt = job.CreatedAt.UTC()
	if started != nil {
		t := started.UTC()
		job.StartedAt = &t
	}
	if finished != nil {
		t := finished.UTC()
		job.FinishedAt = &t
	}
	return job, nil
}

func (s *Postgres) ClaimJob(ctx context.Context, runnerID string) (Job, bool, error) {
	var one int
	if err := s.pool.QueryRow(ctx, `SELECT 1 FROM runners WHERE id = $1::uuid`, runnerID).Scan(&one); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, false, ErrNotFound
		}
		return Job{}, false, err
	}
	job, err := scanJob(s.pool.QueryRow(ctx, `
		UPDATE autopkg_jobs SET status = 'running', runner_id = $1::uuid, started_at = now()
		WHERE id = (
			SELECT id FROM autopkg_jobs
			WHERE status = 'queued'
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id::text, pipeline_name, status, COALESCE(runner_id::text, ''), spec, logs, result,
			created_at, started_at, finished_at
	`, runnerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, err
	}
	return job, true, nil
}

func (s *Postgres) AppendJobLog(ctx context.Context, id, runnerID, chunk string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE autopkg_jobs SET logs = logs || $3
		WHERE id = $1::uuid AND runner_id = $2::uuid AND status = 'running'
	`, id, runnerID, chunk)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalid
	}
	return nil
}

func (s *Postgres) FinishJob(ctx context.Context, id, runnerID, status, logs string, result map[string]any) error {
	if status != "succeeded" && status != "failed" {
		return ErrInvalid
	}
	var resultArg any
	if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			return err
		}
		resultArg = string(b)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE autopkg_jobs SET
			status = $3,
			logs = CASE WHEN $4 <> '' THEN $4 ELSE logs END,
			result = COALESCE($5::jsonb, result),
			finished_at = now()
		WHERE id = $1::uuid AND runner_id = $2::uuid AND status = 'running'
	`, id, runnerID, status, logs, resultArg)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalid
	}
	return nil
}
