package store

import (
	"context"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
)

func scanRepo(row pgx.Row) (model.RecipeRepo, error) {
	var r model.RecipeRepo
	err := row.Scan(&r.ID, &r.Name, &r.URL, &r.Ref, &r.ManagedBy, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

const repoCols = `id, name, url, ref, managed_by, created_at, updated_at`

// CreateRecipeRepo inserts a recipe repository.
func (s *Store) CreateRecipeRepo(ctx context.Context, p model.Principal, in model.RecipeRepo) (model.RecipeRepo, error) {
	if err := checkName("name", in.Name); err != nil {
		return model.RecipeRepo{}, err
	}
	if in.URL == "" {
		return model.RecipeRepo{}, invalid("url is required")
	}
	if in.Ref == "" {
		in.Ref = "main"
	}
	if err := checkRef(in.Ref); err != nil {
		return model.RecipeRepo{}, err
	}
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.RecipeRepo{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO recipe_repos (id, name, url, ref, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		in.ID, in.Name, in.URL, in.Ref, in.ManagedBy, now, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.RecipeRepo{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "recipe_repo", in.ID, in); err != nil {
		_ = tx.Rollback(ctx)
		return model.RecipeRepo{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.RecipeRepo{}, err
	}
	return in, nil
}

// ListRecipeRepos returns every recipe repo.
func (s *Store) ListRecipeRepos(ctx context.Context) ([]model.RecipeRepo, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+repoCols+` FROM recipe_repos ORDER BY name`)
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

// GetRecipeRepo loads one repo.
func (s *Store) GetRecipeRepo(ctx context.Context, id string) (model.RecipeRepo, error) {
	r, err := scanRepo(s.pool.QueryRow(ctx, `SELECT `+repoCols+` FROM recipe_repos WHERE id=$1`, id))
	if err != nil {
		return model.RecipeRepo{}, notFound(err)
	}
	return r, nil
}

// UpdateRecipeRepo replaces a repo.
func (s *Store) UpdateRecipeRepo(ctx context.Context, p model.Principal, id string, in model.RecipeRepo) (model.RecipeRepo, error) {
	cur, err := s.GetRecipeRepo(ctx, id)
	if err != nil {
		return model.RecipeRepo{}, err
	}
	if err := checkName("name", in.Name); err != nil {
		return model.RecipeRepo{}, err
	}
	if in.URL == "" {
		return model.RecipeRepo{}, invalid("url is required")
	}
	if in.Ref == "" {
		in.Ref = "main"
	}
	if err := checkRef(in.Ref); err != nil {
		return model.RecipeRepo{}, err
	}
	now := s.now()
	in.ID = id
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt = cur.CreatedAt
	in.UpdatedAt = now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.RecipeRepo{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE recipe_repos SET name=$2, url=$3, ref=$4, managed_by=$5, updated_at=$6 WHERE id=$1`,
		id, in.Name, in.URL, in.Ref, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.RecipeRepo{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return model.RecipeRepo{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "recipe_repo", id, in); err != nil {
		_ = tx.Rollback(ctx)
		return model.RecipeRepo{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.RecipeRepo{}, err
	}
	return in, nil
}

// DeleteRecipeRepo removes a repo that no recipe references.
func (s *Store) DeleteRecipeRepo(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM recipe_repos WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback(ctx)
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "recipe_repo", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func scanRecipe(row pgx.Row) (model.Recipe, error) {
	var r model.Recipe
	var trust []byte
	err := row.Scan(&r.ID, &r.Identifier, &r.Name, &r.RepoID, &r.Enabled, &r.Override, &trust,
		&r.RunnerPoolID, &r.Labels, &r.ManagedBy, &r.CreatedAt, &r.UpdatedAt)
	if r.Labels == nil {
		r.Labels = []string{}
	}
	if len(trust) == 0 {
		trust = []byte("{}")
	}
	r.TrustInfo = trust
	return r, err
}

const recipeCols = `id, identifier, name, repo_id, enabled, override_content, trust_info, runner_pool_id, labels, managed_by, created_at, updated_at`

func (s *Store) normalizeRecipe(in model.Recipe) (model.Recipe, error) {
	if err := checkName("identifier", in.Identifier); err != nil {
		return model.Recipe{}, err
	}
	if err := checkName("name", in.Name); err != nil {
		return model.Recipe{}, err
	}
	labels, err := validateLabels(in.Labels)
	if err != nil {
		return model.Recipe{}, err
	}
	in.Labels = labels
	trust, err := trustString(in.TrustInfo)
	if err != nil {
		return model.Recipe{}, err
	}
	in.TrustInfo = []byte(trust)
	in.ManagedBy = managedBy(in.ManagedBy)
	if in.RepoID != nil && *in.RepoID == "" {
		in.RepoID = nil
	}
	if in.RunnerPoolID != nil && *in.RunnerPoolID == "" {
		in.RunnerPoolID = nil
	}
	return in, nil
}

// CreateRecipe inserts a recipe override.
func (s *Store) CreateRecipe(ctx context.Context, p model.Principal, in model.Recipe) (model.Recipe, error) {
	var err error
	in, err = s.normalizeRecipe(in)
	if err != nil {
		return model.Recipe{}, err
	}
	now := s.now()
	in.ID = newID()
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Recipe{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO recipes (id, identifier, name, repo_id, enabled, override_content, trust_info, runner_pool_id, labels, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)`,
		in.ID, in.Identifier, in.Name, optUUID(in.RepoID), in.Enabled, in.Override, string(in.TrustInfo),
		optUUID(in.RunnerPoolID), in.Labels, in.ManagedBy, now, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Recipe{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "recipe", in.ID, map[string]any{"identifier": in.Identifier, "name": in.Name}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Recipe{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Recipe{}, err
	}
	return s.GetRecipe(ctx, in.ID)
}

// ListRecipes returns recipes with their latest job.
func (s *Store) ListRecipes(ctx context.Context) ([]model.Recipe, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+recipeCols+` FROM recipes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Recipe{}
	for rows.Next() {
		r, err := scanRecipe(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.attachLastJobs(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) attachLastJobs(ctx context.Context, recipes []model.Recipe) error {
	if len(recipes) == 0 {
		return nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (recipe_id) recipe_id, id, status, result, trigger, finished_at, created_at
		FROM jobs ORDER BY recipe_id, created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	by := map[string]*model.JobSummary{}
	for rows.Next() {
		var recipeID string
		var js model.JobSummary
		if err := rows.Scan(&recipeID, &js.ID, &js.Status, &js.Result, &js.Trigger, &js.FinishedAt, &js.CreatedAt); err != nil {
			return err
		}
		cp := js
		by[recipeID] = &cp
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range recipes {
		recipes[i].LastJob = by[recipes[i].ID]
	}
	return nil
}

// GetRecipe loads one recipe and its latest job.
func (s *Store) GetRecipe(ctx context.Context, id string) (model.Recipe, error) {
	r, err := scanRecipe(s.pool.QueryRow(ctx, `SELECT `+recipeCols+` FROM recipes WHERE id=$1`, id))
	if err != nil {
		return model.Recipe{}, notFound(err)
	}
	one := []model.Recipe{r}
	if err := s.attachLastJobs(ctx, one); err != nil {
		return model.Recipe{}, err
	}
	return one[0], nil
}

// UpdateRecipe replaces a recipe.
func (s *Store) UpdateRecipe(ctx context.Context, p model.Principal, id string, in model.Recipe) (model.Recipe, error) {
	if _, err := s.GetRecipe(ctx, id); err != nil {
		return model.Recipe{}, err
	}
	var err error
	in, err = s.normalizeRecipe(in)
	if err != nil {
		return model.Recipe{}, err
	}
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Recipe{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE recipes SET identifier=$2, name=$3, repo_id=$4, enabled=$5, override_content=$6,
			trust_info=$7::jsonb, runner_pool_id=$8, labels=$9, managed_by=$10, updated_at=$11
		WHERE id=$1`,
		id, in.Identifier, in.Name, optUUID(in.RepoID), in.Enabled, in.Override, string(in.TrustInfo),
		optUUID(in.RunnerPoolID), in.Labels, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Recipe{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return model.Recipe{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "recipe", id, map[string]any{"identifier": in.Identifier}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Recipe{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Recipe{}, err
	}
	return s.GetRecipe(ctx, id)
}

// DeleteRecipe removes a recipe and its schedules and jobs.
func (s *Store) DeleteRecipe(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM recipes WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback(ctx)
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "recipe", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func scanSchedule(row pgx.Row) (model.Schedule, error) {
	var sc model.Schedule
	err := row.Scan(&sc.ID, &sc.Name, &sc.RecipeID, &sc.RecipeIdentifier, &sc.Cron, &sc.Enabled,
		&sc.ManagedBy, &sc.LastEnqueuedAt, &sc.CreatedAt, &sc.UpdatedAt)
	return sc, err
}

const scheduleCols = `s.id, s.name, s.recipe_id, r.identifier, s.cron, s.enabled, s.managed_by, s.last_enqueued_at, s.created_at, s.updated_at`

// CreateSchedule inserts a cron schedule. last_enqueued_at starts at now so the
// first fire is the next cron instant, not an immediate backfill.
func (s *Store) CreateSchedule(ctx context.Context, p model.Principal, in model.Schedule) (model.Schedule, error) {
	if err := checkName("name", in.Name); err != nil {
		return model.Schedule{}, err
	}
	if err := parseCron(in.Cron); err != nil {
		return model.Schedule{}, err
	}
	if in.RecipeID == "" {
		return model.Schedule{}, invalid("recipe_id is required")
	}
	if _, err := s.GetRecipe(ctx, in.RecipeID); err != nil {
		return model.Schedule{}, err
	}
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.Cron = trim(in.Cron)
	last := now
	in.LastEnqueuedAt = &last
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Schedule{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO schedules (id, name, recipe_id, cron, enabled, managed_by, last_enqueued_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)`,
		in.ID, in.Name, in.RecipeID, in.Cron, in.Enabled, in.ManagedBy, now, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Schedule{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "schedule", in.ID, map[string]any{"name": in.Name, "cron": in.Cron, "recipe_id": in.RecipeID}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Schedule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Schedule{}, err
	}
	return s.GetSchedule(ctx, in.ID)
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// ListSchedules returns schedules.
func (s *Store) ListSchedules(ctx context.Context) ([]model.Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleCols+` FROM schedules s JOIN recipes r ON r.id=s.recipe_id ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Schedule{}
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// GetSchedule loads one schedule.
func (s *Store) GetSchedule(ctx context.Context, id string) (model.Schedule, error) {
	sc, err := scanSchedule(s.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM schedules s JOIN recipes r ON r.id=s.recipe_id WHERE s.id=$1`, id))
	if err != nil {
		return model.Schedule{}, notFound(err)
	}
	return sc, nil
}

// UpdateSchedule replaces a schedule. The last enqueue time is preserved.
func (s *Store) UpdateSchedule(ctx context.Context, p model.Principal, id string, in model.Schedule) (model.Schedule, error) {
	if _, err := s.GetSchedule(ctx, id); err != nil {
		return model.Schedule{}, err
	}
	if err := checkName("name", in.Name); err != nil {
		return model.Schedule{}, err
	}
	if err := parseCron(in.Cron); err != nil {
		return model.Schedule{}, err
	}
	if _, err := s.GetRecipe(ctx, in.RecipeID); err != nil {
		return model.Schedule{}, err
	}
	now := s.now()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.Cron = trim(in.Cron)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Schedule{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE schedules SET name=$2, recipe_id=$3, cron=$4, enabled=$5, managed_by=$6, updated_at=$7 WHERE id=$1`,
		id, in.Name, in.RecipeID, in.Cron, in.Enabled, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Schedule{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return model.Schedule{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "schedule", id, map[string]any{"cron": in.Cron, "enabled": in.Enabled}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Schedule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Schedule{}, err
	}
	return s.GetSchedule(ctx, id)
}

// DeleteSchedule removes a schedule.
func (s *Store) DeleteSchedule(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM schedules WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "schedule", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func scanSettings(row pgx.Row) (model.PipelineSettings, error) {
	var p model.PipelineSettings
	err := row.Scan(&p.ID, &p.MaxConcurrency, &p.PerRunnerParallelism, &p.TimeoutSeconds, &p.MaxRetries, &p.LeaseSeconds, &p.ManagedBy, &p.UpdatedAt)
	return p, err
}

// GetPipelineSettings returns the singleton settings row.
func (s *Store) GetPipelineSettings(ctx context.Context) (model.PipelineSettings, error) {
	p, err := scanSettings(s.pool.QueryRow(ctx, `
		SELECT id, max_concurrency, per_runner_parallelism, timeout_seconds, max_retries, lease_seconds, managed_by, updated_at
		FROM pipeline_settings WHERE id='default'`))
	if err != nil {
		return model.PipelineSettings{}, notFound(err)
	}
	return p, nil
}

func validateSettings(in model.PipelineSettings) error {
	if in.MaxConcurrency < 1 {
		return invalid("max_concurrency must be >= 1")
	}
	if in.PerRunnerParallelism < 1 {
		return invalid("per_runner_parallelism must be >= 1")
	}
	if in.TimeoutSeconds < 1 {
		return invalid("timeout_seconds must be >= 1")
	}
	if in.MaxRetries < 0 {
		return invalid("max_retries must be >= 0")
	}
	if in.LeaseSeconds < 5 {
		return invalid("lease_seconds must be >= 5")
	}
	return nil
}

// UpdatePipelineSettings replaces the singleton.
func (s *Store) UpdatePipelineSettings(ctx context.Context, p model.Principal, in model.PipelineSettings) (model.PipelineSettings, error) {
	if err := validateSettings(in); err != nil {
		return model.PipelineSettings{}, err
	}
	in.ID = "default"
	in.ManagedBy = managedBy(in.ManagedBy)
	now := s.now()
	in.UpdatedAt = now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.PipelineSettings{}, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE pipeline_settings SET max_concurrency=$1, per_runner_parallelism=$2, timeout_seconds=$3,
			max_retries=$4, lease_seconds=$5, managed_by=$6, updated_at=$7 WHERE id='default'`,
		in.MaxConcurrency, in.PerRunnerParallelism, in.TimeoutSeconds, in.MaxRetries, in.LeaseSeconds, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.PipelineSettings{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "pipeline_settings", "default", in); err != nil {
		_ = tx.Rollback(ctx)
		return model.PipelineSettings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.PipelineSettings{}, err
	}
	return in, nil
}

// ResetPipelineSettings restores factory defaults. Used when Terraform destroys the singleton.
func (s *Store) ResetPipelineSettings(ctx context.Context, p model.Principal) (model.PipelineSettings, error) {
	return s.UpdatePipelineSettings(ctx, p, model.PipelineSettings{
		MaxConcurrency: 4, PerRunnerParallelism: 1, TimeoutSeconds: 3600,
		MaxRetries: 2, LeaseSeconds: 120, ManagedBy: "system",
	})
}

func scanRule(row pgx.Row) (model.PromotionRule, error) {
	var r model.PromotionRule
	err := row.Scan(&r.ID, &r.Name, &r.FromCatalog, &r.ToCatalog, &r.SoakDays, &r.ManualHold, &r.Enabled, &r.ManagedBy, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

const ruleCols = `id, name, from_catalog, to_catalog, soak_days, manual_hold, enabled, managed_by, created_at, updated_at`

func validateRule(in model.PromotionRule) (model.PromotionRule, error) {
	if err := checkName("name", in.Name); err != nil {
		return model.PromotionRule{}, err
	}
	if err := checkName("from_catalog", in.FromCatalog); err != nil {
		return model.PromotionRule{}, err
	}
	if err := checkName("to_catalog", in.ToCatalog); err != nil {
		return model.PromotionRule{}, err
	}
	if in.FromCatalog == in.ToCatalog {
		return model.PromotionRule{}, invalid("from_catalog and to_catalog must differ")
	}
	if in.SoakDays < 0 {
		return model.PromotionRule{}, invalid("soak_days must be >= 0")
	}
	in.ManagedBy = managedBy(in.ManagedBy)
	return in, nil
}

// CreatePromotionRule inserts a rule.
func (s *Store) CreatePromotionRule(ctx context.Context, p model.Principal, in model.PromotionRule) (model.PromotionRule, error) {
	var err error
	in, err = validateRule(in)
	if err != nil {
		return model.PromotionRule{}, err
	}
	now := s.now()
	in.ID = newID()
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.PromotionRule{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO promotion_rules (id, name, from_catalog, to_catalog, soak_days, manual_hold, enabled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
		in.ID, in.Name, in.FromCatalog, in.ToCatalog, in.SoakDays, in.ManualHold, in.Enabled, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.PromotionRule{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "promotion_rule", in.ID, in); err != nil {
		_ = tx.Rollback(ctx)
		return model.PromotionRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.PromotionRule{}, err
	}
	return in, nil
}

// ListPromotionRules returns rules ordered by name.
func (s *Store) ListPromotionRules(ctx context.Context) ([]model.PromotionRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ruleCols+` FROM promotion_rules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.PromotionRule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetPromotionRule loads one rule.
func (s *Store) GetPromotionRule(ctx context.Context, id string) (model.PromotionRule, error) {
	r, err := scanRule(s.pool.QueryRow(ctx, `SELECT `+ruleCols+` FROM promotion_rules WHERE id=$1`, id))
	if err != nil {
		return model.PromotionRule{}, notFound(err)
	}
	return r, nil
}

// UpdatePromotionRule replaces a rule.
func (s *Store) UpdatePromotionRule(ctx context.Context, p model.Principal, id string, in model.PromotionRule) (model.PromotionRule, error) {
	cur, err := s.GetPromotionRule(ctx, id)
	if err != nil {
		return model.PromotionRule{}, err
	}
	in, err = validateRule(in)
	if err != nil {
		return model.PromotionRule{}, err
	}
	now := s.now()
	in.ID = id
	in.CreatedAt = cur.CreatedAt
	in.UpdatedAt = now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.PromotionRule{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE promotion_rules SET name=$2, from_catalog=$3, to_catalog=$4, soak_days=$5, manual_hold=$6, enabled=$7, managed_by=$8, updated_at=$9
		WHERE id=$1`, id, in.Name, in.FromCatalog, in.ToCatalog, in.SoakDays, in.ManualHold, in.Enabled, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.PromotionRule{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return model.PromotionRule{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "promotion_rule", id, in); err != nil {
		_ = tx.Rollback(ctx)
		return model.PromotionRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.PromotionRule{}, err
	}
	return in, nil
}

// DeletePromotionRule removes a rule.
func (s *Store) DeletePromotionRule(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM promotion_rules WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "promotion_rule", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func scanPool(row pgx.Row) (model.RunnerPool, error) {
	var p model.RunnerPool
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Labels, &p.ManagedBy, &p.CreatedAt, &p.UpdatedAt)
	if p.Labels == nil {
		p.Labels = []string{}
	}
	return p, err
}

const poolCols = `id, name, description, labels, managed_by, created_at, updated_at`

// CreateRunnerPool inserts a pool.
func (s *Store) CreateRunnerPool(ctx context.Context, p model.Principal, in model.RunnerPool) (model.RunnerPool, error) {
	if err := checkName("name", in.Name); err != nil {
		return model.RunnerPool{}, err
	}
	labels, err := validateLabels(in.Labels)
	if err != nil {
		return model.RunnerPool{}, err
	}
	now := s.now()
	in.ID = newID()
	in.Labels = labels
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.RunnerPool{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO runner_pools (id, name, description, labels, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$6)`, in.ID, in.Name, in.Description, in.Labels, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.RunnerPool{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "runner_pool", in.ID, in); err != nil {
		_ = tx.Rollback(ctx)
		return model.RunnerPool{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.RunnerPool{}, err
	}
	return in, nil
}

// ListRunnerPools returns pools.
func (s *Store) ListRunnerPools(ctx context.Context) ([]model.RunnerPool, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+poolCols+` FROM runner_pools ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RunnerPool{}
	for rows.Next() {
		p, err := scanPool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetRunnerPool loads a pool.
func (s *Store) GetRunnerPool(ctx context.Context, id string) (model.RunnerPool, error) {
	p, err := scanPool(s.pool.QueryRow(ctx, `SELECT `+poolCols+` FROM runner_pools WHERE id=$1`, id))
	if err != nil {
		return model.RunnerPool{}, notFound(err)
	}
	return p, nil
}

// GetRunnerPoolByName loads a pool by name.
func (s *Store) GetRunnerPoolByName(ctx context.Context, name string) (model.RunnerPool, error) {
	p, err := scanPool(s.pool.QueryRow(ctx, `SELECT `+poolCols+` FROM runner_pools WHERE name=$1`, name))
	if err != nil {
		return model.RunnerPool{}, notFound(err)
	}
	return p, nil
}

// UpdateRunnerPool replaces a pool.
func (s *Store) UpdateRunnerPool(ctx context.Context, p model.Principal, id string, in model.RunnerPool) (model.RunnerPool, error) {
	cur, err := s.GetRunnerPool(ctx, id)
	if err != nil {
		return model.RunnerPool{}, err
	}
	if err := checkName("name", in.Name); err != nil {
		return model.RunnerPool{}, err
	}
	labels, err := validateLabels(in.Labels)
	if err != nil {
		return model.RunnerPool{}, err
	}
	now := s.now()
	in.ID = id
	in.Labels = labels
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt = cur.CreatedAt
	in.UpdatedAt = now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.RunnerPool{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE runner_pools SET name=$2, description=$3, labels=$4, managed_by=$5, updated_at=$6 WHERE id=$1`,
		id, in.Name, in.Description, in.Labels, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.RunnerPool{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return model.RunnerPool{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "runner_pool", id, in); err != nil {
		_ = tx.Rollback(ctx)
		return model.RunnerPool{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.RunnerPool{}, err
	}
	return in, nil
}

// DeleteRunnerPool removes a pool that no recipe references.
func (s *Store) DeleteRunnerPool(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM runner_pools WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback(ctx)
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "runner_pool", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func scanManifest(row pgx.Row) (model.Manifest, error) {
	var m model.Manifest
	err := row.Scan(&m.ID, &m.Name, &m.Catalogs, &m.IncludedManifests, &m.ManagedInstalls, &m.OptionalInstalls, &m.ManagedUninstalls, &m.ManagedBy, &m.CreatedAt, &m.UpdatedAt)
	m.Catalogs = labelsOrEmpty(m.Catalogs)
	m.IncludedManifests = labelsOrEmpty(m.IncludedManifests)
	m.ManagedInstalls = labelsOrEmpty(m.ManagedInstalls)
	m.OptionalInstalls = labelsOrEmpty(m.OptionalInstalls)
	m.ManagedUninstalls = labelsOrEmpty(m.ManagedUninstalls)
	return m, err
}

const manifestCols = `id, name, catalogs, included_manifests, managed_installs, optional_installs, managed_uninstalls, managed_by, created_at, updated_at`

func validateStringList(field string, in []string) ([]string, error) {
	if in == nil {
		return []string{}, nil
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = trim(v)
		if v == "" {
			continue
		}
		if err := checkName(field, v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// CreateManifest inserts a Munki manifest.
func (s *Store) CreateManifest(ctx context.Context, p model.Principal, in model.Manifest) (model.Manifest, error) {
	var err error
	if err = checkName("name", in.Name); err != nil {
		return model.Manifest{}, err
	}
	if in.Catalogs, err = validateStringList("catalog", in.Catalogs); err != nil {
		return model.Manifest{}, err
	}
	if in.IncludedManifests, err = validateStringList("included_manifest", in.IncludedManifests); err != nil {
		return model.Manifest{}, err
	}
	if in.ManagedInstalls, err = validateStringList("managed_install", in.ManagedInstalls); err != nil {
		return model.Manifest{}, err
	}
	if in.OptionalInstalls, err = validateStringList("optional_install", in.OptionalInstalls); err != nil {
		return model.Manifest{}, err
	}
	if in.ManagedUninstalls, err = validateStringList("managed_uninstall", in.ManagedUninstalls); err != nil {
		return model.Manifest{}, err
	}
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Manifest{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO manifests (id, name, catalogs, included_manifests, managed_installs, optional_installs, managed_uninstalls, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`,
		in.ID, in.Name, in.Catalogs, in.IncludedManifests, in.ManagedInstalls, in.OptionalInstalls, in.ManagedUninstalls, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Manifest{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "manifest", in.ID, map[string]any{"name": in.Name}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Manifest{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Manifest{}, err
	}
	return in, nil
}

// ListManifests returns manifests.
func (s *Store) ListManifests(ctx context.Context) ([]model.Manifest, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+manifestCols+` FROM manifests ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Manifest{}
	for rows.Next() {
		m, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetManifest loads a manifest by id.
func (s *Store) GetManifest(ctx context.Context, id string) (model.Manifest, error) {
	m, err := scanManifest(s.pool.QueryRow(ctx, `SELECT `+manifestCols+` FROM manifests WHERE id=$1`, id))
	if err != nil {
		return model.Manifest{}, notFound(err)
	}
	return m, nil
}

// GetManifestByName loads a manifest by its Munki name.
func (s *Store) GetManifestByName(ctx context.Context, name string) (model.Manifest, error) {
	m, err := scanManifest(s.pool.QueryRow(ctx, `SELECT `+manifestCols+` FROM manifests WHERE name=$1`, name))
	if err != nil {
		return model.Manifest{}, notFound(err)
	}
	return m, nil
}

// UpdateManifest replaces a manifest.
func (s *Store) UpdateManifest(ctx context.Context, p model.Principal, id string, in model.Manifest) (model.Manifest, error) {
	cur, err := s.GetManifest(ctx, id)
	if err != nil {
		return model.Manifest{}, err
	}
	if err = checkName("name", in.Name); err != nil {
		return model.Manifest{}, err
	}
	if in.Catalogs, err = validateStringList("catalog", in.Catalogs); err != nil {
		return model.Manifest{}, err
	}
	if in.IncludedManifests, err = validateStringList("included_manifest", in.IncludedManifests); err != nil {
		return model.Manifest{}, err
	}
	if in.ManagedInstalls, err = validateStringList("managed_install", in.ManagedInstalls); err != nil {
		return model.Manifest{}, err
	}
	if in.OptionalInstalls, err = validateStringList("optional_install", in.OptionalInstalls); err != nil {
		return model.Manifest{}, err
	}
	if in.ManagedUninstalls, err = validateStringList("managed_uninstall", in.ManagedUninstalls); err != nil {
		return model.Manifest{}, err
	}
	now := s.now()
	in.ID = id
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt = cur.CreatedAt
	in.UpdatedAt = now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Manifest{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE manifests SET name=$2, catalogs=$3, included_manifests=$4, managed_installs=$5, optional_installs=$6,
			managed_uninstalls=$7, managed_by=$8, updated_at=$9 WHERE id=$1`,
		id, in.Name, in.Catalogs, in.IncludedManifests, in.ManagedInstalls, in.OptionalInstalls, in.ManagedUninstalls, in.ManagedBy, now)
	if err != nil {
		_ = tx.Rollback(ctx)
		return model.Manifest{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return model.Manifest{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "update", "manifest", id, map[string]any{"name": in.Name}); err != nil {
		_ = tx.Rollback(ctx)
		return model.Manifest{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Manifest{}, err
	}
	return in, nil
}

// DeleteManifest removes a manifest.
func (s *Store) DeleteManifest(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM manifests WHERE id=$1`, id)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if tag.RowsAffected() == 0 {
		_ = tx.Rollback(ctx)
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "manifest", id, nil); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
