package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Arequ/mission-control/internal/model"
)

// SeedDemo inserts a local-development catalog when the database has no recipes.
// It is idempotent: a database that already has recipes is left alone.
func (s *Store) SeedDemo(ctx context.Context) error {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM recipes`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return s.seedFleet(ctx)
	}
	p := model.Principal{Kind: "system", ID: "seed", Name: "seed"}
	if _, err := s.UpdatePipelineSettings(ctx, p, model.PipelineSettings{
		MaxConcurrency: 4, PerRunnerParallelism: 2, TimeoutSeconds: 3600,
		MaxRetries: 2, LeaseSeconds: 300, ManagedBy: "terraform",
	}); err != nil {
		return err
	}
	pool, err := s.CreateRunnerPool(ctx, p, model.RunnerPool{
		Name: "mac-minis", Description: "Office Mac minis", Labels: []string{"macos", "autopkg"}, ManagedBy: "terraform",
	})
	if err != nil {
		return err
	}
	repo, err := s.CreateRecipeRepo(ctx, p, model.RecipeRepo{
		Name: "autopkg-recipes", URL: "https://github.com/autopkg/recipes.git", Ref: "master", ManagedBy: "terraform",
	})
	if err != nil {
		return err
	}
	if _, err := s.CreatePromotionRule(ctx, p, model.PromotionRule{
		Name: "testing-to-production", FromCatalog: "testing", ToCatalog: "production",
		SoakDays: 7, Enabled: true, ManagedBy: "terraform",
	}); err != nil {
		return err
	}
	if _, err := s.CreateManifest(ctx, p, model.Manifest{
		Name: "site_default", Catalogs: []string{"production"},
		ManagedInstalls: []string{"VSCode", "Docker"}, ManagedBy: "terraform",
	}); err != nil {
		return err
	}
	if _, err := s.CreateManifest(ctx, p, model.Manifest{
		Name: "testing", Catalogs: []string{"testing", "production"},
		ManagedInstalls: []string{"Chrome", "Firefox", "Zoom", "Slack"}, ManagedBy: "terraform",
	}); err != nil {
		return err
	}

	type spec struct {
		name, cron, tz string
		enabled        bool
	}
	specs := []spec{
		{"Chrome", "15 6 * * *", "UTC", true},
		{"Firefox", "0 7 * * 1-5", "UTC", true},
		{"Zoom", "30 18 * * 1-5", "America/New_York", true},
		{"Slack", "0 */6 * * *", "UTC", true},
		{"VSCode", "0 2 * * 0", "UTC", true},
		{"OnePassword", "45 4 * * *", "UTC", true},
		{"Rectangle", "0 9 * * 1", "UTC", true},
		{"GoogleDrive", "20 12 * * *", "UTC", true},
		{"Edge", "0 3 * * *", "UTC", true},
		{"Spotify", "15 21 * * 5", "UTC", true},
		{"Docker", "0 1 * * *", "UTC", true},
		{"CompanyPortal", "0 5 * * 1", "UTC", false},
	}
	ids := map[string]string{}
	for _, sp := range specs {
		rec, err := s.CreateRecipe(ctx, p, model.Recipe{
			Identifier: "local.munki." + sp.name, Name: sp.name, RepoID: &repo.ID,
			Enabled: sp.enabled, Override: fmt.Sprintf("<plist><dict><key>NAME</key><string>%s</string></dict></plist>", sp.name),
			TrustInfo: []byte(`{}`), RunnerPoolID: &pool.ID, Labels: []string{"macos", "autopkg"}, ManagedBy: "terraform",
		})
		if err != nil {
			return err
		}
		ids[sp.name] = rec.ID
		if _, err := s.CreateSchedule(ctx, p, model.Schedule{
			Name: sp.name + "-schedule", RecipeID: rec.ID, Cron: sp.cron, Timezone: sp.tz, Enabled: true, ManagedBy: "terraform",
		}); err != nil {
			return err
		}
	}

	mini1, _, err := s.RegisterRunner(ctx, p, "mini-1", []string{"macos", "autopkg"}, pool.Name, "mini-1.local", "15.1", "2.7.2")
	if err != nil {
		return err
	}
	mini2, _, err := s.RegisterRunner(ctx, p, "mini-2", []string{"macos", "autopkg"}, pool.Name, "mini-2.local", "14.6", "2.7.1")
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	type pkgSpec struct {
		name, version string
		catalog       string
		soakAge       time.Duration
		promotedAge   time.Duration
	}
	pkgs := []pkgSpec{
		{"Chrome", "131.0.6778.139", "testing", 3 * 24 * time.Hour, 0},
		{"Firefox", "132.0.2", "testing", 24 * time.Hour, 0},
		// 6.0.2 is still behind CVE-2024-42439 (fixed in 6.1.0), so the issue's
		// action is to run the Zoom recipe. Chrome and Firefox are already at
		// a version that clears, and their action is a promotion pull request.
		{"Zoom", "6.0.2", "testing", (6*24 + 12) * time.Hour, 0},
		{"Slack", "4.41.96", "testing", 2 * 24 * time.Hour, 0},
		{"OnePassword", "8.10.56", "testing", 4 * 24 * time.Hour, 0},
		{"GoogleDrive", "96.0", "testing", 5 * 24 * time.Hour, 0},
		{"VSCode", "1.95.2", "production", 9 * 24 * time.Hour, 2 * 24 * time.Hour},
		{"Docker", "27.3.1", "production", 16 * 24 * time.Hour, 9 * 24 * time.Hour},
	}
	for _, pk := range pkgs {
		raw, err := json.Marshal(map[string]any{
			"name": pk.name, "version": pk.version, "catalogs": []string{"testing"},
			"installer_item_location": pk.name + "-" + pk.version + ".pkg",
			"installer_item_hash":     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"installer_item_size":     120000,
			"notes":                   "internal import note",
			"_metadata":               map[string]any{"recipe": "local.munki." + pk.name},
		})
		if err != nil {
			return err
		}
		inserted, _, err := s.InsertPackage(ctx, p, model.Package{
			Name: pk.name, Version: pk.version, Filename: pk.name + "-" + pk.version + ".pkg",
			RecipeIdentifier: "local.munki." + pk.name, Pkginfo: raw,
		})
		if err != nil {
			return err
		}
		soakStart := now.Add(-pk.soakAge)
		var promoted *time.Time
		if pk.catalog == "production" {
			t := now.Add(-pk.promotedAge)
			promoted = &t
		}
		if _, err := s.pool.Exec(ctx, `
			UPDATE packages SET catalog=$2, soak_started_at=$3, promoted_at=$4 WHERE id=$1`,
			inserted.ID, pk.catalog, soakStart, promoted); err != nil {
			return err
		}
	}
	if err := s.RegenerateCatalogs(ctx); err != nil {
		return err
	}

	type jobSpec struct {
		recipe, status, result, errMsg string
		runner                         *string
		age                            time.Duration
		attempt                        int
		running                        bool
	}
	mini1ID := mini1.ID
	jobs := []jobSpec{
		{"Slack", "failed", "error", "autopkg run failed", nil, 30 * 24 * time.Hour, 3, false},
		{"Chrome", "succeeded", "new_version", "", nil, 3 * 24 * time.Hour, 1, false},
		{"Firefox", "succeeded", "new_version", "", nil, 24 * time.Hour, 1, false},
		{"Zoom", "succeeded", "new_version", "", nil, (6*24 + 12) * time.Hour, 1, false},
		{"Slack", "succeeded", "new_version", "", nil, 2 * 24 * time.Hour, 1, false},
		{"OnePassword", "succeeded", "new_version", "", nil, 4 * 24 * time.Hour, 1, false},
		{"GoogleDrive", "succeeded", "new_version", "", nil, 5 * 24 * time.Hour, 1, false},
		{"VSCode", "succeeded", "new_version", "", nil, 9 * 24 * time.Hour, 1, false},
		{"Docker", "succeeded", "new_version", "", nil, 16 * 24 * time.Hour, 1, false},
		{"Rectangle", "succeeded", "no_change", "", nil, 6 * time.Hour, 1, false},
		{"Spotify", "failed", "trust_failed", "verify-trust-info failed", nil, 3 * time.Hour, 1, false},
		{"Edge", "queued", "", "", nil, 20 * time.Minute, 0, false},
		{"Docker", "running", "", "", &mini1ID, 8 * time.Minute, 1, true},
	}
	for _, j := range jobs {
		created := now.Add(-j.age)
		var finished *time.Time
		var started *time.Time
		var lease *time.Time
		if j.status == "succeeded" || j.status == "failed" {
			f := created.Add(4 * time.Minute)
			finished = &f
			started = &created
		}
		if j.running {
			started = &created
			exp := now.Add(6 * time.Hour)
			lease = &exp
		}
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO jobs (id, recipe_id, trigger, status, result, attempt, max_attempts, runner_id, lease_expires_at, timeout_seconds, started_at, finished_at, error, created_at, updated_at)
			VALUES ($1,$2,'schedule',$3,$4,$5,3,$6,$7,3600,$8,$9,$10,$11,$11)`,
			newID(), ids[j.recipe], j.status, j.result, j.attempt, j.runner, lease, started, finished, j.errMsg, created); err != nil {
			return err
		}
	}
	if _, err := s.pool.Exec(ctx, `UPDATE runners SET last_heartbeat_at=$2 WHERE id=$1`, mini2.ID, now.Add(-3*time.Hour)); err != nil {
		return err
	}
	return s.seedFleet(ctx)
}
