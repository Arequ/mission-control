package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/testutil"
)

func newClock(t *testing.T, s *store.Store) *clock.Manual {
	t.Helper()
	c := &clock.Manual{}
	c.Set(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	s.SetClock(c)
	return c
}

func actor() model.Principal {
	return model.Principal{Kind: "test", ID: "test", Name: "test"}
}

func settings(concurrency, parallel, retries, lease int) model.PipelineSettings {
	return model.PipelineSettings{
		MaxConcurrency:       concurrency,
		PerRunnerParallelism: parallel,
		TimeoutSeconds:       600,
		MaxRetries:           retries,
		LeaseSeconds:         lease,
		ManagedBy:            "test",
	}
}

type fixture struct {
	pool   model.RunnerPool
	recipe model.Recipe
}

func seedRecipe(t *testing.T, s *store.Store, labels []string, withPool bool) fixture {
	t.Helper()
	ctx := context.Background()
	p := actor()
	var pool model.RunnerPool
	var err error
	if withPool {
		pool, err = s.CreateRunnerPool(ctx, p, model.RunnerPool{Name: "mac-minis", Labels: []string{"macos", "autopkg"}, ManagedBy: "terraform"})
		if err != nil {
			t.Fatal(err)
		}
	}
	repo, err := s.CreateRecipeRepo(ctx, p, model.RecipeRepo{Name: "recipes", URL: "https://example.test/recipes.git", Ref: "main", ManagedBy: "terraform"})
	if err != nil {
		t.Fatal(err)
	}
	rec := model.Recipe{
		Identifier: "local.munki.Firefox",
		Name:       "Firefox",
		RepoID:     &repo.ID,
		Enabled:    true,
		Override:   "<plist/>",
		TrustInfo:  []byte(`{}`),
		Labels:     labels,
		ManagedBy:  "terraform",
	}
	if withPool {
		rec.RunnerPoolID = &pool.ID
	}
	rec, err = s.CreateRecipe(ctx, p, rec)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{pool: pool, recipe: rec}
}

func register(t *testing.T, s *store.Store, name, pool string, labels []string) model.Runner {
	t.Helper()
	rn, _, err := s.RegisterRunner(context.Background(), actor(), name, labels, pool, "host", "linux", "fake")
	if err != nil {
		t.Fatal(err)
	}
	return rn
}

func enqueue(t *testing.T, s *store.Store, recipeID string) model.Job {
	t.Helper()
	job, err := s.EnqueueManual(context.Background(), actor(), recipeID)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestFleetConcurrencyAndPerRunnerParallelism(t *testing.T) {
	s := testutil.NewStore(t)
	newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(2, 1, 2, 60)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, []string{"macos", "autopkg"}, true)
	a := register(t, s, "a", fx.pool.Name, []string{"macos", "autopkg"})
	b := register(t, s, "b", fx.pool.Name, []string{"macos", "autopkg"})
	c := register(t, s, "c", fx.pool.Name, []string{"macos", "autopkg"})
	enqueue(t, s, fx.recipe.ID)
	enqueue(t, s, fx.recipe.ID)
	enqueue(t, s, fx.recipe.ID)

	l1, err := s.Lease(ctx, a.ID)
	if err != nil || l1 == nil {
		t.Fatalf("lease a: %v %#v", err, l1)
	}
	l2, err := s.Lease(ctx, b.ID)
	if err != nil || l2 == nil {
		t.Fatalf("lease b: %v %#v", err, l2)
	}
	l3, err := s.Lease(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if l3 != nil {
		t.Fatal("fleet concurrency of 2 allowed a third lease")
	}
	again, err := s.Lease(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again != nil {
		t.Fatal("runner a exceeded per-runner parallelism")
	}
	if _, err := s.CompleteJob(ctx, l1.JobID, a.ID, "no_change", ""); err != nil {
		t.Fatal(err)
	}
	l3, err = s.Lease(ctx, c.ID)
	if err != nil || l3 == nil {
		t.Fatalf("expected the freed slot to be leased: %v %#v", err, l3)
	}
}

func TestLabelAndPoolMatching(t *testing.T) {
	s := testutil.NewStore(t)
	newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(4, 2, 1, 60)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, []string{"macos", "autopkg"}, true)
	enqueue(t, s, fx.recipe.ID)
	wrongLabels := register(t, s, "labels", fx.pool.Name, []string{"macos"})
	if lease, err := s.Lease(ctx, wrongLabels.ID); err != nil || lease != nil {
		t.Fatalf("labels should not match: %v %#v", err, lease)
	}
	otherPool := register(t, s, "pool", "", []string{"macos", "autopkg"})
	if lease, err := s.Lease(ctx, otherPool.ID); err != nil || lease != nil {
		t.Fatalf("pool should not match: %v %#v", err, lease)
	}
	ok := register(t, s, "ok", fx.pool.Name, []string{"autopkg", "macos", "extra"})
	lease, err := s.Lease(ctx, ok.ID)
	if err != nil || lease == nil {
		t.Fatalf("expected match: %v %#v", err, lease)
	}
	if lease.Recipe.Identifier != "local.munki.Firefox" {
		t.Fatal(lease.Recipe.Identifier)
	}
}

func TestDisabledRecipeIsNotLeased(t *testing.T) {
	s := testutil.NewStore(t)
	newClock(t, s)
	ctx := context.Background()
	fx := seedRecipe(t, s, nil, false)
	job := enqueue(t, s, fx.recipe.ID)
	fx.recipe.Enabled = false
	if _, err := s.UpdateRecipe(ctx, actor(), fx.recipe.ID, fx.recipe); err != nil {
		t.Fatal(err)
	}
	rn := register(t, s, "r", "", nil)
	lease, err := s.Lease(ctx, rn.ID)
	if err != nil || lease != nil {
		t.Fatalf("disabled recipe leased: %v %#v", err, lease)
	}
	fx.recipe.Enabled = true
	if _, err := s.UpdateRecipe(ctx, actor(), fx.recipe.ID, fx.recipe); err != nil {
		t.Fatal(err)
	}
	lease, err = s.Lease(ctx, rn.ID)
	if err != nil || lease == nil || lease.JobID != job.ID {
		t.Fatalf("expected re-enabled job: %v %#v", err, lease)
	}
}

func TestLeaseExpiryRetriesThenFails(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(2, 1, 1, 30)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, nil, false)
	job := enqueue(t, s, fx.recipe.ID)
	rn := register(t, s, "r", "", nil)
	lease, err := s.Lease(ctx, rn.ID)
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	if lease.Attempt != 1 {
		t.Fatalf("attempt %d", lease.Attempt)
	}
	clk.Advance(31 * time.Second)
	requeued, failed, err := s.ReclaimExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if requeued != 1 || failed != 0 {
		t.Fatalf("requeued=%d failed=%d", requeued, failed)
	}
	got, err := s.GetJob(ctx, job.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "queued" || got.Attempt != 1 {
		t.Fatalf("after reclaim: %+v", got)
	}
	lease, err = s.Lease(ctx, rn.ID)
	if err != nil || lease == nil || lease.Attempt != 2 {
		t.Fatalf("second lease: %v %#v", err, lease)
	}
	clk.Advance(31 * time.Second)
	requeued, failed, err = s.ReclaimExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if requeued != 0 || failed != 1 {
		t.Fatalf("requeued=%d failed=%d", requeued, failed)
	}
	got, err = s.GetJob(ctx, job.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" || got.Result != "error" {
		t.Fatalf("final job: %+v", got)
	}
}

func TestRunnerErrorRetriesThenFails(t *testing.T) {
	s := testutil.NewStore(t)
	newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(2, 1, 1, 60)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, nil, false)
	job := enqueue(t, s, fx.recipe.ID)
	rn := register(t, s, "r", "", nil)
	lease, err := s.Lease(ctx, rn.ID)
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteJob(ctx, lease.JobID, rn.ID, "error", "autopkg failed"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetJob(ctx, job.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "queued" {
		t.Fatalf("expected requeue, got %+v", got)
	}
	lease, err = s.Lease(ctx, rn.ID)
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteJob(ctx, lease.JobID, rn.ID, "error", "autopkg failed"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetJob(ctx, job.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" || got.Result != "error" {
		t.Fatalf("final %+v", got)
	}
}

func TestEnqueueDueFollowsCron(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	fx := seedRecipe(t, s, nil, false)
	if _, err := s.CreateSchedule(ctx, actor(), model.Schedule{
		Name: "nightly", RecipeID: fx.recipe.ID, Cron: "* * * * *", Enabled: true, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.EnqueueDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("fresh schedule should wait for the next cron instant: n=%d err=%v", n, err)
	}
	clk.Advance(time.Minute)
	n, err = s.EnqueueDue(ctx)
	if err != nil || n != 1 {
		t.Fatalf("expected one job, n=%d err=%v", n, err)
	}
	n, err = s.EnqueueDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("should not stack a second job, n=%d err=%v", n, err)
	}
	jobs, err := s.ListJobs(ctx, fx.recipe.ID, 10)
	if err != nil || len(jobs) != 1 || jobs[0].Trigger != "schedule" {
		t.Fatalf("jobs %#v %v", jobs, err)
	}
}
