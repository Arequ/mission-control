package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestEnqueueDueCollapsesConcurrentReplicas(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	fx := seedRecipe(t, s, nil, false)
	clk.Set(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	if _, err := s.CreateSchedule(ctx, actor(), model.Schedule{
		Name: "every-minute", RecipeID: fx.recipe.ID, Cron: "* * * * *", Enabled: true, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	var wg sync.WaitGroup
	var added atomic.Int32
	var failed atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := s.EnqueueDue(ctx)
			if err != nil {
				failed.Add(1)
				return
			}
			added.Add(int32(n))
		}()
	}
	wg.Wait()
	if failed.Load() != 0 || added.Load() != 1 {
		t.Fatalf("concurrent enqueue added=%d failed=%d", added.Load(), failed.Load())
	}
	jobs, _, err := s.ListJobs(ctx, fx.recipe.ID, 20, 0)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs %#v %v", jobs, err)
	}
}

func TestLeaseHammerEnforcesCaps(t *testing.T) {
	s := testutil.NewStore(t)
	newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(2, 1, 2, 120)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, []string{"macos", "autopkg"}, true)
	for i := 0; i < 20; i++ {
		enqueue(t, s, fx.recipe.ID)
	}
	var ids []string
	for i := 0; i < 6; i++ {
		ids = append(ids, register(t, s, "hammer-"+string(rune('a'+i)), fx.pool.Name, []string{"macos", "autopkg"}).ID)
	}
	var wg sync.WaitGroup
	var failed atomic.Int32
	for _, id := range ids {
		for n := 0; n < 4; n++ {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				if _, err := s.Lease(ctx, id); err != nil {
					failed.Add(1)
				}
			}(id)
		}
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("lease errors: %d", failed.Load())
	}
	jobs, _, err := s.ListJobs(ctx, fx.recipe.ID, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	leased := 0
	per := map[string]int{}
	for _, j := range jobs {
		if j.Status == "leased" || j.Status == "running" {
			leased++
			if j.RunnerID != nil {
				per[*j.RunnerID]++
			}
		}
	}
	if leased != 2 {
		t.Fatalf("fleet cap: leased=%d jobs=%d", leased, len(jobs))
	}
	for id, n := range per {
		if n > 1 {
			t.Fatalf("runner %s holds %d", id, n)
		}
	}
}

func TestStaleAttemptCannotCompleteReassignedJob(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(2, 1, 2, 30)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, nil, false)
	job := enqueue(t, s, fx.recipe.ID)
	rn := register(t, s, "same", "", nil)
	other := register(t, s, "other", "", nil)
	first, err := s.Lease(ctx, rn.ID)
	if err != nil || first == nil || first.Attempt != 1 {
		t.Fatalf("lease %#v %v", first, err)
	}
	if _, err := s.CompleteJob(ctx, first.JobID, other.ID, first.Attempt, "no_change", ""); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("other runner complete: %v", err)
	}
	clk.Advance(time.Minute)
	requeued, failed, err := s.ReclaimExpired(ctx)
	if err != nil || requeued != 1 || failed != 0 {
		t.Fatalf("reclaim requeued=%d failed=%d err=%v", requeued, failed, err)
	}
	second, err := s.Lease(ctx, rn.ID)
	if err != nil || second == nil || second.Attempt != 2 || second.JobID != job.ID {
		t.Fatalf("second lease %#v %v", second, err)
	}
	if _, err := s.CompleteJob(ctx, second.JobID, rn.ID, first.Attempt, "no_change", ""); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("stale attempt complete: %v", err)
	}
	got, err := s.GetJob(ctx, job.ID, false)
	if err != nil || got.Status != "leased" || got.Attempt != 2 {
		t.Fatalf("job changed by stale complete: %+v %v", got, err)
	}
	if _, err := s.RenewLease(ctx, second.JobID, rn.ID, first.Attempt); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("stale renew: %v", err)
	}
	if err := s.AppendLogs(ctx, second.JobID, rn.ID, first.Attempt, []model.LogLine{{Stream: "stdout", Line: "stale"}}); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("stale logs: %v", err)
	}
	done, err := s.CompleteJob(ctx, second.JobID, rn.ID, second.Attempt, "no_change", "")
	if err != nil || done.Status != "succeeded" {
		t.Fatalf("current attempt: %+v %v", done, err)
	}
	var ve *store.ValidationError
	if _, err := s.CompleteJob(ctx, second.JobID, rn.ID, second.Attempt, "no_change", ""); err == nil || !errors.As(err, &ve) {
		t.Fatalf("double complete: %v", err)
	}
}

func TestRenewExpiredLeaseIsRejectedAndCompleteStillCounts(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(2, 1, 1, 30)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, nil, false)
	enqueue(t, s, fx.recipe.ID)
	rn := register(t, s, "renew", "", nil)
	lease, err := s.Lease(ctx, rn.ID)
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	if _, err := s.RenewLease(ctx, lease.JobID, rn.ID, lease.Attempt); !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("renew after expiry: %v", err)
	}
	done, err := s.CompleteJob(ctx, lease.JobID, rn.ID, lease.Attempt, "no_change", "")
	if err != nil || done.Status != "succeeded" {
		t.Fatalf("complete after expiry before reclaim: %+v %v", done, err)
	}
}

func TestTrustFailedIsNotRetried(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	if _, err := s.UpdatePipelineSettings(ctx, actor(), settings(2, 1, 3, 30)); err != nil {
		t.Fatal(err)
	}
	fx := seedRecipe(t, s, nil, false)
	job := enqueue(t, s, fx.recipe.ID)
	rn := register(t, s, "trust", "", nil)
	lease, err := s.Lease(ctx, rn.ID)
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	done, err := s.CompleteJob(ctx, lease.JobID, rn.ID, lease.Attempt, "trust_failed", "verify-trust-info failed")
	if err != nil || done.Status != "failed" || done.Result != "trust_failed" {
		t.Fatalf("trust_failed %+v %v", done, err)
	}
	clk.Advance(time.Hour)
	requeued, _, err := s.ReclaimExpired(ctx)
	if err != nil || requeued != 0 {
		t.Fatalf("reclaim %d %v", requeued, err)
	}
	again, err := s.Lease(ctx, rn.ID)
	if err != nil || again != nil {
		t.Fatalf("trust_failed was retried: %#v %v", again, err)
	}
	got, err := s.GetJob(ctx, job.ID, false)
	if err != nil || got.Status != "failed" {
		t.Fatalf("job %+v %v", got, err)
	}
}

func TestCronDSTMissedTicksAndImpossible(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	fx := seedRecipe(t, s, nil, false)
	if _, err := s.CreateSchedule(ctx, actor(), model.Schedule{
		Name: "never", RecipeID: fx.recipe.ID, Cron: "0 0 31 2 *", Enabled: true,
	}); err == nil {
		t.Fatal("31 Feb cron was accepted")
	}

	clk.Set(time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC))
	if _, err := s.CreateSchedule(ctx, actor(), model.Schedule{
		Name: "fallback", RecipeID: fx.recipe.ID, Cron: "30 1 * * *", Timezone: "America/New_York", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	clk.Set(time.Date(2026, 11, 1, 6, 31, 0, 0, time.UTC))
	n, err := s.EnqueueDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("DST fall-back second 01:30 enqueued n=%d err=%v", n, err)
	}

	clk.Set(time.Date(2026, 3, 7, 7, 30, 0, 0, time.UTC))
	if _, err := s.CreateSchedule(ctx, actor(), model.Schedule{
		Name: "spring", RecipeID: fx.recipe.ID, Cron: "30 2 * * *", Timezone: "America/New_York", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	clk.Set(time.Date(2026, 3, 8, 12, 0, 0, 0, time.UTC))
	n, err = s.EnqueueDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("spring-forward gap enqueued n=%d err=%v", n, err)
	}
	clk.Set(time.Date(2026, 3, 9, 6, 31, 0, 0, time.UTC))
	n, err = s.EnqueueDue(ctx)
	if err != nil || n != 1 {
		t.Fatalf("expected the next real 02:30, n=%d err=%v", n, err)
	}

	missed, err := s.CreateRecipe(ctx, actor(), model.Recipe{
		Identifier: "local.munki.Missed", Name: "Missed", RepoID: fx.recipe.RepoID, Enabled: true,
		Override: "<plist/>", TrustInfo: []byte(`{}`), ManagedBy: "terraform",
	})
	if err != nil {
		t.Fatal(err)
	}
	clk.Set(time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC))
	if _, err := s.CreateSchedule(ctx, actor(), model.Schedule{
		Name: "daily", RecipeID: missed.ID, Cron: "0 6 * * *", Timezone: "UTC", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	clk.Set(time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC))
	n, err = s.EnqueueDue(ctx)
	if err != nil || n != 1 {
		t.Fatalf("missed windows n=%d err=%v", n, err)
	}
	n, err = s.EnqueueDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("missed windows collapsed to more than one: n=%d err=%v", n, err)
	}
}

func TestListJobsParameterIsNotSQL(t *testing.T) {
	s := testutil.NewStore(t)
	newClock(t, s)
	ctx := context.Background()
	fx := seedRecipe(t, s, nil, false)
	enqueue(t, s, fx.recipe.ID)
	jobs, total, err := s.ListJobs(ctx, "' OR 1=1 --", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 || total != 0 {
		t.Fatalf("injection returned jobs=%d total=%d", len(jobs), total)
	}
	_, total, err = s.ListJobs(ctx, fx.recipe.ID, 1, 0)
	if err != nil || total != 1 {
		t.Fatalf("total=%d err=%v", total, err)
	}
}

func TestCatalogAllSoakAndPackageIdentity(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	p := actor()
	if _, err := s.CreatePromotionRule(ctx, p, model.PromotionRule{
		Name: "testing-to-production", FromCatalog: "testing", ToCatalog: "production",
		SoakDays: 7, Enabled: true, ManagedBy: "terraform",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePromotionRule(ctx, p, model.PromotionRule{
		Name: "too-long", FromCatalog: "testing", ToCatalog: "production", SoakDays: 4000, Enabled: true,
	}); err == nil {
		t.Fatal("soak above MaxSoakDays was accepted")
	}
	raw := []byte(`{"name":"Firefox","version":"130.0","catalogs":["testing"],"notes":"secret note","_metadata":{"x":1},"installer_item_hash":"aaa"}`)
	first, imported, err := s.InsertPackage(ctx, p, model.Package{
		Name: "Firefox", Version: "130.0", Filename: "Firefox-130.0.pkg", Pkginfo: raw,
	})
	if err != nil || !imported {
		t.Fatal(err)
	}
	all, err := munki.ParseCatalog(mustCatalog(t, s, "all"))
	if err != nil || len(all) != 1 || all[0]["name"] != "Firefox" {
		t.Fatalf("all catalog %#v %v", all, err)
	}
	if _, ok := all[0]["notes"]; ok {
		t.Fatalf("notes leaked: %#v", all[0])
	}
	if _, ok := all[0]["_metadata"]; ok {
		t.Fatalf("underscore key leaked: %#v", all[0])
	}
	again, imported, err := s.InsertPackage(ctx, p, model.Package{
		Name: "Firefox", Version: "130.0", Filename: "Firefox-130.0.pkg",
		Pkginfo: []byte(`{"name":"Firefox","version":"130.0","installer_item_hash":"bbb"}`),
	})
	if err == nil || !errors.Is(err, store.ErrConflict) || imported {
		t.Fatalf("hash mismatch imported=%v err=%v", imported, err)
	}
	if again.ID != first.ID {
		t.Fatalf("conflict replaced id")
	}
	kept, err := s.GetPackage(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	if err := json.Unmarshal(kept.Pkginfo, &info); err != nil {
		t.Fatal(err)
	}
	if info["installer_item_hash"] != "aaa" {
		t.Fatalf("hash overwritten: %#v", info)
	}
	if _, _, err := s.InsertPackage(ctx, p, model.Package{
		Name: "Other", Version: "1", Filename: "Firefox-130.0.pkg",
		Pkginfo: []byte(`{"name":"Other","version":"1","installer_item_hash":"ccc"}`),
	}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("filename collision: %v", err)
	}
	if _, _, err := s.InsertPackage(ctx, p, model.Package{
		Name: "Bad", Version: "1", Filename: "../etc/passwd",
		Pkginfo: []byte(`{"name":"Bad","version":"1"}`),
	}); err == nil {
		t.Fatal("path traversal filename accepted")
	}

	clk.Advance(8 * 24 * time.Hour)
	var moved atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := s.PromoteDue(ctx)
			if err != nil {
				t.Errorf("promote: %v", err)
				return
			}
			moved.Add(int32(n))
		}()
	}
	wg.Wait()
	if moved.Load() != 1 {
		t.Fatalf("concurrent promote moved %d", moved.Load())
	}
	got, err := s.GetPackage(ctx, first.ID)
	if err != nil || got.Catalog != "production" {
		t.Fatalf("after promote %+v %v", got, err)
	}
	testing, err := munki.ParseCatalog(mustCatalog(t, s, "testing"))
	if err != nil || len(testing) != 0 {
		t.Fatalf("testing %#v %v", testing, err)
	}
	all, err = munki.ParseCatalog(mustCatalog(t, s, "all"))
	if err != nil || len(all) != 1 {
		t.Fatalf("all after promote %#v %v", all, err)
	}
	if _, err := s.PromotePackage(ctx, p, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PromotePackage(ctx, p, first.ID); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetPackage(ctx, first.ID)
	if err != nil || got.Catalog != "production" {
		t.Fatalf("second manual promote %+v %v", got, err)
	}

	if _, err := s.Pool().Exec(ctx, `
		INSERT INTO promotion_rules (id, name, from_catalog, to_catalog, soak_days, enabled, managed_by)
		VALUES ('huge', 'huge-soak', 'production', 'archive', 2000000000, true, 'test')`); err != nil {
		t.Fatal(err)
	}
	n, err := s.PromoteDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("overflow soak promoted n=%d err=%v", n, err)
	}
	got, err = s.GetPackage(ctx, first.ID)
	if err != nil || got.Catalog != "production" {
		t.Fatalf("overflow moved the package: %+v %v", got, err)
	}
}
