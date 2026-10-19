package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/testutil"
)

func TestSeedDemoIsRealisticAndIdempotent(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	if err := s.SeedDemo(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.SeedDemo(ctx); err != nil {
		t.Fatal(err)
	}
	recipes, err := s.ListRecipes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipes) != 12 {
		t.Fatalf("recipes=%d", len(recipes))
	}
	var disabled, withJob int
	for _, r := range recipes {
		if !r.Enabled {
			disabled++
		}
		if r.LastJob != nil {
			withJob++
		}
	}
	if disabled != 1 || withJob < 10 {
		t.Fatalf("disabled=%d withJob=%d", disabled, withJob)
	}
	schedules, err := s.ListSchedules(ctx)
	if err != nil || len(schedules) != 12 {
		t.Fatalf("schedules %#v %v", schedules, err)
	}
	runners, err := s.ListRunners(ctx, 45*time.Second)
	if err != nil || len(runners) != 2 {
		t.Fatalf("runners %#v %v", runners, err)
	}
	online := 0
	for _, rn := range runners {
		if rn.Status == "online" {
			online++
		}
	}
	if online != 1 {
		t.Fatalf("expected one runner inside the 45s window, online=%d %#v", online, runners)
	}
	testing, err := s.ListPackages(ctx, "testing")
	if err != nil || len(testing) < 4 {
		t.Fatalf("testing %#v %v", testing, err)
	}
	for _, pkg := range testing {
		if pkg.SoakStatus != "soaking" {
			t.Fatalf("seed package should still be soaking: %+v", pkg)
		}
	}
	prod, err := s.ListPackages(ctx, "production")
	if err != nil || len(prod) != 2 {
		t.Fatalf("production %#v %v", prod, err)
	}
	n, err := s.PromoteDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("seed promoted immediately n=%d err=%v", n, err)
	}
}
