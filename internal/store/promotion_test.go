package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/Arequ/mission-control/internal/testutil"
)

func pkginfo(name, version, catalog string) json.RawMessage {
	raw, err := json.Marshal(map[string]any{
		"name": name, "version": version, "catalogs": []string{catalog},
		"installer_item_location": name + "-" + version + ".pkg",
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func TestCatalogGenerationAndPromotion(t *testing.T) {
	s := testutil.NewStore(t)
	clk := newClock(t, s)
	ctx := context.Background()
	p := actor()
	rule, err := s.CreatePromotionRule(ctx, p, model.PromotionRule{
		Name: "testing-to-production", FromCatalog: "testing", ToCatalog: "production",
		SoakDays: 7, ManualHold: false, Enabled: true, ManagedBy: "terraform",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, imported, err := s.InsertPackage(ctx, p, model.Package{
		Name: "Firefox", Version: "130.0", Filename: "Firefox-130.0.pkg",
		RecipeIdentifier: "local.munki.Firefox", Pkginfo: pkginfo("Firefox", "130.0", "testing"),
	})
	if err != nil || !imported {
		t.Fatalf("import: imported=%v err=%v", imported, err)
	}
	if first.Catalog != "testing" || first.SoakStatus != "soaking" {
		t.Fatalf("package %+v", first)
	}
	body, err := s.CatalogBody(ctx, "testing")
	if err != nil {
		t.Fatal(err)
	}
	items, err := munki.ParseCatalog(body)
	if err != nil || len(items) != 1 || items[0]["name"] != "Firefox" {
		t.Fatalf("testing catalog %#v %v", items, err)
	}
	n, err := s.PromoteDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("early promote n=%d err=%v", n, err)
	}
	clk.Advance(7 * 24 * time.Hour)
	n, err = s.PromoteDue(ctx)
	if err != nil || n != 1 {
		t.Fatalf("promote n=%d err=%v", n, err)
	}
	got, err := s.GetPackage(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Catalog != "production" || got.SoakStatus != "promoted" || got.PromotedAt == nil {
		t.Fatalf("after promote %+v", got)
	}
	testing, err := munki.ParseCatalog(mustCatalog(t, s, "testing"))
	if err != nil || len(testing) != 0 {
		t.Fatalf("testing still has %#v %v", testing, err)
	}
	prod, err := munki.ParseCatalog(mustCatalog(t, s, "production"))
	if err != nil || len(prod) != 1 || prod[0]["version"] != "130.0" {
		t.Fatalf("production %#v %v", prod, err)
	}

	rule.ManualHold = true
	if _, err := s.UpdatePromotionRule(ctx, p, rule.ID, rule); err != nil {
		t.Fatal(err)
	}
	second, imported, err := s.InsertPackage(ctx, p, model.Package{
		Name: "Firefox", Version: "131.0", Filename: "Firefox-131.0.pkg",
		Pkginfo: pkginfo("Firefox", "131.0", "testing"),
	})
	if err != nil || !imported {
		t.Fatal(err)
	}
	clk.Advance(30 * 24 * time.Hour)
	n, err = s.PromoteDue(ctx)
	if err != nil || n != 0 {
		t.Fatalf("hold should block promotion n=%d err=%v", n, err)
	}
	held, err := s.GetPackage(ctx, second.ID)
	if err != nil || held.SoakStatus != "held" || held.Catalog != "testing" {
		t.Fatalf("held %+v %v", held, err)
	}
	promoted, err := s.PromotePackage(ctx, p, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Catalog != "production" {
		t.Fatalf("manual promote %+v", promoted)
	}
	dup, imported, err := s.InsertPackage(ctx, p, model.Package{
		Name: "Firefox", Version: "130.0", Filename: "Firefox-130.0.pkg",
		Pkginfo: pkginfo("Firefox", "130.0", "testing"),
	})
	if err != nil || imported || dup.ID != first.ID {
		t.Fatalf("duplicate imported=%v id=%s err=%v", imported, dup.ID, err)
	}
}

func mustCatalog(t *testing.T, s interface {
	CatalogBody(context.Context, string) ([]byte, error)
}, name string) []byte {
	t.Helper()
	b, err := s.CatalogBody(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
