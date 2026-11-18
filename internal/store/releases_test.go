package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
)

var reviewer = model.Principal{Kind: "session", ID: "sam", Name: "sam@example.com", Scopes: map[string]bool{"releases:update": true, "rush:update": true}}

// A reviewer who decides releases but was not granted rush:update.
var deciderOnly = model.Principal{Kind: "session", ID: "ops", Name: "ops@example.com", Scopes: map[string]bool{"releases:update": true}}
var advisorP = model.Principal{Kind: "api", ID: "advisor", Name: "advisor"}

func releaseStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	st := newCoverageStore(t)
	for _, rec := range vuln.FixtureRecords() {
		if err := st.insertFixture(ctx, rec, st.now()); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []model.PromotionRule{
		{Name: "alpha-to-beta", FromCatalog: "alpha", ToCatalog: "beta", SoakDays: 1, Enabled: true},
		{Name: "beta-to-production", FromCatalog: "beta", ToCatalog: "production", SoakDays: 3, Enabled: true},
	} {
		if _, err := st.CreatePromotionRule(ctx, model.System, r); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func importPkg(t *testing.T, st *Store, name, version, catalog string) model.Package {
	t.Helper()
	info, _ := json.Marshal(map[string]any{"name": name, "version": version, "display_name": "Google Chrome"})
	pkg, _, err := st.InsertPackage(context.Background(), model.System, model.Package{
		Name: name, Version: version, Catalog: catalog, Filename: name + "-" + version + ".pkg", Pkginfo: info,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func reviewFor(t *testing.T, st *Store, pkgID string) model.ReleaseReview {
	t.Helper()
	list, err := st.ListReleaseReviews(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		if r.PackageID == pkgID {
			return r
		}
	}
	t.Fatalf("no review for %s", pkgID)
	return model.ReleaseReview{}
}

func fixedIDs(t *testing.T, r model.ReleaseReview) []string {
	t.Helper()
	var list []vuln.ReleaseCVE
	if err := json.Unmarshal(r.Fixed, &list); err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, c := range list {
		out = append(out, c.CVE)
	}
	return out
}

func TestReleaseReviewScoresFixesAgainstProduction(t *testing.T) {
	ctx := context.Background()
	st := releaseStore(t)
	importPkg(t, st, "GoogleChrome", "131.0.6778.69", "production")
	next := importPkg(t, st, "GoogleChrome", "131.0.6778.108", "")
	if next.Catalog != "alpha" {
		t.Fatalf("new build landed in %s", next.Catalog)
	}

	r := reviewFor(t, st, next.ID)
	if r.Status != "pending" || r.BaselineVersion != "131.0.6778.69" || r.FinalCatalog != "production" {
		t.Fatalf("review %+v", r)
	}
	if got := strings.Join(fixedIDs(t, r), ","); !strings.Contains(got, "CVE-2024-11395") || !strings.Contains(got, "CVE-2024-12053") {
		t.Fatalf("fixed %s", got)
	}
	// Fixture CVEs are CVSS 8.8 with no KEV or EPSS: worth fixing, not a rush.
	if r.Priority != "low" {
		t.Fatalf("priority %s %v", r.Priority, r.Reasons)
	}
	// A LOW build cannot be rushed, even by someone allowed to rush.
	if _, err := st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "rush"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("rushed a LOW build: %v", err)
	}

	// CISA lists one as exploited: the same build becomes a rush candidate.
	if _, err := st.pool.Exec(ctx, `UPDATE vuln_cves SET kev=true WHERE cve_id='CVE-2024-11395'`); err != nil {
		t.Fatal(err)
	}
	if err := st.ReevaluatePendingReleases(ctx); err != nil {
		t.Fatal(err)
	}
	r = reviewFor(t, st, next.ID)
	if r.Priority != "high" || !strings.Contains(strings.Join(r.Reasons, " "), "CVE-2024-11395") {
		t.Fatalf("after KEV %s %v", r.Priority, r.Reasons)
	}
	// Nothing moved on its own.
	if pkg, _ := st.GetPackage(ctx, next.ID); pkg.Catalog != "alpha" {
		t.Fatalf("HIGH promoted itself to %s", pkg.Catalog)
	}

	// releases:update alone decides reviews but cannot skip the soak.
	if _, err := st.DecideRelease(ctx, deciderOnly, r.ID, model.ReleaseDecision{Decision: "rush"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("rush without rush:update: %v", err)
	}
	// A reviewer with rush:update rushes it: straight to production, audited.
	r, err := st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "rush", Note: "exploited in the wild"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "rushed" || r.Catalog != "production" || r.DecidedBy != "sam@example.com" {
		t.Fatalf("rushed %+v", r)
	}
	body, err := st.CatalogBody(ctx, "production")
	if err != nil || !strings.Contains(string(body), "131.0.6778.108") {
		t.Fatalf("production catalog %v %s", err, body)
	}
	// Rush is once; reject stays possible after shipping and pulls the build.
	if _, err := st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "rush"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second rush %v", err)
	}
	r, err = st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "reject", Note: "breaks SSO"})
	if err != nil || r.Status != "rejected" || r.Catalog != RejectedCatalog {
		t.Fatalf("reject after ship %v %+v", err, r)
	}
	body, _ = st.CatalogBody(ctx, "production")
	if strings.Contains(string(body), "131.0.6778.108") {
		t.Fatal("rejected build still in production")
	}
	if _, err := st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "reject"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("reject twice %v", err)
	}
	if _, err := st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "approve"}); err == nil {
		t.Fatal("unknown decision accepted")
	}
}

func TestReleaseReviewNormalTrackAndSupersede(t *testing.T) {
	ctx := context.Background()
	st := releaseStore(t)
	importPkg(t, st, "GoogleChrome", "131.0.6778.69", "production")
	first := importPkg(t, st, "GoogleChrome", "131.0.6778.85", "")
	second := importPkg(t, st, "GoogleChrome", "131.0.6778.108", "")
	if r := reviewFor(t, st, first.ID); r.Status != "superseded" {
		t.Fatalf("older pending build %s", r.Status)
	}
	r := reviewFor(t, st, second.ID)
	r, err := st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "normal"})
	if err != nil || r.Status != "normal" || r.Catalog != "alpha" {
		t.Fatalf("normal %v %+v", err, r)
	}
}

func TestReleaseReviewUnmappedAppAndRejectStopsSoak(t *testing.T) {
	ctx := context.Background()
	st := releaseStore(t)
	pkg := importPkg(t, st, "Granola", "7.749.1", "")
	r := reviewFor(t, st, pkg.ID)
	if r.Priority != "low" || r.SoftwareKey != "" || !strings.Contains(strings.Join(r.Reasons, " "), "No NVD product mapping") {
		t.Fatalf("unmapped %+v", r)
	}
	if _, err := st.DecideRelease(ctx, reviewer, r.ID, model.ReleaseDecision{Decision: "reject"}); err != nil {
		t.Fatal(err)
	}
	// Backdate the soak: a rejected build never promotes.
	if _, err := st.pool.Exec(ctx, `UPDATE packages SET soak_started_at = now() - interval '30 days' WHERE id=$1`, pkg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PromoteDue(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetPackage(ctx, pkg.ID); got.Catalog != RejectedCatalog {
		t.Fatalf("rejected build promoted to %s", got.Catalog)
	}
}

func TestReleaseNotesLeaseSubmitAndValidation(t *testing.T) {
	ctx := context.Background()
	st := releaseStore(t)
	importPkg(t, st, "Granola", "7.700.0", "production")
	pkg := importPkg(t, st, "Granola", "7.749.1", "")

	task, err := st.LeaseReleaseNotes(ctx, advisorP)
	if err != nil {
		t.Fatal(err)
	}
	if task.Name != "Granola" || task.BaselineVersion != "7.700.0" {
		t.Fatalf("task %+v", task)
	}
	if _, err := st.LeaseReleaseNotes(ctx, advisorP); !errors.Is(err, ErrNotFound) {
		t.Fatalf("leased twice %v", err)
	}
	if _, err := st.SubmitReleaseNotes(ctx, advisorP, task.ID, model.ReleaseNotesInput{Summary: "x", Recommendation: "maybe"}); err == nil {
		t.Fatal("bad recommendation accepted")
	}
	r, err := st.SubmitReleaseNotes(ctx, advisorP, task.ID, model.ReleaseNotesInput{
		Summary:        "Fixes a remote code execution bug.\x00",
		Recommendation: "HIGH",
		SecurityFixes:  true,
		// Junk and a planted lowercase id: only valid ids survive, upper-cased.
		CVEs:    []string{"cve-2099-12345", "not-a-cve", "CVE-2099-12345", "CVE-1; DROP"},
		Sources: []string{"https://granola.ai/changelog", "javascript:alert(1)", "http://insecure.example", "https://user:pw@evil.example/x"},
		Model:   "claude-fable-5-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Notes.Status != "done" || strings.Join(r.Notes.CVEs, ",") != "CVE-2099-12345" ||
		strings.Join(r.Notes.Sources, ",") != "https://granola.ai/changelog" || strings.ContainsRune(r.Notes.Summary, 0) {
		t.Fatalf("notes %+v", r.Notes)
	}
	// The model said HIGH, but the CVE has no NVD score: priority stays LOW
	// and the reason says why. The model's call is shown, not obeyed.
	if r.Priority != "low" || r.Notes.Recommendation != "high" || !strings.Contains(strings.Join(r.Reasons, " "), "not scored yet") {
		t.Fatalf("priority %s reasons %v", r.Priority, r.Reasons)
	}
	if got := fixedIDs(t, r); strings.Join(got, ",") != "CVE-2099-12345" {
		t.Fatalf("fixed from notes %v", got)
	}

	// Once NVD scores it critical, the same notes make the build HIGH.
	if _, err := st.pool.Exec(ctx, `INSERT INTO vuln_cves (cve_id, cvss_score, severity, updated_at) VALUES ('CVE-2099-12345', 9.8, 'critical', now())`); err != nil {
		t.Fatal(err)
	}
	if err := st.EvaluateRelease(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if r = reviewFor(t, st, pkg.ID); r.Priority != "high" {
		t.Fatalf("scored critical but %s %v", r.Priority, r.Reasons)
	}
	// Notes can only be submitted against a live lease.
	if _, err := st.SubmitReleaseNotes(ctx, advisorP, r.ID, model.ReleaseNotesInput{Summary: "again", Recommendation: "low"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("resubmit %v", err)
	}
}
