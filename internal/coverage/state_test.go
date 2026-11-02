package coverage

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	if got := Classify(false, now, now, day); got != Missing {
		t.Fatalf("missing %s", got)
	}
	if got := Classify(true, now.Add(-time.Hour), now, day); got != Seen {
		t.Fatalf("seen %s", got)
	}
	if got := Classify(true, now.Add(-48*time.Hour), now, day); got != Stale {
		t.Fatalf("stale %s", got)
	}
	if got := Classify(true, time.Time{}, now, day); got != Stale {
		t.Fatalf("zero timestamp %s", got)
	}
	if got := Classify(true, now.Add(-time.Hour), now, 0); got != Seen {
		t.Fatalf("default window %s", got)
	}
}

func TestFiltersAndPercent(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	fresh := Cell{Source: "osquery", Present: true, LastSeen: now.Add(-time.Hour), State: Seen}
	stale := Cell{Source: "netskope", Present: true, LastSeen: now.Add(-9 * 24 * time.Hour), State: Stale}
	missing := Cell{Source: "blastshield", Present: false, State: Missing}
	cells := []Cell{fresh, stale, missing}

	if !HasGaps(cells) || SeenCount(cells) != 1 {
		t.Fatalf("gaps/seen %+v", cells)
	}
	if !Keep(cells, Filter{Kind: "gaps"}, now) {
		t.Fatal("gaps")
	}
	if !Keep(cells, Filter{Kind: "missing", Source: "blastshield"}, now) || Keep(cells, Filter{Kind: "missing", Source: "osquery"}, now) {
		t.Fatal("missing source")
	}
	if Keep(cells, Filter{Kind: "single"}, now) {
		t.Fatal("two snapshots is not a single source")
	}
	only := []Cell{{Source: "osquery", Present: true, LastSeen: now, State: Seen}, {Source: "munki", Present: false, State: Missing}}
	if !Keep(only, Filter{Kind: "single"}, now) {
		t.Fatal("single")
	}
	ghost := []Cell{{Source: "osquery", Present: false, State: Missing}, {Source: "kolide", Present: true, LastSeen: now, State: Seen}}
	if !Keep(ghost, Filter{Kind: "ghost"}, now) || Keep(cells, Filter{Kind: "ghost"}, now) {
		t.Fatal("ghost")
	}
	if !Keep(cells, Filter{Kind: "stale", StaleDays: 7}, now) || Keep(cells, Filter{Kind: "stale", StaleDays: 30}, now) {
		t.Fatal("stale over days")
	}
	if Percent(6, 8) != 75 || Percent(0, 0) != 0 || Percent(1, 3) != 33.3 {
		t.Fatalf("percent %v %v %v", Percent(6, 8), Percent(0, 0), Percent(1, 3))
	}
}
