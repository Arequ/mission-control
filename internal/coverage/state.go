package coverage

import (
	"math"
	"time"
)

const (
	// Seen means the source reported the device inside its stale window.
	Seen = "seen"
	// Stale means the source has a snapshot older than its threshold.
	Stale = "stale"
	// Missing means the source has no snapshot for the device.
	Missing = "missing"
)

// Source describes one column in the coverage matrix.
type Source struct {
	Key    string
	Name   string
	Short  string
	Native bool
}

// Sources is the fixed set of tools, in matrix order.
var Sources = []Source{
	{Key: "osquery", Name: "osquery", Short: "OQ", Native: true},
	{Key: "munki", Name: "Munki", Short: "MU", Native: true},
	{Key: "crowdstrike", Name: "CrowdStrike", Short: "CS"},
	{Key: "rapid7", Name: "Rapid7 Insight", Short: "R7"},
	{Key: "netskope", Name: "Netskope", Short: "NS"},
	{Key: "proofpoint", Name: "Proofpoint", Short: "PP"},
	{Key: "blastshield", Name: "BlastShield", Short: "BS"},
	{Key: "kolide", Name: "Kolide", Short: "KO"},
}

// SourceByKey returns the catalog entry, or the zero value.
func SourceByKey(key string) Source {
	for _, s := range Sources {
		if s.Key == key {
			return s
		}
	}
	return Source{}
}

// KnownSource reports whether key is one of the eight coverage sources.
func KnownSource(key string) bool {
	return SourceByKey(key).Key != ""
}

// Cell is one source's state for one device.
type Cell struct {
	Source   string
	Present  bool
	LastSeen time.Time
	State    string
}

// Classify returns seen, stale, or missing.
// A snapshot with no timestamp is stale: the source has a record, but not a fresh one.
func Classify(present bool, lastSeen time.Time, now time.Time, staleAfter time.Duration) string {
	if !present {
		return Missing
	}
	if staleAfter <= 0 {
		staleAfter = 24 * time.Hour
	}
	if lastSeen.IsZero() || now.Sub(lastSeen) > staleAfter {
		return Stale
	}
	return Seen
}

// Percent is seen/total rounded to one decimal. An empty fleet is 0.
func Percent(seen, total int) float64 {
	if total <= 0 {
		return 0
	}
	return math.Round(float64(seen)/float64(total)*1000) / 10
}

// Filter selects matrix rows.
// Kind is all, gaps, missing, single, ghost, or stale.
type Filter struct {
	Kind      string
	Source    string
	StaleDays int
}

// Keep reports whether a row matches the filter.
// "single" counts sources that have a snapshot, including stale ones.
// "ghost" means osquery has no snapshot.
// "stale" means some snapshot is older than StaleDays.
func Keep(cells []Cell, f Filter, now time.Time) bool {
	switch f.Kind {
	case "", "all":
		return true
	case "gaps":
		for _, c := range cells {
			if c.State != Seen {
				return true
			}
		}
		return false
	case "missing":
		for _, c := range cells {
			if c.Source == f.Source && c.State == Missing {
				return true
			}
		}
		return false
	case "single":
		n := 0
		for _, c := range cells {
			if c.Present {
				n++
			}
		}
		return n == 1
	case "ghost":
		for _, c := range cells {
			if c.Source == "osquery" {
				return !c.Present
			}
		}
		return true
	case "stale":
		days := f.StaleDays
		if days <= 0 {
			days = 7
		}
		limit := time.Duration(days) * 24 * time.Hour
		for _, c := range cells {
			if c.Present && !c.LastSeen.IsZero() && now.Sub(c.LastSeen) >= limit {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// SeenCount is the number of sources inside their fresh window.
func SeenCount(cells []Cell) int {
	n := 0
	for _, c := range cells {
		if c.State == Seen {
			n++
		}
	}
	return n
}

// HasGaps is true when any source is stale or missing.
func HasGaps(cells []Cell) bool {
	for _, c := range cells {
		if c.State != Seen {
			return true
		}
	}
	return false
}
