package vuln

import (
	"strings"
	"testing"
)

func TestUrgentThresholds(t *testing.T) {
	for _, tc := range []struct {
		c    ReleaseCVE
		want bool
	}{
		{ReleaseCVE{CVSS: 4.3, KEV: true}, true},
		{ReleaseCVE{CVSS: 9.0}, true},
		{ReleaseCVE{CVSS: 8.9}, false},
		{ReleaseCVE{CVSS: 7.5, EPSS: 0.2, EPSSKnown: true}, true},
		{ReleaseCVE{CVSS: 7.5, EPSS: 0.2}, false}, // an unknown EPSS is not a score
		{ReleaseCVE{CVSS: 6.9, EPSS: 0.9, EPSSKnown: true}, false},
	} {
		if got := Urgent(tc.c); got != tc.want {
			t.Fatalf("%+v: %v", tc.c, got)
		}
	}
}

func TestJudgeRelease(t *testing.T) {
	high := JudgeRelease(ReleaseInput{Mapped: true, Baseline: "1.0", NotesDone: true, Exposed: 12,
		Fixed: []ReleaseCVE{{CVE: "CVE-2026-0001", CVSS: 6.1}, {CVE: "CVE-2026-0002", CVSS: 8.1, KEV: true, Scored: true}}})
	if high.Priority != "high" || !strings.Contains(high.Reasons[0], "CVE-2026-0002") || !strings.Contains(strings.Join(high.Reasons, " "), "12 device") {
		t.Fatalf("%+v", high)
	}
	low := JudgeRelease(ReleaseInput{Mapped: false, NotesDone: false, NotesSecFix: true})
	got := strings.Join(low.Reasons, " | ")
	if low.Priority != "low" || !strings.Contains(got, "No NVD product mapping") || !strings.Contains(got, "not read yet") || !strings.Contains(got, "without CVE IDs") {
		t.Fatalf("%s", got)
	}
}

func TestMatchMunkiName(t *testing.T) {
	for _, name := range []string{"GoogleChrome", "Firefox", "Slack", "1Password"} {
		if _, ok := MatchMunkiName(name, nil); !ok {
			t.Fatalf("%s not matched", name)
		}
	}
	if _, ok := MatchMunkiName("Granola", nil); ok {
		t.Fatal("Granola matched a curated product")
	}
	p, ok := MatchMunkiName("Granola", []Override{{Name: "Granola", Vendor: "granola", Product: "granola"}})
	if !ok || p.Key() != "a:granola:granola" {
		t.Fatalf("override %v %v", p, ok)
	}
}
