package vuln

import "time"

// FixtureRecords are real CVEs with the affected ranges used by the dev seed.
// The ids are not invented. Bounds that differ from a Linux CPE on purpose are
// noted on the record: a Mac stable build is the bound we match, so a patched
// Mac is not flagged. Source is "fixture" until a live feed replaces the row.
// CVE-2024-12053's score is the Chromium high type-confusion vector shared with
// CVE-2024-11395. It is not a separately fetched NVD base score.
func FixtureRecords() []Record {
	return []Record{
		{
			ID: "CVE-2024-11395", Source: "fixture", Severity: "high", Score: 8.8,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
			Description: "Type confusion in V8 in Google Chrome prior to 131.0.6778.85.",
			Published:   date("2024-11-19"),
			Ranges: []ProductBound{{
				Part: "a", Vendor: "google", Product: "chrome",
				Bound: Bound{EndExcl: "131.0.6778.85"},
			}},
		},
		{
			ID: "CVE-2024-12053", Source: "fixture", Severity: "high", Score: 8.8,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
			Description: "Type confusion in V8 in Google Chrome prior to 131.0.6778.108. The stored score is the sibling Chromium high vector, marked fixture, not a fetched NVD score.",
			Published:   date("2024-11-21"),
			Ranges: []ProductBound{{
				Part: "a", Vendor: "google", Product: "chrome",
				Bound: Bound{EndExcl: "131.0.6778.108"},
			}},
		},
		{
			ID: "CVE-2024-11110", Source: "fixture", Severity: "medium", Score: 6.5,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
			Description: "Inappropriate implementation in Extensions in Google Chrome. NVD's CPE ends before 131.0.6778.69. The Mac stable fix is 131.0.6778.69 and 131.0.6778.70, so the bound ends before 131.0.6778.70 and a patched Mac is not flagged.",
			Published:   date("2024-11-12"),
			Ranges: []ProductBound{{
				Part: "a", Vendor: "google", Product: "chrome",
				Bound: Bound{EndExcl: "131.0.6778.70"},
			}},
		},
		{
			ID: "CVE-2024-7971", Source: "fixture", Severity: "high", Score: 8.8,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
			Description: "Type confusion in V8 in Google Chrome prior to 128.0.6613.85 on Mac. Listed in the CISA KEV catalog.",
			Published:   date("2024-08-21"),
			KEV:         true, KEVName: "Google Chromium V8 Type Confusion Vulnerability",
			KEVAdded: date("2024-08-26"), KEVDue: date("2024-09-16"),
			Ranges: []ProductBound{{
				Part: "a", Vendor: "google", Product: "chrome",
				Bound: Bound{EndExcl: "128.0.6613.85"},
			}},
		},
		{
			ID: "CVE-2024-9680", Source: "fixture", Severity: "high", Score: 7.5,
			Description: "Use-after-free in Animation timelines in Firefox, fixed in Firefox 131.0.2, ESR 128.3.1, and ESR 115.16.1. Stored as backport trains so a patched ESR is not flagged by the 131.0.2 fix. Score 7.5 follows the CERT-EU assessment. The vector was not published with that score.",
			Published:   date("2024-10-09"),
			KEV:         true, KEVName: "Mozilla Firefox Animation Timeline Use-After-Free Vulnerability",
			KEVAdded: date("2024-10-15"), KEVDue: date("2024-11-05"),
			Trains: []Train{
				{Part: "a", Vendor: "mozilla", Product: "firefox", Major: 131, FixedVersion: "131.0.2", Mode: "backport"},
				{Part: "a", Vendor: "mozilla", Product: "firefox", Major: 128, FixedVersion: "128.3.1", Mode: "backport"},
				{Part: "a", Vendor: "mozilla", Product: "firefox", Major: 115, FixedVersion: "115.16.1", Mode: "backport"},
			},
		},
		{
			ID: "CVE-2024-44308", Source: "fixture", Severity: "high", Score: 0,
			Description: "JavaScriptCore vulnerability fixed in macOS Sequoia 15.1.1 build 24B91. Apple lists it for Sequoia. Other macOS trains are not flagged. No CVSS base score is stored.",
			Published:   date("2024-11-19"),
			KEV:         true, KEVName: "Apple Multiple Products JavaScriptCore Vulnerability",
			KEVAdded: date("2024-11-21"), KEVDue: date("2024-12-12"),
			Trains: []Train{
				{Part: "o", Vendor: "apple", Product: "macos", Major: 15, FixedVersion: "15.1.1", FixedBuild: "24B91", Mode: "independent"},
			},
		},
		{
			ID: "CVE-2024-44309", Source: "fixture", Severity: "high", Score: 0,
			Description: "WebKit cookie vulnerability fixed in macOS Sequoia 15.1.1 build 24B91. Apple lists it for Sequoia. Other macOS trains are not flagged. No CVSS base score is stored.",
			Published:   date("2024-11-19"),
			KEV:         true, KEVName: "Apple Multiple Products WebKit Vulnerability",
			KEVAdded: date("2024-11-21"), KEVDue: date("2024-12-12"),
			Trains: []Train{
				{Part: "o", Vendor: "apple", Product: "macos", Major: 15, FixedVersion: "15.1.1", FixedBuild: "24B91", Mode: "independent"},
			},
		},
		{
			ID: "CVE-2024-42439", Source: "fixture", Severity: "medium", Score: 6.5,
			Vector:      "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H",
			Description: "Zoom Workplace Desktop for macOS before 6.1.0.",
			Published:   date("2024-08-14"),
			Ranges: []ProductBound{{
				Part: "a", Vendor: "zoom", Product: "workplace_desktop",
				Bound: Bound{EndExcl: "6.1.0"},
			}},
		},
	}
}

func date(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
