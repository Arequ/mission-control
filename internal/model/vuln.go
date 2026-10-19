package model

import (
	"encoding/json"
	"time"
)

// VulnerabilitySettings is the singleton feed and SLA configuration.
// NVDAPIKey is write-only: the API stores it and Public never returns it.
type VulnerabilitySettings struct {
	ID              string        `json:"id"`
	NVDEnabled      bool          `json:"nvd_enabled"`
	KEVEnabled      bool          `json:"kev_enabled"`
	EPSSEnabled     bool          `json:"epss_enabled"`
	AppleEnabled    bool          `json:"apple_enabled"`
	Rapid7Enabled   bool          `json:"rapid7_enabled"`
	SyncCron        string        `json:"sync_cron"`
	Timezone        string        `json:"timezone"`
	HasNVDAPIKey    bool          `json:"has_nvd_api_key"`
	NVDAPIKey       string        `json:"nvd_api_key,omitempty"`
	SLACriticalDays int           `json:"sla_critical_days"`
	SLAHighDays     int           `json:"sla_high_days"`
	SLAMediumDays   int           `json:"sla_medium_days"`
	SLALowDays      int           `json:"sla_low_days"`
	SLAKEVDays      int           `json:"sla_kev_days"`
	Overrides       []CPEOverride `json:"cpe_overrides"`
	ManagedBy       string        `json:"managed_by"`
	LastSyncAt      time.Time     `json:"last_sync_at"`
	LastSyncStatus  string        `json:"last_sync_status"`
	LastSyncError   string        `json:"last_sync_error"`
	NVDCursor       string        `json:"nvd_cursor"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// Public clears the write-only key.
func (s VulnerabilitySettings) Public() VulnerabilitySettings {
	s.NVDAPIKey = ""
	if s.Overrides == nil {
		s.Overrides = []CPEOverride{}
	}
	return s
}

// CPEOverride maps one bundle id or app name onto a CPE vendor and product.
type CPEOverride struct {
	BundleID      string `json:"bundle_id"`
	Name          string `json:"name"`
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	Part          string `json:"part"`
	VersionSource string `json:"version_source"`
}

// VulnerabilityIssue is one CVE on one piece of software.
type VulnerabilityIssue struct {
	ID             string     `json:"id"`
	CVEID          string     `json:"cve_id"`
	SoftwareKey    string     `json:"software_key"`
	SoftwareName   string     `json:"software_name"`
	Status         string     `json:"status"`
	Assignee       string     `json:"assignee"`
	Notes          string     `json:"notes"`
	RiskUntil      *time.Time `json:"risk_until,omitempty"`
	OpenedAt       time.Time  `json:"opened_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	AutoResolved   bool       `json:"auto_resolved"`
	Revision       int        `json:"revision"`
	Description    string     `json:"description"`
	Score          float64    `json:"cvss_score"`
	Vector         string     `json:"cvss_vector"`
	Severity       string     `json:"severity"`
	KEV            bool       `json:"kev"`
	KEVName        string     `json:"kev_name,omitempty"`
	KEVAdded       *time.Time `json:"kev_added,omitempty"`
	KEVDue         *time.Time `json:"kev_due,omitempty"`
	EPSS           float64    `json:"epss"`
	EPSSPercentile float64    `json:"epss_percentile"`
	EPSSKnown      bool       `json:"epss_known"`
	Source         string     `json:"source"`
	DeviceCount    int        `json:"device_count"`
	SLADays        int        `json:"sla_days"`
	SLADue         time.Time  `json:"sla_due"`
	WithinSLA      bool       `json:"within_sla"`
	Fix            IssueFix   `json:"fix"`
}

// IssueFix is the next step. Promote and install are GitOps links.
// Run recipe is the only direct operational action.
type IssueFix struct {
	Action         string `json:"action"`
	FixedVersion   string `json:"fixed_version,omitempty"`
	FixedBuild     string `json:"fixed_build,omitempty"`
	Catalog        string `json:"catalog,omitempty"`
	CatalogVersion string `json:"catalog_version,omitempty"`
	RecipeID       string `json:"recipe_id,omitempty"`
	RecipeName     string `json:"recipe_name,omitempty"`
	RecipeStatus   string `json:"recipe_status,omitempty"`
	RequiredOS     string `json:"required_os,omitempty"`
	PRURL          string `json:"pr_url,omitempty"`
	PRTitle        string `json:"pr_title,omitempty"`
	PRBody         string `json:"pr_body,omitempty"`
}

// IssueUpdate changes operational state. Revision must match.
type IssueUpdate struct {
	Status    string     `json:"status"`
	Assignee  string     `json:"assignee"`
	Notes     string     `json:"notes"`
	RiskUntil *time.Time `json:"risk_until"`
	Revision  int        `json:"revision"`
}

// IssueNote is an audit note on an issue.
type IssueNote struct {
	Note     string `json:"note"`
	Revision int    `json:"revision"`
}

// IssueEvent is one line of the timeline.
type IssueEvent struct {
	ID     string          `json:"id"`
	At     time.Time       `json:"at"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"`
	Detail json.RawMessage `json:"detail"`
}

// AffectedDevice is one Mac still matching the issue.
type AffectedDevice struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	ComputerName string `json:"computer_name"`
	Serial       string `json:"serial"`
	Username     string `json:"username"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Evidence     string `json:"evidence"`
}

// VulnerabilityDetail is the issue plus the devices and the timeline.
type VulnerabilityDetail struct {
	VulnerabilityIssue
	Devices  []AffectedDevice `json:"devices"`
	Events   []IssueEvent     `json:"events"`
	Installs int              `json:"installs"`
	Affected int              `json:"affected"`
}

// VulnerabilitySummary is the headline counts. They are computed, not seeded.
type VulnerabilitySummary struct {
	Open           int `json:"open"`
	KEV            int `json:"kev"`
	KEVDevices     int `json:"kev_devices"`
	WithFix        int `json:"with_fix"`
	WithinSLA      int `json:"within_sla"`
	DueThisWeek    int `json:"due_this_week"`
	OpenedThisWeek int `json:"opened_this_week"`
}

// VulnerabilityList is one page of issues plus the unfiltered headline.
type VulnerabilityList struct {
	Issues  []VulnerabilityIssue `json:"issues"`
	Summary VulnerabilitySummary `json:"summary"`
	Total   int                  `json:"total"`
	Limit   int                  `json:"limit"`
	Offset  int                  `json:"offset"`
}

// IssueFilter selects a page. HasFix is applied after fix linkage.
type IssueFilter struct {
	KEV      *bool
	Severity string
	Status   string
	Active   bool
	HasFix   *bool
	Q        string
	Limit    int
	Offset   int
	DeviceID string
}
