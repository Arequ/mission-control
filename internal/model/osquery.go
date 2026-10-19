package model

import "time"

// OsqueryQuery is a Terraform-managed query. Scheduled queries go on the global
// schedule. Packs reference queries by id and run them for matching hosts.
type OsqueryQuery struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	SQL         string    `json:"sql"`
	Platform    string    `json:"platform"`
	Interval    int       `json:"interval"`
	Snapshot    bool      `json:"snapshot"`
	Removed     bool      `json:"removed"`
	Scheduled   bool      `json:"scheduled"`
	ManagedBy   string    `json:"managed_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// OsqueryPack groups queries and is included in a host's config when the host
// matches one of Labels. An empty label list means every host.
type OsqueryPack struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Platform    string             `json:"platform"`
	Interval    *int               `json:"interval,omitempty"`
	Shard       *int               `json:"shard,omitempty"`
	Discovery   []string           `json:"discovery"`
	Labels      []string           `json:"labels"`
	QueryIDs    []string           `json:"query_ids"`
	Queries     []OsqueryPackQuery `json:"queries,omitempty"`
	Enabled     bool               `json:"enabled"`
	ManagedBy   string             `json:"managed_by"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// OsqueryPackQuery is a query as rendered inside a pack.
type OsqueryPackQuery struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Interval int    `json:"interval"`
	Platform string `json:"platform"`
	Snapshot bool   `json:"snapshot"`
}

// OsqueryLabel is a dynamic SQL label or a manual serial list.
type OsqueryLabel struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Kind        string    `json:"kind"`
	SQL         string    `json:"sql"`
	Platform    string    `json:"platform"`
	Serials     []string  `json:"serials"`
	DeviceIDs   []string  `json:"device_ids"`
	ManagedBy   string    `json:"managed_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Members     int       `json:"members,omitempty"`
}

// EnrollSecret is a rotatable osquery enroll secret. The raw secret is write-only.
type EnrollSecret struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret,omitempty"`
	Enabled   bool      `json:"enabled"`
	ManagedBy string    `json:"managed_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Device is one enrolled host, keyed by hardware UUID and serial.
type Device struct {
	ID               string          `json:"id"`
	NodeInvalid      bool            `json:"node_invalid"`
	HostIdentifier   string          `json:"host_identifier"`
	HardwareUUID     string          `json:"hardware_uuid"`
	Serial           string          `json:"serial"`
	Hostname         string          `json:"hostname"`
	ComputerName     string          `json:"computer_name"`
	Platform         string          `json:"platform"`
	OSName           string          `json:"os_name"`
	OSVersion        string          `json:"os_version"`
	OSBuild          string          `json:"os_build"`
	OSDisplay        string          `json:"os_display,omitempty"`
	HardwareModel    string          `json:"hardware_model"`
	ModelName        string          `json:"model_name,omitempty"`
	HardwareVendor   string          `json:"hardware_vendor"`
	CPUBrand         string          `json:"cpu_brand"`
	CPUType          string          `json:"cpu_type"`
	CPUPhysicalCores int             `json:"cpu_physical_cores"`
	CPULogicalCores  int             `json:"cpu_logical_cores"`
	PhysicalMemory   int64           `json:"physical_memory"`
	PrimaryIP        string          `json:"primary_ip"`
	PrimaryMAC       string          `json:"primary_mac"`
	Username         string          `json:"username"`
	DiskEncrypted    *bool           `json:"disk_encrypted"`
	UptimeSeconds    int64           `json:"uptime_seconds"`
	OsqueryVersion   string          `json:"osquery_version"`
	EnrolledAt       time.Time       `json:"enrolled_at"`
	LastEnrolledAt   time.Time       `json:"last_enrolled_at"`
	LastSeenAt       *time.Time      `json:"last_seen_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	Status           string          `json:"status,omitempty"`
	Labels           []string        `json:"labels,omitempty"`
	Apps             []DeviceApp     `json:"apps,omitempty"`
	Events           []AuditEntry    `json:"events,omitempty"`
	Coverage         *DeviceCoverage `json:"coverage,omitempty"`
}

// DeviceApp is one installed application from the latest inventory snapshot.
type DeviceApp struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	BundleID string `json:"bundle_id"`
	Version  string `json:"version"`
}

// DeviceListFilter selects a page of devices.
type DeviceListFilter struct {
	Q            string
	Platform     string
	Status       string
	Label        string
	Limit        int
	Offset       int
	OfflineAfter time.Duration
}

// ResultLog is one stored osquery result row.
type ResultLog struct {
	ID         int64             `json:"id"`
	DeviceID   string            `json:"device_id"`
	QueryName  string            `json:"query_name"`
	Action     string            `json:"action"`
	Columns    map[string]string `json:"columns"`
	UnixTime   int64             `json:"unix_time"`
	ReceivedAt time.Time         `json:"received_at"`
}

// FleetSummary is the overview payload.
type FleetSummary struct {
	TotalDevices        int            `json:"total_devices"`
	OnlineDevices       int            `json:"online_devices"`
	EnrolledThisWeek    int            `json:"enrolled_this_week"`
	OfflineAfterSeconds int            `json:"offline_after_seconds"`
	MacOSVersions       []VersionCount `json:"macos_versions"`
	AutoPkg             AutoPkgSummary `json:"autopkg"`
}

// VersionCount is one bar in the macOS distribution.
type VersionCount struct {
	Version string `json:"version"`
	Name    string `json:"name"`
	Count   int    `json:"count"`
}

// AutoPkgSummary is the small AutoPKG status on the fleet overview.
type AutoPkgSummary struct {
	Recipes            int        `json:"recipes"`
	Enabled            int        `json:"enabled"`
	TestingPackages    int        `json:"testing_packages"`
	ProductionPackages int        `json:"production_packages"`
	LastRecipe         string     `json:"last_recipe,omitempty"`
	LastResult         string     `json:"last_result,omitempty"`
	LastFinishedAt     *time.Time `json:"last_finished_at,omitempty"`
}

// LiveQuery is an operator-issued distributed query.
type LiveQuery struct {
	ID             string              `json:"id"`
	SQL            string              `json:"sql"`
	Status         string              `json:"status"`
	CreatedBy      string              `json:"created_by"`
	TimeoutSeconds int                 `json:"timeout_seconds"`
	CreatedAt      time.Time           `json:"created_at"`
	FinishedAt     *time.Time          `json:"finished_at,omitempty"`
	DeviceIDs      []string            `json:"device_ids,omitempty"`
	Labels         []string            `json:"labels,omitempty"`
	Targets        []LiveQueryTarget   `json:"targets,omitempty"`
	Rows           []map[string]string `json:"rows,omitempty"`
}

// LiveQueryTarget is one device's slice of a live query.
type LiveQueryTarget struct {
	DeviceID     string              `json:"device_id"`
	Hostname     string              `json:"hostname,omitempty"`
	ComputerName string              `json:"computer_name,omitempty"`
	Status       string              `json:"status"`
	StatusCode   *int                `json:"status_code,omitempty"`
	Error        string              `json:"error,omitempty"`
	Rows         []map[string]string `json:"rows,omitempty"`
	CompletedAt  *time.Time          `json:"completed_at,omitempty"`
}

// LiveQueryRequest is the operational body for POST /api/v1/live-queries.
type LiveQueryRequest struct {
	SQL            string   `json:"sql"`
	DeviceIDs      []string `json:"device_ids"`
	Labels         []string `json:"labels"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}
