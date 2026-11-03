package model

import (
	"encoding/json"
	"time"
)

// KeelEnrollSecret is a rotatable Keel enroll secret. The raw secret is write-only.
type KeelEnrollSecret struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret,omitempty"`
	Enabled   bool      `json:"enabled"`
	ManagedBy string    `json:"managed_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// KeelSummary is the resource count block of one run.
type KeelSummary struct {
	Total       int `json:"total"`
	OK          int `json:"ok"`
	Changed     int `json:"changed"`
	WouldChange int `json:"would_change"`
	Failed      int `json:"failed"`
	Skipped     int `json:"skipped"`
}

// KeelRun is the extracted columns of one stored report.
type KeelRun struct {
	RunID       string      `json:"run_id"`
	Serial      string      `json:"serial"`
	Hostname    string      `json:"hostname"`
	Mode        string      `json:"mode"`
	KeelVersion string      `json:"keel_version"`
	StartedAt   time.Time   `json:"started_at"`
	ReceivedAt  time.Time   `json:"received_at"`
	DurationMS  int64       `json:"duration_ms"`
	LeafRole    string      `json:"leaf_role"`
	LeafMatch   string      `json:"leaf_match,omitempty"`
	Roles       []string    `json:"roles"`
	Summary     KeelSummary `json:"summary"`
	Warnings    []string    `json:"warnings"`
	// CompileError is true when a warning starts with "compile: ". Such a
	// device counts as failing.
	CompileError bool `json:"compile_error"`
}

// Failing reports a failed resource or a policy that did not compile.
func (r *KeelRun) Failing() bool {
	return r != nil && (r.Summary.Failed > 0 || r.CompileError)
}

// KeelDevice is one serial: its key binding and the latest run, if any.
// DeviceID is the unified device with the same serial, when one exists.
type KeelDevice struct {
	Serial     string     `json:"serial"`
	Hostname   string     `json:"hostname"`
	DeviceID   string     `json:"device_id,omitempty"`
	Enrolled   bool       `json:"enrolled"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
	Stale      bool       `json:"stale"`
	LastRun    *KeelRun   `json:"last_run,omitempty"`
}

// KeelDeviceDetail is a device plus the body of its latest report.
type KeelDeviceDetail struct {
	KeelDevice
	Report json.RawMessage `json:"report"`
}

// KeelRoleProfile is one profile enabled by devices whose leaf is a role.
type KeelRoleProfile struct {
	Name    string `json:"name"`
	Devices int    `json:"devices"`
}

// KeelRole is one role in the fleet. Devices counts devices whose leaf role
// is this one. Inherited counts devices whose chain includes it.
type KeelRole struct {
	Name      string            `json:"name"`
	Parents   []string          `json:"parents"`
	Chain     []string          `json:"chain"`
	Devices   int               `json:"devices"`
	Inherited int               `json:"inherited"`
	Profiles  []KeelRoleProfile `json:"profiles"`
}

// KeelOverview is the fleet walk-through for the Configuration page.
type KeelOverview struct {
	Devices           int          `json:"devices"`
	Reporting         int          `json:"reporting"`
	StaleAfterSeconds int          `json:"stale_after_seconds"`
	Roles             []KeelRole   `json:"roles"`
	Failed            []KeelDevice `json:"failed"`
	Pending           []KeelDevice `json:"pending"`
	Warned            []KeelDevice `json:"warned"`
	Stale             []KeelDevice `json:"stale"`
}

// KeelSettingsVariant is one distinct effective configuration of a profile.
type KeelSettingsVariant struct {
	Enabled  bool            `json:"enabled"`
	Settings json.RawMessage `json:"settings"`
	Devices  int             `json:"devices"`
	Serials  []string        `json:"serials"`
}

// KeelRoleSettings is the effective settings of one profile across the
// devices whose leaf role is Role, taken from each device's latest report.
type KeelRoleSettings struct {
	Role     string                `json:"role"`
	Profile  string                `json:"profile"`
	Devices  int                   `json:"devices"`
	Missing  int                   `json:"missing"`
	Variants []KeelSettingsVariant `json:"variants"`
}
