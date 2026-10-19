package model

import "time"

// ConditionalItem is one Munki manifest conditional_items dictionary.
type ConditionalItem struct {
	Condition         string   `json:"condition"`
	ManagedInstalls   []string `json:"managed_installs"`
	OptionalInstalls  []string `json:"optional_installs"`
	ManagedUninstalls []string `json:"managed_uninstalls"`
	IncludedManifests []string `json:"included_manifests"`
}

// MunkiEnrollment is a shared client credential. Secret is write-only.
type MunkiEnrollment struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret,omitempty"`
	Manifest  string    `json:"manifest"`
	Enabled   bool      `json:"enabled"`
	ManagedBy string    `json:"managed_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Public clears the write-only secret.
func (e MunkiEnrollment) Public() MunkiEnrollment {
	e.Secret = ""
	return e
}

// MunkiClient is a per-device credential and manifest binding.
// Token is write-only. An empty token means the device authenticates with
// the enrollment secret or the enrollment-derived token.
type MunkiClient struct {
	ID           string    `json:"id"`
	Serial       string    `json:"serial"`
	EnrollmentID string    `json:"enrollment_id"`
	Token        string    `json:"token,omitempty"`
	Manifest     string    `json:"manifest"`
	Enabled      bool      `json:"enabled"`
	ManagedBy    string    `json:"managed_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Public clears the write-only token.
func (c MunkiClient) Public() MunkiClient {
	c.Token = ""
	return c
}

// MunkiCard is the device-page summary of the latest check-in.
type MunkiCard struct {
	Status          string     `json:"status"`
	LastRunStart    *time.Time `json:"last_run_start,omitempty"`
	LastRunEnd      *time.Time `json:"last_run_end,omitempty"`
	Pending         int        `json:"pending"`
	PendingInstalls []string   `json:"pending_installs"`
	PendingRemovals []string   `json:"pending_removals"`
	Errors          []string   `json:"errors"`
	Warnings        []string   `json:"warnings"`
	MunkiVersion    string     `json:"munki_version"`
	ConsoleUser     string     `json:"console_user"`
	Manifest        string     `json:"manifest"`
}
