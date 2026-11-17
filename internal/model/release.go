package model

import (
	"encoding/json"
	"time"
)

// ReleaseReview is the human gate on one imported build. Priority and the CVE
// lists come from the vulnerability feeds; Notes come from the release-notes
// advisor and are advisory. Only a person with releases:update decides.
type ReleaseReview struct {
	ID              string          `json:"id"`
	PackageID       string          `json:"package_id"`
	Name            string          `json:"name"`
	DisplayName     string          `json:"display_name"`
	Version         string          `json:"version"`
	BaselineVersion string          `json:"baseline_version"`
	Catalog         string          `json:"catalog"`
	FinalCatalog    string          `json:"final_catalog"`
	SoftwareKey     string          `json:"software_key"`
	Priority        string          `json:"priority"`
	Reasons         []string        `json:"reasons"`
	Fixed           json.RawMessage `json:"fixed"`
	StillOpen       json.RawMessage `json:"still_open"`
	ExposedDevices  int             `json:"exposed_devices"`
	Status          string          `json:"status"`
	DecidedBy       string          `json:"decided_by,omitempty"`
	DecidedAt       *time.Time      `json:"decided_at,omitempty"`
	DecisionNote    string          `json:"decision_note,omitempty"`
	Notes           ReleaseNotes    `json:"notes"`
	CreatedAt       time.Time       `json:"created_at"`
	EvaluatedAt     time.Time       `json:"evaluated_at"`
}

// ReleaseNotes is what the advisor found. Recommendation is the model's own
// read and never changes Priority.
type ReleaseNotes struct {
	Status         string     `json:"status"`
	Summary        string     `json:"summary"`
	Recommendation string     `json:"recommendation"`
	Rationale      string     `json:"rationale"`
	SecurityFixes  bool       `json:"security_fixes"`
	CVEs           []string   `json:"cves"`
	Sources        []string   `json:"sources"`
	Model          string     `json:"model,omitempty"`
	Error          string     `json:"error,omitempty"`
	Attempts       int        `json:"attempts"`
	At             *time.Time `json:"at,omitempty"`
}

// ReleaseNotesInput is the advisor's submission. The server validates every field.
type ReleaseNotesInput struct {
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation"`
	Rationale      string   `json:"rationale"`
	SecurityFixes  bool     `json:"security_fixes"`
	CVEs           []string `json:"cves"`
	Sources        []string `json:"sources"`
	Model          string   `json:"model"`
}

// ReleaseNotesTask is a leased review for the advisor to research.
type ReleaseNotesTask struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	DisplayName      string `json:"display_name"`
	Developer        string `json:"developer"`
	Description      string `json:"description"`
	Version          string `json:"version"`
	BaselineVersion  string `json:"baseline_version"`
	RecipeIdentifier string `json:"recipe_identifier"`
	LeaseSeconds     int    `json:"lease_seconds"`
}

// ReleaseDecision is a reviewer's call. rush moves the build to the final
// catalog now; normal leaves it on the soak schedule; reject pulls it out of
// every catalog clients read.
type ReleaseDecision struct {
	Decision string `json:"decision"`
	Note     string `json:"note"`
}
