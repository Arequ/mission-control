// Package model holds API and domain types shared by the server.
package model

import (
	"encoding/json"
	"time"
)

// Principal is the caller recorded in the audit log.
type Principal struct {
	Kind   string          `json:"kind"`
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Scopes map[string]bool `json:"-"`
}

// System is the actor for scheduler and promotion passes.
var System = Principal{Kind: "system", Name: "scheduler", ID: "system"}

// Allows reports whether the principal has the scope. config:write implies config:read.
func (p Principal) Allows(scope string) bool {
	if p.Scopes["*"] || p.Scopes[scope] {
		return true
	}
	const read = ":read"
	if len(scope) > len(read) && scope[len(scope)-len(read):] == read {
		write := scope[:len(scope)-len(read)] + ":write"
		return p.Scopes[write]
	}
	return false
}

// RecipeRepo is a git repository of AutoPkg recipes.
type RecipeRepo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Ref       string    `json:"ref"`
	ManagedBy string    `json:"managed_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Recipe is an AutoPkg recipe override managed as config.
type Recipe struct {
	ID           string          `json:"id"`
	Identifier   string          `json:"identifier"`
	Name         string          `json:"name"`
	RepoID       *string         `json:"repo_id"`
	Enabled      bool            `json:"enabled"`
	Override     string          `json:"override"`
	TrustInfo    json.RawMessage `json:"trust_info"`
	RunnerPoolID *string         `json:"runner_pool_id"`
	Labels       []string        `json:"labels"`
	ManagedBy    string          `json:"managed_by"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	LastJob      *JobSummary     `json:"last_job,omitempty"`
}

// Schedule runs a recipe on a five-field cron expression.
type Schedule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	RecipeID         string     `json:"recipe_id"`
	RecipeIdentifier string     `json:"recipe_identifier,omitempty"`
	Cron             string     `json:"cron"`
	Enabled          bool       `json:"enabled"`
	ManagedBy        string     `json:"managed_by"`
	LastEnqueuedAt   *time.Time `json:"last_enqueued_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// PipelineSettings are fleet-wide AutoPkg run limits. There is one row.
type PipelineSettings struct {
	ID                   string    `json:"id"`
	MaxConcurrency       int       `json:"max_concurrency"`
	PerRunnerParallelism int       `json:"per_runner_parallelism"`
	TimeoutSeconds       int       `json:"timeout_seconds"`
	MaxRetries           int       `json:"max_retries"`
	LeaseSeconds         int       `json:"lease_seconds"`
	ManagedBy            string    `json:"managed_by"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// PromotionRule moves pkginfo from one catalog to another after a soak.
type PromotionRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	FromCatalog string    `json:"from_catalog"`
	ToCatalog   string    `json:"to_catalog"`
	SoakDays    int       `json:"soak_days"`
	ManualHold  bool      `json:"manual_hold"`
	Enabled     bool      `json:"enabled"`
	ManagedBy   string    `json:"managed_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RunnerPool groups runners by name and labels.
type RunnerPool struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Labels      []string  `json:"labels"`
	ManagedBy   string    `json:"managed_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Manifest is a Munki manifest. It is config, served read-only to clients.
type Manifest struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Catalogs          []string  `json:"catalogs"`
	IncludedManifests []string  `json:"included_manifests"`
	ManagedInstalls   []string  `json:"managed_installs"`
	OptionalInstalls  []string  `json:"optional_installs"`
	ManagedUninstalls []string  `json:"managed_uninstalls"`
	ManagedBy         string    `json:"managed_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Runner is a registered mc-runner agent.
type Runner struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	PoolID          *string    `json:"pool_id"`
	PoolName        string     `json:"pool_name,omitempty"`
	Labels          []string   `json:"labels"`
	Hostname        string     `json:"hostname"`
	OSVersion       string     `json:"os_version"`
	AutopkgVersion  string     `json:"autopkg_version"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at,omitempty"`
	RegisteredAt    time.Time  `json:"registered_at"`
	Status          string     `json:"status"`
	ActiveJobs      int        `json:"active_jobs"`
}

// Job is one AutoPkg run.
type Job struct {
	ID               string     `json:"id"`
	RecipeID         string     `json:"recipe_id"`
	RecipeIdentifier string     `json:"recipe_identifier,omitempty"`
	RecipeName       string     `json:"recipe_name,omitempty"`
	ScheduleID       *string    `json:"schedule_id,omitempty"`
	Trigger          string     `json:"trigger"`
	Status           string     `json:"status"`
	Result           string     `json:"result,omitempty"`
	Attempt          int        `json:"attempt"`
	MaxAttempts      int        `json:"max_attempts"`
	RunnerID         *string    `json:"runner_id,omitempty"`
	RunnerName       string     `json:"runner_name,omitempty"`
	LeaseExpiresAt   *time.Time `json:"lease_expires_at,omitempty"`
	TimeoutSeconds   int        `json:"timeout_seconds"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	Error            string     `json:"error,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Logs             []LogLine  `json:"logs,omitempty"`
}

// JobSummary is the latest run attached to a recipe.
type JobSummary struct {
	ID         string     `json:"id"`
	Status     string     `json:"status"`
	Result     string     `json:"result,omitempty"`
	Trigger    string     `json:"trigger"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// LogLine is one streamed line of autopkg output.
type LogLine struct {
	ID     int64     `json:"id"`
	Stream string    `json:"stream"`
	Line   string    `json:"line"`
	At     time.Time `json:"at"`
}

// Lease is what a runner receives when it takes a job.
type Lease struct {
	JobID          string       `json:"job_id"`
	Attempt        int          `json:"attempt"`
	LeaseExpiresAt time.Time    `json:"lease_expires_at"`
	LeaseSeconds   int          `json:"lease_seconds"`
	TimeoutSeconds int          `json:"timeout_seconds"`
	Recipe         LeaseRecipe  `json:"recipe"`
	Repos          []RecipeRepo `json:"repos"`
}

// LeaseRecipe is the override payload for one run.
type LeaseRecipe struct {
	ID         string          `json:"id"`
	Identifier string          `json:"identifier"`
	Name       string          `json:"name"`
	Override   string          `json:"override"`
	TrustInfo  json.RawMessage `json:"trust_info"`
}

// Package is an imported Munki item.
type Package struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Version          string          `json:"version"`
	Catalog          string          `json:"catalog"`
	Filename         string          `json:"filename"`
	RecipeIdentifier string          `json:"recipe_identifier,omitempty"`
	JobID            *string         `json:"job_id,omitempty"`
	SoakStartedAt    time.Time       `json:"soak_started_at"`
	SoakEndsAt       *time.Time      `json:"soak_ends_at,omitempty"`
	SoakStatus       string          `json:"soak_status"`
	PromotedAt       *time.Time      `json:"promoted_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	Pkginfo          json.RawMessage `json:"pkginfo,omitempty"`
}

// Catalog is a generated Munki catalog.
type Catalog struct {
	Name        string     `json:"name"`
	ItemCount   int        `json:"item_count"`
	GeneratedAt *time.Time `json:"generated_at,omitempty"`
}

// AuditEntry records who changed what.
type AuditEntry struct {
	ID           int64           `json:"id"`
	At           time.Time       `json:"at"`
	Actor        string          `json:"actor"`
	ActorKind    string          `json:"actor_kind"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Detail       json.RawMessage `json:"detail"`
}

// Token is an API token. The raw secret is only returned at creation.
type Token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Token      string     `json:"token,omitempty"`
}

// BootstrapToken registers runners.
type BootstrapToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Token     string     `json:"token,omitempty"`
}

// ImportResult is the outcome of uploading a built package.
type ImportResult struct {
	Imported bool     `json:"imported"`
	Reason   string   `json:"reason,omitempty"`
	Package  *Package `json:"package,omitempty"`
}
