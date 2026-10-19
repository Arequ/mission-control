// Package store is the persistence boundary for Mission Control.
// Postgres is the production implementation. Memory backs unit tests.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/config"
)

// Sentinel errors handlers translate into HTTP statuses.
var (
	ErrNotFound     = errors.New("not found")
	ErrUnauthorized = errors.New("unauthorized")
	ErrConflict     = errors.New("conflict")
	ErrInvalid      = errors.New("invalid")
)

// Device is one enrolled endpoint.
type Device struct {
	ID               string                     `json:"id"`
	HostIdentifier   string                     `json:"hostIdentifier"`
	Hostname         string                     `json:"hostname"`
	ComputerName     string                     `json:"computerName"`
	UUID             string                     `json:"uuid"`
	HardwareSerial   string                     `json:"hardwareSerial"`
	HardwareModel    string                     `json:"hardwareModel"`
	HardwareVendor   string                     `json:"hardwareVendor"`
	CPUBrand         string                     `json:"cpuBrand"`
	CPUPhysicalCores int                        `json:"cpuPhysicalCores"`
	PhysicalMemory   int64                      `json:"physicalMemory"`
	Platform         string                     `json:"platform"`
	OSName           string                     `json:"osName"`
	OSVersion        string                     `json:"osVersion"`
	OSBuild          string                     `json:"osBuild"`
	OSQueryVersion   string                     `json:"osqueryVersion"`
	PrimaryUser      string                     `json:"primaryUser"`
	ConfigHash       string                     `json:"configHash"`
	ConfigDrift      bool                       `json:"configDrift"`
	Labels           []string                   `json:"labels"`
	Inventory        map[string]json.RawMessage `json:"inventory,omitempty"`
	LastSeenAt       *time.Time                 `json:"lastSeenAt,omitempty"`
	EnrolledAt       time.Time                  `json:"enrolledAt"`
	UpdatedAt        time.Time                  `json:"updatedAt"`
	NodeKeyHash      string                     `json:"-"`
}

// App is one installed application on a device.
type App struct {
	Name     string `json:"name"`
	BundleID string `json:"bundleId"`
	Path     string `json:"path"`
	Version  string `json:"version"`
}

// QueryResult is one scheduled-query log line.
type QueryResult struct {
	Name        string          `json:"name"`
	CollectedAt time.Time       `json:"collectedAt"`
	Snapshot    json.RawMessage `json:"snapshot,omitempty"`
	Added       json.RawMessage `json:"added,omitempty"`
	Removed     json.RawMessage `json:"removed,omitempty"`
}

// LabelUpdate sets or clears a single label membership.
type LabelUpdate struct {
	Name   string
	Member bool
}

// DeviceFilter controls list queries.
type DeviceFilter struct {
	Query  string
	Limit  int
	Offset int
}

// NamedCount is a fleet aggregate bucket.
type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// AppCount is how many devices report an application name.
type AppCount struct {
	Name    string `json:"name"`
	Devices int    `json:"devices"`
}

// FleetSummary is the dashboard payload.
type FleetSummary struct {
	Devices     int          `json:"devices"`
	Online      int          `json:"online"`
	Offline     int          `json:"offline"`
	ConfigDrift int          `json:"configDrift"`
	Platforms   []NamedCount `json:"platforms"`
	OSVersions  []NamedCount `json:"osVersions"`
	Models      []NamedCount `json:"models"`
	TopApps     []AppCount   `json:"topApps"`
	Recent      []Device     `json:"recent"`
	GeneratedAt time.Time    `json:"generatedAt"`
}

// LiveTarget is one device's progress on a distributed query.
type LiveTarget struct {
	DeviceID      string          `json:"deviceId"`
	Hostname      string          `json:"hostname"`
	Status        string          `json:"status"`
	Results       json.RawMessage `json:"results,omitempty"`
	OSQueryStatus *int            `json:"osqueryStatus,omitempty"`
}

// LiveQuery is an on-demand distributed query.
type LiveQuery struct {
	ID        string       `json:"id"`
	SQL       string       `json:"sql"`
	CreatedBy string       `json:"createdBy,omitempty"`
	CreatedAt time.Time    `json:"createdAt"`
	Targets   []LiveTarget `json:"targets,omitempty"`
}

// Runner is a registered AutoPkg worker.
type Runner struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Labels         map[string]string `json:"labels,omitempty"`
	AutoPkgVersion string            `json:"autopkgVersion,omitempty"`
	OSVersion      string            `json:"osVersion,omitempty"`
	LastSeenAt     *time.Time        `json:"lastSeenAt,omitempty"`
	CreatedAt      time.Time         `json:"createdAt"`
	Token          string            `json:"token,omitempty"`
}

// RunnerHeartbeat is the metadata a runner reports while polling.
type RunnerHeartbeat struct {
	Labels         map[string]string
	AutoPkgVersion string
	OSVersion      string
}

// Job is one AutoPkg pipeline run sitting in the queue.
type Job struct {
	ID           string         `json:"id"`
	PipelineName string         `json:"pipelineName"`
	Status       string         `json:"status"`
	RunnerID     string         `json:"runnerId,omitempty"`
	Spec         map[string]any `json:"spec,omitempty"`
	Logs         string         `json:"logs,omitempty"`
	Result       map[string]any `json:"result,omitempty"`
	CreatedAt    time.Time      `json:"createdAt"`
	StartedAt    *time.Time     `json:"startedAt,omitempty"`
	FinishedAt   *time.Time     `json:"finishedAt,omitempty"`
}

// Store is everything the HTTP layer needs from persistence.
type Store interface {
	config.ResourceStore

	EnsureToken(ctx context.Context, name, token, role string) error
	AuthenticateToken(ctx context.Context, token string) (auth.Principal, error)
	CreateToken(ctx context.Context, name, role string) (plaintext string, principal auth.Principal, err error)

	EnrollDevice(ctx context.Context, nodeKey string, incoming Device) (Device, error)
	DeviceByNodeKey(ctx context.Context, nodeKey string) (Device, bool, error)
	TouchDevice(ctx context.Context, id string, configHash string) error
	ApplyInventory(ctx context.Context, id string, patch Device, snapshots map[string]json.RawMessage, apps *[]App, labels []LabelUpdate) error
	ListDevices(ctx context.Context, filter DeviceFilter) ([]Device, error)
	GetDevice(ctx context.Context, id string) (Device, error)
	ListApps(ctx context.Context, deviceID string) ([]App, error)
	ListResults(ctx context.Context, deviceID string, limit int) ([]QueryResult, error)
	AddResult(ctx context.Context, deviceID string, result QueryResult) error
	AppCounts(ctx context.Context, limit int) ([]AppCount, error)
	FleetSummary(ctx context.Context, expectedConfigHash map[string]string) (FleetSummary, error)

	CreateLiveQuery(ctx context.Context, sql string, createdBy string, deviceIDs []string) (LiveQuery, error)
	ListLiveQueries(ctx context.Context) ([]LiveQuery, error)
	GetLiveQuery(ctx context.Context, id string) (LiveQuery, error)
	PendingQueries(ctx context.Context, deviceID string) (map[string]string, error)
	WriteQueryResults(ctx context.Context, deviceID string, results map[string]json.RawMessage, statuses map[string]int) error

	CreateRunner(ctx context.Context, name string, labels map[string]string) (Runner, error)
	AuthenticateRunner(ctx context.Context, token string) (Runner, error)
	HeartbeatRunner(ctx context.Context, id string, hb RunnerHeartbeat) error
	ListRunners(ctx context.Context) ([]Runner, error)

	CreateJob(ctx context.Context, pipeline string, spec map[string]any) (Job, error)
	ListJobs(ctx context.Context) ([]Job, error)
	GetJob(ctx context.Context, id string) (Job, error)
	ClaimJob(ctx context.Context, runnerID string) (Job, bool, error)
	AppendJobLog(ctx context.Context, id, runnerID, chunk string) error
	FinishJob(ctx context.Context, id, runnerID, status, logs string, result map[string]any) error
}
