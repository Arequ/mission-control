// Package config implements Mission Control's declarative resource model.
//
// Documents use a Kubernetes-style envelope (apiVersion, kind, metadata, spec)
// written as YAML. The server validates them, diffs them against stored state,
// and applies the result. See docs/ARCHITECTURE.md for why this shape was
// chosen over CUE.
package config

import (
	"context"
	"time"
)

// APIVersion is the only resource version accepted in this foundation.
const APIVersion = "missioncontrol.io/v1"

// Resource kinds. Osquery and Label kinds are reconciled into agent config.
// The remaining kinds are stored and exposed by the API; their controllers
// arrive in later phases.
const (
	KindOsqueryQuery    = "OsqueryQuery"
	KindOsqueryPack     = "OsqueryPack"
	KindLabel           = "Label"
	KindMunkiRepo       = "MunkiRepo"
	KindMunkiCatalog    = "MunkiCatalog"
	KindMunkiManifest   = "MunkiManifest"
	KindMunkiPkgInfo    = "MunkiPkgInfo"
	KindAutoPkgRepo     = "AutoPkgRepo"
	KindAutoPkgPipeline = "AutoPkgPipeline"
	KindRole            = "Role"
	KindIntegration     = "Integration"
)

// Change operations produced by the planner.
const (
	OpCreate    = "create"
	OpUpdate    = "update"
	OpDelete    = "delete"
	OpUnchanged = "unchanged"
)

// Ownership of a resource.
const (
	ManagedByConfig = "config"
	ManagedByAPI    = "api"
)

// Resource is one declarative document.
type Resource struct {
	APIVersion string         `json:"apiVersion" yaml:"apiVersion"`
	Kind       string         `json:"kind" yaml:"kind"`
	Metadata   Metadata       `json:"metadata" yaml:"metadata"`
	Spec       map[string]any `json:"spec" yaml:"spec"`
	Status     *Status        `json:"status,omitempty" yaml:"status,omitempty"`
	// SourcePath is set by the loader and may be sent by clients. It is not
	// part of the on-disk schema beyond being ignored if present.
	SourcePath string `json:"sourcePath,omitempty" yaml:"-"`
}

// Metadata identifies a resource. Name and Namespace form the identity.
type Metadata struct {
	Name        string            `json:"name" yaml:"name"`
	Namespace   string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Status is server-owned. Files may not set it; the loader strips it.
type Status struct {
	ManagedBy  string     `json:"managedBy,omitempty" yaml:"managedBy,omitempty"`
	Generation int64      `json:"generation,omitempty" yaml:"generation,omitempty"`
	SpecHash   string     `json:"specHash,omitempty" yaml:"specHash,omitempty"`
	SourcePath string     `json:"sourcePath,omitempty" yaml:"sourcePath,omitempty"`
	AppliedAt  *time.Time `json:"appliedAt,omitempty" yaml:"appliedAt,omitempty"`
	Drift      bool       `json:"drift,omitempty" yaml:"drift,omitempty"`
	Message    string     `json:"message,omitempty" yaml:"message,omitempty"`
}

// ResourceID is the identity of a resource.
type ResourceID struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// ID returns the resource identity, defaulting the namespace.
func (r Resource) ID() ResourceID {
	ns := r.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	return ResourceID{Kind: r.Kind, Namespace: ns, Name: r.Metadata.Name}
}

func (id ResourceID) String() string {
	return id.Kind + "/" + id.Namespace + "/" + id.Name
}

// Key is the map key form of an identity.
func (id ResourceID) Key() string {
	return id.String()
}

// Diagnostic is one validation error.
type Diagnostic struct {
	Path    string `json:"path,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Name    string `json:"name,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// Change is one planned mutation. Resource is set for create and update.
type Change struct {
	Op        string    `json:"op"`
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Diff      []string  `json:"diff,omitempty"`
	Resource  *Resource `json:"resource,omitempty"`
}

// Plan is the result of comparing desired resources to current state.
type Plan struct {
	Changes []Change    `json:"changes"`
	Summary PlanSummary `json:"summary"`
}

// PlanSummary counts operations. Unchanged resources are omitted from Changes
// unless the caller asked for a verbose plan.
type PlanSummary struct {
	Create    int `json:"create"`
	Update    int `json:"update"`
	Delete    int `json:"delete"`
	Unchanged int `json:"unchanged"`
}

// ApplyOptions controls planning and apply.
type ApplyOptions struct {
	// Prune deletes config-managed resources missing from the desired set.
	// Directory sync prunes. The CLI does not, unless --prune is set.
	Prune bool
	// Verbose includes unchanged resources in Changes.
	Verbose bool
	// ManagedBy is stamped on upserts. Empty means config.
	ManagedBy string
}

// ResourceStore is the slice of persistence the reconciler needs.
type ResourceStore interface {
	ListResources(ctx context.Context) ([]Resource, error)
	ApplyChanges(ctx context.Context, changes []Change) error
}
