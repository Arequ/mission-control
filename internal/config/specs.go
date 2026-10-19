package config

// Typed specs. Validation decodes spec into these structs with unknown fields
// rejected, then writes the canonical form back onto the resource.

// OsqueryQuerySpec is a single scheduled query.
type OsqueryQuerySpec struct {
	Query       string `json:"query"`
	Interval    int    `json:"interval"`
	Platform    string `json:"platform,omitempty"`
	Snapshot    *bool  `json:"snapshot,omitempty"`
	Removed     *bool  `json:"removed,omitempty"`
	Description string `json:"description,omitempty"`
}

// PackQuery is a query inside an OsqueryPack.
type PackQuery struct {
	Name        string `json:"name"`
	Query       string `json:"query"`
	Interval    int    `json:"interval"`
	Platform    string `json:"platform,omitempty"`
	Snapshot    *bool  `json:"snapshot,omitempty"`
	Removed     *bool  `json:"removed,omitempty"`
	Description string `json:"description,omitempty"`
}

// OsqueryPackSpec groups queries into an osquery pack.
type OsqueryPackSpec struct {
	Platform    string      `json:"platform,omitempty"`
	Description string      `json:"description,omitempty"`
	Discovery   []string    `json:"discovery,omitempty"`
	Queries     []PackQuery `json:"queries"`
}

// LabelSpec is an osquery query whose rows mean "this device is a member".
type LabelSpec struct {
	Query       string `json:"query"`
	Interval    int    `json:"interval"`
	Platform    string `json:"platform,omitempty"`
	Description string `json:"description,omitempty"`
}

// MunkiRepoSpec describes a served Munki repository. Serving itself is a later phase.
type MunkiRepoSpec struct {
	Description   string `json:"description,omitempty"`
	PublicBaseURL string `json:"publicBaseURL,omitempty"`
}

// MunkiCatalogSpec is a named catalog, optionally with a soak hint used by promotion.
type MunkiCatalogSpec struct {
	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description,omitempty"`
	SoakHours   *int   `json:"soakHours,omitempty"`
}

// MunkiManifestSpec is the declarative form of a Munki manifest.
type MunkiManifestSpec struct {
	DisplayName       string   `json:"displayName,omitempty"`
	Description       string   `json:"description,omitempty"`
	Catalog           string   `json:"catalog"`
	IncludedManifests []string `json:"includedManifests,omitempty"`
	ManagedInstalls   []string `json:"managedInstalls,omitempty"`
	ManagedUninstalls []string `json:"managedUninstalls,omitempty"`
	OptionalInstalls  []string `json:"optionalInstalls,omitempty"`
	ManagedUpdates    []string `json:"managedUpdates,omitempty"`
}

// MunkiPkgInfoSpec is the declarative form of a pkginfo item.
type MunkiPkgInfoSpec struct {
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	DisplayName         string   `json:"displayName,omitempty"`
	Description         string   `json:"description,omitempty"`
	Catalogs            []string `json:"catalogs"`
	InstallerType       string   `json:"installerType,omitempty"`
	UnattendedInstall   *bool    `json:"unattendedInstall,omitempty"`
	UnattendedUninstall *bool    `json:"unattendedUninstall,omitempty"`
	PackageKey          string   `json:"packageKey,omitempty"`
}

// AutoPkgRepoSpec points at a recipe repository.
type AutoPkgRepoSpec struct {
	URL         string `json:"url"`
	Branch      string `json:"branch,omitempty"`
	Description string `json:"description,omitempty"`
}

// PromotionSpec moves a built package from testing to production after a soak.
type PromotionSpec struct {
	TestingCatalog    string `json:"testingCatalog"`
	ProductionCatalog string `json:"productionCatalog"`
	SoakHours         int    `json:"soakHours"`
}

// TrustSpec records whether the runner must verify AutoPkg trust info.
type TrustSpec struct {
	Verify bool `json:"verify"`
}

// AutoPkgPipelineSpec is a scheduled (or manual) recipe run plus promotion policy.
type AutoPkgPipelineSpec struct {
	Description string         `json:"description,omitempty"`
	Repo        string         `json:"repo"`
	Recipe      string         `json:"recipe"`
	Schedule    string         `json:"schedule,omitempty"`
	Promotion   *PromotionSpec `json:"promotion,omitempty"`
	Trust       *TrustSpec     `json:"trust,omitempty"`
}

// RoleRule is one permission grant. Enforcement of Role resources is a later phase;
// token roles are what the API enforces today.
type RoleRule struct {
	Verbs     []string `json:"verbs"`
	Resources []string `json:"resources"`
}

// RoleSpec is a declarative RBAC role.
type RoleSpec struct {
	Description string     `json:"description,omitempty"`
	Rules       []RoleRule `json:"rules"`
}

// IntegrationSpec declares an outbound integration. urlRef is preferred so
// secrets stay out of git.
type IntegrationSpec struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	URLRef      string `json:"urlRef,omitempty"`
}
