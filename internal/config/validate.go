package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	nameRE         = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	queryNameRE    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,62}$`)
	cronFieldRE    = regexp.MustCompile(`^(\*|[0-9]+|[0-9]+-[0-9]+|\*/[0-9]+)(/[0-9]+)?(,[0-9]+)*$|^\*$|^[0-9*,/-]+$`)
	installerTypes = map[string]bool{
		"": true, "package": true, "copy_from_dmg": true, "appdmg": true,
		"profile": true, "nopkg": true, "apple_update_metadata": true, "startosinstall": true,
	}
	integrationTypes = map[string]bool{"webhook": true, "slack": true, "generic": true}
	roleVerbs        = map[string]bool{"get": true, "list": true, "watch": true, "create": true, "update": true, "delete": true}
)

// Validate normalizes resources and returns every problem it finds.
// On success, each spec is replaced with its canonical typed form.
func Validate(resources []Resource) []Diagnostic {
	var diags []Diagnostic
	seen := map[string]string{}
	for i := range resources {
		diags = append(diags, validateOne(&resources[i])...)
		id := resources[i].ID()
		key := id.Key()
		if resources[i].Metadata.Name == "" || resources[i].Kind == "" {
			continue
		}
		if prev, ok := seen[key]; ok {
			diags = append(diags, Diagnostic{
				Path:    resources[i].SourcePath,
				Kind:    resources[i].Kind,
				Name:    resources[i].Metadata.Name,
				Message: fmt.Sprintf("duplicate %s (also defined in %s)", id, prev),
			})
			continue
		}
		seen[key] = resources[i].SourcePath
	}
	return diags
}

func validateOne(r *Resource) []Diagnostic {
	var diags []Diagnostic
	add := func(field, msg string) {
		diags = append(diags, Diagnostic{
			Path:    r.SourcePath,
			Kind:    r.Kind,
			Name:    r.Metadata.Name,
			Field:   field,
			Message: msg,
		})
	}
	if r.APIVersion != APIVersion {
		add("apiVersion", fmt.Sprintf("must be %s", APIVersion))
	}
	if !knownKind(r.Kind) {
		add("kind", "unknown kind")
	}
	if !nameRE.MatchString(r.Metadata.Name) {
		add("metadata.name", "must be a lowercase DNS label (start and end with a letter or digit, max 63 characters)")
	}
	if r.Metadata.Namespace == "" {
		r.Metadata.Namespace = "default"
	} else if !nameRE.MatchString(r.Metadata.Namespace) {
		add("metadata.namespace", "must be a lowercase DNS label")
	}
	if r.Spec == nil {
		add("spec", "required")
		return diags
	}

	switch r.Kind {
	case KindOsqueryQuery:
		var spec OsqueryQuerySpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		validateQuery(add, "spec", spec.Query, spec.Interval, spec.Platform)
		r.Spec = mustMap(add, spec)
	case KindOsqueryPack:
		var spec OsqueryPackSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if !validPlatform(spec.Platform) {
			add("spec.platform", "must be darwin, windows, linux, posix, or empty")
		}
		if len(spec.Queries) == 0 {
			add("spec.queries", "at least one query is required")
		}
		names := map[string]bool{}
		for i, q := range spec.Queries {
			field := fmt.Sprintf("spec.queries[%d]", i)
			if !queryNameRE.MatchString(q.Name) {
				add(field+".name", "must start with a letter and contain only letters, digits, underscore, or hyphen")
			}
			if names[q.Name] {
				add(field+".name", "duplicate query name in pack")
			}
			names[q.Name] = true
			validateQuery(add, field, q.Query, q.Interval, q.Platform)
		}
		for i, d := range spec.Discovery {
			if !looksLikeSelect(d) {
				add(fmt.Sprintf("spec.discovery[%d]", i), "must be a SELECT query")
			}
		}
		r.Spec = mustMap(add, spec)
	case KindLabel:
		var spec LabelSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		validateQuery(add, "spec", spec.Query, spec.Interval, spec.Platform)
		r.Spec = mustMap(add, spec)
	case KindMunkiRepo:
		var spec MunkiRepoSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if spec.PublicBaseURL != "" && !validHTTPURL(spec.PublicBaseURL) {
			add("spec.publicBaseURL", "must be an http(s) URL")
		}
		r.Spec = mustMap(add, spec)
	case KindMunkiCatalog:
		var spec MunkiCatalogSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if spec.SoakHours != nil && *spec.SoakHours < 0 {
			add("spec.soakHours", "must be >= 0")
		}
		r.Spec = mustMap(add, spec)
	case KindMunkiManifest:
		var spec MunkiManifestSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if strings.TrimSpace(spec.Catalog) == "" {
			add("spec.catalog", "required")
		}
		r.Spec = mustMap(add, spec)
	case KindMunkiPkgInfo:
		var spec MunkiPkgInfoSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if strings.TrimSpace(spec.Name) == "" {
			add("spec.name", "required")
		}
		if strings.TrimSpace(spec.Version) == "" {
			add("spec.version", "required")
		}
		if len(spec.Catalogs) == 0 {
			add("spec.catalogs", "at least one catalog is required")
		}
		if !installerTypes[spec.InstallerType] {
			add("spec.installerType", "unsupported installer type")
		}
		r.Spec = mustMap(add, spec)
	case KindAutoPkgRepo:
		var spec AutoPkgRepoSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if !validHTTPURL(spec.URL) {
			add("spec.url", "must be an http(s) URL")
		}
		r.Spec = mustMap(add, spec)
	case KindAutoPkgPipeline:
		var spec AutoPkgPipelineSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if !nameRE.MatchString(spec.Repo) {
			add("spec.repo", "must match an AutoPkgRepo metadata.name")
		}
		if strings.TrimSpace(spec.Recipe) == "" || strings.ContainsAny(spec.Recipe, " \t\n") {
			add("spec.recipe", "required and must not contain whitespace")
		}
		if spec.Schedule != "" && !validCron(spec.Schedule) {
			add("spec.schedule", "must be a 5-field cron expression")
		}
		if spec.Promotion != nil {
			if strings.TrimSpace(spec.Promotion.TestingCatalog) == "" {
				add("spec.promotion.testingCatalog", "required")
			}
			if strings.TrimSpace(spec.Promotion.ProductionCatalog) == "" {
				add("spec.promotion.productionCatalog", "required")
			}
			if spec.Promotion.SoakHours < 0 {
				add("spec.promotion.soakHours", "must be >= 0")
			}
		}
		r.Spec = mustMap(add, spec)
	case KindRole:
		var spec RoleSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if len(spec.Rules) == 0 {
			add("spec.rules", "at least one rule is required")
		}
		for i, rule := range spec.Rules {
			if len(rule.Verbs) == 0 {
				add(fmt.Sprintf("spec.rules[%d].verbs", i), "required")
			}
			for _, v := range rule.Verbs {
				if !roleVerbs[v] {
					add(fmt.Sprintf("spec.rules[%d].verbs", i), "unknown verb "+v)
				}
			}
			if len(rule.Resources) == 0 {
				add(fmt.Sprintf("spec.rules[%d].resources", i), "required")
			}
		}
		r.Spec = mustMap(add, spec)
	case KindIntegration:
		var spec IntegrationSpec
		if err := decodeSpec(r.Spec, &spec); err != nil {
			add("spec", err.Error())
			break
		}
		if !integrationTypes[spec.Type] {
			add("spec.type", "must be webhook, slack, or generic")
		}
		if spec.URL == "" && spec.URLRef == "" {
			add("spec.urlRef", "set urlRef (preferred) or url")
		}
		if spec.URL != "" && !validHTTPURL(spec.URL) {
			add("spec.url", "must be an http(s) URL")
		}
		if spec.URLRef != "" && !strings.HasPrefix(spec.URLRef, "env://") {
			add("spec.urlRef", "must look like env://VAR_NAME")
		}
		r.Spec = mustMap(add, spec)
	}
	return diags
}

func validateQuery(add func(string, string), prefix, query string, interval int, platform string) {
	if !looksLikeSelect(query) {
		add(prefix+".query", "must be a SELECT query")
	}
	if interval < 1 {
		add(prefix+".interval", "must be >= 1 second")
	}
	if !validPlatform(platform) {
		add(prefix+".platform", "must be darwin, windows, linux, posix, or empty")
	}
}

func looksLikeSelect(query string) bool {
	q := strings.TrimSpace(query)
	if q == "" {
		return false
	}
	upper := strings.ToUpper(q)
	return strings.HasPrefix(upper, "SELECT") || strings.HasPrefix(upper, "WITH")
}

func validPlatform(p string) bool {
	switch p {
	case "", "darwin", "windows", "linux", "posix":
		return true
	default:
		return false
	}
}

func validHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

func validCron(expr string) bool {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	for _, f := range fields {
		if !cronFieldRE.MatchString(f) {
			return false
		}
	}
	return true
}

func knownKind(kind string) bool {
	switch kind {
	case KindOsqueryQuery, KindOsqueryPack, KindLabel,
		KindMunkiRepo, KindMunkiCatalog, KindMunkiManifest, KindMunkiPkgInfo,
		KindAutoPkgRepo, KindAutoPkgPipeline, KindRole, KindIntegration:
		return true
	default:
		return false
	}
}

func mustMap(add func(string, string), v any) map[string]any {
	m, err := specMap(v)
	if err != nil {
		add("spec", err.Error())
		return map[string]any{}
	}
	return m
}
