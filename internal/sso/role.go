// Package sso implements OIDC login for the web UI.
package sso

// Roles that map onto API token scopes. admin is every scope.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// ValidRole reports whether role is one of the three UI roles.
func ValidRole(role string) bool {
	switch role {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	default:
		return false
	}
}

// ScopesForRole returns the API scopes a role may use.
// config:write stays off viewer and operator so the UI cannot edit GitOps
// resources. admin includes "*", which Allows treats as every scope. The UI
// still does not send the Terraform client header.
func ScopesForRole(role string) map[string]bool {
	read := []string{
		"config:read", "jobs:read", "runners:read", "munki:read",
		"osquery:read", "audit:read", "logs:read", "vuln:read",
	}
	switch role {
	case RoleAdmin:
		return map[string]bool{"*": true}
	case RoleOperator:
		set := map[string]bool{}
		for _, s := range read {
			set[s] = true
		}
		for _, s := range []string{"jobs:write", "runners:write", "munki:write", "osquery:write", "vuln:write"} {
			set[s] = true
		}
		return set
	default:
		set := map[string]bool{}
		for _, s := range read {
			set[s] = true
		}
		return set
	}
}

// Binding is one group-to-role row.
type Binding struct {
	Group string
	Role  string
}

// MapRole picks the highest role whose group is in groups.
// A binding group of "*" matches every authenticated user of that provider.
// No match returns false. Comparison is exact, after trimming is the caller's job.
func MapRole(groups []string, bindings []Binding) (string, bool) {
	rank := map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}
	have := map[string]bool{}
	for _, g := range groups {
		have[g] = true
	}
	best := 0
	role := ""
	for _, b := range bindings {
		if !ValidRole(b.Role) {
			continue
		}
		if b.Group != "*" && !have[b.Group] {
			continue
		}
		if rank[b.Role] > best {
			best = rank[b.Role]
			role = b.Role
		}
	}
	return role, best > 0
}
