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
// still does not send the Terraform client header. keel:admin (clearing a
// device key) is admin only, through "*".
func ScopesForRole(role string) map[string]bool {
	read := []string{
		"config:read", "jobs:read", "runners:read", "munki:read",
		"osquery:read", "audit:read", "logs:read", "vuln:read", "keel:read",
		"releases:read",
	}
	switch role {
	case RoleAdmin:
		return map[string]bool{"*": true}
	case RoleOperator:
		set := map[string]bool{}
		for _, s := range read {
			set[s] = true
		}
		// releases:update decides release reviews (rush, normal track, reject),
		// next to munki:write, which already promotes by hand.
		for _, s := range []string{"jobs:write", "runners:write", "munki:write", "osquery:write", "vuln:write", "releases:update"} {
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

// MapRole picks the highest built-in role whose group is in groups. Custom
// roles are resolved by ResolveAccess; this stays for callers that only know
// the built-in three.
func MapRole(groups []string, bindings []Binding) (string, bool) {
	a, ok := ResolveAccess(groups, bindings, nil)
	if !ok {
		return "", false
	}
	if r := a.Primary(); BuiltinRole(r) {
		return r, true
	}
	return "", false
}
