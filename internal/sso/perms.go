package sso

import (
	"fmt"
	"sort"
	"strings"
)

// Areas are the parts of Mission Control a permission can name.
// rush is its own area so skipping the soak can be granted apart from
// deciding reviews: rush:update moves a HIGH build straight to production.
var Areas = []string{"audit", "config", "jobs", "keel", "logs", "munki", "osquery", "releases", "runners", "rush", "vuln"}

// Actions are read (view), write (create or trigger), and update (change or decide).
// Holding write or update on an area also allows read on it; write and update
// do not imply each other.
var Actions = []string{"read", "write", "update"}

// ValidPermission reports whether p is "<area>:<action>" from the lists above.
func ValidPermission(p string) bool {
	area, action, ok := strings.Cut(p, ":")
	if !ok {
		return false
	}
	return contains(Areas, area) && contains(Actions, action)
}

// CheckCustomPermission rejects permissions a Terraform-defined role may not grant.
// "*" is admin only. Config changes come from Terraform alone, so no browser
// role gets config:write or config:update.
func CheckCustomPermission(p string) error {
	if p == "*" {
		return fmt.Errorf("permission * is reserved for the built-in admin role")
	}
	if !ValidPermission(p) {
		return fmt.Errorf("permission %q must be <area>:<read|write|update>, area one of %s", p, strings.Join(Areas, ", "))
	}
	if p == "config:write" || p == "config:update" {
		return fmt.Errorf("permission %s is not grantable: configuration is applied by Terraform", p)
	}
	return nil
}

// BuiltinRole reports whether name is viewer, operator, or admin.
func BuiltinRole(name string) bool { return ValidRole(name) }

// Access is what a signed-in user may do: every role their groups matched,
// and the union of those roles' permissions.
type Access struct {
	Roles  []string
	Scopes map[string]bool
}

// Primary is the role shown in the UI: the highest built-in role held, else
// the first custom role by name.
func (a Access) Primary() string {
	rank := map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}
	best, out := 0, ""
	for _, r := range a.Roles {
		if rank[r] > best {
			best, out = rank[r], r
		}
	}
	if out != "" {
		return out
	}
	if len(a.Roles) > 0 {
		return a.Roles[0]
	}
	return ""
}

// Permissions lists the scopes in a stable order for the session endpoint.
func (a Access) Permissions() []string {
	out := make([]string, 0, len(a.Scopes))
	for s, on := range a.Scopes {
		if on {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ResolveAccess maps a user's groups through bindings. Every matching binding
// counts: a member of "IT Ops" and "IT Engineers" gets both roles' permissions.
// custom holds Terraform-defined roles by name. A binding to a role that no
// longer exists grants nothing. No match returns false.
func ResolveAccess(groups []string, bindings []Binding, custom map[string][]string) (Access, bool) {
	have := map[string]bool{}
	for _, g := range groups {
		have[g] = true
	}
	roles := map[string]bool{}
	scopes := map[string]bool{}
	for _, b := range bindings {
		if b.Group != "*" && !have[b.Group] {
			continue
		}
		switch {
		case BuiltinRole(b.Role):
			for s := range ScopesForRole(b.Role) {
				scopes[s] = true
			}
		default:
			perms, ok := custom[b.Role]
			if !ok {
				continue
			}
			for _, p := range perms {
				// Re-check at use: a row written before a rule tightened must not widen access.
				if CheckCustomPermission(p) == nil {
					scopes[p] = true
				}
			}
		}
		roles[b.Role] = true
	}
	if len(roles) == 0 {
		return Access{}, false
	}
	out := Access{Scopes: scopes}
	for r := range roles {
		out.Roles = append(out.Roles, r)
	}
	sort.Strings(out.Roles)
	return out, true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
