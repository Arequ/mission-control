package sso

import (
	"reflect"
	"testing"

	"github.com/Arequ/mission-control/internal/model"
)

func TestResolveAccessUnionsEveryMatchingRole(t *testing.T) {
	bindings := []Binding{
		{Group: "IT Ops", Role: "it-ops"},
		{Group: "IT Engineers", Role: "it-engineers"},
		{Group: "*", Role: RoleViewer},
		{Group: "Gone", Role: "deleted-role"},
	}
	custom := map[string][]string{
		"it-ops":       {"releases:update", "munki:read"},
		"it-engineers": {"jobs:write"},
	}
	a, ok := ResolveAccess([]string{"IT Ops", "IT Engineers", "Gone"}, bindings, custom)
	if !ok {
		t.Fatal("no access")
	}
	if want := []string{"it-engineers", "it-ops", "viewer"}; !reflect.DeepEqual(a.Roles, want) {
		t.Fatalf("roles %v", a.Roles)
	}
	for _, s := range []string{"releases:update", "munki:read", "jobs:write", "vuln:read"} {
		if !a.Scopes[s] {
			t.Fatalf("missing %s in %v", s, a.Permissions())
		}
	}
	if a.Primary() != RoleViewer {
		t.Fatalf("primary %s", a.Primary())
	}
}

func TestResolveAccessIgnoresUngrantablePermissions(t *testing.T) {
	// A row that predates the rule must not hand out config writes or *.
	custom := map[string][]string{"sneaky": {"config:write", "*", "munki:read"}}
	a, ok := ResolveAccess([]string{"g"}, []Binding{{Group: "g", Role: "sneaky"}}, custom)
	if !ok {
		t.Fatal("no access")
	}
	if a.Scopes["config:write"] || a.Scopes["*"] || !a.Scopes["munki:read"] {
		t.Fatalf("scopes %v", a.Permissions())
	}
}

func TestResolveAccessNoMatch(t *testing.T) {
	if _, ok := ResolveAccess([]string{"other"}, []Binding{{Group: "g", Role: "it-ops"}}, map[string][]string{"it-ops": {"munki:read"}}); ok {
		t.Fatal("unmatched group got access")
	}
	if _, ok := ResolveAccess([]string{"g"}, []Binding{{Group: "g", Role: "missing"}}, nil); ok {
		t.Fatal("binding to a missing role granted access")
	}
}

func TestCheckCustomPermission(t *testing.T) {
	for _, ok := range []string{"releases:update", "munki:read", "jobs:write", "config:read"} {
		if err := CheckCustomPermission(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"*", "config:write", "config:update", "munki:delete", "nope:read", "munki", ""} {
		if CheckCustomPermission(bad) == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestUpdateImpliesReadButNotWrite(t *testing.T) {
	p := model.Principal{Scopes: map[string]bool{"releases:update": true}}
	if !p.Allows("releases:read") || !p.Allows("releases:update") {
		t.Fatal("update should allow read and update")
	}
	if p.Allows("releases:write") {
		t.Fatal("update must not imply write")
	}
}
