package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/testutil"
)

// TestCustomRolesGateEndpoints binds two IdP groups to Terraform-defined roles
// and checks that a session holding both gets exactly the union: it can read
// Munki and run jobs, but cannot promote a package or write config.
func TestCustomRolesGateEndpoints(t *testing.T) {
	ctx := t.Context()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(Options{Store: st, Blobs: blobs}).Handler())
	t.Cleanup(ts.Close)
	tf := map[string]string{"Authorization": "Bearer mc_admin", "X-Mission-Control-Client": "terraform", "Content-Type": "application/json"}

	status, body := do(t, ts, http.MethodPost, "/api/v1/sso/config", "", tf,
		`{"name":"okta","issuer":"https://idp.example.com","client_id":"mc","client_secret":"example-oidc-client-secret","allowed_domains":["example.com"],"group_claim":"groups","enabled":true}`)
	if status != http.StatusCreated {
		t.Fatalf("provider %d %s", status, body)
	}
	var prov struct{ ID string }
	_ = json.Unmarshal([]byte(body), &prov)

	// Ungrantable permissions and built-in names are refused at the API.
	for _, bad := range []string{
		`{"name":"sneaky","permissions":["config:write"]}`,
		`{"name":"sneaky","permissions":["*"]}`,
		`{"name":"admin","permissions":["munki:read"]}`,
		`{"name":"Bad Name","permissions":["munki:read"]}`,
		`{"name":"empty","permissions":[]}`,
	} {
		if status, body := do(t, ts, http.MethodPost, "/api/v1/sso/roles", "", tf, bad); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", bad, status, body)
		}
	}
	// Roles are config: the UI cannot create one without the Terraform header.
	if status, _ := do(t, ts, http.MethodPost, "/api/v1/sso/roles", "mc_admin", map[string]string{"Content-Type": "application/json"},
		`{"name":"it-ops","permissions":["munki:read"]}`); status != http.StatusForbidden {
		t.Fatalf("role without terraform header %d", status)
	}

	status, body = do(t, ts, http.MethodPost, "/api/v1/sso/roles", "", tf,
		`{"name":"it-ops","description":"IT Ops","permissions":["munki:read","releases:update","munki:read"]}`)
	if status != http.StatusCreated || !strings.Contains(body, `"permissions":["munki:read","releases:update"]`) {
		t.Fatalf("it-ops %d %s", status, body)
	}
	var itOps struct{ ID string }
	_ = json.Unmarshal([]byte(body), &itOps)
	if status, body := do(t, ts, http.MethodPost, "/api/v1/sso/roles", "", tf, `{"name":"it-engineers","permissions":["jobs:write"]}`); status != http.StatusCreated {
		t.Fatalf("it-engineers %d %s", status, body)
	}
	if status, body := do(t, ts, http.MethodPost, "/api/v1/sso/role-bindings", "", tf,
		`{"provider_id":"`+prov.ID+`","group":"IT Ops","role":"no-such-role"}`); status != http.StatusBadRequest {
		t.Fatalf("binding to a missing role %d %s", status, body)
	}
	for _, b := range []string{`"group":"IT Ops","role":"it-ops"`, `"group":"IT Engineers","role":"it-engineers"`} {
		if status, body := do(t, ts, http.MethodPost, "/api/v1/sso/role-bindings", "", tf, `{"provider_id":"`+prov.ID+`",`+b+`}`); status != http.StatusCreated {
			t.Fatalf("binding %s: %d %s", b, status, body)
		}
	}
	// A role a binding uses cannot be deleted out from under it.
	if status, _ := do(t, ts, http.MethodDelete, "/api/v1/sso/roles/"+itOps.ID, "", tf, ""); status != http.StatusConflict {
		t.Fatalf("delete in-use role %d", status)
	}

	raw, user, err := st.CreateSession(ctx, store.SessionRecord{
		ProviderID: prov.ID, Subject: "sam", Email: "sam@example.com", Name: "Sam",
		Groups: []string{"IT Ops", "IT Engineers"},
	}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(user.Roles, ",") != "it-engineers,it-ops" {
		t.Fatalf("roles %v", user.Roles)
	}

	call := func(method, path, body string) int {
		t.Helper()
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		} else {
			rdr = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: raw})
		req.Header.Set(csrfHeader, user.CSRFToken)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if got := call(http.MethodGet, "/api/v1/packages", ""); got != http.StatusOK {
		t.Fatalf("munki:read list packages %d", got)
	}
	if got := call(http.MethodPost, "/api/v1/jobs", `{"recipe_id":"missing"}`); got == http.StatusForbidden || got == http.StatusUnauthorized {
		t.Fatalf("jobs:write from it-engineers refused %d", got)
	}
	if got := call(http.MethodPost, "/api/v1/packages/missing/promote", ""); got != http.StatusForbidden {
		t.Fatalf("promote needs munki:write, got %d", got)
	}
	if got := call(http.MethodGet, "/api/v1/vulnerability-issues", ""); got != http.StatusForbidden {
		t.Fatalf("vuln:read was never granted, got %d", got)
	}

	var me model.SessionUser
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: raw})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(res.Body).Decode(&me)
	res.Body.Close()
	if strings.Join(me.Permissions, ",") != "jobs:write,munki:read,releases:update" {
		t.Fatalf("session permissions %v", me.Permissions)
	}

	// Tightening a role applies on the next request, without a new login.
	if status, body := do(t, ts, http.MethodPut, "/api/v1/sso/roles/"+itOps.ID, "", tf, `{"name":"it-ops","permissions":["releases:update"]}`); status != http.StatusOK {
		t.Fatalf("update role %d %s", status, body)
	}
	if got := call(http.MethodGet, "/api/v1/packages", ""); got != http.StatusForbidden {
		t.Fatalf("munki:read removed but still allowed: %d", got)
	}
	// Renaming would orphan bindings.
	if status, _ := do(t, ts, http.MethodPut, "/api/v1/sso/roles/"+itOps.ID, "", tf, `{"name":"it-ops-2","permissions":["releases:update"]}`); status != http.StatusBadRequest {
		t.Fatalf("rename %d", status)
	}

	// A user whose groups match nothing cannot sign in.
	if _, _, err := st.CreateSession(ctx, store.SessionRecord{ProviderID: prov.ID, Subject: "x", Email: "x@example.com", Groups: []string{"Other"}}, 0, 0); err == nil {
		t.Fatal("unbound user signed in")
	} else {
		var ve *store.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("unexpected error %v", err)
		}
	}
}
