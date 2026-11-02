package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/munki"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestMunkiRepoAndCheckinGuards(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := blobs.Put(ctx, "icons/Firefox.png", bytes.NewReader([]byte("png")), 3, "image/png"); err != nil {
		t.Fatal(err)
	}
	srv := New(Options{Store: st, Blobs: blobs, RepoToken: "mc_repo"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	tf := map[string]string{"Authorization": "Bearer mc_admin", "X-Mission-Control-Client": "terraform", "Content-Type": "application/json"}
	status, body := do(t, ts, http.MethodPost, "/api/v1/munki/enrollments", "", tf, `{"name":"fleet","secret":"example-munki-enrollment-secret","manifest":"site_default","enabled":true}`)
	if status != http.StatusCreated || strings.Contains(body, "example-munki-enrollment-secret") {
		t.Fatalf("secret visible %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := jsonUnmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	status, body = do(t, ts, http.MethodGet, "/api/v1/munki/enrollments/"+created.ID, "mc_admin", nil, "")
	if status != http.StatusOK || strings.Contains(body, "secret") && strings.Contains(body, "example-munki") {
		t.Fatalf("get leaked %d %s", status, body)
	}

	for _, path := range []string{
		"/repo/pkgs/../../etc/passwd",
		"/repo/pkgsinfo/../../etc/passwd",
		"/repo/icons/../../etc/passwd",
		"/repo/pkgs/%2e%2e%2fpasswd",
		"/repo/icons/bad%00.png",
	} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.SetBasicAuth("munki", "mc_repo")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s -> %d", path, res.StatusCode)
		}
	}

	derived := munki.DeriveDeviceToken("example-munki-enrollment-secret", "C02DEMO0001")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/munki/checkin", strings.NewReader(otherSerialPlist))
	req.SetBasicAuth("C02DEMO0001", derived)
	req.Header.Set("Content-Type", "application/xml")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("derived token cross-serial %d", res.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/munki/checkin", strings.NewReader(`<!DOCTYPE plist [<!ENTITY a "x">]><plist version="1.0"><dict/></plist>`))
	req.SetBasicAuth("munki", "example-munki-enrollment-secret")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge && res.StatusCode != http.StatusBadRequest {
		t.Fatalf("entity %d", res.StatusCode)
	}

	var bomb bytes.Buffer
	zw := gzip.NewWriter(&bomb)
	_, _ = zw.Write(bytes.Repeat([]byte("A"), munki.MaxReportBytes+1))
	_ = zw.Close()
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/munki/checkin", &bomb)
	req.SetBasicAuth("munki", "example-munki-enrollment-secret")
	req.Header.Set("Content-Encoding", "gzip")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("gzip bomb %d", res.StatusCode)
	}

	status, _ = do(t, ts, http.MethodPut, "/api/v1/munki/enrollments/"+created.ID, "", tf, `{"name":"fleet","secret":"","manifest":"site_default","enabled":false}`)
	if status != http.StatusOK {
		t.Fatal(status)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/catalogs/testing", nil)
	req.SetBasicAuth("munki", "example-munki-enrollment-secret")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled enrollment still authed %d", res.StatusCode)
	}
}

const otherSerialPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MachineInfo</key><dict><key>serial_number</key><string>OTHERSERIAL1</string></dict>
<key>ManagedInstallVersion</key><string>6.6</string>
<key>EndTime</key><date>2020-01-01T00:00:00Z</date>
</dict></plist>`
