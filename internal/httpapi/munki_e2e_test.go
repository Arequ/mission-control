package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestMunkiClientCheckinShowsOnDevice(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Options{Store: st, Blobs: blobs, RepoToken: "mc_repo"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	tf := map[string]string{"Authorization": "Bearer mc_admin", "X-Mission-Control-Client": "terraform", "Content-Type": "application/json"}
	status, body := do(t, ts, http.MethodPost, "/api/v1/manifests", "", tf, `{"name":"site_default","catalogs":["production"],"managed_installs":["Firefox"]}`)
	if status != http.StatusCreated {
		t.Fatalf("manifest %d %s", status, body)
	}
	status, body = do(t, ts, http.MethodPost, "/api/v1/munki/enrollments", "", tf, `{"name":"fleet","secret":"example-munki-enrollment-secret","manifest":"site_default","enabled":true}`)
	if status != http.StatusCreated || bytes.Contains([]byte(body), []byte("example-munki-enrollment-secret")) {
		t.Fatalf("enrollment leaked or failed %d %s", status, body)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/repo/manifests/C02DEMO0001", nil)
	req.SetBasicAuth("C02DEMO0001", "example-munki-enrollment-secret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	manifest := readBody(t, res)
	if res.StatusCode != http.StatusOK || !bytes.Contains(manifest, []byte("site_default")) || !bytes.Contains(manifest, []byte("production")) {
		t.Fatalf("manifest %d %s", res.StatusCode, manifest)
	}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/repo/catalogs/production", nil)
	req.SetBasicAuth("C02DEMO0001", "example-munki-enrollment-secret")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("catalog %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(checkinPlist))
	_ = zw.Close()
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/munki/checkin", bytes.NewReader(buf.Bytes()))
	req.SetBasicAuth("C02DEMO0001", "example-munki-enrollment-secret")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Idempotency-Key", "demo-1")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw := readBody(t, res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("checkin %d %s", res.StatusCode, raw)
	}
	var checkin struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(raw, &checkin); err != nil || checkin.DeviceID == "" {
		t.Fatal(string(raw))
	}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/munki/checkin", bytes.NewReader(buf.Bytes()))
	req.SetBasicAuth("C02DEMO0001", "example-munki-enrollment-secret")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Idempotency-Key", "demo-1")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	replay := readBody(t, res)
	if res.StatusCode != http.StatusOK || !bytes.Contains(replay, []byte(`"replayed":true`)) {
		t.Fatalf("replay %d %s", res.StatusCode, replay)
	}

	status, body = do(t, ts, http.MethodGet, "/api/v1/devices/"+checkin.DeviceID, "mc_admin", nil, "")
	if status != http.StatusOK || !bytes.Contains([]byte(body), []byte(`"munki_version":"6.6.3"`)) || !bytes.Contains([]byte(body), []byte("GoogleChrome")) {
		t.Fatalf("device %d %s", status, body)
	}
}

const checkinPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MachineInfo</key><dict>
  <key>hostname</key><string>ava-mbp.local</string>
  <key>serial_number</key><string>C02DEMO0001</string>
  <key>os_vers</key><string>15.1.1</string>
</dict>
<key>ManagedInstallVersion</key><string>6.6.3</string>
<key>ConsoleUser</key><string>ava</string>
<key>StartTime</key><date>2020-01-01T00:00:00Z</date>
<key>EndTime</key><date>2020-01-01T00:01:00Z</date>
<key>InstalledItems</key><array><dict>
  <key>name</key><string>Firefox</string>
  <key>installed_version</key><string>132.0.1</string>
  <key>installed</key><true/>
</dict></array>
<key>ItemsToInstall</key><array><dict>
  <key>name</key><string>GoogleChrome</string>
  <key>version_to_install</key><string>131.0</string>
</dict></array>
<key>Warnings</key><array><string>optional skipped</string></array>
</dict></plist>`

func readBody(t *testing.T, res *http.Response) []byte {
	t.Helper()
	defer res.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(res.Body)
	return buf.Bytes()
}
