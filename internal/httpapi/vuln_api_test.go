package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/testutil"
)

func TestVulnerabilitySettingsAreWriteOnly(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureAPIToken(ctx, "jobs", "mc_jobs", []string{"jobs:read"}); err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Options{Store: st, Blobs: blobs, Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	tf := map[string]string{"X-Mission-Control-Client": "terraform"}
	body := `{
		"nvd_enabled": true, "kev_enabled": true, "epss_enabled": true, "apple_enabled": true, "rapid7_enabled": false,
		"sync_cron": "20 3 * * *", "timezone": "UTC", "nvd_api_key": "example-nvd-api-key",
		"sla_critical_days": 7, "sla_high_days": 14, "sla_medium_days": 30, "sla_low_days": 90, "sla_kev_days": 14,
		"cpe_overrides": [
			{"bundle_id": "com.zebra.App", "vendor": "zebra", "product": "app"},
			{"bundle_id": "com.acme.Browser", "vendor": "acme", "product": "browser"}
		]
	}`
	status, got := do(t, ts, http.MethodPut, "/api/v1/vulnerability-settings", "mc_admin", nil, body)
	if status != http.StatusForbidden || !strings.Contains(got, "Terraform") {
		t.Fatalf("settings write without terraform header %d %s", status, got)
	}
	status, got = do(t, ts, http.MethodPut, "/api/v1/vulnerability-settings", "mc_admin", tf, body)
	if status != http.StatusOK || strings.Contains(got, "example-nvd-api-key") || !strings.Contains(got, `"has_nvd_api_key":true`) {
		t.Fatalf("settings put leaked or rejected %d %s", status, got)
	}
	zebra := strings.Index(got, "com.zebra.App")
	acme := strings.Index(got, "com.acme.Browser")
	if zebra < 0 || acme < 0 || zebra > acme {
		t.Fatalf("override order follows vendor sort, not configuration order: %s", got)
	}
	status, got = do(t, ts, http.MethodGet, "/api/v1/vulnerability-settings", "mc_admin", nil, "")
	if status != http.StatusOK || strings.Contains(got, "example-nvd-api-key") || !strings.Contains(got, `"has_nvd_api_key":true`) {
		t.Fatalf("settings get %d %s", status, got)
	}
	var audit string
	if err := st.Pool().QueryRow(ctx, `SELECT coalesce(string_agg(detail::text, ''), '') FROM audit_log`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, "example-nvd-api-key") {
		t.Fatalf("audit contains the NVD key: %s", audit)
	}
	keep := `{
		"nvd_enabled": true, "kev_enabled": true, "epss_enabled": true, "apple_enabled": true, "rapid7_enabled": false,
		"sync_cron": "20 3 * * *", "timezone": "UTC",
		"sla_critical_days": 7, "sla_high_days": 14, "sla_medium_days": 30, "sla_low_days": 90, "sla_kev_days": 14,
		"cpe_overrides": [{"bundle_id": "com.acme.Browser", "vendor": "acme", "product": "browser"}]
	}`
	status, got = do(t, ts, http.MethodPut, "/api/v1/vulnerability-settings", "mc_admin", tf, keep)
	if status != http.StatusOK || strings.Contains(got, "example-nvd-api-key") || !strings.Contains(got, `"has_nvd_api_key":true`) || strings.Contains(got, "com.zebra.App") {
		t.Fatalf("empty key should keep the stored key %d %s", status, got)
	}
	status, got = do(t, ts, http.MethodGet, "/api/v1/vulnerability-issues", "mc_jobs", nil, "")
	if status != http.StatusForbidden {
		t.Fatalf("jobs token issues %d %s", status, got)
	}
	status, got = do(t, ts, http.MethodDelete, "/api/v1/vulnerability-settings", "mc_admin", tf, "")
	if status != http.StatusOK || strings.Contains(got, "example-nvd-api-key") || strings.Contains(got, `"has_nvd_api_key":true`) || strings.Contains(got, "com.acme.Browser") {
		t.Fatalf("reset %d %s", status, got)
	}
}
