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

func TestLogViewAPIGuardsAndQuery(t *testing.T) {
	ctx := context.Background()
	st := testutil.NewStore(t)
	if err := st.EnsureAPIToken(ctx, "admin", "mc_admin", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureAPIToken(ctx, "config", "mc_config", []string{"config:read", "config:write"}); err != nil {
		t.Fatal(err)
	}
	elastic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_pit") {
			_, _ = w.Write([]byte(`{"id":"pit-logs"}`))
			return
		}
		if r.Header.Get("Authorization") != "ApiKey super-secret" {
			t.Errorf("elastic auth %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[
			{"_id":"a","sort":[1,0],"_source":{"@timestamp":"2026-10-19T01:00:00Z","message":"installed Firefox","log":{"file":{"path":"/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log","offset":1}},"host":{"name":"mbp"}}},
			{"_id":"b","sort":[2,0],"_source":{"@timestamp":"2026-10-19T01:00:02Z","message":"end check","log":{"file":{"path":"/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log","offset":2}},"host":{"name":"mbp"}}}
		]}}`))
	}))
	t.Cleanup(elastic.Close)
	blobs, err := storage.New("local", t.TempDir(), "", "", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	srv := New(Options{Store: st, Blobs: blobs, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	body := `{
		"name":"Munki install log","description":"one mac","default_window":"1h","max_lines":1000,
		"device_scoped":false,"time_zone":"UTC","elastic_url":"` + elastic.URL + `","elastic_api_key":"super-secret",
		"sources":[{"label":"Munki","color":"#ff9f0a","index_pattern":"logs-munki-*","kql":"","message_field":"message","timestamp_field":"@timestamp","file_field":"log.file.path","host_field":"host.name","sequence_field":"log.file.offset"}]
	}`
	status, text := do(t, ts, http.MethodPost, "/api/v1/log-views", "mc_admin", nil, body)
	if status != http.StatusForbidden {
		t.Fatalf("missing terraform header %d %s", status, text)
	}
	status, text = do(t, ts, http.MethodPost, "/api/v1/log-views", "mc_admin", map[string]string{"X-Mission-Control-Client": "terraform"}, body)
	if status != http.StatusCreated || strings.Contains(text, "super-secret") || !strings.Contains(text, `"has_elastic_api_key":true`) {
		t.Fatalf("create %d %s", status, text)
	}
	if strings.Contains(logs.String(), "super-secret") {
		t.Fatal("api key leaked into logs")
	}
	id := between(t, text, `"id":"`, `"`)
	status, text = do(t, ts, http.MethodGet, "/api/v1/log-views/"+id, "mc_config", nil, "")
	if status != http.StatusOK || strings.Contains(text, "super-secret") {
		t.Fatalf("get %d %s", status, text)
	}
	status, text = do(t, ts, http.MethodPost, "/api/v1/log-views/"+id+"/query", "mc_config", nil, `{"align":"start","from":"2026-10-19T00:00:00Z","to":"2026-10-19T02:00:00Z","limit":10}`)
	if status != http.StatusForbidden {
		t.Fatalf("config token queried logs %d %s", status, text)
	}
	status, text = do(t, ts, http.MethodPost, "/api/v1/log-views/"+id+"/query", "mc_admin", nil, `{"align":"start","from":"2026-10-19T00:00:00Z","to":"2026-10-19T02:00:00Z","limit":10}`)
	if status != http.StatusOK || !strings.Contains(text, "installed Firefox") || !strings.Contains(text, "ManagedSoftwareUpdate.log") {
		t.Fatalf("query %d %s", status, text)
	}
	if strings.Contains(text, "super-secret") {
		t.Fatal("query leaked the key")
	}
}

func between(t *testing.T, s, a, b string) string {
	t.Helper()
	i := strings.Index(s, a)
	if i < 0 {
		t.Fatalf("missing %s in %s", a, s)
	}
	rest := s[i+len(a):]
	j := strings.Index(rest, b)
	if j < 0 {
		t.Fatal(s)
	}
	return rest[:j]
}
