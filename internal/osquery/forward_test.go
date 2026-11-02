package osquery

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestElasticForwarderBulk(t *testing.T) {
	var got string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bulk" {
			t.Errorf("path %s", r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer srv.Close()
	err := (ElasticForwarder{URL: srv.URL, Index: "osquery-results", APIKey: "abc123", HTTP: srv.Client()}).Forward(context.Background(), []ResultEvent{{
		DeviceID: "d1", QueryName: "mc_os_version", Action: "snapshot",
		Columns: map[string]string{"version": "26.1"}, ReceivedAt: time.Unix(10, 0).UTC(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "ApiKey abc123" {
		t.Fatalf("auth %q", auth)
	}
	if !strings.Contains(got, `"_index":"osquery-results"`) || !strings.Contains(got, `"version":"26.1"`) {
		t.Fatalf("body %s", got)
	}
	if err := (NopForwarder{}).Forward(context.Background(), []ResultEvent{{DeviceID: "d"}}); err != nil {
		t.Fatal(err)
	}
}

func TestElasticForwarderRedactsSecrets(t *testing.T) {
	err := (ElasticForwarder{
		URL:    "http://elastic:super-secret-key@127.0.0.1:1",
		APIKey: "super-secret-key",
		HTTP:   &http.Client{Timeout: time.Second},
	}).Forward(context.Background(), []ResultEvent{{DeviceID: "d", QueryName: "q", Action: "added"}})
	if err == nil {
		t.Fatal("expected dial error")
	}
	if strings.Contains(err.Error(), "super-secret-key") || strings.Contains(err.Error(), "elastic:") {
		t.Fatalf("secret leaked: %s", err.Error())
	}
}
