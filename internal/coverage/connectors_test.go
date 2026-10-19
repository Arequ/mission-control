package coverage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestKQLAndDSL(t *testing.T) {
	got, err := compileKQL(`event.dataset:"rapid7.insight" AND NOT host.name:unused`)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	text := string(b)
	if !strings.Contains(text, "rapid7.insight") || !strings.Contains(text, "must_not") || !strings.Contains(text, "host.name") {
		t.Fatalf("kql %s", text)
	}
	or, err := compileKQL(`host.name:a OR host.name:b`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := or["bool"].(map[string]any)["should"]; !ok {
		t.Fatalf("or %#v", or)
	}
	wild, err := compileKQL(`agent.id:abc*`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wild["wildcard"]; !ok {
		t.Fatalf("wildcard %#v", wild)
	}
	dsl, err := compileDSL(`{"query":{"term":{"host.name":"mbp"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dsl["term"]; !ok {
		t.Fatalf("dsl %#v", dsl)
	}
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	wrapped, err := CompileQuery("kql", "", "@timestamp", since)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(wrapped)
	if !strings.Contains(string(raw), "@timestamp") || !strings.Contains(string(raw), "match_all") {
		t.Fatalf("window %s", raw)
	}
}

func TestFalconFake(t *testing.T) {
	var sawSecret bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "super-secret") || strings.Contains(r.Header.Get("Authorization"), "super-secret") {
			sawSecret = true
		}
		switch {
		case r.URL.Path == "/oauth2/token":
			if err := r.ParseForm(); err != nil && len(body) > 0 {
				_ = r.Form.Encode()
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			_ = r.ParseForm()
			values, _ := urlValues(string(body))
			if values.Get("grant_type") != "client_credentials" || values.Get("client_id") != "cid" || values.Get("client_secret") != "super-secret" {
				t.Errorf("oauth form %#v", values)
			}
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case r.URL.Path == "/devices/queries/devices-scroll/v1":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("scroll auth %s", r.Header.Get("Authorization"))
			}
			if r.URL.Query().Get("offset") == "" {
				_, _ = w.Write([]byte(`{"resources":["aid-1"],"meta":{"pagination":{"offset":"next"}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"resources":["aid-2"],"meta":{"pagination":{"offset":""}}}`))
		case r.URL.Path == "/devices/entities/devices/v2" && r.Method == http.MethodPost:
			var req struct {
				IDs []string `json:"ids"`
			}
			_ = json.Unmarshal(body, &req)
			if len(req.IDs) != 2 {
				t.Errorf("ids %#v", req.IDs)
			}
			_, _ = w.Write([]byte(`{"resources":[
				{"device_id":"aid-1","serial_number":"SER-1","hostname":"mbp","mac_address":"02:00:00:00:00:01","local_ip":"10.0.0.5","os_version":"26.1","last_seen":"2026-10-19T11:00:00Z","agent_version":"7.18"},
				{"device_id":"aid-2","serial_number":"System Serial Number","hostname":"air","mac_address":"02:00:00:00:00:02","local_ip":"10.0.0.6","os_version":"15.7","last_seen":"2026-10-10T11:00:00Z","agent_version":"7.17"}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	got, err := Falcon{}.Poll(context.Background(), Config{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "super-secret"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].NativeID != "aid-1" || got[0].Keys.Serial != "SER-1" || got[0].OSVersion != "26.1" || got[0].LastSeen.IsZero() {
		t.Fatalf("%+v", got)
	}
	if got[1].Keys.Serial != "System Serial Number" {
		t.Fatalf("placeholder serial should be preserved for the matcher: %+v", got[1].Keys)
	}
	if !sawSecret {
		t.Fatal("expected the oauth body to carry the secret to the fake, and nowhere else")
	}
}

func TestKolideFake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kolide-token" {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v0/devices") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("cursor") == "" {
			_, _ = w.Write([]byte(`{"data":[{"id":12,"name":"Ava's Mac","serial":"SER-K","hardware_uuid":"uuid-k","operating_system":"macOS 26.1","last_seen_at":"2026-10-19T10:00:00Z","remote_ip":"10.1.1.8","primary_mac_address":"02:00:5e:00:00:01","assigned_owner":{"email":"ava@acme.example"}}],"pagination":{"next":"` + r.Host + `","next_cursor":"n"}}`))
			// next must be absolute; rewrite below
			return
		}
	}))
	// Rebuild with a proper next URL now that we know the host.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kolide-token" {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("cursor") == "" {
			next := srv.URL + "/api/v0/devices?per_page=100&cursor=n"
			_, _ = w.Write([]byte(`{"data":[{"id":12,"name":"Ava's Mac","serial":"SER-K","hardware_uuid":"uuid-k","operating_system":"macOS 26.1","last_seen_at":"2026-10-19T10:00:00Z","remote_ip":"10.1.1.8","primary_mac_address":"02:00:5e:00:00:01","assigned_owner":{"email":"ava@acme.example"}}],"pagination":{"next":"` + next + `"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":13,"name":"spare","serial":"SER-2","operating_system":"macOS 15.7","last_seen_at":"2026-10-01T00:00:00Z"}],"pagination":{"next":""}}`))
	})
	got, err := Kolide{}.Poll(context.Background(), Config{BaseURL: srv.URL, APIToken: "kolide-token"}, srv.Client())
	srv.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].NativeID != "12" || got[0].Keys.PrimaryUser != "ava@acme.example" || got[0].Keys.HardwareUUID != "uuid-k" {
		t.Fatalf("%+v", got)
	}
}

func TestElasticMapping(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs-rapid7.insight-*/_search" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "ApiKey es-key" {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"hits":{"hits":[
			{"_source":{"@timestamp":"2026-10-19T09:00:00Z","agent":{"id":"r7-1","version":"1.2.3"},"host":{"name":"mbp-eng","serial_number":"SER-1","id":"uuid-1","mac":"02:00:5e:10:01:40","ip":"10.20.4.20","os":{"version":"15.7.1"}},"user":{"email":"ava.thompson"}}},
			{"_source":{"@timestamp":"2026-10-18T09:00:00Z","agent":{"id":"r7-1","version":"1.2.2"},"host":{"name":"old"}}},
			{"_source":{"@timestamp":"2026-10-19T08:00:00Z","agent":{"id":"r7-2"},"host":{"name":"other","serial_number":"SER-2"}}}
		]}}`))
	}))
	defer srv.Close()
	got, err := Elastic{}.Poll(context.Background(), Config{
		ElasticURL: srv.URL, ElasticAPIKey: "es-key", IndexPattern: "logs-rapid7.insight-*",
		QueryLanguage: "kql", Query: `event.dataset:"rapid7.insight"`, TimeField: "@timestamp",
		Now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), Lookback: 48 * time.Hour,
		FieldMap: map[string]string{
			"native_id": "agent.id", "serial": "host.serial_number", "hardware_uuid": "host.id",
			"hostname": "host.name", "primary_user": "user.email", "mac": "host.mac",
			"os_version": "host.os.version", "ip_address": "host.ip", "agent_version": "agent.version",
			"last_seen": "@timestamp",
		},
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "rapid7.insight") || !strings.Contains(string(body), "@timestamp") {
		t.Fatalf("search body %s", body)
	}
	if len(got) != 2 {
		t.Fatalf("deduped %+v", got)
	}
	if got[0].NativeID != "r7-1" || got[0].Keys.Serial != "SER-1" || got[0].OSVersion != "15.7.1" || got[0].AgentVersion != "1.2.3" || got[0].Keys.PrimaryUser != "ava.thompson" {
		t.Fatalf("first %+v", got[0])
	}
	if got[0].LastSeen.UTC().Format(time.RFC3339) != "2026-10-19T09:00:00Z" {
		t.Fatalf("last seen %s", got[0].LastSeen)
	}
}

func TestAPIStubs(t *testing.T) {
	for _, source := range []string{"rapid7", "netskope", "proofpoint", "blastshield"} {
		t.Run(source, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/devices" {
					t.Errorf("path %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer "+source+"-token" {
					t.Errorf("auth %s", r.Header.Get("Authorization"))
				}
				_, _ = w.Write([]byte(`{"devices":[{"id":"1","serial":"S","hardware_uuid":"U","mac":"02:00:00:00:00:09","hostname":"h","primary_user":"u","os_version":"26.1","ip_address":"10.0.0.1","agent_version":"9","last_seen":"2026-10-19T01:02:03Z"}]}`))
			}))
			defer srv.Close()
			p, err := PollerFor(source, "api")
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.Poll(context.Background(), Config{BaseURL: srv.URL, APIToken: source + "-token"}, srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].NativeID != "1" || got[0].Keys.Hostname != "h" || got[0].AgentVersion != "9" {
				t.Fatalf("%+v", got)
			}
			if _, err := p.Poll(context.Background(), Config{BaseURL: srv.URL}, srv.Client()); err == nil {
				t.Fatal("expected missing token")
			}
		})
	}
}

func urlValues(body string) (mapGetter, error) {
	return formGetter(body), nil
}

type mapGetter interface {
	Get(string) string
}

type formGetter string

func (f formGetter) Get(k string) string {
	for _, part := range strings.Split(string(f), "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && kv[0] == k {
			return kv[1]
		}
	}
	return ""
}
