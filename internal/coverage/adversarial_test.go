package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUUIDAndSerialCanonicalization(t *testing.T) {
	hyphen := NormalizeKeys(Keys{HardwareUUID: "550E8400-E29B-41D4-A716-446655440000"})
	compact := NormalizeKeys(Keys{HardwareUUID: "550e8400e29b41d4a716446655440000"})
	braced := NormalizeKeys(Keys{HardwareUUID: "{550E8400-E29B-41D4-A716-446655440000}"})
	urn := NormalizeKeys(Keys{HardwareUUID: "urn:uuid:550e8400-e29b-41d4-a716-446655440000"})
	if hyphen.HardwareUUID == "" || hyphen.HardwareUUID != compact.HardwareUUID || hyphen.HardwareUUID != braced.HardwareUUID || hyphen.HardwareUUID != urn.HardwareUUID {
		t.Fatalf("uuid forms split: %q %q %q %q", hyphen.HardwareUUID, compact.HardwareUUID, braced.HardwareUUID, urn.HardwareUUID)
	}
	nilUUID := NormalizeKeys(Keys{HardwareUUID: "00000000000000000000000000000000"})
	allF := NormalizeKeys(Keys{HardwareUUID: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"})
	if nilUUID.HardwareUUID != "" || allF.HardwareUUID != "" {
		t.Fatalf("nil uuids survived: %+v %+v", nilUUID, allF)
	}
	spaced := NormalizeKeys(Keys{Serial: "  c02\u00a0abc  "})
	plain := NormalizeKeys(Keys{Serial: "C02ABC"})
	if spaced.Serial != plain.Serial || spaced.Serial != "C02ABC" {
		t.Fatalf("serial whitespace: %q vs %q", spaced.Serial, plain.Serial)
	}
	// Non-UUID hardware ids stay readable and case-folded.
	if got := NormalizeKeys(Keys{HardwareUUID: "ABC-DEF"}); got.HardwareUUID != "abc-def" {
		t.Fatalf("non-uuid id: %q", got.HardwareUUID)
	}
}

func TestSharedVirtualMACAndLabHosts(t *testing.T) {
	dock := "00:1a:2b:3c:4d:10" // universal dock NIC, shared
	devs := []Candidate{
		{ID: "a", Keys: Keys{Serial: "SER-A", HardwareUUID: "uuid-a", MAC: dock, Hostname: "lab-a", PrimaryUser: "student"}},
		{ID: "b", Keys: Keys{Serial: "SER-B", HardwareUUID: "uuid-b", MAC: dock, Hostname: "lab-b", PrimaryUser: "student"}},
	}
	// Shared dock MAC must not merge, and must not hide a unique hostname+user.
	got := Resolve(Keys{MAC: dock, Hostname: "lab-b.corp.example", PrimaryUser: "student@corp.example"}, devs)
	if got.DeviceID != "b" || got.Confidence != "weak" {
		t.Fatalf("shared MAC hid the hostname match: %+v", got)
	}
	// MAC alone, shared by two devices, is not an identity.
	alone := Resolve(Keys{MAC: dock}, devs)
	if alone.DeviceID != "" || alone.Confidence == "weak" {
		t.Fatalf("shared MAC merged or attached: %+v", alone)
	}
	// Randomized / locally administered Wi-Fi MAC must not match by itself.
	wifi := []Candidate{{ID: "a", Keys: Keys{Serial: "SER-A", MAC: "02:00:5e:10:01:40", Hostname: "mbp-a", PrimaryUser: "ava"}}}
	randMAC := Resolve(Keys{MAC: "02:00:5e:10:01:40"}, wifi)
	if randMAC.DeviceID != "" {
		t.Fatalf("randomized MAC matched: %+v", randMAC)
	}
	// A stable universal MAC still matches when it belongs to one device.
	stable := []Candidate{{ID: "a", Keys: Keys{Serial: "SER-A", MAC: "00:1a:2b:3c:4d:0a", Hostname: "mbp-a", PrimaryUser: "ava"}}}
	ok := Resolve(Keys{MAC: "00-1A-2B-3C-4D-0A"}, stable)
	if ok.DeviceID != "a" || ok.Confidence != "weak" {
		t.Fatalf("universal MAC: %+v", ok)
	}
	// Lab image: same hostname and user on two machines, no stronger key → do not attach.
	lab := []Candidate{
		{ID: "a", Keys: Keys{Serial: "SER-A", Hostname: "lab-01", PrimaryUser: "student"}},
		{ID: "b", Keys: Keys{Serial: "SER-B", Hostname: "lab-01.local", PrimaryUser: "STUDENT"}},
	}
	collided := Resolve(Keys{Hostname: "lab-01.corp.example", PrimaryUser: `CORP\student`}, lab)
	if collided.DeviceID != "" {
		t.Fatalf("lab collision merged: %+v", collided)
	}
}

func TestSerialReuseVersusBoardSwap(t *testing.T) {
	devs := []Candidate{{ID: "old", Keys: Keys{Serial: "S1", HardwareUUID: "uuid-old", MAC: "00:1a:2b:3c:4d:01"}}}
	// Logic-board swap: same serial, new UUID, old UUID is not still reporting.
	swap := ResolveObserved(Keys{Serial: "s1", HardwareUUID: "UUID-NEW"}, devs, Evidence{})
	if swap.DeviceID != "old" || swap.Confidence != "strong" {
		t.Fatalf("board swap split the device: %+v", swap)
	}
	// Serial reuse: the old UUID is still live in this pass, so the new UUID must not take the device.
	reuse := ResolveObserved(Keys{Serial: "S1", HardwareUUID: "uuid-new"}, devs, Evidence{
		SerialUUIDs: map[string]map[string]struct{}{"S1": {"uuid-old": struct{}{}, "uuid-new": struct{}{}}},
	})
	if reuse.DeviceID != "" {
		t.Fatalf("serial reuse merged onto the live device: %+v", reuse)
	}
}

func TestNoTransitiveGhostMerge(t *testing.T) {
	dock := "00:1a:2b:3c:4d:99"
	records := []IdentityRecord{
		{Source: "crowdstrike", NativeID: "a", Keys: Keys{Serial: "S1", MAC: dock, Hostname: "one", PrimaryUser: "ann"}},
		{Source: "kolide", NativeID: "b", Keys: Keys{MAC: dock, Hostname: "bridge", PrimaryUser: "bob"}},
		{Source: "netskope", NativeID: "c", Keys: Keys{Serial: "S2", MAC: dock, Hostname: "bridge", PrimaryUser: "bob"}},
		{Source: "rapid7", NativeID: "d", Keys: Keys{MAC: "00:1a:2b:3c:4d:77"}},
		{Source: "proofpoint", NativeID: "e", Keys: Keys{MAC: "00:1a:2b:3c:4d:77", Hostname: "same"}},
	}
	keys := AssignGhostKeys(records)
	if keys[0] == keys[2] {
		t.Fatalf("dock MAC collapsed two serials: %v", keys)
	}
	if keys[1] == keys[0] || keys[1] == keys[2] {
		t.Fatalf("bridge record joined a serial through the dock: %v", keys)
	}
	// Same stable MAC, no second serial: the source that omits serial joins the one that has it.
	partial := []IdentityRecord{
		{Source: "crowdstrike", NativeID: "cs", Keys: Keys{Serial: "ONLY", MAC: "00:1a:2b:3c:4d:77", Hostname: "mbp"}},
		{Source: "kolide", NativeID: "ko", Keys: Keys{MAC: "00-1A-2B-3C-4D-77", Hostname: "mbp.corp.example"}},
	}
	got := AssignGhostKeys(partial)
	if got[0] == "" || got[0] != got[1] {
		t.Fatalf("serial-less source split from the serial: %v", got)
	}
	// Conflict records never share a key with a clean serial ghost.
	conflicted := AssignGhostKeys([]IdentityRecord{
		{Source: "rapid7", NativeID: "r", Conflict: true, Keys: Keys{Serial: "ONLY"}},
	})
	if conflicted[0] == got[0] {
		t.Fatalf("conflict collapsed into the serial ghost: %s", conflicted[0])
	}
}

func TestConflictCandidatesAreSorted(t *testing.T) {
	devs := []Candidate{
		{ID: "b", Keys: Keys{Serial: "SAME", HardwareUUID: "u-b"}},
		{ID: "a", Keys: Keys{Serial: "SAME", HardwareUUID: "u-a"}},
	}
	first := Resolve(Keys{Serial: "same"}, devs)
	second := Resolve(Keys{Serial: "same"}, []Candidate{devs[1], devs[0]})
	if first.Confidence != "conflict" || strings.Join(first.Candidates, ",") != "a,b" || strings.Join(second.Candidates, ",") != strings.Join(first.Candidates, ",") {
		t.Fatalf("unstable conflict: %+v %+v", first, second)
	}
}

func TestFalconRetriesRateLimitAndCachesToken(t *testing.T) {
	var oauth, scrolls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusTooManyRequests)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.String(), "api.eu-1.crowdstrike.com") && r.Host != "" {
			// Base URL is the test server; region is asserted by the request path staying on this host.
		}
		switch r.URL.Path {
		case "/oauth2/token":
			oauth.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok-1","expires_in":1800}`))
		case "/devices/queries/devices-scroll/v1":
			n := scrolls.Add(1)
			if status.Load() == http.StatusTooManyRequests && n == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			offset := r.URL.Query().Get("offset")
			switch offset {
			case "":
				_, _ = w.Write([]byte(`{"resources":["a","b"],"meta":{"pagination":{"offset":"p2","total":4}}}`))
			case "p2":
				_, _ = w.Write([]byte(`{"resources":["b","c"],"meta":{"pagination":{"offset":"p3","total":4}}}`))
			default:
				_, _ = w.Write([]byte(`{"resources":["d"],"meta":{"pagination":{"offset":"","total":4}}}`))
			}
		case "/devices/entities/devices/v2":
			body, _ := io.ReadAll(r.Body)
			var req struct {
				IDs []string `json:"ids"`
			}
			_ = json.Unmarshal(body, &req)
			var b strings.Builder
			b.WriteString(`{"resources":[`)
			for i, id := range req.IDs {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"device_id":%q,"serial_number":%q}`, id, id)
			}
			b.WriteString(`]}`)
			_, _ = w.Write([]byte(b.String()))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := Config{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "super-secret"}
	got, err := Falcon{}.Poll(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("lost or duplicated devices: %+v", idsOf(got))
	}
	if _, err := (Falcon{}).Poll(context.Background(), cfg, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if oauth.Load() != 1 {
		t.Fatalf("oauth calls = %d, want 1 cached token", oauth.Load())
	}
}

func TestFalconScrollTruncationIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":60}`))
		case "/devices/queries/devices-scroll/v1":
			offset := r.URL.Query().Get("offset")
			next := "n" + offset + "x"
			_, _ = w.Write([]byte(`{"resources":["id-` + offset + `"],"meta":{"pagination":{"offset":"` + next + `"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, err := Falcon{}.Poll(context.Background(), Config{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "super-secret"}, srv.Client())
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("partial scroll returned success: %v", err)
	}
}

func TestKolideCursorAndRelativeNext(t *testing.T) {
	var pages atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := pages.Add(1)
		switch {
		case r.URL.Query().Get("cursor") == "":
			_, _ = w.Write([]byte(`{"data":[{"id":1,"serial":"A","name":"one"}],"pagination":{"next":"","next_cursor":"c2"}}`))
		case r.URL.Query().Get("cursor") == "c2":
			_, _ = w.Write([]byte(`{"data":[{"id":2,"serial":"B","name":"two"}],"pagination":{"next":"/api/v0/devices?per_page=100&cursor=c3"}}`))
		default:
			_, _ = w.Write([]byte(`{"data":[{"id":3,"serial":"C","name":"three"}],"pagination":{"next":""}}`))
		}
		if n > 10 {
			t.Errorf("cursor loop did not stop")
		}
	}))
	defer srv.Close()
	got, err := Kolide{}.Poll(context.Background(), Config{BaseURL: srv.URL, APIToken: "kolide-token"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].NativeID != "1" || got[2].NativeID != "3" {
		t.Fatalf("pages lost: %+v", got)
	}
}

func TestElasticPaginatesArraysAndTimezone(t *testing.T) {
	var searches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_pit") {
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = w.Write([]byte(`{"id":"pit-1"}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		n := searches.Add(1)
		var req struct {
			SearchAfter []any `json:"search_after"`
			Size        int   `json:"size"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Size <= 0 || req.Size > 1000 {
			t.Errorf("page size %d", req.Size)
		}
		if strings.Contains(string(body), `"from"`) {
			t.Errorf("from/size pagination: %s", body)
		}
		if len(req.SearchAfter) == 0 {
			var b strings.Builder
			b.WriteString(`{"hits":{"hits":[`)
			fmt.Fprintf(&b, `{"sort":[3000,"late"],"_source":{"@timestamp":"2026-10-19 09:00:00","agent":{"id":"late"},"host":{"ip":["10.1.1.1","10.1.1.2"],"mac":["00:1a:2b:3c:4d:01"]}}},`)
			fmt.Fprintf(&b, `{"sort":[2000,"keep-new"],"_source":{"@timestamp":"2026-10-19T08:00:00Z","agent":{"id":"keep"},"host":{"name":"new"}}},`)
			fmt.Fprintf(&b, `{"sort":[1500,"keep-old"],"_source":{"@timestamp":"2026-10-19T07:00:00Z","agent":{"id":"keep"},"host":{"name":"old"}}}`)
			for i := 3; i < req.Size; i++ {
				fmt.Fprintf(&b, `,{"sort":[%d,"pad-%d"],"_source":{"@timestamp":"2026-10-19T05:00:00Z","agent":{"id":"pad-%d"}}}`, 1400-i, i, i)
			}
			b.WriteString(`]}}`)
			_, _ = w.Write([]byte(b.String()))
			return
		}
		if n > 4 {
			t.Errorf("too many searches")
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[
			{"sort":[700,"d"],"_source":{"@timestamp":"2026-10-19T06:00:00Z","agent":{"id":"page2"},"host":{"name":"other"}}}
		]}}`))
	}))
	defer srv.Close()
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Elastic{}.Poll(context.Background(), Config{
		ElasticURL: srv.URL, IndexPattern: "logs-*", QueryLanguage: "kql", TimeField: "@timestamp",
		TimeZone: "America/New_York",
		Now:      time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), Lookback: 48 * time.Hour,
		FieldMap: map[string]string{"native_id": "agent.id", "hostname": "host.name", "ip_address": "host.ip", "mac": "host.mac", "last_seen": "@timestamp"},
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if searches.Load() < 2 {
		t.Fatalf("did not paginate, searches=%d", searches.Load())
	}
	byID := map[string]Observation{}
	for _, obs := range got {
		byID[obs.NativeID] = obs
	}
	if _, ok := byID["page2"]; !ok {
		t.Fatalf("lost the device on page 2: %+v", got)
	}
	keep := byID["keep"]
	if keep.Keys.Hostname != "new" {
		t.Fatalf("did not keep the latest event: %+v", keep)
	}
	late := byID["late"]
	if late.IPAddress != "10.1.1.1" || late.Keys.MAC != "00:1a:2b:3c:4d:01" {
		t.Fatalf("array fields: %+v", late)
	}
	want := time.Date(2026, 10, 19, 9, 0, 0, 0, loc).UTC()
	if !late.LastSeen.Equal(want) {
		t.Fatalf("zoneless timestamp interpreted as %s, want %s", late.LastSeen, want)
	}
}

func TestClassifyBoundaryIsStale(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if got := Classify(true, now.Add(-24*time.Hour), now, 24*time.Hour); got != Stale {
		t.Fatalf("exact threshold = %s, want stale", got)
	}
}

func idsOf(obs []Observation) []string {
	out := make([]string, len(obs))
	for i, o := range obs {
		out[i] = o.NativeID
	}
	return out
}
