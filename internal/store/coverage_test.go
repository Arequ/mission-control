package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

var coverageSeq atomic.Int64

// newCoverageStore opens a throwaway database without importing testutil
// (that package imports store, and these tests need unexported helpers).
func newCoverageStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	admin := os.Getenv("TEST_DATABASE_ADMIN")
	if admin == "" {
		admin = "postgres://missioncontrol:missioncontrol@127.0.0.1:5432/postgres?sslmode=disable"
	}
	pool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	name := fmt.Sprintf("mc_test_%d_%d", os.Getpid(), coverageSeq.Add(1))
	if _, err := pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		pool.Close()
		t.Fatalf("create database %s: %v", name, err)
	}
	pool.Close()
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	s, err := Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		pool, err := pgxpool.New(context.Background(), admin)
		if err != nil {
			return
		}
		defer pool.Close()
		_, _ = pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return s
}

func TestIdentitySnapshotsAndCoverageMath(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	p := model.Principal{Kind: "api_token", Name: "test"}
	a := enrollDevice(t, s, "dev-a", "SER-A", "uuid-a", "00:1a:2b:3c:4d:0a", "mbp-a", "ava")
	b := enrollDevice(t, s, "dev-b", "SER-B", "uuid-b", "00:1a:2b:3c:4d:0b", "mba-b", "noah")
	now := s.Now()

	err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "cs-a", LastSeen: now.Add(-time.Minute), OSVersion: "26.1", Keys: coverage.Keys{Serial: "ser-a", HardwareUUID: "UUID-A", Hostname: "mbp-a", PrimaryUser: "ava"}},
		{NativeID: "cs-placeholder", LastSeen: now.Add(-time.Minute), Keys: coverage.Keys{Serial: "System Serial Number", HardwareUUID: "uuid-b", Hostname: "mba-b"}},
		{NativeID: "cs-ghost", LastSeen: now.Add(-time.Hour), Keys: coverage.Keys{Serial: "GHOST-1", Hostname: "unknown-mac"}},
		{NativeID: "cs-conflict", LastSeen: now.Add(-time.Hour), Keys: coverage.Keys{Serial: "SER-A", HardwareUUID: "uuid-b"}},
		{NativeID: "cs-mac", LastSeen: now.Add(-time.Minute), Keys: coverage.Keys{MAC: "00-1A-2B-3C-4D-0A", Hostname: "wrong-host"}},
	}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	// Placeholder-only serial must not attach, even if some other device has a normal serial.
	if err := s.ApplyObservations(ctx, "kolide", []coverage.Observation{
		{NativeID: "ko-blank", LastSeen: now, Keys: coverage.Keys{Serial: "To Be Filled By O.E.M.", Hostname: "mbp-a"}},
		{NativeID: "ko-host", LastSeen: now, Keys: coverage.Keys{Hostname: "mba-b", PrimaryUser: "Noah"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	snaps := loadSnapMap(t, s, "crowdstrike")
	if snaps["cs-a"].DeviceID != a || snaps["cs-a"].Confidence != "strong" || !containsAll(snaps["cs-a"].MatchedOn, "serial", "hardware_uuid") {
		t.Fatalf("strong %+v", snaps["cs-a"])
	}
	if snaps["cs-placeholder"].DeviceID != b || strings.Join(snaps["cs-placeholder"].MatchedOn, ",") != "hardware_uuid" {
		t.Fatalf("placeholder serial should match on uuid only: %+v", snaps["cs-placeholder"])
	}
	if snaps["cs-ghost"].DeviceID != "" || snaps["cs-ghost"].Confidence != "none" {
		t.Fatalf("ghost %+v", snaps["cs-ghost"])
	}
	if snaps["cs-conflict"].DeviceID != "" || snaps["cs-conflict"].Confidence != "conflict" {
		t.Fatalf("conflict %+v", snaps["cs-conflict"])
	}
	if snaps["cs-mac"].DeviceID != a || snaps["cs-mac"].Confidence != "weak" {
		t.Fatalf("mac %+v", snaps["cs-mac"])
	}
	kolide := loadSnapMap(t, s, "kolide")
	if kolide["ko-blank"].DeviceID != "" {
		t.Fatalf("placeholder serial and hostname alone matched %s", kolide["ko-blank"].DeviceID)
	}
	if kolide["ko-host"].DeviceID != b || kolide["ko-host"].Confidence != "weak" {
		t.Fatalf("hostname plus user %+v", kolide["ko-host"])
	}

	// Second poll with a disagreeing hostname emits one disagreement, not a second sighting.
	if err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "cs-a", LastSeen: now, OSVersion: "26.1", Keys: coverage.Keys{Serial: "SER-A", HardwareUUID: "uuid-a", Hostname: "old-name", PrimaryUser: "ava"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	events := coverageEvents(t, s, a)
	// The weak MAC record disagrees on hostname immediately. The second poll adds the rename and does not sight the device again.
	if countKind(events, "source_seen") != 1 || countKind(events, "field_disagreement") != 2 || countKind(events, "source_lost") != 0 {
		t.Fatalf("events %#v", events)
	}
	// The mac-only record was for the same device and disappeared in the full sync, but cs-a remains.
	if countKind(events, "source_lost") != 0 {
		t.Fatal("source still present")
	}
	ghostEvents := coverageEvents(t, s, snaps["cs-ghost"].SubjectID)
	if countKind(ghostEvents, "source_seen") != 1 || countKind(ghostEvents, "source_lost") != 1 {
		t.Fatalf("ghost events %#v", ghostEvents)
	}

	stale, err := s.CreateConnector(ctx, p, model.Connector{
		Name: "netskope", Source: "netskope", Mode: "elastic", Enabled: true,
		ElasticURL: "https://elasticsearch.example.invalid", IndexPattern: "logs-netskope-*",
		StaleAfterSeconds: 3600, IntervalSeconds: 3600, ManagedBy: "terraform",
		ElasticAPIKey: "super-secret-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if stale.ElasticAPIKey != "" || stale.ClientSecret != "" || !stale.HasElasticAPIKey {
		t.Fatalf("secret leaked %+v", stale)
	}
	again, err := s.UpdateConnector(ctx, p, stale.ID, model.Connector{
		Name: "netskope", Mode: "elastic", Enabled: true, ElasticURL: stale.ElasticURL,
		IndexPattern: stale.IndexPattern, StaleAfterSeconds: 86400, IntervalSeconds: 3600,
	})
	if err != nil || !again.HasElasticAPIKey || again.StaleAfterSeconds != 86400 {
		t.Fatalf("update %+v %v", again, err)
	}
	var auditDetail string
	if err := s.Pool().QueryRow(ctx, `SELECT detail::text FROM audit_log WHERE resource_id=$1 AND action='create'`, stale.ID).Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditDetail, "super-secret-token") {
		t.Fatalf("audit stored the credential: %s", auditDetail)
	}

	if err := s.ApplyObservations(ctx, "netskope", []coverage.Observation{
		{NativeID: "ns-a", LastSeen: now.Add(-9 * 24 * time.Hour), OSVersion: "15.7.1", IPAddress: "192.168.1.23", Keys: coverage.Keys{Serial: "SER-A", Hostname: "mbp-a", PrimaryUser: "ava"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	matrix, err := s.CoverageMatrix(ctx, "stale", "netskope", "", 7, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Total < 1 {
		t.Fatalf("stale filter %#v", matrix.Rows)
	}
	missing, err := s.CoverageMatrix(ctx, "missing", "blastshield", "", 7, 50, 0)
	if err != nil || missing.Total < 2 {
		t.Fatalf("missing blastshield total=%d err=%v", missing.Total, err)
	}
	ghosts, err := s.CoverageMatrix(ctx, "ghost", "", "", 7, 50, 0)
	if err != nil || ghosts.Total < 1 {
		t.Fatalf("ghosts %#v %v", ghosts.Rows, err)
	}
	pane, err := s.CoverageDevice(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if pane.Seen < 1 || pane.Match.Confidence != "strong" {
		t.Fatalf("pane %+v", pane)
	}
	var disagreed bool
	for _, field := range pane.Fields {
		if field.Field == "os_version" {
			for _, v := range field.Values {
				if v.Source == "netskope" && v.Disagrees && v.Value == "15.7.1" {
					disagreed = true
				}
			}
		}
	}
	if !disagreed {
		t.Fatalf("expected netskope os disagreement %+v", pane.Fields)
	}
	rematchFrom := snaps["cs-a"].DeviceID
	if err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "cs-a", LastSeen: now, Keys: coverage.Keys{Serial: "SER-B", HardwareUUID: "uuid-b", Hostname: "mba-b"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	moved := loadSnapMap(t, s, "crowdstrike")["cs-a"]
	if moved.DeviceID != b || moved.DeviceID == rematchFrom {
		t.Fatalf("rematch %+v", moved)
	}
	if countKind(coverageEvents(t, s, b), "rematched") < 1 {
		t.Fatal("expected rematched event")
	}
}

func TestConnectorSyncUsesFakeFalcon(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	enrollDevice(t, s, "dev-a", "SER-1", "uuid-1", "02:00:00:00:00:01", "mbp", "ava")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/oauth2/token":
			if strings.Contains(r.URL.String(), "sync-secret") {
				t.Errorf("secret in url")
			}
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case "/devices/queries/devices-scroll/v1":
			_, _ = w.Write([]byte(`{"resources":["aid"],"meta":{"pagination":{"offset":""}}}`))
		case "/devices/entities/devices/v2":
			if !strings.Contains(string(body), "aid") {
				t.Errorf("body %s", body)
			}
			_, _ = w.Write([]byte(`{"resources":[{"device_id":"aid","serial_number":"SER-1","hostname":"mbp","mac_address":"02:00:00:00:00:01","local_ip":"10.0.0.8","os_version":"26.1","last_seen":"2026-10-19T11:00:00Z","agent_version":"7.18"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p := model.Principal{Kind: "api_token", Name: "test"}
	created, err := s.CreateConnector(ctx, p, model.Connector{
		Name: "crowdstrike", Source: "crowdstrike", Mode: "api", Enabled: true, BaseURL: srv.URL,
		ClientID: "cid", ClientSecret: "sync-secret", IntervalSeconds: 60, StaleAfterSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.syncConnector(ctx, mustLoad(t, s, created.ID))
	got := loadSnapMap(t, s, "crowdstrike")
	if got["aid"].DeviceID == "" || got["aid"].Fields["os_version"] != "26.1" {
		t.Fatalf("%+v", got["aid"])
	}
	pub, err := s.GetConnector(ctx, created.ID)
	if err != nil || pub.LastSyncStatus != "ok" || pub.LastSyncCount != 1 || pub.ClientSecret != "" {
		t.Fatalf("%+v %v", pub, err)
	}
}

func enrollDevice(t *testing.T, s *Store, id, serial, uuid, mac, host, user string) string {
	t.Helper()
	now := s.Now()
	_, err := s.Pool().Exec(context.Background(), `
		INSERT INTO devices (
			id, node_key_hash, host_identifier, hardware_uuid, serial, hostname, computer_name,
			platform, os_name, os_version, hardware_model, hardware_vendor, primary_ip, primary_mac, username,
			enrolled_at, last_enrolled_at, last_seen_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'darwin','macOS','26.1','Mac16,1','Apple','10.0.0.5',$8,$9,$10,$10,$10,$10,$10)`,
		id, "hash-"+id, host, uuid, serial, host, host, mac, user, now)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func loadSnapMap(t *testing.T, s *Store, source string) map[string]snapRow {
	t.Helper()
	m, err := s.loadSourceSnapshots(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func coverageEvents(t *testing.T, s *Store, subject string) []string {
	t.Helper()
	rows, err := s.Pool().Query(context.Background(), `SELECT kind FROM coverage_events WHERE subject_id=$1`, subject)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

func countKind(events []string, kind string) int {
	n := 0
	for _, e := range events {
		if e == kind {
			n++
		}
	}
	return n
}

func containsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, v := range have {
		set[v] = true
	}
	for _, v := range want {
		if !set[v] {
			return false
		}
	}
	return true
}

func mustLoad(t *testing.T, s *Store, id string) storedConnector {
	t.Helper()
	c, err := s.loadConnector(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSeedCoverageShapes(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	if err := s.SeedDemo(ctx); err != nil {
		t.Fatal(err)
	}
	matrix, err := s.CoverageMatrix(ctx, "", "", "", 7, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Total < 42 || len(matrix.Sources) != 8 {
		t.Fatalf("matrix total=%d sources=%d", matrix.Total, len(matrix.Sources))
	}
	ghosts, err := s.CoverageMatrix(ctx, "ghost", "", "", 7, 20, 0)
	if err != nil || ghosts.Total < 2 {
		t.Fatalf("ghosts %d %v", ghosts.Total, err)
	}
	missing, err := s.CoverageMatrix(ctx, "missing", "crowdstrike", "", 7, 20, 0)
	if err != nil || missing.Total < 1 {
		t.Fatalf("missing cs %d %v", missing.Total, err)
	}
	single, err := s.CoverageMatrix(ctx, "single", "", "", 7, 20, 0)
	if err != nil || single.Total < 1 {
		t.Fatalf("single %d %v", single.Total, err)
	}
	stale, err := s.CoverageMatrix(ctx, "stale", "", "", 7, 50, 0)
	if err != nil || stale.Total < 1 {
		t.Fatalf("stale %d %v", stale.Total, err)
	}
	conflicts, err := s.CoverageMatrix(ctx, "all", "", "conflict-host", 7, 10, 0)
	if err != nil || conflicts.Total != 1 || conflicts.Rows[0].Kind != "conflict" {
		t.Fatalf("conflict %#v %v", conflicts.Rows, err)
	}
	pane, err := s.CoverageDevice(ctx, "dev-0001")
	if err != nil {
		t.Fatal(err)
	}
	if pane.Seen < 5 || pane.Seen > 7 || len(pane.Events) < 4 {
		t.Fatalf("ava seen=%d events=%d", pane.Seen, len(pane.Events))
	}
	var hostDisagree bool
	for _, field := range pane.Fields {
		if field.Field != "hostname" {
			continue
		}
		for _, v := range field.Values {
			if v.Source == "proofpoint" && v.Disagrees {
				hostDisagree = true
			}
		}
	}
	if !hostDisagree {
		t.Fatalf("ava hostname %+v", pane.Fields)
	}
	raw, _ := json.Marshal(pane)
	if strings.Contains(string(raw), "mc_dev_") {
		t.Fatal("seed credential leaked into the pane")
	}
	connectors, err := s.ListConnectors(ctx)
	if err != nil || len(connectors) != 8 {
		t.Fatalf("connectors %d %v", len(connectors), err)
	}
	for _, c := range connectors {
		if c.ClientSecret != "" || c.APIToken != "" || c.ElasticAPIKey != "" {
			t.Fatalf("secret returned %+v", c)
		}
	}
}
