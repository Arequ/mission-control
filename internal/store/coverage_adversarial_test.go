package store

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/Arequ/mission-control/internal/model"
)

func TestEmptyPollDoesNotWipeSnapshots(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	enrollDevice(t, s, "dev-a", "SER-A", "uuid-a", "00:1a:2b:3c:4d:0a", "mbp-a", "ava")
	now := s.Now()
	if err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "cs-a", LastSeen: now, Keys: coverage.Keys{Serial: "SER-A"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyObservations(ctx, "crowdstrike", nil, true, true); err != nil {
		t.Fatal(err)
	}
	if loadSnapMap(t, s, "crowdstrike")["cs-a"].DeviceID == "" {
		t.Fatal("empty poll deleted the snapshot")
	}
}

func TestSerialReuseBoardSwapAndGhostPromotion(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	old := enrollDevice(t, s, "dev-old", "S1", "uuid-old", "00:1a:2b:3c:4d:11", "mbp-old", "ava")
	now := s.Now()
	if err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "still-old", LastSeen: now, Keys: coverage.Keys{Serial: "S1", HardwareUUID: "uuid-old"}},
		{NativeID: "reused", LastSeen: now, Keys: coverage.Keys{Serial: "S1", HardwareUUID: "uuid-new", MAC: "00:1a:2b:3c:4d:11"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	snaps := loadSnapMap(t, s, "crowdstrike")
	if snaps["still-old"].DeviceID != old {
		t.Fatalf("live uuid lost its device: %+v", snaps["still-old"])
	}
	if snaps["reused"].DeviceID != "" {
		t.Fatalf("reused serial attached to the live device: %+v", snaps["reused"])
	}
	if snaps["reused"].SubjectID == old {
		t.Fatal("serial reuse collapsed into the enrolled device")
	}

	if err := s.ApplyObservations(ctx, "kolide", []coverage.Observation{
		{NativeID: "board", LastSeen: now, Keys: coverage.Keys{Serial: "S1", HardwareUUID: "uuid-board"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	if got := loadSnapMap(t, s, "kolide")["board"]; got.DeviceID != old || got.Confidence != "strong" {
		t.Fatalf("logic-board swap split the device: %+v", got)
	}

	if err := s.ApplyObservations(ctx, "netskope", []coverage.Observation{
		{NativeID: "ghost", LastSeen: now, Keys: coverage.Keys{Serial: "GHOST-NEW", MAC: "00:1a:2b:3c:4d:22"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	ghost := loadSnapMap(t, s, "netskope")["ghost"]
	if ghost.DeviceID != "" {
		t.Fatalf("expected a ghost: %+v", ghost)
	}
	enrollDevice(t, s, "dev-ghost", "GHOST-NEW", "uuid-ghost", "00:1a:2b:3c:4d:22", "ghost-host", "nina")
	if err := s.ApplyObservations(ctx, "netskope", []coverage.Observation{
		{NativeID: "ghost", LastSeen: now, Keys: coverage.Keys{Serial: "ghost-new"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	promoted := loadSnapMap(t, s, "netskope")["ghost"]
	if promoted.DeviceID != "dev-ghost" {
		t.Fatalf("ghost did not become the device: %+v", promoted)
	}
	matrix, err := s.CoverageMatrix(ctx, "ghost", "", "GHOST-NEW", 7, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Total != 0 {
		t.Fatalf("promoted ghost still listed: %+v", matrix.Rows)
	}
}

func TestPartialSerialJoinsWithoutTransitiveMerge(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	now := s.Now()
	dock := "00:1a:2b:3c:4d:99"
	if err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "cs-1", LastSeen: now, Keys: coverage.Keys{Serial: "S1", MAC: dock, Hostname: "one", PrimaryUser: "ann"}},
		{NativeID: "cs-2", LastSeen: now, Keys: coverage.Keys{Serial: "S2", MAC: dock, Hostname: "two", PrimaryUser: "bob"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyObservations(ctx, "kolide", []coverage.Observation{
		{NativeID: "ko-bridge", LastSeen: now, Keys: coverage.Keys{MAC: dock, Hostname: "two", PrimaryUser: "bob"}},
		{NativeID: "ko-only-mac", LastSeen: now, Keys: coverage.Keys{MAC: "00:1a:2b:3c:4d:77"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	cs := loadSnapMap(t, s, "crowdstrike")
	ko := loadSnapMap(t, s, "kolide")
	if cs["cs-1"].SubjectID == cs["cs-2"].SubjectID {
		t.Fatal("shared dock collapsed two serials")
	}
	if ko["ko-bridge"].SubjectID == cs["cs-1"].SubjectID || ko["ko-bridge"].SubjectID == cs["cs-2"].SubjectID {
		t.Fatalf("bridge joined a serial through the dock: %+v", ko["ko-bridge"])
	}
	if err := s.ApplyObservations(ctx, "rapid7", []coverage.Observation{
		{NativeID: "r7", LastSeen: now, Keys: coverage.Keys{MAC: "00:1a:2b:3c:4d:77", Hostname: "solo"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	// A later source that adds the serial must pull the MAC-only record's
	// subject onto that serial. Re-applying the weak source joins it.
	if err := s.ApplyObservations(ctx, "proofpoint", []coverage.Observation{
		{NativeID: "pp", LastSeen: now, Keys: coverage.Keys{Serial: "ONLY", MAC: "00:1a:2b:3c:4d:77"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyObservations(ctx, "rapid7", []coverage.Observation{
		{NativeID: "r7", LastSeen: now, Keys: coverage.Keys{MAC: "00:1a:2b:3c:4d:77"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	pp := loadSnapMap(t, s, "proofpoint")["pp"]
	r7 := loadSnapMap(t, s, "rapid7")["r7"]
	if pp.SubjectID == "" || pp.SubjectID != r7.SubjectID {
		t.Fatalf("serial-less source stayed split: pp=%+v r7=%+v", pp, r7)
	}
}

func TestCoverageDenominatorExcludesGhosts(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	enrollDevice(t, s, "dev-a", "SER-A", "uuid-a", "00:1a:2b:3c:4d:0a", "mbp-a", "ava")
	now := s.Now()
	if err := s.ProjectOsquery(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "ghost", LastSeen: now, Keys: coverage.Keys{Serial: "GHOST-1", Hostname: "unknown"}},
	}, true, true); err != nil {
		t.Fatal(err)
	}
	matrix, err := s.CoverageMatrix(ctx, "", "", "", 7, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cs float64
	for _, col := range matrix.Sources {
		if col.Key == "crowdstrike" {
			cs = col.Percent
		}
	}
	if cs != 0 {
		t.Fatalf("ghost inflated crowdstrike coverage to %v", cs)
	}
	missing, err := s.CoverageMatrix(ctx, "missing", "crowdstrike", "", 7, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if missing.Total != 1 || missing.Rows[0].Kind != "device" {
		t.Fatalf("missing filter included non-devices: %+v", missing.Rows)
	}
}

func TestOverlappingSyncDoesNotDoubleIngest(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	enrollDevice(t, s, "dev-a", "SER-1", "uuid-1", "00:1a:2b:3c:4d:01", "mbp", "ava")
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":1800}`))
		case "/devices/queries/devices-scroll/v1":
			_, _ = w.Write([]byte(`{"resources":["aid"],"meta":{"pagination":{"offset":""}}}`))
		case "/devices/entities/devices/v2":
			_, _ = w.Write([]byte(`{"resources":[{"device_id":"aid","serial_number":"SER-1","hostname":"mbp","last_seen":"2026-10-19T11:00:00Z"}]}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "super-secret-token leaked")
		}
	}))
	defer srv.Close()
	p := model.Principal{Kind: "api_token", Name: "test"}
	created, err := s.CreateConnector(ctx, p, model.Connector{
		Name: "crowdstrike", Source: "crowdstrike", Mode: "api", Enabled: true, BaseURL: srv.URL,
		ClientID: "cid", ClientSecret: "super-secret-token", IntervalSeconds: 60, StaleAfterSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, `UPDATE source_connectors SET sync_lock_until=$2 WHERE id=$1`, created.ID, s.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	before := hits
	s.syncConnector(ctx, mustLoad(t, s, created.ID))
	if hits != before {
		t.Fatalf("overlapping sync polled the vendor, hits %d -> %d", before, hits)
	}
	if _, err := s.Pool().Exec(ctx, `UPDATE source_connectors SET sync_lock_until=NULL WHERE id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	s.syncConnector(ctx, mustLoad(t, s, created.ID))
	if loadSnapMap(t, s, "crowdstrike")["aid"].DeviceID == "" {
		t.Fatal("unlocked sync did not ingest")
	}
	var events int
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM coverage_events WHERE source='crowdstrike' AND kind='source_seen'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	s.syncConnector(ctx, mustLoad(t, s, created.ID))
	var again int
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM coverage_events WHERE source='crowdstrike' AND kind='source_seen'`).Scan(&again); err != nil {
		t.Fatal(err)
	}
	if again != events {
		t.Fatalf("second sync double-ingested events %d -> %d", events, again)
	}
	pub, err := s.GetConnector(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pub.LastSyncError, "super-secret-token") || pub.ClientSecret != "" {
		t.Fatalf("secret leaked: %+v", pub)
	}
}

func TestFailedPollKeepsSnapshots(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	enrollDevice(t, s, "dev-a", "SER-1", "uuid-1", "00:1a:2b:3c:4d:01", "mbp", "ava")
	now := s.Now()
	if err := s.ApplyObservations(ctx, "crowdstrike", []coverage.Observation{
		{NativeID: "keep", LastSeen: now, Keys: coverage.Keys{Serial: "SER-1"}},
	}, true, false); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom super-secret-token", http.StatusInternalServerError)
	}))
	defer srv.Close()
	p := model.Principal{Kind: "api_token", Name: "test"}
	created, err := s.CreateConnector(ctx, p, model.Connector{
		Name: "crowdstrike", Source: "crowdstrike", Mode: "api", Enabled: true, BaseURL: srv.URL,
		ClientID: "cid", ClientSecret: "super-secret-token", IntervalSeconds: 60, StaleAfterSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.syncConnector(ctx, mustLoad(t, s, created.ID))
	if loadSnapMap(t, s, "crowdstrike")["keep"].DeviceID == "" {
		t.Fatal("failed poll removed the snapshot")
	}
	pub, err := s.GetConnector(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pub.LastSyncStatus != "error" || strings.Contains(pub.LastSyncError, "super-secret-token") {
		t.Fatalf("status=%s err=%s", pub.LastSyncStatus, pub.LastSyncError)
	}
	var audit string
	if err := s.Pool().QueryRow(ctx, `SELECT coalesce(string_agg(detail::text, ''), '') FROM audit_log`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, "super-secret-token") {
		t.Fatalf("audit leaked the secret: %s", audit)
	}
}

func TestMatrixScale(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	const n = 5000
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := s.Now()
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (
			id, node_key_hash, host_identifier, hardware_uuid, serial, hostname, computer_name,
			platform, primary_mac, username, os_version, last_seen_at, created_at, updated_at)
		SELECT 'dev-' || i,
			'hash-' || i,
			'host-' || i,
			'uuid-' || i,
			'SER' || i,
			'host-' || i,
			'host-' || i,
			'darwin',
			'00:1a:' || lpad(to_hex((i / 65536) % 256), 2, '0') || ':' || lpad(to_hex((i / 256) % 256), 2, '0') || ':' || lpad(to_hex(i % 256), 2, '0') || ':01',
			'user-' || i,
			'15.7',
			$2,
			$2,
			$2
		FROM generate_series(1, $1) AS i`, n, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO source_snapshots (
			id, source, native_id, device_id, subject_id, serial, hostname, primary_user,
			fields, confidence, last_seen_at, updated_at)
		SELECT src || '-' || i,
			src,
			src || '-' || i,
			'dev-' || i,
			'dev-' || i,
			'SER' || i,
			'host-' || i,
			'user-' || i,
			'{}'::jsonb,
			'strong',
			$2,
			$2
		FROM generate_series(1, $1) AS i
		CROSS JOIN (VALUES ('osquery'), ('munki'), ('crowdstrike'), ('rapid7'), ('netskope'), ('proofpoint'), ('blastshield'), ('kolide')) AS v(src)`, n, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Pool().Query(ctx, `EXPLAIN (ANALYZE, FORMAT TEXT) SELECT source, device_id, subject_id, last_seen_at FROM source_snapshots`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var explain strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		explain.WriteString(line)
		explain.WriteByte('\n')
	}
	start := time.Now()
	matrix, err := s.CoverageMatrix(ctx, "", "", "", 7, 100, 0)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Total != n || len(matrix.Sources) != 8 || matrix.Sources[0].Percent != 100 {
		t.Fatalf("matrix total=%d percent=%v elapsed=%s\n%s", matrix.Total, matrix.Sources[0].Percent, elapsed, explain.String())
	}
	t.Logf("matrix %d devices x 8 sources in %s\n%s", n, elapsed, explain.String())
	if elapsed > 3*time.Second {
		t.Fatalf("matrix query too slow: %s\n%s", elapsed, explain.String())
	}
}
