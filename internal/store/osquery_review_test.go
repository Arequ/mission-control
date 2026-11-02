package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"net/url"
	"os"
	"sync/atomic"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var reviewSeq atomic.Int64

func reviewStore(t *testing.T) *Store {
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
	name := fmt.Sprintf("mc_test_%d_%d", os.Getpid(), reviewSeq.Add(1))
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

func TestPlaceholderHardwareIDsStayDistinct(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	secret := "fleet-secret"
	if _, err := st.CreateEnrollSecret(ctx, model.Principal{Name: "t"}, model.EnrollSecret{Name: "fleet", Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	a, _, err := st.EnrollHost(ctx, secret, "vm-a", details("00000000-0000-0000-0000-000000000000", "None", "vm-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := st.EnrollHost(ctx, secret, "vm-b", details("00000000-0000-0000-0000-000000000000", "None", "vm-b"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("placeholder uuid and serial collapsed two hosts")
	}
	again, _, err := st.EnrollHost(ctx, secret, "vm-a", details("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "0", "vm-a"))
	if err != nil {
		t.Fatal(err)
	}
	if again != a {
		t.Fatalf("hostname fallback re-enroll split the device: %s %s", a, again)
	}
	emptyA, _, err := st.EnrollHost(ctx, secret, "host-a", details("", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	emptyB, _, err := st.EnrollHost(ctx, secret, "host-b", details("", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if emptyA == emptyB {
		t.Fatal("empty uuid and serial collapsed two host identifiers")
	}
	var uuid, serial string
	if err := st.Pool().QueryRow(ctx, `SELECT hardware_uuid, serial FROM devices WHERE id=$1`, a).Scan(&uuid, &serial); err != nil {
		t.Fatal(err)
	}
	if uuid != "" || serial != "" {
		t.Fatalf("placeholders were stored: uuid=%q serial=%q", uuid, serial)
	}
}

func TestReenrollStoresLargeMemory(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	secret := "fleet-secret"
	if _, err := st.CreateEnrollSecret(ctx, model.Principal{Name: "t"}, model.EnrollSecret{Name: "fleet", Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	info := details("UUID-MEM", "SER-MEM", "mem")
	info["system_info"].(map[string]any)["physical_memory"] = "17179869184"
	info["system_info"].(map[string]any)["cpu_logical_cores"] = "10"
	id, _, err := st.EnrollHost(ctx, secret, "mem", info)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.EnrollHost(ctx, secret, "mem", info); err != nil {
		t.Fatal(err)
	}
	dev, err := st.GetDevice(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if dev.PhysicalMemory != 17179869184 || dev.CPULogicalCores != 10 {
		t.Fatalf("memory=%d cores=%d", dev.PhysicalMemory, dev.CPULogicalCores)
	}
}

func TestSerialChangeKeepsDevice(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	secret := "fleet-secret"
	if _, err := st.CreateEnrollSecret(ctx, model.Principal{Name: "t"}, model.EnrollSecret{Name: "fleet", Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	id, _, err := st.EnrollHost(ctx, secret, "mbp", details("UUID-REAL", "SER-OLD", "mbp"))
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := st.EnrollHost(ctx, secret, "mbp", details("UUID-REAL", "SER-NEW", "mbp"))
	if err != nil {
		t.Fatal(err)
	}
	if again != id {
		t.Fatalf("serial change split the device: %s %s", id, again)
	}
	dev, err := st.GetDevice(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Serial != "SER-NEW" || dev.HardwareUUID != "UUID-REAL" {
		t.Fatalf("identity %+v", dev)
	}
}

func TestSameUUIDEnrollRace(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	secret := "fleet-secret"
	if _, err := st.CreateEnrollSecret(ctx, model.Principal{Name: "t"}, model.EnrollSecret{Name: "fleet", Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	keys := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, key, err := st.EnrollHost(ctx, secret, "race", details("UUID-RACE", "SER-RACE", "race"))
			if err != nil {
				errs <- err
				return
			}
			keys <- key
		}()
	}
	wg.Wait()
	close(errs)
	close(keys)
	for err := range errs {
		t.Fatal(err)
	}
	var devices int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM devices WHERE hardware_uuid='UUID-RACE'`).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if devices != 1 {
		t.Fatalf("devices = %d", devices)
	}
	var working int
	for key := range keys {
		_, invalid, err := st.OsqueryConfig(ctx, key, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !invalid {
			working++
		}
	}
	if working != 1 {
		t.Fatalf("working node keys = %d", working)
	}
}

func TestAppSnapshotDoesNotFalseRemove(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	id, key := enrollOne(t, st)
	chrome := `{"name":"Chrome","path":"/Applications/Google Chrome.app","bundle_identifier":"com.google.Chrome","bundle_short_version":"130.0"}`
	slack := `{"name":"Slack","path":"/Applications/Slack.app","bundle_identifier":"com.tinyspeck.slackmacgap","bundle_short_version":"4.41"}`
	firefox := `{"name":"Firefox","path":"/Applications/Firefox.app","bundle_identifier":"org.mozilla.firefox","bundle_short_version":"131.0"}`
	if err := ingestSnap(ctx, st, key, "mc_apps", 1, chrome, slack, firefox); err != nil {
		t.Fatal(err)
	}
	if acts := auditActions(t, st, id); containsStr(acts, "app_removed") || containsStr(acts, "app_installed") {
		t.Fatalf("baseline emitted events: %v", acts)
	}
	if err := ingestSnap(ctx, st, key, "mc_apps", 2, ""); err != nil {
		t.Fatal(err)
	}
	if got := appSet(t, st, id); len(got) != 3 {
		t.Fatalf("empty snapshot wiped apps: %v", got)
	}
	if acts := auditActions(t, st, id); containsStr(acts, "app_removed") {
		t.Fatalf("empty snapshot removed apps: %v", acts)
	}
	if err := ingestSnapRecords(ctx, st, key, "mc_apps", 3, chrome, slack); err != nil {
		t.Fatal(err)
	}
	got := appSet(t, st, id)
	if _, ok := got["/Applications/Firefox.app"]; ok {
		t.Fatal("event-mode snapshot kept a removed app")
	}
	if len(got) != 2 {
		t.Fatalf("apps %+v", got)
	}
	if err := ingestSnapRecords(ctx, st, key, "mc_apps", 4, chrome, slack); err != nil {
		t.Fatal(err)
	}
	if acts := auditActions(t, st, id); countAction(acts, "app_removed") != 1 {
		t.Fatalf("repeat snapshot flapped removals: %v", acts)
	}
	blank := `{"name":"Chrome","path":"/Applications/Google Chrome.app","bundle_identifier":"com.google.Chrome","bundle_short_version":""}`
	if err := ingestSnap(ctx, st, key, "mc_apps", 5, blank, slack); err != nil {
		t.Fatal(err)
	}
	if appSet(t, st, id)["/Applications/Google Chrome.app"] != "130.0" {
		t.Fatalf("empty version replaced a known version: %+v", appSet(t, st, id))
	}
	if acts := auditActions(t, st, id); countAction(acts, "app_updated") != 0 {
		t.Fatalf("empty version flapped app_updated: %v", acts)
	}
}

func TestPartialAppSnapshot(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	prev := snapshotBatchLimit
	snapshotBatchLimit = 2
	t.Cleanup(func() { snapshotBatchLimit = prev })
	id, key := enrollOne(t, st)
	chrome := `{"name":"Chrome","path":"/Applications/Google Chrome.app","bundle_short_version":"1"}`
	slack := `{"name":"Slack","path":"/Applications/Slack.app","bundle_short_version":"1"}`
	firefox := `{"name":"Firefox","path":"/Applications/Firefox.app","bundle_short_version":"1"}`
	if err := ingestSnap(ctx, st, key, "mc_apps", 1, chrome, slack, firefox); err != nil {
		t.Fatal(err)
	}
	if err := ingestSnapRecords(ctx, st, key, "mc_apps", 2, chrome, slack); err != nil {
		t.Fatal(err)
	}
	got := appSet(t, st, id)
	if len(got) != 3 || got["/Applications/Firefox.app"] != "1" {
		t.Fatalf("partial snapshot removed apps early: %+v", got)
	}
	if acts := auditActions(t, st, id); containsStr(acts, "app_removed") {
		t.Fatalf("partial snapshot emitted app_removed: %v", acts)
	}
	var open bool
	if err := st.Pool().QueryRow(ctx, `SELECT snapshot_open FROM device_query_results WHERE device_id=$1 AND query_name='mc_apps'`, id).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if !open {
		t.Fatal("generation closed before the tail arrived")
	}
	if err := ingestSnapRecords(ctx, st, key, "mc_apps", 2, chrome); err != nil {
		t.Fatal(err)
	}
	got = appSet(t, st, id)
	if _, ok := got["/Applications/Firefox.app"]; ok {
		t.Fatal("closed generation kept an app that was not in the snapshot")
	}
	if _, ok := got["/Applications/Slack.app"]; !ok || got["/Applications/Google Chrome.app"] != "1" {
		t.Fatalf("closed generation dropped a chunk app: %+v", got)
	}
	if err := st.Pool().QueryRow(ctx, `SELECT snapshot_open FROM device_query_results WHERE device_id=$1 AND query_name='mc_apps'`, id).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("generation stayed open after a short tail")
	}
}

func TestResultBatchOverUnnestChunk(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	_, key := enrollOne(t, st)
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < 450; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"mc_apps","action":"snapshot","counter":"1","snapshot":[{"name":"App%d","path":"/Applications/App%d.app","bundle_short_version":"1"}]}`, i, i)
	}
	b.WriteByte(']')
	if _, _, err := st.IngestLogs(ctx, key, "result", json.RawMessage(b.String())); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_result_logs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 450 {
		t.Fatalf("result rows = %d", n)
	}
}

func TestParallelHostIngest(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	secret := "fleet-secret"
	if _, err := st.CreateEnrollSecret(ctx, model.Principal{Name: "t"}, model.EnrollSecret{Name: "fleet", Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	const n = 500
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, key, err := st.EnrollHost(ctx, secret, fmt.Sprintf("host-%d", i), details(fmt.Sprintf("UUID-%d", i), fmt.Sprintf("SER-%d", i), fmt.Sprintf("host-%d", i)))
			if err != nil {
				errs <- err
				return
			}
			body := fmt.Sprintf(`[{"name":"mc_os_version","unixTime":"10","snapshot":[{"name":"macOS","version":"15.%d","platform":"darwin"}]}]`, i%5)
			if _, _, err := st.IngestLogs(ctx, key, "result", json.RawMessage(body)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var devices, logs int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_result_logs`).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if devices != n || logs != n {
		t.Fatalf("devices=%d logs=%d", devices, logs)
	}
}

func TestLogRetentionUsesServerTime(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	clk := &clock.Manual{T: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	st.SetClock(clk)
	_, key := enrollOne(t, st)
	body := `[{"name":"mc_os_version","unixTime":"4102444800","snapshot":[{"version":"15"}]}]`
	if _, _, err := st.IngestLogs(ctx, key, "result", json.RawMessage(body)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.IngestLogs(ctx, key, "status", json.RawMessage(`[{"severity":"0","filename":"tls.cpp","line":"1","message":"ok","version":"5.19.0"}]`)); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PurgeOsqueryLogs(ctx, 0); err != nil || n != 0 {
		t.Fatalf("disabled purge n=%d err=%v", n, err)
	}
	var left int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_result_logs`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("rows %d %v", left, err)
	}
	clk.Advance(48 * time.Hour)
	if _, _, err := st.IngestLogs(ctx, key, "status", json.RawMessage(`[{"message":"still here"}]`)); err != nil {
		t.Fatal(err)
	}
	n, err := st.PurgeOsqueryLogs(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("purged %d", n)
	}
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM osquery_status_logs`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("recent status rows %d %v", left, err)
	}
}

func TestDeviceListUsesSearchIndexes(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	conn, err := st.Pool().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	hostPlan := explainAll(t, tx, `EXPLAIN SELECT id FROM devices WHERE hostname ILIKE '%ava%' ESCAPE '\'`)
	if !strings.Contains(hostPlan, "devices_hostname_trgm_idx") {
		t.Fatalf("hostname search plan:\n%s", hostPlan)
	}
	rows, err := tx.Query(ctx, `EXPLAIN SELECT id FROM devices WHERE platform = 'darwin' ORDER BY last_seen_at DESC NULLS LAST`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if !strings.Contains(b.String(), "devices_platform_seen_idx") {
		t.Fatalf("platform plan:\n%s", b.String())
	}
}

func TestPackIntervalAndDiscovery(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	p := model.Principal{Name: "t"}
	_, key := enrollOne(t, st)
	q, err := st.CreateOsqueryQuery(ctx, p, model.OsqueryQuery{Name: "launchd", SQL: "SELECT 1", Interval: 3600, Platform: "darwin", Snapshot: true})
	if err != nil {
		t.Fatal(err)
	}
	over := 15
	if _, err := st.CreateOsqueryPack(ctx, p, model.OsqueryPack{
		Name: "fast", Platform: "darwin", Interval: &over, Discovery: []string{"SELECT 1 FROM osquery_info"},
		QueryIDs: []string{q.ID}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateOsqueryPack(ctx, p, model.OsqueryPack{
		Name: "natural", QueryIDs: []string{q.ID}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	cfg, invalid, err := st.OsqueryConfig(ctx, key, time.Minute)
	if err != nil || invalid {
		t.Fatalf("config invalid=%v err=%v", invalid, err)
	}
	packs := cfg["packs"].(map[string]any)
	fast := packs["fast"].(map[string]any)
	disc, _ := fast["discovery"].([]string)
	if len(disc) != 1 || disc[0] == "" {
		t.Fatalf("discovery %#v", fast["discovery"])
	}
	qs := fast["queries"].(map[string]any)
	if qs["launchd"].(map[string]any)["interval"] != 15 {
		t.Fatalf("pack interval %#v", qs["launchd"])
	}
	natural := packs["natural"].(map[string]any)["queries"].(map[string]any)
	if natural["launchd"].(map[string]any)["interval"] != 3600 {
		t.Fatalf("query interval %#v", natural["launchd"])
	}
}

func TestDistributedWriteCannotTouchAnotherHost(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	secret := "fleet-secret"
	if _, err := st.CreateEnrollSecret(ctx, model.Principal{Name: "t"}, model.EnrollSecret{Name: "fleet", Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	a, keyA, err := st.EnrollHost(ctx, secret, "a", details("UUID-A", "SER-A", "a"))
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, err := st.EnrollHost(ctx, secret, "b", details("UUID-B", "SER-B", "b"))
	if err != nil {
		t.Fatal(err)
	}
	live, err := st.CreateLiveQuery(ctx, model.Principal{Name: "t"}, model.LiveQueryRequest{SQL: "SELECT 1 AS n", DeviceIDs: []string{a}, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := st.DistributedWrite(ctx, keyB, map[string][]map[string]string{live.ID: {{"n": "1"}}}, map[string]int{live.ID: 0}, nil)
	if err != nil || invalid {
		t.Fatalf("write err=%v invalid=%v", err, invalid)
	}
	got, err := st.GetLiveQuery(ctx, live.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == "complete" || len(got.Rows) != 0 {
		t.Fatalf("other host completed the query: %+v", got)
	}
	if _, _, err := st.DistributedRead(ctx, keyA); err != nil {
		t.Fatal(err)
	}
	invalid, err = st.DistributedWrite(ctx, keyA, map[string][]map[string]string{live.ID: {{"n": "1"}}}, map[string]int{live.ID: 0}, nil)
	if err != nil || invalid {
		t.Fatal(err)
	}
	got, err = st.GetLiveQuery(ctx, live.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "complete" || len(got.Rows) != 1 {
		t.Fatalf("owner write %+v", got)
	}
}

func TestLiveSQLAndNamesCannotInject(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	id, _ := enrollOne(t, st)
	_, err := st.CreateLiveQuery(ctx, model.Principal{Name: "t"}, model.LiveQueryRequest{
		SQL: "SELECT 1; DROP TABLE devices", DeviceIDs: []string{id}, TimeoutSeconds: 30,
	})
	if err == nil {
		t.Fatal("multi-statement sql accepted")
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("devices %d %v", n, err)
	}
	_, err = st.CreateOsqueryLabel(ctx, model.Principal{Name: "t"}, model.OsqueryLabel{Name: "bad'; drop", Kind: "dynamic", SQL: "SELECT 1"})
	if err == nil {
		t.Fatal("label name accepted")
	}
	_, err = st.CreateOsqueryQuery(ctx, model.Principal{Name: "t"}, model.OsqueryQuery{Name: "mc_pwn", SQL: "SELECT 1", Interval: 60})
	if err == nil {
		t.Fatal("reserved query name accepted")
	}
}

func TestNodeKeyIsHashed(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	id, key := enrollOne(t, st)
	if len(key) != 64 {
		t.Fatalf("node key %q", key)
	}
	var hash string
	if err := st.Pool().QueryRow(ctx, `SELECT node_key_hash FROM devices WHERE id=$1`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == key || hash != auth.Hash(key) {
		t.Fatal("node key was stored raw")
	}
	dev, err := st.GetDevice(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(dev)
	if strings.Contains(string(raw), key) {
		t.Fatal("device json contains the node key")
	}
}

func TestEnrollSecretMatchIsNotPrefixScoped(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	p := model.Principal{Name: "t"}
	if _, err := st.CreateEnrollSecret(ctx, p, model.EnrollSecret{Name: "one", Secret: "secret-one", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	second, err := st.CreateEnrollSecret(ctx, p, model.EnrollSecret{Name: "two", Secret: "secret-two", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.EnrollHost(ctx, "secret-two", "h", details("UUID-S", "SER-S", "h")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.EnrollHost(ctx, "secret-tw0", "h2", details("UUID-S2", "SER-S2", "h2")); err == nil {
		t.Fatal("one-character mismatch enrolled")
	}
	second.Enabled = false
	second.Secret = ""
	if _, err := st.UpdateEnrollSecret(ctx, p, second.ID, second); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.EnrollHost(ctx, "secret-two", "h3", details("UUID-S3", "SER-S3", "h3")); err == nil {
		t.Fatal("disabled secret enrolled")
	}
}

func TestClockSkewDoesNotMoveLastSeen(t *testing.T) {
	ctx := context.Background()
	st := reviewStore(t)
	when := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	st.SetClock(&clock.Manual{T: when})
	id, key := enrollOne(t, st)
	body := `[{"name":"mc_os_version","unixTime":"0","snapshot":[{"name":"macOS","version":"15","platform":"darwin"}]}]`
	if _, _, err := st.IngestLogs(ctx, key, "result", json.RawMessage(body)); err != nil {
		t.Fatal(err)
	}
	dev, err := st.GetDevice(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if dev.LastSeenAt == nil || !dev.LastSeenAt.Equal(when) {
		t.Fatalf("last seen %v", dev.LastSeenAt)
	}
	if dev.OSVersion != "15" {
		t.Fatalf("skewed unixTime dropped the snapshot: %+v", dev.OSVersion)
	}
}

func details(uuid, serial, hostname string) map[string]any {
	return map[string]any{
		"system_info": map[string]any{"uuid": uuid, "hardware_serial": serial, "hostname": hostname, "computer_name": hostname},
		"os_version":  map[string]any{"name": "macOS", "platform": "darwin", "version": "15.0"},
	}
}

func enrollOne(t *testing.T, st *Store) (string, string) {
	t.Helper()
	ctx := context.Background()
	secret := "fleet-secret"
	if _, err := st.CreateEnrollSecret(ctx, model.Principal{Name: "t"}, model.EnrollSecret{Name: "fleet", Secret: secret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	id, key, err := st.EnrollHost(ctx, secret, "mbp", details("UUID-1", "SER-1", "mbp"))
	if err != nil {
		t.Fatal(err)
	}
	return id, key
}

func ingestSnap(ctx context.Context, st *Store, key, name string, counter int, rows ...string) error {
	body := fmt.Sprintf(`[{"name":"%s","counter":"%d","action":"snapshot","snapshot":[%s]}]`, name, counter, strings.Join(rows, ","))
	_, _, err := st.IngestLogs(ctx, key, "result", json.RawMessage(body))
	return err
}

func ingestSnapRecords(ctx context.Context, st *Store, key, name string, counter int, rows ...string) error {
	parts := make([]string, len(rows))
	for i, row := range rows {
		parts[i] = fmt.Sprintf(`{"name":"%s","counter":"%d","action":"snapshot","snapshot":[%s]}`, name, counter, row)
	}
	_, _, err := st.IngestLogs(ctx, key, "result", json.RawMessage("["+strings.Join(parts, ",")+"]"))
	return err
}

func auditActions(t *testing.T, st *Store, deviceID string) []string {
	t.Helper()
	rows, err := st.Pool().Query(context.Background(), `SELECT action FROM audit_log WHERE resource_id=$1 ORDER BY id`, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		out = append(out, action)
	}
	return out
}

func appSet(t *testing.T, st *Store, deviceID string) map[string]string {
	t.Helper()
	dev, err := st.GetDevice(context.Background(), deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, app := range dev.Apps {
		out[app.Path] = app.Version
	}
	return out
}

func explainAll(t *testing.T, tx pgx.Tx, query string) string {
	t.Helper()
	rows, err := tx.Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func containsStr(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func countAction(list []string, want string) int {
	n := 0
	for _, item := range list {
		if item == want {
			n++
		}
	}
	return n
}
