package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/keel"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/testutil"
)

func keelKey(serial string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("store-test-" + serial))
	return ed25519.NewKeyFromSeed(seed[:])
}

func keelBody(t *testing.T, serial, runID, mode string, roles []string, profiles []map[string]any, sum map[string]int) ([]byte, keel.Report) {
	t.Helper()
	chain := []map[string]any{}
	for i, name := range roles {
		parents := []string{}
		if i > 0 {
			parents = []string{roles[i-1]}
		}
		chain = append(chain, map[string]any{"name": name, "parents": parents})
	}
	body, err := json.Marshal(map[string]any{
		"schema": keel.Schema, "run_id": runID, "mode": mode, "keel_version": "0.1.0",
		"started_at": "2026-11-03T15:00:00Z", "duration_ms": 10,
		"device":   map[string]any{"serial": serial, "hostname": "h-" + serial},
		"roles":    chain,
		"facts":    map[string]any{"serial": serial},
		"profiles": profiles, "resources": []any{}, "summary": sum,
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := keel.ParseReport(body, serial)
	if err != nil {
		t.Fatal(err)
	}
	return body, r
}

func keelStore(t *testing.T) (*store.Store, *clock.Manual) {
	t.Helper()
	st := testutil.NewStore(t)
	clk := &clock.Manual{T: time.Date(2026, 11, 3, 15, 0, 0, 0, time.UTC)}
	st.SetClock(clk)
	if _, err := st.CreateKeelEnrollSecret(context.Background(), model.Principal{Kind: "system"}, model.KeelEnrollSecret{Name: "fleet", Secret: "keel-store-secret", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return st, clk
}

func enrollKeel(t *testing.T, st *store.Store, serial string) ed25519.PublicKey {
	t.Helper()
	pub := keelKey(serial).Public().(ed25519.PublicKey)
	created, err := st.EnrollKeelDevice(context.Background(), "keel-store-secret", serial, "h-"+serial, pub)
	if err != nil || !created {
		t.Fatalf("enroll %s: %v %v", serial, created, err)
	}
	return pub
}

func TestKeelEnrollStoreRules(t *testing.T) {
	st, _ := keelStore(t)
	ctx := context.Background()
	pub := enrollKeel(t, st, "C02STORE001")
	if created, err := st.EnrollKeelDevice(ctx, "keel-store-secret", "C02STORE001", "", pub); err != nil || created {
		t.Fatalf("re-enroll %v %v", created, err)
	}
	other := keelKey("other").Public().(ed25519.PublicKey)
	if _, err := st.EnrollKeelDevice(ctx, "keel-store-secret", "C02STORE001", "", other); !errors.Is(err, store.ErrKeelKeyMismatch) {
		t.Fatalf("mismatch %v", err)
	}
	if _, err := st.EnrollKeelDevice(ctx, "wrong", "C02STORE002", "", other); !errors.Is(err, store.ErrEnrollRejected) {
		t.Fatalf("bad secret %v", err)
	}
	// A rotated secret stops the old value and keeps enrolled keys.
	secrets, err := st.ListKeelEnrollSecrets(ctx)
	if err != nil || len(secrets) != 1 {
		t.Fatal(secrets, err)
	}
	if _, err := st.UpdateKeelEnrollSecret(ctx, model.Principal{Kind: "system"}, secrets[0].ID, model.KeelEnrollSecret{Name: "fleet", Secret: "keel-store-rotated", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnrollKeelDevice(ctx, "keel-store-secret", "C02STORE003", "", other); !errors.Is(err, store.ErrEnrollRejected) {
		t.Fatalf("old secret after rotation %v", err)
	}
	if created, err := st.EnrollKeelDevice(ctx, "keel-store-rotated", "C02STORE003", "", other); err != nil || !created {
		t.Fatalf("rotated secret %v %v", created, err)
	}
	if _, err := st.KeelPublicKey(ctx, "C02STORE001"); err != nil {
		t.Fatalf("rotation dropped an enrolled key: %v", err)
	}
}

func TestKeelRunsPruneAndReplayFloor(t *testing.T) {
	st, clk := keelStore(t)
	ctx := context.Background()
	const serial = "C02PRUNE001"
	pub := enrollKeel(t, st, serial)
	base := clk.Now().Unix()
	for i := 0; i < store.KeelRunsKept+7; i++ {
		body, r := keelBody(t, serial, fmt.Sprintf("run-%03d", i), "apply", []string{"baseline"}, nil, map[string]int{"total": 1, "ok": 1})
		if err := st.RecordKeelReport(ctx, pub, base+int64(i), r, body); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	runs, err := st.ListKeelRuns(ctx, serial)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != store.KeelRunsKept || runs[0].RunID != fmt.Sprintf("run-%03d", store.KeelRunsKept+6) || runs[len(runs)-1].RunID != "run-007" {
		t.Fatalf("kept %d first=%s last=%s", len(runs), runs[0].RunID, runs[len(runs)-1].RunID)
	}
	var rows int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM keel_runs WHERE serial=$1`, serial).Scan(&rows); err != nil || rows != store.KeelRunsKept {
		t.Fatalf("rows %d %v", rows, err)
	}

	body, r := keelBody(t, serial, "late", "apply", []string{"baseline"}, nil, nil)
	last := base + int64(store.KeelRunsKept+6)
	if err := st.RecordKeelReport(ctx, pub, last, r, body); !errors.Is(err, store.ErrKeelReplay) {
		t.Fatalf("same timestamp %v", err)
	}
	if err := st.RecordKeelReport(ctx, pub, last-100, r, body); !errors.Is(err, store.ErrKeelReplay) {
		t.Fatalf("older timestamp %v", err)
	}
	// A different key (cleared and re-enrolled between verify and insert) cannot write.
	other := keelKey("someone").Public().(ed25519.PublicKey)
	if err := st.RecordKeelReport(ctx, other, last+1, r, body); !errors.Is(err, store.ErrKeelReplay) {
		t.Fatalf("wrong key %v", err)
	}
	// A retried run id with a fresh timestamp is accepted without a second row.
	dup, dr := keelBody(t, serial, fmt.Sprintf("run-%03d", store.KeelRunsKept+6), "apply", []string{"baseline"}, nil, nil)
	if err := st.RecordKeelReport(ctx, pub, last+2, dr, dup); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM keel_runs WHERE serial=$1`, serial).Scan(&rows); err != nil || rows != store.KeelRunsKept {
		t.Fatalf("rows after retry %d %v", rows, err)
	}
	// A NUL escape is valid JSON that jsonb rejects; it is a 400, not a 500.
	nul := []byte(strings.Replace(string(body), `"h-`+serial+`"`, `"h-\u0000"`, 1))
	nr, err := keel.ParseReport(nul, serial)
	if err != nil {
		t.Fatal(err)
	}
	var ve *store.ValidationError
	if err := st.RecordKeelReport(ctx, pub, last+3, nr, nul); !errors.As(err, &ve) {
		t.Fatalf("nul body %v", err)
	}
}

func TestKeelOverviewAndVariants(t *testing.T) {
	st, clk := keelStore(t)
	ctx := context.Background()
	ts := clk.Now().Unix()
	email := map[string]any{"name": "netskope", "enabled": true, "settings": map[string]any{"mode": "email", "enrollment": map[string]any{"auth_token": "[redacted]"}}}
	emailReordered := map[string]any{"name": "netskope", "enabled": true, "settings": map[string]any{"enrollment": map[string]any{"auth_token": "[redacted]"}, "mode": "email"}}
	idp := map[string]any{"name": "netskope", "enabled": true, "settings": map[string]any{"mode": "idp"}}
	munki := map[string]any{"name": "munki", "enabled": true, "settings": map[string]any{"managed_installs": []string{"GoogleChrome", "MacadminsPython"}}}
	off := map[string]any{"name": "screensaver", "enabled": false, "settings": map[string]any{}}
	devices := []struct {
		serial   string
		roles    []string
		profiles []map[string]any
		mode     string
		sum      map[string]int
		age      time.Duration
	}{
		{"C02CACHE001", []string{"baseline", "content_caching"}, []map[string]any{email, munki, off}, "apply", map[string]int{"total": 3, "ok": 3}, 0},
		{"C02CACHE002", []string{"baseline", "content_caching"}, []map[string]any{emailReordered, munki}, "apply", map[string]int{"total": 3, "ok": 2, "failed": 1}, 0},
		{"C02CACHE003", []string{"baseline", "content_caching"}, []map[string]any{idp}, "plan", map[string]int{"total": 3, "ok": 1, "would_change": 2}, 0},
		{"C02CACHE004", []string{"baseline", "content_caching"}, []map[string]any{munki}, "apply", map[string]int{"total": 1, "ok": 1}, 3 * time.Hour},
		{"C02EMPL0001", []string{"baseline", "employee"}, []map[string]any{idp}, "apply", map[string]int{"total": 1, "ok": 1}, 0},
	}
	for i, d := range devices {
		pub := enrollKeel(t, st, d.serial)
		clk.Set(time.Unix(ts, 0).Add(-d.age))
		body, r := keelBody(t, d.serial, "r-"+d.serial, d.mode, d.roles, d.profiles, d.sum)
		if err := st.RecordKeelReport(ctx, pub, ts+int64(i), r, body); err != nil {
			t.Fatal(err)
		}
	}
	clk.Set(time.Unix(ts, 0))
	enrollKeel(t, st, "C02NEVERRPT")
	// A policy that did not compile reports empty roles and a "compile: "
	// warning. It is a failing device and is in no role.
	pub := enrollKeel(t, st, "C02COMPILE1")
	cbody, _ := keelBody(t, "C02COMPILE1", "r-compile", "apply", nil, nil, nil)
	var doc map[string]any
	_ = json.Unmarshal(cbody, &doc)
	doc["warnings"] = []string{"compile: roles/employee.yaml:3: bad"}
	doc["overlays"] = []string{"/etc/keel/overlays.d/50-pilot.yaml"}
	cbody, _ = json.Marshal(doc)
	cr, err := keel.ParseReport(cbody, "C02COMPILE1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordKeelReport(ctx, pub, ts+50, cr, cbody); err != nil {
		t.Fatal(err)
	}

	ov, err := st.KeelOverview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Devices != 7 || ov.Reporting != 5 || len(ov.Failed) != 2 || len(ov.Pending) != 1 || len(ov.Stale) != 1 || len(ov.Warned) != 1 {
		t.Fatalf("overview devices=%d reporting=%d failed=%d pending=%d stale=%d warned=%d", ov.Devices, ov.Reporting, len(ov.Failed), len(ov.Pending), len(ov.Stale), len(ov.Warned))
	}
	failing := map[string]bool{}
	for _, d := range ov.Failed {
		failing[d.Serial] = true
	}
	if !failing["C02COMPILE1"] || !failing["C02CACHE002"] || ov.Warned[0].Serial != "C02COMPILE1" || !ov.Warned[0].LastRun.CompileError {
		t.Fatalf("compile failure not counted: %+v", ov.Failed)
	}
	if ov.Pending[0].Serial != "C02CACHE003" || ov.Stale[0].Serial != "C02CACHE004" {
		t.Fatalf("health %+v %+v %+v", ov.Failed, ov.Pending, ov.Stale)
	}
	byName := map[string]model.KeelRole{}
	for _, r := range ov.Roles {
		byName[r.Name] = r
	}
	if ov.Roles[0].Name != "baseline" || byName["baseline"].Devices != 0 || byName["baseline"].Inherited != 5 {
		t.Fatalf("baseline %+v", byName["baseline"])
	}
	cc := byName["content_caching"]
	if cc.Devices != 4 || strings.Join(cc.Chain, ">") != "baseline>content_caching" || strings.Join(cc.Parents, ",") != "baseline" {
		t.Fatalf("content_caching %+v", cc)
	}
	profiles := map[string]int{}
	for _, p := range cc.Profiles {
		profiles[p.Name] = p.Devices
	}
	if profiles["netskope"] != 3 || profiles["munki"] != 3 || profiles["screensaver"] != 0 {
		t.Fatalf("profiles %+v", cc.Profiles)
	}

	v, err := st.KeelRoleSettings(ctx, "content_caching", "netskope")
	if err != nil {
		t.Fatal(err)
	}
	if v.Devices != 4 || v.Missing != 1 || len(v.Variants) != 2 {
		t.Fatalf("variants %+v", v)
	}
	if v.Variants[0].Devices != 2 || !strings.Contains(string(v.Variants[0].Settings), `"email"`) || strings.Join(v.Variants[0].Serials, ",") != "C02CACHE001,C02CACHE002" {
		t.Fatalf("key order split a variant: %+v", v.Variants)
	}
	if _, err := st.KeelRoleSettings(ctx, "nope", "netskope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown role %v", err)
	}

	if list, total, err := st.ListKeelDevices(ctx, store.KeelDeviceFilter{Status: "warnings"}); err != nil || total != 1 || list[0].Serial != "C02COMPILE1" {
		t.Fatalf("warnings filter %+v %v", list, err)
	}
	list, total, err := st.ListKeelDevices(ctx, store.KeelDeviceFilter{Role: "baseline"})
	if err != nil || total != 5 || len(list) != 5 {
		t.Fatalf("role filter %d %v", total, err)
	}
	list, total, err = st.ListKeelDevices(ctx, store.KeelDeviceFilter{Status: "stale"})
	if err != nil || total != 1 || list[0].Serial != "C02CACHE004" {
		t.Fatalf("stale filter %+v %v", list, err)
	}
	detail, err := st.GetKeelDevice(ctx, "C02NEVERRPT")
	if err != nil || detail.LastRun != nil || string(detail.Report) != "null" || !detail.Enrolled {
		t.Fatalf("never reported %+v %v", detail, err)
	}

	// Clearing a key keeps the history readable.
	if err := st.DeleteKeelKey(ctx, model.Principal{Kind: "api_token", Name: "admin"}, "C02CACHE001"); err != nil {
		t.Fatal(err)
	}
	detail, err = st.GetKeelDevice(ctx, "C02CACHE001")
	if err != nil || detail.Enrolled || detail.LastRun == nil {
		t.Fatalf("after clear %+v %v", detail, err)
	}
}

func TestKeelSeedLinksDevices(t *testing.T) {
	st := testutil.NewStore(t)
	ctx := context.Background()
	if err := st.SeedDemo(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.SeedDemo(ctx); err != nil {
		t.Fatal(err)
	}
	ov, err := st.KeelOverview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Devices != 5 || len(ov.Failed) != 2 || len(ov.Pending) == 0 || len(ov.Stale) == 0 || len(ov.Warned) != 3 {
		t.Fatalf("seed overview %+v", ov)
	}
	d, err := st.GetKeelDevice(ctx, "MCDEV0003")
	if err != nil || d.DeviceID == "" || d.LastRun == nil || d.LastRun.LeafRole != "content_caching" {
		t.Fatalf("content caching seed %+v %v", d, err)
	}
	if !strings.Contains(string(d.Report), `"email"`) || !strings.Contains(string(d.Report), `"[redacted]"`) || !strings.Contains(string(d.Report), "MacadminsPython") {
		t.Fatalf("seed report %s", d.Report)
	}
	runs, err := st.ListKeelRuns(ctx, "MCDEV0001")
	if err != nil || len(runs) != 3 {
		t.Fatalf("seed runs %d %v", len(runs), err)
	}
	if d.LastRun.LeafMatch != "marker content_caching" {
		t.Fatalf("leaf match %q", d.LastRun.LeafMatch)
	}
	c, err := st.GetKeelDevice(ctx, "MCDEV0005")
	if err != nil || !c.LastRun.CompileError || !c.LastRun.Failing() || c.LastRun.LeafRole != "" {
		t.Fatalf("compile error seed %+v %v", c.LastRun, err)
	}
}
