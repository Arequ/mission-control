package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresRoundTrip(t *testing.T) {
	url := os.Getenv("MC_DATABASE_URL")
	if url == "" {
		t.Skip("MC_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		TRUNCATE autopkg_jobs, runners, distributed_targets, distributed_queries,
			query_results, device_apps, devices, resources, api_tokens RESTART IDENTITY CASCADE
	`); err != nil {
		t.Fatal(err)
	}
	st := NewPostgres(pool)
	if err := st.EnsureToken(ctx, "bootstrap", "dev-bootstrap-token", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	p, err := st.AuthenticateToken(ctx, "dev-bootstrap-token")
	if err != nil || p.Role != auth.RoleAdmin {
		t.Fatalf("auth %#v %v", p, err)
	}
	dev, err := st.EnrollDevice(ctx, "node-key", Device{
		HostIdentifier: "HOST",
		Hostname:       "mini.local",
		HardwareSerial: "SERIAL1",
		Platform:       "darwin",
		OSName:         "macOS",
		OSVersion:      "15.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	again, err := st.EnrollDevice(ctx, "node-key-2", Device{
		HostIdentifier: "HOST",
		HardwareSerial: "SERIAL1",
		Hostname:       "mini.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != dev.ID {
		t.Fatalf("reenroll created %s, want %s", again.ID, dev.ID)
	}
	got, ok, err := st.DeviceByNodeKey(ctx, "node-key-2")
	if err != nil || !ok || got.ID != dev.ID {
		t.Fatalf("lookup %#v %v %v", got, ok, err)
	}
	if _, ok, err := st.DeviceByNodeKey(ctx, "node-key"); err != nil || ok {
		t.Fatal("old node key still valid")
	}

	resources, diags, err := config.LoadPath("../../examples/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) > 0 {
		t.Fatal(diags)
	}
	plan, err := config.Apply(ctx, st, resources, config.ApplyOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Create == 0 {
		t.Fatalf("plan %+v", plan.Summary)
	}
	second, err := config.Apply(ctx, st, resources, config.ApplyOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	if second.Summary.Update != 0 || second.Summary.Delete != 0 || second.Summary.Unchanged == 0 {
		t.Fatalf("second plan %+v", second.Summary)
	}
	summary, err := st.FleetSummary(ctx, map[string]string{"darwin": "different"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Devices != 1 || summary.ConfigDrift != 1 {
		t.Fatalf("summary %+v", summary)
	}
}
