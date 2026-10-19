// Package testutil creates throwaway Postgres databases for tests.
package testutil

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"

	"github.com/Arequ/mission-control/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

var seq atomic.Int64

// AdminURL is a Postgres connection string with permission to create databases.
func AdminURL() string {
	if v := os.Getenv("TEST_DATABASE_ADMIN"); v != "" {
		return v
	}
	return "postgres://missioncontrol:missioncontrol@127.0.0.1:5432/postgres?sslmode=disable"
}

// NewStore migrates a fresh database and drops it when the test ends.
func NewStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	admin := AdminURL()
	pool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	name := fmt.Sprintf("mc_test_%d_%d", os.Getpid(), seq.Add(1))
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
	s, err := store.Open(ctx, u.String())
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
