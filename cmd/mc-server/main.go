package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Arequ/mission-control/internal/api"
	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/blob"
	"github.com/Arequ/mission-control/internal/configsync"
	"github.com/Arequ/mission-control/internal/migrate"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/version"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err := run(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	addr := env("MC_HTTP_ADDR", ":8080")
	dbURL := os.Getenv("MC_DATABASE_URL")
	if dbURL == "" {
		return errors.New("MC_DATABASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return err
	}
	if err := migrate.Up(ctx, pool); err != nil {
		return err
	}
	st := store.NewPostgres(pool)

	token := os.Getenv("MC_BOOTSTRAP_TOKEN")
	generated := false
	if token == "" {
		token, err = auth.NewSecret("mc_")
		if err != nil {
			return err
		}
		generated = true
	}
	if err := st.EnsureToken(ctx, "bootstrap", token, auth.RoleAdmin); err != nil {
		return err
	}
	if generated {
		slog.Warn("generated a one-shot bootstrap admin token; set MC_BOOTSTRAP_TOKEN to keep it stable", "token", token)
	}

	secret := os.Getenv("MC_ENROLL_SECRET")
	if secret == "" {
		secret, err = auth.NewSecret("")
		if err != nil {
			return err
		}
		slog.Warn("generated an enroll secret; set MC_ENROLL_SECRET before pointing agents here", "enroll_secret", secret)
	}

	blobs, err := blob.New(blob.Config{
		Driver:    env("MC_BLOB_DRIVER", "local"),
		Dir:       env("MC_BLOB_DIR", "data/blobs"),
		Endpoint:  os.Getenv("MC_BLOB_S3_ENDPOINT"),
		Bucket:    os.Getenv("MC_BLOB_S3_BUCKET"),
		AccessKey: os.Getenv("MC_BLOB_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("MC_BLOB_S3_SECRET_KEY"),
		Region:    env("MC_BLOB_S3_REGION", "us-east-1"),
	})
	if err != nil {
		if errors.Is(err, blob.ErrNotImplemented) {
			slog.Warn("blob store is not available yet", "err", err)
		} else {
			return err
		}
	} else {
		slog.Info("blob store ready", "driver", env("MC_BLOB_DRIVER", "local"))
		_ = blobs
	}

	srv := api.New(st, secret)
	srv.CORSOrigins = splitCSV(env("MC_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"))
	srv.WebDir = os.Getenv("MC_WEB_DIR")

	if dir := os.Getenv("MC_CONFIG_DIR"); dir != "" {
		interval, err := time.ParseDuration(env("MC_CONFIG_SYNC_INTERVAL", "30s"))
		if err != nil {
			return err
		}
		syncer := &configsync.Syncer{
			Dir:      dir,
			Interval: interval,
			GitPull:  env("MC_CONFIG_GIT_PULL", "") == "true",
			Store:    st,
		}
		srv.Sync = syncer
		go syncer.Run(ctx)
		slog.Info("config sync enabled", "dir", dir, "interval", interval.String(), "gitPull", syncer.GitPull)
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       120 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		cert, key := os.Getenv("MC_TLS_CERT"), os.Getenv("MC_TLS_KEY")
		slog.Info("listening", "addr", addr, "version", version.Version, "tls", cert != "" && key != "")
		if cert != "" && key != "" {
			errCh <- httpServer.ListenAndServeTLS(cert, key)
			return
		}
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shut)
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
