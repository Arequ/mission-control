package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/configrepo"
	"github.com/Arequ/mission-control/internal/httpapi"
	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/Arequ/mission-control/internal/storage"
	"github.com/Arequ/mission-control/internal/store"
	"github.com/Arequ/mission-control/internal/vuln"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer st.Close()
	st.SetClock(clock.System{Offset: cfg.ClockOffset})

	if cfg.AdminToken != "" {
		if err := st.EnsureAPIToken(ctx, "admin", cfg.AdminToken, []string{"*"}); err != nil {
			log.Error("seed admin token", "err", err)
			os.Exit(1)
		}
		log.Info("admin token configured", "name", "admin")
	} else {
		log.Warn("MC_ADMIN_TOKEN is empty; the API has no seeded admin credential")
	}
	if cfg.BootstrapToken != "" {
		if err := st.EnsureBootstrapToken(ctx, "bootstrap", cfg.BootstrapToken); err != nil {
			log.Error("seed bootstrap token", "err", err)
			os.Exit(1)
		}
		log.Info("bootstrap token configured", "name", "bootstrap")
	}

	blobs, err := storage.New(cfg.StorageDriver, cfg.StorageDir, cfg.S3Endpoint, cfg.S3Bucket, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3Region, cfg.S3UseSSL)
	if err != nil {
		log.Error("storage", "err", err)
		os.Exit(1)
	}
	if s3, ok := blobs.(*storage.S3); ok {
		if err := s3.EnsureBucket(ctx); err != nil {
			log.Error("s3 bucket", "err", err)
			os.Exit(1)
		}
	}

	if cfg.DevSeed {
		if err := st.SeedDemo(ctx); err != nil {
			log.Error("demo seed", "err", err)
			os.Exit(1)
		}
	}
	st.SetConfigRepo(configrepo.Repo{Slug: cfg.ConfigRepo, Branch: cfg.ConfigBranch})
	st.SetVulnerabilityFeeds(vuln.Feeds{HTTP: vuln.SafeFeedClient()})

	var sink osquery.Forwarder = osquery.NopForwarder{}
	if cfg.ElasticURL != "" {
		sink = osquery.ElasticForwarder{URL: cfg.ElasticURL, Index: cfg.ElasticIndex, APIKey: cfg.ElasticAPIKey, HTTP: &http.Client{Timeout: 3 * time.Second}}
		log.Info("osquery results forwarding to elastic", "index", cfg.ElasticIndex)
	}
	srv := httpapi.New(httpapi.Options{
		Store:              st,
		Blobs:              blobs,
		Logger:             log,
		WebDir:             cfg.WebDir,
		RepoToken:          cfg.RepoToken,
		DevCORS:            cfg.DevCORS,
		OfflineAfter:       cfg.OfflineAfter,
		MaxUpload:          cfg.MaxUploadBytes,
		InventoryInterval:  cfg.InventoryInterval,
		Forwarder:          sink,
		LogRetention:       cfg.LogRetention,
		ConfigRepo:         configrepo.Repo{Slug: cfg.ConfigRepo, Branch: cfg.ConfigBranch},
		PublicURL:          cfg.PublicURL,
		CookieSecure:       cfg.CookieSecure,
		SessionIdle:        cfg.SessionIdle,
		SessionAbsolute:    cfg.SessionAbsolute,
		BreakGlass:         cfg.BreakGlass,
		BreakGlassPassword: cfg.BreakGlassPassword,
	})
	if err := srv.Tick(ctx); err != nil {
		log.Error("initial scheduler tick", "err", err)
	}
	go func() {
		t := time.NewTicker(cfg.SchedulerInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := srv.Tick(ctx); err != nil {
					log.Error("scheduler", "err", err)
				}
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	var tlsServer *http.Server
	if cfg.TLSCert != "" {
		tlsServer = &http.Server{
			Addr:              cfg.TLSAddr,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}
	go func() {
		<-ctx.Done()
		shctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shctx)
		if tlsServer != nil {
			_ = tlsServer.Shutdown(shctx)
		}
	}()
	if tlsServer != nil {
		go func() {
			log.Info("tls listening", "addr", cfg.TLSAddr)
			if err := tlsServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("tls", "err", err)
				os.Exit(1)
			}
		}()
	}
	log.Info("listening", "addr", cfg.HTTPAddr, "storage", cfg.StorageDriver)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http", "err", err)
		os.Exit(1)
	}
}
