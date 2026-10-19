// Package config loads process configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the server process configuration.
type Config struct {
	DatabaseURL       string
	HTTPAddr          string
	AdminToken        string
	BootstrapToken    string
	RepoToken         string
	StorageDriver     string
	StorageDir        string
	S3Endpoint        string
	S3Bucket          string
	S3AccessKey       string
	S3SecretKey       string
	S3Region          string
	S3UseSSL          bool
	WebDir            string
	ClockOffset       time.Duration
	DevCORS           bool
	DevSeed           bool
	SchedulerInterval time.Duration
	LogLevel          string
	OfflineAfter      time.Duration
	MaxUploadBytes    int64
	InventoryInterval time.Duration
	ElasticURL        string
	ElasticIndex      string
	ElasticAPIKey     string
}

// Load reads configuration from the environment.
func Load() (Config, error) {
	cfg := Config{
		DatabaseURL:       getenv("DATABASE_URL", "postgres://missioncontrol:missioncontrol@127.0.0.1:5432/missioncontrol?sslmode=disable"),
		HTTPAddr:          getenv("MC_HTTP_ADDR", ":8080"),
		AdminToken:        os.Getenv("MC_ADMIN_TOKEN"),
		BootstrapToken:    os.Getenv("MC_BOOTSTRAP_TOKEN"),
		RepoToken:         os.Getenv("MC_REPO_TOKEN"),
		StorageDriver:     getenv("MC_STORAGE_DRIVER", "local"),
		StorageDir:        getenv("MC_STORAGE_DIR", "data"),
		S3Endpoint:        os.Getenv("MC_S3_ENDPOINT"),
		S3Bucket:          getenv("MC_S3_BUCKET", "mission-control"),
		S3AccessKey:       os.Getenv("MC_S3_ACCESS_KEY"),
		S3SecretKey:       os.Getenv("MC_S3_SECRET_KEY"),
		S3Region:          getenv("MC_S3_REGION", "us-east-1"),
		S3UseSSL:          getenvBool("MC_S3_USE_SSL", false),
		WebDir:            getenv("MC_WEB_DIR", "web/dist"),
		DevCORS:           getenvBool("MC_DEV_CORS", false),
		DevSeed:           getenvBool("MC_DEV_SEED", false),
		SchedulerInterval: 5 * time.Second,
		LogLevel:          getenv("MC_LOG_LEVEL", "info"),
		OfflineAfter:      45 * time.Second,
		MaxUploadBytes:    512 << 20,
		InventoryInterval: 5 * time.Minute,
		ElasticURL:        os.Getenv("MC_ELASTIC_URL"),
		ElasticIndex:      getenv("MC_ELASTIC_INDEX", "osquery-results"),
		ElasticAPIKey:     os.Getenv("MC_ELASTIC_API_KEY"),
	}
	if v := os.Getenv("MC_OFFLINE_AFTER"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("MC_OFFLINE_AFTER: %w", err)
		}
		cfg.OfflineAfter = d
	}
	if v := os.Getenv("MC_CLOCK_OFFSET"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("MC_CLOCK_OFFSET: %w", err)
		}
		cfg.ClockOffset = d
	}
	if v := os.Getenv("MC_SCHEDULER_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("MC_SCHEDULER_INTERVAL: %w", err)
		}
		cfg.SchedulerInterval = d
	}
	if v := os.Getenv("MC_INVENTORY_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("MC_INVENTORY_INTERVAL: %w", err)
		}
		cfg.InventoryInterval = d
	}
	if v := os.Getenv("MC_MAX_UPLOAD_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("MC_MAX_UPLOAD_BYTES: %w", err)
		}
		cfg.MaxUploadBytes = n
	}
	switch cfg.StorageDriver {
	case "local", "s3":
	default:
		return Config{}, fmt.Errorf("MC_STORAGE_DRIVER must be local or s3")
	}
	return cfg, nil
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getenvBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
