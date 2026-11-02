package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/Arequ/mission-control/internal/runneragent"
)

func main() {
	var (
		server    = flag.String("server", getenv("MC_SERVER", "http://127.0.0.1:8080"), "mission control base URL")
		bootstrap = flag.String("bootstrap-token", os.Getenv("MC_BOOTSTRAP_TOKEN"), "bootstrap token used to register")
		token     = flag.String("token", os.Getenv("MC_RUNNER_TOKEN"), "existing runner token")
		name      = flag.String("name", getenv("MC_RUNNER_NAME", hostname()), "runner name")
		labels    = flag.String("labels", getenv("MC_RUNNER_LABELS", "macos,autopkg"), "comma-separated labels")
		pool      = flag.String("pool", os.Getenv("MC_RUNNER_POOL"), "runner pool name")
		autopkg   = flag.String("autopkg", getenv("MC_AUTOPKG", "autopkg"), "autopkg binary (or fake-autopkg)")
		state     = flag.String("state", getenv("MC_RUNNER_STATE", defaultStatePath()), "where to persist the runner token")
		cache     = flag.String("repo-cache", getenv("MC_REPO_CACHE", defaultRepoCache()), "git cache for recipe repos")
		syncRepos = flag.Bool("sync-repos", getenv("MC_SYNC_REPOS", "") == "1" || strings.EqualFold(os.Getenv("MC_SYNC_REPOS"), "true"), "clone recipe repos before each run")
		version   = flag.String("autopkg-version", getenv("MC_AUTOPKG_VERSION", "fake"), "reported autopkg version")
	)
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if *bootstrap == "" && *token == "" && !stateExists(*state) {
		fmt.Fprintln(os.Stderr, "set MC_BOOTSTRAP_TOKEN or --bootstrap-token to register")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	agent := &runneragent.Agent{Config: runneragent.Config{
		ServerURL:      strings.TrimRight(*server, "/"),
		BootstrapToken: *bootstrap,
		Token:          *token,
		Name:           *name,
		Labels:         splitLabels(*labels),
		Pool:           *pool,
		Hostname:       hostname(),
		OSVersion:      runtime.GOOS + "/" + runtime.GOARCH,
		AutopkgBin:     *autopkg,
		AutopkgVersion: *version,
		SyncRepos:      *syncRepos,
		RepoCache:      *cache,
		StatePath:      *state,
	}}
	log.Info("runner starting", "server", *server, "name", *name, "pool", *pool)
	if err := agent.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("runner stopped", "err", err)
		os.Exit(1)
	}
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func splitLabels(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "mc-runner"
	}
	return h
}

func defaultStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "runner-state.json"
	}
	return home + "/.mission-control/runner.json"
}

func defaultRepoCache() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "repo-cache"
	}
	return home + "/.mission-control/repos"
}

func stateExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
