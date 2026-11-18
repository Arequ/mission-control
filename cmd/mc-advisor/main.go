// mc-advisor reads release notes for pending Mission Control release reviews
// with the Claude Code CLI (claude -p) and reports what it found. Run it where
// `claude` is signed in. It needs an API token with releases:write and makes
// only outbound calls. It never decides a review; people do.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Arequ/mission-control/internal/advisor"
)

func main() {
	var (
		server   = flag.String("server", getenv("MC_SERVER", "http://127.0.0.1:8080"), "mission control base URL")
		token    = flag.String("token", os.Getenv("MC_ADVISOR_TOKEN"), "API token with releases:write (or MC_ADVISOR_TOKEN)")
		claude   = flag.String("claude", getenv("MC_CLAUDE", "claude"), "path to the claude CLI")
		modelID  = flag.String("model", os.Getenv("MC_ADVISOR_MODEL"), "optional claude --model")
		budget   = flag.Float64("max-budget-usd", envFloat("MC_ADVISOR_MAX_BUDGET_USD", 1), "per-review spend cap passed to claude (0 for none)")
		timeout  = flag.Duration("timeout", 6*time.Minute, "per-review time limit")
		interval = flag.Duration("interval", time.Minute, "wait between leases when idle")
		once     = flag.Bool("once", false, "research at most one review, then exit")
	)
	flag.Parse()
	if *token == "" {
		slog.Error("an API token with releases:write is required (-token or MC_ADVISOR_TOKEN)")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := advisor.Run(ctx, advisor.Config{
		Server: *server, Token: *token, Claude: *claude, Model: *modelID,
		MaxBudgetUSD: *budget, Timeout: *timeout, Interval: *interval, Once: *once,
	})
	if err != nil {
		slog.Error("advisor", "err", err.Error())
		os.Exit(1)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envFloat(k string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(k), 64); err == nil {
		return v
	}
	return def
}
