// Package configsync reconciles a directory (optionally git-pulled) into the store.
package configsync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Arequ/mission-control/internal/config"
	"github.com/Arequ/mission-control/internal/store"
)

// Status is the last directory sync, safe to show in the API.
type Status struct {
	Directory   string             `json:"directory"`
	GitPull     bool               `json:"gitPull"`
	LastAttempt *time.Time         `json:"lastAttempt,omitempty"`
	LastSuccess *time.Time         `json:"lastSuccess,omitempty"`
	LastError   string             `json:"lastError,omitempty"`
	Summary     config.PlanSummary `json:"summary"`
}

// Syncer applies a config directory on an interval. Invalid files are not applied,
// so a bad commit cannot prune the fleet.
type Syncer struct {
	Dir      string
	Interval time.Duration
	GitPull  bool
	Store    store.Store

	mu     sync.RWMutex
	status Status
}

// Status returns a copy of the latest sync status.
func (s *Syncer) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Run syncs immediately and then on each interval until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	s.Tick(ctx)
	if s.Interval <= 0 {
		return
	}
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Tick(ctx)
		}
	}
}

// Tick loads the directory and applies it with prune.
func (s *Syncer) Tick(ctx context.Context) {
	now := time.Now().UTC()
	status := s.Status()
	status.Directory = s.Dir
	status.GitPull = s.GitPull
	status.LastAttempt = &now
	status.LastError = ""

	if s.GitPull {
		if err := gitPull(ctx, s.Dir); err != nil {
			status.LastError = err.Error()
			s.set(status)
			return
		}
	}
	resources, diags, err := config.LoadPath(s.Dir)
	if err != nil {
		status.LastError = err.Error()
		s.set(status)
		return
	}
	if len(diags) > 0 {
		status.LastError = formatDiags(diags)
		s.set(status)
		return
	}
	plan, err := config.Apply(ctx, s.Store, resources, config.ApplyOptions{Prune: true})
	if err != nil {
		status.LastError = err.Error()
		s.set(status)
		return
	}
	status.Summary = plan.Summary
	status.LastSuccess = &now
	s.set(status)
}

func (s *Syncer) set(status Status) {
	s.mu.Lock()
	s.status = status
	s.mu.Unlock()
}

func gitPull(ctx context.Context, dir string) error {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "pull", "--ff-only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git pull: %s", msg)
	}
	return nil
}

func formatDiags(diags []config.Diagnostic) string {
	parts := make([]string, 0, len(diags))
	for i, d := range diags {
		if i == 8 {
			parts = append(parts, fmt.Sprintf("... %d more", len(diags)-i))
			break
		}
		where := d.Path
		if d.Field != "" {
			where = strings.TrimSpace(where + " " + d.Field)
		}
		if where == "" {
			parts = append(parts, d.Message)
			continue
		}
		parts = append(parts, where+": "+d.Message)
	}
	return "config invalid: " + strings.Join(parts, "; ")
}
