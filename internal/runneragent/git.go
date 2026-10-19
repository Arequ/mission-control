package runneragent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Arequ/mission-control/internal/model"
)

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// syncRepos clones or fast-forwards each configured recipe repository into cache.
func syncRepos(ctx context.Context, cache string, repos []model.RecipeRepo) error {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	for _, repo := range repos {
		name := safeName.ReplaceAllString(repo.Name, "-")
		if name == "" {
			name = "repo"
		}
		dest := filepath.Join(cache, name)
		if strings.HasPrefix(strings.TrimSpace(repo.URL), "-") || strings.ContainsAny(repo.URL, " \t\r\n") {
			return fmt.Errorf("refusing repo url %q", repo.URL)
		}
		if repo.Ref == "" || strings.HasPrefix(repo.Ref, "-") || strings.ContainsAny(repo.Ref, " \t\r\n") {
			return fmt.Errorf("refusing repo ref %q", repo.Ref)
		}
		if _, err := os.Stat(filepath.Join(dest, ".git")); err != nil {
			cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", repo.Ref, "--", repo.URL, dest)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("clone %s: %w (%s)", repo.Name, err, out)
			}
			continue
		}
		fetch := exec.CommandContext(ctx, "git", "-C", dest, "fetch", "--depth", "1", "origin", repo.Ref)
		if out, err := fetch.CombinedOutput(); err != nil {
			return fmt.Errorf("fetch %s: %w (%s)", repo.Name, err, out)
		}
		co := exec.CommandContext(ctx, "git", "-C", dest, "checkout", repo.Ref)
		if out, err := co.CombinedOutput(); err != nil {
			return fmt.Errorf("checkout %s: %w (%s)", repo.Name, err, out)
		}
	}
	return nil
}
