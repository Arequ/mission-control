package config

import (
	"testing"

	"github.com/Arequ/mission-control/internal/configrepo"
)

func TestConfigRepoDefaultsAndRejects(t *testing.T) {
	t.Setenv("MC_CONFIG_REPO", "")
	t.Setenv("MC_CONFIG_BRANCH", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigRepo != configrepo.DefaultSlug || cfg.ConfigBranch != configrepo.DefaultBranch {
		t.Fatalf("%s %s", cfg.ConfigRepo, cfg.ConfigBranch)
	}

	t.Setenv("MC_CONFIG_REPO", "Example-Org/config.repo")
	t.Setenv("MC_CONFIG_BRANCH", "release/1")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigRepo != "Example-Org/config.repo" || cfg.ConfigBranch != "release/1" {
		t.Fatalf("%s %s", cfg.ConfigRepo, cfg.ConfigBranch)
	}

	for _, slug := range []string{"https://evil.example/phish", "owner/name/extra", "owner/name?x=1"} {
		t.Setenv("MC_CONFIG_REPO", slug)
		if _, err := Load(); err == nil {
			t.Fatalf("accepted %s", slug)
		}
	}
	t.Setenv("MC_CONFIG_REPO", configrepo.DefaultSlug)
	t.Setenv("MC_CONFIG_BRANCH", "../main")
	if _, err := Load(); err == nil {
		t.Fatal("accepted branch traversal")
	}
}
