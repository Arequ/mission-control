package runneragent

import (
	"context"
	"strings"
	"testing"

	"github.com/Arequ/mission-control/internal/model"
)

func TestSyncReposRejectsOptionInjection(t *testing.T) {
	err := syncRepos(context.Background(), t.TempDir(), []model.RecipeRepo{{
		Name: "recipes", URL: "--upload-pack=touch /tmp/pwned", Ref: "main",
	}})
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("url: %v", err)
	}
	err = syncRepos(context.Background(), t.TempDir(), []model.RecipeRepo{{
		Name: "recipes", URL: "https://example.test/recipes.git", Ref: "--branch",
	}})
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("ref: %v", err)
	}
}
