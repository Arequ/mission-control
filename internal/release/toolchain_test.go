package release

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGo1272IsThePinnedToolchain keeps both modules, the container images,
// and CI on the same Go release. The go directive is the pin: go mod tidy
// drops a toolchain line that only repeats it, and an older go command
// downloads 1.27.2 before it builds.
func TestGo1272IsThePinnedToolchain(t *testing.T) {
	root := moduleRoot(t)
	const version = "1.27.2"
	for _, rel := range []string{"go.mod", "terraform-provider-missioncontrol/go.mod"} {
		text := read(t, filepath.Join(root, rel))
		if !strings.Contains(text, "\ngo "+version+"\n") {
			t.Errorf("%s go directive is not %s", rel, version)
		}
		if strings.Contains(text, "toolchain ") && !strings.Contains(text, "toolchain go"+version) {
			t.Errorf("%s toolchain line is not go%s", rel, version)
		}
	}
	for _, rel := range []string{"Dockerfile", "Dockerfile.runner"} {
		text := read(t, filepath.Join(root, rel))
		if !strings.Contains(text, "golang:"+version+"-bookworm") {
			t.Errorf("%s does not build with golang:%s-bookworm", rel, version)
		}
	}
	ci := read(t, filepath.Join(root, ".github/workflows/ci.yml"))
	if !strings.Contains(ci, `go-version: "1.27.2"`) {
		t.Error("CI does not install Go 1.27.2")
	}
	if strings.Contains(ci, "1.27.0") {
		t.Error("CI still mentions Go 1.27.0")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
