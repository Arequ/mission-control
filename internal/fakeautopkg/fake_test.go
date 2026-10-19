package fakeautopkg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyAndRun(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "Firefox.recipe")
	body := `<plist><dict><key>NAME</key><string>Firefox</string><key>VERSION</key><string>130.0</string></dict></plist>`
	if err := os.WriteFile(override, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trust, []byte(`{"parent_recipes":[{"identifier":"parent","sha256":"abc"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Main([]string{"verify-trust-info", "--override", override, "--trust", trust}); code != 0 {
		t.Fatal(code)
	}
	out := filepath.Join(dir, "out")
	if code := Main([]string{"run", "--override", override, "--output", out}); code != 0 {
		t.Fatal(code)
	}
	if _, err := os.Stat(filepath.Join(out, "Firefox-130.0.pkg")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trust, []byte(`{"fail":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Main([]string{"verify-trust-info", "--override", override, "--trust", trust}); code == 0 {
		t.Fatal("expected trust failure")
	}
}
