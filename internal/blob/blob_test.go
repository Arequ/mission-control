package blob

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
)

func TestLocalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := New(Config{Driver: "local", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.Put(ctx, "pkgs/Example.dmg", bytes.NewReader([]byte("pkg-bytes"))); err != nil {
		t.Fatal(err)
	}
	rc, err := st.Open(ctx, "pkgs/Example.dmg")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "pkg-bytes" {
		t.Fatalf("body %q", body)
	}
	if _, err := st.Open(ctx, "../secret"); err == nil {
		t.Fatal("path escape should fail")
	}
	if err := st.Delete(ctx, "pkgs/Example.dmg"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Open(ctx, filepath.Join("pkgs", "Example.dmg")); err == nil {
		t.Fatal("expected missing object")
	}
}

func TestS3NotImplemented(t *testing.T) {
	_, err := New(Config{Driver: "s3", Endpoint: "http://127.0.0.1:9000", Bucket: "pkgs"})
	if err == nil {
		t.Fatal("expected not implemented")
	}
}
