package storage

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestValidateKeyRejectsTraversal(t *testing.T) {
	ok := []string{"pkgs/Firefox-130.pkg", "a"}
	bad := []string{"", "..", "../etc/passwd", "pkgs/../../etc/passwd", "pkgs\\evil", "a/../b", "foo/../../x", "a\x00b"}
	for _, key := range ok {
		if err := ValidateKey(key); err != nil {
			t.Fatalf("%q: %v", key, err)
		}
	}
	for _, key := range bad {
		if err := ValidateKey(key); err == nil {
			t.Fatalf("%q accepted", key)
		}
	}
	dir := t.TempDir()
	local := &Local{Dir: dir}
	if err := local.Put(context.Background(), "../outside", bytes.NewReader([]byte("x")), 1, ""); err == nil {
		t.Fatal("local put escaped the root")
	}
	if err := local.Put(context.Background(), "pkgs/ok.pkg", bytes.NewReader([]byte("pkg")), 3, ""); err != nil {
		t.Fatal(err)
	}
	rc, err := local.Open(context.Background(), "pkgs/ok.pkg")
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
}

func TestNormalizeEndpoint(t *testing.T) {
	host, secure, err := NormalizeEndpoint("https://s3.example:9000", false)
	if err != nil || host != "s3.example:9000" || !secure {
		t.Fatalf("https %q %v %v", host, secure, err)
	}
	host, secure, err = NormalizeEndpoint("http://127.0.0.1:9000", true)
	if err != nil || host != "127.0.0.1:9000" || secure {
		t.Fatalf("http %q %v %v", host, secure, err)
	}
	if _, _, err := NormalizeEndpoint("https://s3.example/bucket", true); err == nil {
		t.Fatal("path accepted")
	}
	if _, err := NewS3("http://127.0.0.1:9000", "", "a", "b", "us-east-1", false); err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Fatalf("empty bucket: %v", err)
	}
}
