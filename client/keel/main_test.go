package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Arequ/mission-control/internal/keel"
)

// The example client is copied into the Keel repo, so it must agree with the
// server's verifier byte for byte.
func TestReferenceClientMatchesServer(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema":"keel.report/v1"}`)
	if !bytes.Equal(SignedMessage("DF7XP7HY3N", 1793750400, body), keel.Message("DF7XP7HY3N", 1793750400, body)) {
		t.Fatal("message differs from internal/keel")
	}
	req, err := ReportRequest("https://mc.example/", "DF7XP7HY3N", priv, 1793750400, body)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.String() != "https://mc.example/api/v1/keel/report" {
		t.Fatal(req.URL)
	}
	sent, _ := io.ReadAll(req.Body)
	ts, err := keel.ParseTimestamp(req.Header.Get(keel.HeaderTimestamp))
	if err != nil || strconv.FormatInt(ts, 10) != "1793750400" {
		t.Fatal(err)
	}
	if err := keel.Verify(priv.Public().(ed25519.PublicKey), req.Header.Get(keel.HeaderSerial), ts, req.Header.Get(keel.HeaderSignature), sent); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keel-report.key")
	if err := writeKey(path); err != nil {
		t.Fatal(err)
	}
	if err := writeKey(path); err == nil {
		t.Fatal("init replaced an existing key")
	}
	if _, err := readKey(path); err != nil {
		t.Fatal(err)
	}
}
