// Command keel-report is a reference client for the Keel reporting contract.
// It shows how a device enrolls its Ed25519 key and signs a report. Keel
// itself lives in another repository; this file uses only the standard
// library so it can be copied there.
//
//	keel-report -server https://mc.example -key /opt/coreweave/cert/keel-report.key init
//	KEEL_ENROLL_SECRET=... keel-report -server https://mc.example -key ... -serial DF7XP7HY3N enroll
//	keel-report -server https://mc.example -key ... -serial DF7XP7HY3N report run.json
//
// The enroll secret is read from the environment, never from argv, so it does
// not show up in ps. The key file is a PKCS#8 PEM private key, mode 0600.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	server := flag.String("server", "", "Mission Control base URL")
	keyPath := flag.String("key", "/opt/coreweave/cert/keel-report.key", "Ed25519 private key (PKCS#8 PEM)")
	serial := flag.String("serial", "", "device serial")
	hostname := flag.String("hostname", "", "device hostname (enroll only)")
	flag.Parse()
	if err := run(*server, *keyPath, *serial, *hostname, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "keel-report:", err)
		os.Exit(1)
	}
}

func run(server, keyPath, serial, hostname string, args []string) error {
	if len(args) == 0 {
		return errors.New("command is init, enroll, or report <body.json>")
	}
	switch args[0] {
	case "init":
		return writeKey(keyPath)
	case "enroll":
		priv, err := readKey(keyPath)
		if err != nil {
			return err
		}
		secret := os.Getenv("KEEL_ENROLL_SECRET")
		if secret == "" {
			return errors.New("set KEEL_ENROLL_SECRET")
		}
		req, err := EnrollRequest(server, secret, serial, hostname, priv.Public().(ed25519.PublicKey))
		if err != nil {
			return err
		}
		return send(req, http.StatusCreated, http.StatusOK)
	case "report":
		if len(args) != 2 {
			return errors.New("report needs a body file")
		}
		priv, err := readKey(keyPath)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		req, err := ReportRequest(server, serial, priv, time.Now().Unix(), body)
		if err != nil {
			return err
		}
		return send(req, http.StatusAccepted)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// SignedMessage is the exact byte string the device signs:
// "keel-report-v1\n<serial>\n<timestamp>\n<lowercase hex sha256(body)>", no trailing newline.
func SignedMessage(serial string, timestamp int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte("keel-report-v1\n" + serial + "\n" + strconv.FormatInt(timestamp, 10) + "\n" + hex.EncodeToString(sum[:]))
}

// ReportRequest signs body exactly as it will be sent. Do not re-encode the
// body after signing: the server hashes the raw request bytes.
func ReportRequest(server, serial string, priv ed25519.PrivateKey, timestamp int64, body []byte) (*http.Request, error) {
	sig := ed25519.Sign(priv, SignedMessage(serial, timestamp, body))
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(server, "/")+"/api/v1/keel/report", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keel-Serial", serial)
	req.Header.Set("X-Keel-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Keel-Signature", base64.StdEncoding.EncodeToString(sig))
	return req, nil
}

// EnrollRequest binds the public key to serial. The secret goes in a header.
func EnrollRequest(server, secret, serial, hostname string, pub ed25519.PublicKey) (*http.Request, error) {
	body, err := json.Marshal(map[string]string{
		"serial": serial, "hostname": hostname, "public_key": base64.StdEncoding.EncodeToString(pub),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(server, "/")+"/api/v1/keel/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	return req, nil
}

func send(req *http.Request, ok ...int) error {
	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	for _, code := range ok {
		if res.StatusCode == code {
			fmt.Printf("%d %s", res.StatusCode, msg)
			return nil
		}
	}
	return fmt.Errorf("%s: %d %s", req.URL.Path, res.StatusCode, strings.TrimSpace(string(msg)))
}

func writeKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists; refusing to replace an enrolled key", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("key file is not a PKCS#8 PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key file is not Ed25519")
	}
	return priv, nil
}
