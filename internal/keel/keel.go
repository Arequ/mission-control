// Package keel implements the server side of the Keel reporting contract
// (keel/docs/reporting.md in the Keel repository): Ed25519 device keys, the
// signed report message, and the report body.
package keel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	// Schema is the only report schema this server accepts.
	Schema = "keel.report/v1"
	// MaxBody is the largest report body. Larger bodies get 413.
	MaxBody = 2 << 20
	// Skew is how far X-Keel-Timestamp may be from the server clock.
	Skew = 300 * time.Second
	// MessagePrefix is the first line of the signed message.
	MessagePrefix = "keel-report-v1"

	// HeaderSerial, HeaderTimestamp, and HeaderSignature carry the report signature.
	HeaderSerial    = "X-Keel-Serial"
	HeaderTimestamp = "X-Keel-Timestamp"
	HeaderSignature = "X-Keel-Signature"
)

var (
	// ErrBadHeader means a signature header is missing or malformed.
	ErrBadHeader = errors.New("keel: malformed signature headers")
	// ErrSkew means the timestamp is outside the allowed window.
	ErrSkew = errors.New("keel: timestamp outside the allowed window")
	// ErrBadSignature means the signature does not verify with the bound key.
	ErrBadSignature = errors.New("keel: signature does not verify")
	// ErrTooLarge means the body is over MaxBody.
	ErrTooLarge = errors.New("keel: report body too large")
)

// ValidSerial reports whether s is a plausible Mac serial: 4 to 64 letters,
// digits, '_' or '-'. It is the same rule as a Munki per-device client.
func ValidSerial(s string) bool {
	if len(s) < 4 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// ParsePublicKey decodes a standard base64 Ed25519 public key (32 bytes).
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("public_key must be standard base64 of a 32-byte Ed25519 key")
	}
	return ed25519.PublicKey(raw), nil
}

// Message is the exact byte string a device signs for one report:
//
//	keel-report-v1\n<serial>\n<timestamp>\n<lowercase hex sha256(body)>
//
// There is no trailing newline.
func Message(serial string, timestamp int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	var b bytes.Buffer
	b.WriteString(MessagePrefix)
	b.WriteByte('\n')
	b.WriteString(serial)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(timestamp, 10))
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	return b.Bytes()
}

// Sign returns the base64 signature header value for a report. Devices and
// tests use it; the server only verifies.
func Sign(priv ed25519.PrivateKey, serial string, timestamp int64, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Message(serial, timestamp, body)))
}

// ParseTimestamp accepts only canonical unix seconds: ASCII digits, no sign,
// no leading zero. That keeps the header and the signed line identical.
func ParseTimestamp(header string) (int64, error) {
	if header == "" || len(header) > 19 {
		return 0, ErrBadHeader
	}
	for i := 0; i < len(header); i++ {
		if header[i] < '0' || header[i] > '9' {
			return 0, ErrBadHeader
		}
	}
	ts, err := strconv.ParseInt(header, 10, 64)
	if err != nil || strconv.FormatInt(ts, 10) != header {
		return 0, ErrBadHeader
	}
	return ts, nil
}

// CheckSkew rejects a timestamp more than Skew from now in either direction.
func CheckSkew(ts int64, now time.Time) error {
	d := now.Unix() - ts
	if d < 0 {
		d = -d
	}
	if d > int64(Skew/time.Second) {
		return ErrSkew
	}
	return nil
}

// Verify checks the signature header against the key bound to serial.
func Verify(pub ed25519.PublicKey, serial string, ts int64, sigHeader string, body []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(sigHeader))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, Message(serial, ts, body), sig) {
		return ErrBadSignature
	}
	return nil
}

// Summary is the run summary. Plan runs report WouldChange instead of Changed.
type Summary struct {
	Total       int `json:"total"`
	OK          int `json:"ok"`
	Changed     int `json:"changed"`
	WouldChange int `json:"would_change"`
	Failed      int `json:"failed"`
	Skipped     int `json:"skipped"`
}

// Role is one entry of the ordered role chain.
type Role struct {
	Name    string   `json:"name"`
	Parents []string `json:"parents"`
	// Match is optional: why the device landed in this (leaf) role, for
	// example "marker content_caching" or "default".
	Match string `json:"match,omitempty"`
}

// CompilePrefix starts the warning Keel sends when its policy did not compile.
// Such a run reports empty roles, profiles, and resources.
const CompilePrefix = "compile: "

// Device is the device block of a report.
type Device struct {
	Serial      string `json:"serial"`
	Hostname    string `json:"hostname"`
	Model       string `json:"model"`
	OSVersion   string `json:"os_version"`
	Arch        string `json:"arch"`
	ConsoleUser string `json:"console_user"`
}

// Report holds the fields the server extracts into columns. The full body is
// stored as JSON so unknown fields survive.
type Report struct {
	Schema      string    `json:"schema"`
	RunID       string    `json:"run_id"`
	KeelVersion string    `json:"keel_version"`
	Mode        string    `json:"mode"`
	StartedAt   time.Time `json:"-"`
	DurationMS  int64     `json:"duration_ms"`
	Device      Device    `json:"device"`
	Roles       []Role    `json:"roles"`
	Summary     Summary   `json:"summary"`
	Warnings    []string  `json:"warnings"`
	Overlays    []string  `json:"overlays"`
}

// CompileFailed reports whether the policy failed to compile on the device.
func (r Report) CompileFailed() bool {
	for _, w := range r.Warnings {
		if strings.HasPrefix(w, CompilePrefix) {
			return true
		}
	}
	return false
}

// LeafMatch is the leaf role's match reason, if Keel sent one.
func (r Report) LeafMatch() string {
	if len(r.Roles) == 0 {
		return ""
	}
	return r.Roles[len(r.Roles)-1].Match
}

// LeafRole is the most specific role: the last entry of the chain.
func (r Report) LeafRole() string {
	if len(r.Roles) == 0 {
		return ""
	}
	return r.Roles[len(r.Roles)-1].Name
}

// RoleNames is the chain as names, least to most specific.
func (r Report) RoleNames() []string {
	out := make([]string, 0, len(r.Roles))
	for _, role := range r.Roles {
		out = append(out, role.Name)
	}
	return out
}

// BodyError is a body that verified but does not follow the contract.
type BodyError struct{ Msg string }

func (e *BodyError) Error() string { return e.Msg }

func bodyErr(msg string) error { return &BodyError{Msg: msg} }

// ParseReport decodes a verified body. Unknown fields are ignored, as the
// contract requires. headerSerial is X-Keel-Serial and must equal device.serial.
func ParseReport(body []byte, headerSerial string) (Report, error) {
	var wire struct {
		Report
		StartedAt  string          `json:"started_at"`
		Profiles   json.RawMessage `json:"profiles"`
		Resources  json.RawMessage `json:"resources"`
		Facts      json.RawMessage `json:"facts"`
		DurationMS json.Number     `json:"duration_ms"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&wire); err != nil {
		return Report{}, bodyErr("report body is not a JSON object of the v1 schema")
	}
	if dec.More() {
		return Report{}, bodyErr("report body has trailing data")
	}
	r := wire.Report
	if r.Schema != Schema {
		return Report{}, bodyErr("schema must be " + Schema)
	}
	if r.Device.Serial != headerSerial {
		return Report{}, bodyErr("device.serial does not match " + HeaderSerial)
	}
	r.RunID = strings.TrimSpace(r.RunID)
	if r.RunID == "" || len(r.RunID) > 128 {
		return Report{}, bodyErr("run_id is required (at most 128 characters)")
	}
	if r.Mode != "apply" && r.Mode != "plan" {
		return Report{}, bodyErr("mode must be apply or plan")
	}
	started, err := time.Parse(time.RFC3339Nano, wire.StartedAt)
	if err != nil {
		return Report{}, bodyErr("started_at must be RFC 3339")
	}
	r.StartedAt = started.UTC()
	if wire.DurationMS != "" {
		ms, err := wire.DurationMS.Int64()
		if err != nil || ms < 0 {
			return Report{}, bodyErr("duration_ms must be a non-negative integer")
		}
		r.DurationMS = ms
	}
	for _, role := range r.Roles {
		if strings.TrimSpace(role.Name) == "" {
			return Report{}, bodyErr("every role needs a name")
		}
	}
	for _, raw := range []json.RawMessage{wire.Profiles, wire.Resources} {
		if len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && bytes.TrimSpace(raw)[0] != '[' {
			return Report{}, bodyErr("profiles and resources must be arrays")
		}
	}
	if len(wire.Facts) > 0 && !bytes.Equal(bytes.TrimSpace(wire.Facts), []byte("null")) && bytes.TrimSpace(wire.Facts)[0] != '{' {
		return Report{}, bodyErr("facts must be an object")
	}
	return r, nil
}
