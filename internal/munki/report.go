package munki

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"howett.net/plist"
)

const (
	// MaxReportBytes is the largest decompressed check-in body accepted.
	MaxReportBytes = 8 << 20
	// MaxCompressedBytes is the largest gzip body accepted before inflate.
	MaxCompressedBytes = 2 << 20
	maxDepth           = 16
	maxMapKeys         = 256
	maxArray           = 10000
	maxString          = 64 << 10
	maxStoredMessages  = 100
	maxMessageRunes    = 500
	maxNameRunes       = 200
)

// ErrLimits means the plist is too large or too nested to parse safely.
var ErrLimits = errors.New("report exceeds limits")

// Report is a parsed ManagedInstallReport.
type Report struct {
	Serial        string
	HardwareUUID  string
	Hostname      string
	ComputerName  string
	OSVersion     string
	Arch          string
	Model         string
	IP            string
	ManifestName  string
	ConsoleUser   string
	MunkiVersion  string
	RunType       string
	Start         time.Time
	End           time.Time
	Installed     []InstalledItem
	Pending       []PendingItem
	Removals      []PendingItem
	Errors        []string
	Warnings      []string
	ProblemCount  int
	FailedInstall int
}

// InstalledItem is one installed Munki item.
type InstalledItem struct {
	Name        string
	DisplayName string
	Version     string
}

// PendingItem is an install or removal still outstanding.
type PendingItem struct {
	Name    string
	Version string
}

// DeriveDeviceToken is the per-device bearer a client can send instead of the
// shared enrollment secret. username is the serial. The server recomputes it
// from the stored enrollment secret; the raw secret is never returned by the API.
func DeriveDeviceToken(secret, serial string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("munki-device-v1\n"))
	_, _ = mac.Write([]byte(serial))
	return hex.EncodeToString(mac.Sum(nil))
}

// ParseReport decodes a ManagedInstallReport plist.
// installInfo is the optional InstallInfo plist; nil is fine.
func ParseReport(report, installInfo []byte) (Report, error) {
	if len(report) == 0 || len(report) > MaxReportBytes {
		return Report{}, fmt.Errorf("%w: size", ErrLimits)
	}
	root, err := decodePlist(report)
	if err != nil {
		return Report{}, err
	}
	if err := walkLimit(root, 0); err != nil {
		return Report{}, err
	}
	dict, ok := root.(map[string]any)
	if !ok {
		return Report{}, fmt.Errorf("report must be a dictionary")
	}
	var extra map[string]any
	if len(installInfo) > 0 {
		if len(installInfo) > MaxReportBytes {
			return Report{}, fmt.Errorf("%w: install info size", ErrLimits)
		}
		raw, err := decodePlist(installInfo)
		if err != nil {
			return Report{}, fmt.Errorf("install info: %w", err)
		}
		if err := walkLimit(raw, 0); err != nil {
			return Report{}, err
		}
		extra, _ = raw.(map[string]any)
	}
	return buildReport(dict, extra), nil
}

func decodePlist(b []byte) (any, error) {
	b = bytes.TrimSpace(b)
	lower := bytes.ToLower(b)
	if bytes.Contains(lower, []byte("<!entity")) {
		return nil, fmt.Errorf("%w: entity", ErrLimits)
	}
	if idx := bytes.Index(lower, []byte("<!doctype")); idx >= 0 {
		end := bytes.IndexByte(lower[idx:], '>')
		if end > 0 && bytes.Contains(lower[idx:idx+end], []byte("[")) {
			return nil, fmt.Errorf("%w: entity", ErrLimits)
		}
	}
	var raw any
	if _, err := plist.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("plist: %w", err)
	}
	return raw, nil
}

func walkLimit(v any, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: nesting", ErrLimits)
	}
	switch t := v.(type) {
	case map[string]any:
		if len(t) > maxMapKeys {
			return fmt.Errorf("%w: keys", ErrLimits)
		}
		for k, vv := range t {
			if len(k) > 256 || !utf8.ValidString(k) {
				return fmt.Errorf("%w: key", ErrLimits)
			}
			if err := walkLimit(vv, depth+1); err != nil {
				return err
			}
		}
	case []any:
		if len(t) > maxArray {
			return fmt.Errorf("%w: array", ErrLimits)
		}
		for _, vv := range t {
			if err := walkLimit(vv, depth+1); err != nil {
				return err
			}
		}
	case string:
		if len(t) > maxString || !utf8.ValidString(t) {
			return fmt.Errorf("%w: string", ErrLimits)
		}
	}
	return nil
}

func buildReport(d, install map[string]any) Report {
	machine, _ := d["MachineInfo"].(map[string]any)
	conds, _ := d["Conditions"].(map[string]any)
	r := Report{
		Serial:       firstString(machine, conds, "serial_number", "serial", "system_serial_number"),
		HardwareUUID: firstString(machine, conds, "hardware_uuid", "machine_uuid", "system_uuid", "uuid"),
		Hostname:     firstString(machine, conds, "hostname"),
		ComputerName: firstString(machine, conds, "computer_name", "hostname"),
		OSVersion:    firstString(machine, conds, "os_vers", "os_version"),
		Arch:         firstString(machine, conds, "arch"),
		Model:        firstString(machine, conds, "machine_model"),
		IP:           firstString(machine, conds, "ipv4_address"),
		ManifestName: clip(asString(d["ManifestName"]), maxNameRunes),
		ConsoleUser:  clip(asString(d["ConsoleUser"]), maxNameRunes),
		MunkiVersion: firstNonEmpty(asString(d["ManagedInstallVersion"]), firstString(machine, conds, "munki_version")),
		RunType:      clip(asString(d["RunType"]), 32),
		Start:        asTime(d["StartTime"]),
		End:          asTime(d["EndTime"]),
	}
	r.MunkiVersion = clip(r.MunkiVersion, 64)
	r.Serial = clip(strings.TrimSpace(r.Serial), 64)
	r.HardwareUUID = clip(strings.TrimSpace(r.HardwareUUID), 64)
	r.Hostname = clip(strings.TrimSpace(r.Hostname), 255)
	if r.Serial == "" && looksLikeSerial(r.ManifestName) {
		r.Serial = r.ManifestName
	}
	for _, item := range asArray(d["InstalledItems"]) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, exists := m["installed"]; exists && !asBool(m["installed"]) {
			continue
		}
		name := clip(asString(m["name"]), maxNameRunes)
		if name == "" {
			continue
		}
		ver := firstNonEmpty(asString(m["installed_version"]), asString(m["version_to_install"]), asString(m["version"]))
		r.Installed = append(r.Installed, InstalledItem{
			Name:        name,
			DisplayName: clip(firstNonEmpty(asString(m["display_name"]), name), maxNameRunes),
			Version:     clip(ver, 128),
		})
		if len(r.Installed) >= 5000 {
			break
		}
	}
	r.Pending = pendingFrom(d["ItemsToInstall"])
	r.Removals = pendingFrom(d["ItemsToRemove"])
	if install != nil {
		if len(r.Pending) == 0 {
			r.Pending = pendingFrom(install["managed_installs"])
		}
		if len(r.Removals) == 0 {
			r.Removals = pendingFrom(firstPresent(install["removals"], install["managed_uninstalls"]))
		}
	}
	r.Errors = messages(d["Errors"])
	r.Warnings = messages(d["Warnings"])
	r.ProblemCount = len(asArray(d["ProblemInstalls"]))
	for _, item := range asArray(d["InstallResults"]) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if asInt(m["status"]) != 0 {
			r.FailedInstall++
			name := clip(asString(m["name"]), maxNameRunes)
			if name != "" && len(r.Errors) < maxStoredMessages {
				r.Errors = append(r.Errors, clip("install failed: "+name, maxMessageRunes))
			}
		}
	}
	for _, item := range asArray(d["RemovalResults"]) {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if asInt(m["status"]) != 0 && len(r.Errors) < maxStoredMessages {
			name := clip(asString(m["name"]), maxNameRunes)
			if name != "" {
				r.Errors = append(r.Errors, clip("removal failed: "+name, maxMessageRunes))
			}
		}
	}
	return r
}

// Status is ok, warning, pending, or error.
func (r Report) Status() string {
	if len(r.Errors) > 0 || r.ProblemCount > 0 || r.FailedInstall > 0 {
		return "error"
	}
	if len(r.Warnings) > 0 {
		return "warning"
	}
	if len(r.Pending) > 0 || len(r.Removals) > 0 {
		return "pending"
	}
	return "ok"
}

func pendingFrom(v any) []PendingItem {
	var out []PendingItem
	for _, item := range asArray(v) {
		switch t := item.(type) {
		case map[string]any:
			name := clip(asString(t["name"]), maxNameRunes)
			if name == "" {
				continue
			}
			out = append(out, PendingItem{Name: name, Version: clip(firstNonEmpty(asString(t["version_to_install"]), asString(t["version"])), 128)})
		case string:
			name := clip(strings.TrimSpace(t), maxNameRunes)
			if name != "" {
				out = append(out, PendingItem{Name: name})
			}
		}
		if len(out) >= 2000 {
			break
		}
	}
	return out
}

func messages(v any) []string {
	var out []string
	for _, item := range asArray(v) {
		var s string
		switch t := item.(type) {
		case string:
			s = t
		case map[string]any:
			s = firstNonEmpty(asString(t["message"]), asString(t["name"]))
		}
		s = clip(strings.TrimSpace(s), maxMessageRunes)
		if s == "" {
			continue
		}
		out = append(out, s)
		if len(out) >= maxStoredMessages {
			break
		}
	}
	return out
}

func looksLikeSerial(s string) bool {
	if len(s) < 8 || len(s) > 20 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func firstString(a, b map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(asString(a[k])); s != "" {
			return s
		}
	}
	for _, k := range keys {
		if s := strings.TrimSpace(asString(b[k])); s != "" {
			return s
		}
	}
	return ""
}

func firstPresent(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func asArray(v any) []any {
	a, _ := v.([]any)
	return a
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func asBool(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case uint64:
		return int(t)
	case float64:
		return int(t)
	default:
		return 0
	}
}

func asTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case string:
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05"} {
			if tm, err := time.Parse(layout, strings.TrimSpace(t)); err == nil {
				return tm.UTC()
			}
		}
	}
	return time.Time{}
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
