// Package coverage matches security-tool records onto unified devices and
// decides whether each source is seeing, stale, or missing.
package coverage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
)

// Keys are the identifiers a source reported for one device.
type Keys struct {
	Serial       string
	HardwareUUID string
	MAC          string
	Hostname     string
	PrimaryUser  string
}

// Candidate is one enrolled device that a record might match.
type Candidate struct {
	ID string
	Keys
}

// Match is the result of identity resolution.
// Confidence is strong, weak, none, or conflict.
// On conflict DeviceID is empty: the record is not attached to either side.
type Match struct {
	DeviceID   string
	Confidence string
	MatchedOn  []string
	Candidates []string
	Note       string
}

// NormalizeKeys drops placeholder identifiers and canonicalizes the rest.
// Callers can compare the result with ==.
func NormalizeKeys(k Keys) Keys {
	return Keys{
		Serial:       normalizeSerial(k.Serial),
		HardwareUUID: normalizeUUID(k.HardwareUUID),
		MAC:          normalizeMAC(k.MAC),
		Hostname:     normalizeHost(k.Hostname),
		PrimaryUser:  normalizeUser(k.PrimaryUser),
	}
}

// Resolve matches an observation to at most one device.
//
// Strong keys (serial, hardware UUID) are tried first. If they name two
// different devices, the result is a conflict and weak keys are not consulted.
// A placeholder serial or UUID is ignored, so a real UUID still matches when
// the serial is "System Serial Number" or another OEM filler.
//
// Weak keys are MAC, or hostname together with primary user. Hostname alone
// never matches. A weak candidate is skipped when its serial or UUID
// contradicts a real strong key on the observation.
func Resolve(obs Keys, candidates []Candidate) Match {
	obs = NormalizeKeys(obs)
	norm := make([]Candidate, len(candidates))
	for i, c := range candidates {
		norm[i] = Candidate{ID: c.ID, Keys: NormalizeKeys(c.Keys)}
	}

	serialHits := idsWhere(norm, func(c Candidate) bool {
		return obs.Serial != "" && c.Serial == obs.Serial
	})
	uuidHits := idsWhere(norm, func(c Candidate) bool {
		return obs.HardwareUUID != "" && c.HardwareUUID == obs.HardwareUUID
	})

	if obs.Serial != "" || obs.HardwareUUID != "" {
		if len(serialHits) > 1 || len(uuidHits) > 1 {
			return conflict(union(serialHits, uuidHits), "strong key matches more than one device")
		}
		if len(serialHits) == 1 && len(uuidHits) == 1 && serialHits[0] != uuidHits[0] {
			return conflict([]string{serialHits[0], uuidHits[0]}, "serial and hardware UUID point at different devices")
		}
		if len(serialHits) == 1 && len(uuidHits) == 1 {
			return Match{DeviceID: serialHits[0], Confidence: "strong", MatchedOn: []string{"serial", "hardware_uuid"}}
		}
		if len(serialHits) == 1 {
			return Match{DeviceID: serialHits[0], Confidence: "strong", MatchedOn: []string{"serial"}}
		}
		if len(uuidHits) == 1 {
			return Match{DeviceID: uuidHits[0], Confidence: "strong", MatchedOn: []string{"hardware_uuid"}}
		}
	}

	macHits := eligible(norm, obs, func(c Candidate) bool {
		return obs.MAC != "" && c.MAC == obs.MAC
	})
	hostHits := eligible(norm, obs, func(c Candidate) bool {
		return obs.Hostname != "" && obs.PrimaryUser != "" && c.Hostname == obs.Hostname && c.PrimaryUser == obs.PrimaryUser
	})
	if len(macHits) > 1 || len(hostHits) > 1 {
		return conflict(union(macHits, hostHits), "weak key matches more than one device")
	}
	if len(macHits) == 1 && len(hostHits) == 1 && macHits[0] != hostHits[0] {
		return conflict([]string{macHits[0], hostHits[0]}, "MAC and hostname plus primary user point at different devices")
	}
	if len(macHits) == 1 && len(hostHits) == 1 {
		return Match{DeviceID: macHits[0], Confidence: "weak", MatchedOn: []string{"mac", "hostname", "primary_user"}}
	}
	if len(macHits) == 1 {
		return Match{DeviceID: macHits[0], Confidence: "weak", MatchedOn: []string{"mac"}}
	}
	if len(hostHits) == 1 {
		return Match{DeviceID: hostHits[0], Confidence: "weak", MatchedOn: []string{"hostname", "primary_user"}}
	}
	return Match{Confidence: "none"}
}

// GhostKey groups unmatched records that share an identity.
// Conflicts stay on their own key so two disagreeing strong keys are not merged.
func GhostKey(source, nativeID string, k Keys, conflict bool) string {
	if conflict {
		return "conflict:" + source + ":" + nativeID
	}
	k = NormalizeKeys(k)
	switch {
	case k.Serial != "":
		return "serial:" + k.Serial
	case k.HardwareUUID != "":
		return "uuid:" + k.HardwareUUID
	case k.MAC != "":
		return "mac:" + k.MAC
	case k.Hostname != "" && k.PrimaryUser != "":
		return "host:" + k.Hostname + "|" + k.PrimaryUser
	default:
		return "native:" + source + ":" + nativeID
	}
}

// SubjectID is the device id, or a stable id for an unmatched cluster.
func SubjectID(deviceID, ghostKey string) string {
	if deviceID != "" {
		return deviceID
	}
	sum := sha256.Sum256([]byte(ghostKey))
	return "ghost-" + hex.EncodeToString(sum[:8])
}

func conflict(ids []string, note string) Match {
	return Match{Confidence: "conflict", Candidates: unique(ids), Note: note}
}

func eligible(cands []Candidate, obs Keys, pred func(Candidate) bool) []string {
	var ids []string
	for _, c := range cands {
		if !pred(c) {
			continue
		}
		if obs.Serial != "" && c.Serial != "" && obs.Serial != c.Serial {
			continue
		}
		if obs.HardwareUUID != "" && c.HardwareUUID != "" && obs.HardwareUUID != c.HardwareUUID {
			continue
		}
		ids = append(ids, c.ID)
	}
	return unique(ids)
}

func idsWhere(cands []Candidate, pred func(Candidate) bool) []string {
	var ids []string
	for _, c := range cands {
		if pred(c) {
			ids = append(ids, c.ID)
		}
	}
	return unique(ids)
}

func union(a, b []string) []string {
	return unique(append(append([]string{}, a...), b...))
}

func unique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func normalizeSerial(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || isPlaceholder(s, serialPlaceholders) {
		return ""
	}
	return strings.ToUpper(s)
}

func normalizeUUID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "{}")
	s = strings.ToLower(s)
	if s == "" || isPlaceholder(s, uuidPlaceholders) {
		return ""
	}
	return s
}

func normalizeMAC(s string) string {
	hexOnly := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return unicode.ToLower(r)
		default:
			return -1
		}
	}, s)
	if len(hexOnly) != 12 {
		return ""
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = hexOnly[i*2 : i*2+2]
	}
	mac := strings.Join(parts, ":")
	if isPlaceholder(mac, macPlaceholders) {
		return ""
	}
	return mac
}

func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if strings.HasSuffix(s, ".local") {
		s = strings.TrimSuffix(s, ".local")
	}
	if s == "" || isPlaceholder(s, hostPlaceholders) {
		return ""
	}
	return s
}

func normalizeUser(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || isPlaceholder(s, userPlaceholders) {
		return ""
	}
	return s
}

func isPlaceholder(s string, list []string) bool {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.Join(strings.Fields(n), " ")
	// Trailing periods are punctuation ("o.e.m.") and not part of the filler.
	trimmed := strings.Trim(n, ".")
	for _, p := range list {
		pt := strings.Trim(p, ".")
		if n == p || trimmed == p || n == pt || trimmed == pt {
			return true
		}
	}
	return false
}

var serialPlaceholders = []string{
	"0", "00", "000", "00000000", "000000000000", "0000000000000000",
	"unknown", "n/a", "na", "none", "null", "nil", "undefined",
	"not available", "not specified", "invalid", "system serial number",
	"to be filled by o.e.m.", "to be filled by oem", "default string",
	"serial number", "chassis serial number", "default", "xxxxxxxx",
	"system serial#", "oem",
}

var uuidPlaceholders = []string{
	"0", "unknown", "n/a", "none", "null",
	"00000000-0000-0000-0000-000000000000",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
}

var macPlaceholders = []string{
	"00:00:00:00:00:00",
	"ff:ff:ff:ff:ff:ff",
}

var hostPlaceholders = []string{
	"localhost", "unknown", "none", "(none)", "n/a", "null",
}

var userPlaceholders = []string{
	"unknown", "n/a", "na", "none", "null", "undefined",
}
