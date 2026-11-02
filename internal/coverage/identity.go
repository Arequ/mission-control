// Package coverage matches security-tool records onto unified devices and
// decides whether each source is seeing, stale, or missing.
package coverage

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
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

// Evidence is the set of serial/UUID pairs still being reported in this pass.
// A logic-board swap keeps the serial and presents a new UUID while the old
// UUID goes quiet. Serial reuse is the other way around: the old UUID is still
// live, so a second UUID must not take the device.
type Evidence struct {
	SerialUUIDs map[string]map[string]struct{}
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

// IdentityRecord is one unmatched observation considered for ghost clustering.
type IdentityRecord struct {
	Source   string
	NativeID string
	Keys     Keys
	Conflict bool
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
func Resolve(obs Keys, candidates []Candidate) Match {
	return ResolveObserved(obs, candidates, Evidence{})
}

// ResolveObserved matches one observation.
//
// Strong keys (serial, hardware UUID) are tried first. If they name two
// different devices, the result is a conflict and weak keys are not consulted.
// A placeholder serial or UUID is ignored. A new UUID on a serial whose old
// UUID is no longer reporting is the same device (logic-board swap). A new
// UUID on a serial that is still reporting the old UUID is a different device
// (serial reuse) and is not attached.
//
// Weak keys are a universal MAC that belongs to one device, or a hostname
// together with a primary user when that pair belongs to one device. A shared
// MAC (docks, USB-C adapters) and a locally administered MAC (randomized
// Wi-Fi, VPN, virtual adapters) are not identities. Hostname alone never matches.
func ResolveObserved(obs Keys, candidates []Candidate, ev Evidence) Match {
	obs = NormalizeKeys(obs)
	ev = normalizeEvidence(ev)
	norm := make([]Candidate, len(candidates))
	for i, c := range candidates {
		norm[i] = Candidate{ID: c.ID, Keys: NormalizeKeys(c.Keys)}
	}
	byID := map[string]Candidate{}
	macOwners := map[string]int{}
	for _, c := range norm {
		byID[c.ID] = c
		if universalMAC(c.MAC) {
			macOwners[c.MAC]++
		}
	}

	serialHits := idsWhere(norm, func(c Candidate) bool {
		return obs.Serial != "" && c.Serial == obs.Serial
	})
	uuidHits := idsWhere(norm, func(c Candidate) bool {
		return obs.HardwareUUID != "" && c.HardwareUUID == obs.HardwareUUID
	})
	blocked := map[string]bool{}

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
		if len(serialHits) == 1 && obs.HardwareUUID != "" {
			owner := byID[serialHits[0]]
			if owner.HardwareUUID != "" && owner.HardwareUUID != obs.HardwareUUID && evidenceHasOtherUUID(ev, obs.Serial, obs.HardwareUUID) {
				blocked[owner.ID] = true
				serialHits = nil
			}
		}
		if len(serialHits) == 1 {
			on := []string{"serial"}
			if obs.HardwareUUID != "" && byID[serialHits[0]].HardwareUUID == obs.HardwareUUID {
				on = append(on, "hardware_uuid")
			}
			return Match{DeviceID: serialHits[0], Confidence: "strong", MatchedOn: on}
		}
		if len(uuidHits) == 1 {
			return Match{DeviceID: uuidHits[0], Confidence: "strong", MatchedOn: []string{"hardware_uuid"}}
		}
	}

	macHits := []string{}
	if universalMAC(obs.MAC) && macOwners[obs.MAC] == 1 {
		macHits = eligible(norm, obs, blocked, func(c Candidate) bool {
			return c.MAC == obs.MAC
		})
	}
	hostHits := eligible(norm, obs, blocked, func(c Candidate) bool {
		return obs.Hostname != "" && obs.PrimaryUser != "" && hostsEqual(c.Hostname, obs.Hostname) && usersEqual(c.PrimaryUser, obs.PrimaryUser)
	})
	if len(hostHits) > 1 {
		hostHits = nil
	}
	if len(macHits) > 1 {
		macHits = nil
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

// AssignGhostKeys clusters unmatched records without letting a shared weak key
// chain two strong identities together. The key is stable for the same cluster
// regardless of source, so two tools describing one machine share a subject
// and two machines that only share a dock do not.
func AssignGhostKeys(records []IdentityRecord) []string {
	out := make([]string, len(records))
	if len(records) == 0 {
		return out
	}
	norm := make([]IdentityRecord, len(records))
	for i, r := range records {
		r.Keys = NormalizeKeys(r.Keys)
		norm[i] = r
	}
	parent := make([]int, len(norm))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	component := func(root int) (serials, uuids map[string]struct{}) {
		serials = map[string]struct{}{}
		uuids = map[string]struct{}{}
		for i, r := range norm {
			if r.Conflict || find(i) != root {
				continue
			}
			if r.Keys.Serial != "" {
				serials[r.Keys.Serial] = struct{}{}
			}
			if r.Keys.HardwareUUID != "" {
				uuids[r.Keys.HardwareUUID] = struct{}{}
			}
		}
		return serials, uuids
	}
	compatible := func(a, b int) bool {
		if a == b {
			return true
		}
		ss, us := component(a)
		ts, vs := component(b)
		return len(mergeSet(ss, ts)) <= 1 && len(mergeSet(us, vs)) <= 1
	}
	union := func(i, j int) bool {
		ri, rj := find(i), find(j)
		if ri == rj {
			return true
		}
		if norm[i].Conflict || norm[j].Conflict || !compatible(ri, rj) {
			return false
		}
		parent[rj] = ri
		return true
	}
	strong := func(root int) bool {
		ss, us := component(root)
		return len(ss)+len(us) > 0
	}

	bySerial := map[string][]int{}
	byUUID := map[string][]int{}
	for i, r := range norm {
		if r.Conflict {
			continue
		}
		if r.Keys.Serial != "" {
			bySerial[r.Keys.Serial] = append(bySerial[r.Keys.Serial], i)
		}
		if r.Keys.HardwareUUID != "" {
			byUUID[r.Keys.HardwareUUID] = append(byUUID[r.Keys.HardwareUUID], i)
		}
	}
	linkSame := func(ids []int) {
		for _, id := range ids[1:] {
			union(ids[0], id)
		}
	}
	for _, ids := range bySerial {
		linkSame(ids)
	}
	for _, ids := range byUUID {
		linkSame(ids)
	}

	macStrong := map[string]map[int]struct{}{}
	for i, r := range norm {
		if r.Conflict || !universalMAC(r.Keys.MAC) || !strong(find(i)) {
			continue
		}
		root := find(i)
		if macStrong[r.Keys.MAC] == nil {
			macStrong[r.Keys.MAC] = map[int]struct{}{}
		}
		macStrong[r.Keys.MAC][root] = struct{}{}
	}
	hostAmbiguous := map[string]bool{}
	type hostPair struct{ host, user string }
	seenHost := map[string]map[string]int{}
	var pairs []hostPair
	for _, r := range norm {
		if r.Conflict || r.Keys.Hostname == "" || r.Keys.PrimaryUser == "" {
			continue
		}
		hk := r.Keys.Hostname + "|" + r.Keys.PrimaryUser
		if seenHost[hk] == nil {
			seenHost[hk] = map[string]int{}
			pairs = append(pairs, hostPair{r.Keys.Hostname, r.Keys.PrimaryUser})
		}
		seenHost[hk][r.Source]++
		if seenHost[hk][r.Source] > 1 {
			hostAmbiguous[hk] = true
		}
	}

	strongHostRoot := func(host, user string) (int, bool) {
		found := map[int]struct{}{}
		var root int
		for i, r := range norm {
			if r.Conflict || !strong(find(i)) || r.Keys.Hostname == "" || r.Keys.PrimaryUser == "" {
				continue
			}
			if hostsEqual(r.Keys.Hostname, host) && usersEqual(r.Keys.PrimaryUser, user) {
				root = find(i)
				found[root] = struct{}{}
			}
		}
		if len(found) != 1 {
			return 0, false
		}
		return root, true
	}

	for i, r := range norm {
		if r.Conflict || r.Keys.Serial != "" || r.Keys.HardwareUUID != "" {
			continue
		}
		if universalMAC(r.Keys.MAC) && len(macStrong[r.Keys.MAC]) > 1 {
			continue
		}
		var macRoot, hostRoot int
		macOK, hostOK := false, false
		if universalMAC(r.Keys.MAC) && len(macStrong[r.Keys.MAC]) == 1 {
			for root := range macStrong[r.Keys.MAC] {
				macRoot = root
			}
			macOK = true
		}
		if r.Keys.Hostname != "" && r.Keys.PrimaryUser != "" && !hostAmbiguous[r.Keys.Hostname+"|"+r.Keys.PrimaryUser] {
			if root, ok := strongHostRoot(r.Keys.Hostname, r.Keys.PrimaryUser); ok {
				hostRoot = root
				hostOK = true
			}
		}
		switch {
		case macOK && hostOK && macRoot != hostRoot:
		case macOK:
			union(i, macRoot)
		case hostOK:
			union(i, hostRoot)
		}
	}

	for i := 0; i < len(norm); i++ {
		if norm[i].Conflict || strong(find(i)) || !universalMAC(norm[i].Keys.MAC) || len(macStrong[norm[i].Keys.MAC]) > 1 {
			continue
		}
		for j := i + 1; j < len(norm); j++ {
			if norm[j].Conflict || norm[j].Keys.MAC != norm[i].Keys.MAC || !weakHostsCompatible(norm[i].Keys, norm[j].Keys) {
				continue
			}
			union(i, j)
		}
	}
	for _, p := range pairs {
		hk := p.host + "|" + p.user
		if hostAmbiguous[hk] {
			continue
		}
		var ids []int
		for i, r := range norm {
			if r.Conflict || r.Keys.Hostname == "" || r.Keys.PrimaryUser == "" || strong(find(i)) {
				continue
			}
			if hostsEqual(r.Keys.Hostname, p.host) && usersEqual(r.Keys.PrimaryUser, p.user) {
				ids = append(ids, i)
			}
		}
		if len(ids) < 2 {
			continue
		}
		macs := map[string]struct{}{}
		for _, id := range ids {
			if universalMAC(norm[id].Keys.MAC) {
				macs[norm[id].Keys.MAC] = struct{}{}
			}
		}
		if len(macs) > 1 {
			continue
		}
		for _, id := range ids[1:] {
			union(ids[0], id)
		}
	}

	keyOf := map[int]string{}
	for i := range norm {
		root := find(i)
		if _, ok := keyOf[root]; ok {
			out[i] = keyOf[root]
			continue
		}
		var members []IdentityRecord
		for j, r := range norm {
			if find(j) == root {
				members = append(members, r)
			}
		}
		key := clusterKey(members)
		keyOf[root] = key
		out[i] = key
	}
	return out
}

// GhostKey is the cluster key of one record. Conflicts stay on their own key.
func GhostKey(source, nativeID string, k Keys, conflict bool) string {
	return AssignGhostKeys([]IdentityRecord{{
		Source: source, NativeID: nativeID, Keys: k, Conflict: conflict,
	}})[0]
}

// SubjectID is the device id, or a stable id for an unmatched cluster.
func SubjectID(deviceID, ghostKey string) string {
	if deviceID != "" {
		return deviceID
	}
	sum := sha256.Sum256([]byte(ghostKey))
	return "ghost-" + hex.EncodeToString(sum[:8])
}

func clusterKey(members []IdentityRecord) string {
	if len(members) == 1 && members[0].Conflict {
		return "conflict:" + members[0].Source + ":" + members[0].NativeID
	}
	serials := map[string]struct{}{}
	uuids := map[string]struct{}{}
	macs := map[string]struct{}{}
	var hosts []string
	users := map[string]struct{}{}
	for _, r := range members {
		if r.Keys.Serial != "" {
			serials[r.Keys.Serial] = struct{}{}
		}
		if r.Keys.HardwareUUID != "" {
			uuids[r.Keys.HardwareUUID] = struct{}{}
		}
		if universalMAC(r.Keys.MAC) {
			macs[r.Keys.MAC] = struct{}{}
		}
		if r.Keys.Hostname != "" && r.Keys.PrimaryUser != "" {
			hosts = append(hosts, r.Keys.Hostname)
			users[r.Keys.PrimaryUser] = struct{}{}
		}
	}
	if len(serials) == 1 {
		return "serial:" + only(serials)
	}
	if len(uuids) == 1 {
		return "uuid:" + only(uuids)
	}
	if len(macs) == 1 {
		return "mac:" + only(macs)
	}
	if len(users) == 1 && len(hosts) > 0 {
		return "host:" + shortest(hosts) + "|" + only(users)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].Source != members[j].Source {
			return members[i].Source < members[j].Source
		}
		return members[i].NativeID < members[j].NativeID
	})
	return "native:" + members[0].Source + ":" + members[0].NativeID
}

func weakHostsCompatible(a, b Keys) bool {
	if a.Hostname == "" || b.Hostname == "" || a.PrimaryUser == "" || b.PrimaryUser == "" {
		return true
	}
	return hostsEqual(a.Hostname, b.Hostname) && usersEqual(a.PrimaryUser, b.PrimaryUser)
}

func evidenceHasOtherUUID(ev Evidence, serial, uuid string) bool {
	for other := range ev.SerialUUIDs[serial] {
		if other != "" && other != uuid {
			return true
		}
	}
	return false
}

func normalizeEvidence(ev Evidence) Evidence {
	out := Evidence{SerialUUIDs: map[string]map[string]struct{}{}}
	for serial, uuids := range ev.SerialUUIDs {
		for uuid := range uuids {
			k := NormalizeKeys(Keys{Serial: serial, HardwareUUID: uuid})
			if k.Serial == "" || k.HardwareUUID == "" {
				continue
			}
			if out.SerialUUIDs[k.Serial] == nil {
				out.SerialUUIDs[k.Serial] = map[string]struct{}{}
			}
			out.SerialUUIDs[k.Serial][k.HardwareUUID] = struct{}{}
		}
	}
	return out
}

func conflict(ids []string, note string) Match {
	ids = unique(ids)
	sort.Strings(ids)
	return Match{Confidence: "conflict", Candidates: ids, Note: note}
}

func eligible(cands []Candidate, obs Keys, blocked map[string]bool, pred func(Candidate) bool) []string {
	var ids []string
	for _, c := range cands {
		if blocked[c.ID] || !pred(c) {
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

func mergeSet(a, b map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

func only(s map[string]struct{}) string {
	for k := range s {
		return k
	}
	return ""
}

func shortest(in []string) string {
	best := in[0]
	for _, v := range in[1:] {
		if len(v) < len(best) || (len(v) == len(best) && v < best) {
			best = v
		}
	}
	return best
}

func normalizeSerial(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\u00a0', '\u200b', '\ufeff':
			return ' '
		default:
			return r
		}
	}, s)
	s = strings.TrimSpace(s)
	if s == "" || isPlaceholder(s, serialPlaceholders) {
		return ""
	}
	s = strings.Join(strings.Fields(s), "")
	folded := strings.ToLower(s)
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '-', ':', '.':
			return -1
		default:
			return r
		}
	}, folded)
	if len(compact) >= 8 && isHexString(compact) && allSameRune(compact) {
		return ""
	}
	return strings.ToUpper(s)
}

func normalizeUUID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToLower(s), "urn:uuid:")
	s = strings.Trim(s, "{}")
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\u00a0', '\u200b', '\ufeff':
			return -1
		default:
			return r
		}
	}, s)
	s = strings.TrimSpace(s)
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t':
			return -1
		default:
			return unicode.ToLower(r)
		}
	}, s)
	if len(compact) == 32 && isHexString(compact) {
		if allSameRune(compact) {
			return ""
		}
		return compact[0:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" + compact[16:20] + "-" + compact[20:32]
	}
	if s == "" || isPlaceholder(s, uuidPlaceholders) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(s))
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

// universalMAC is a globally unique unicast address. Locally administered
// addresses are randomized Wi-Fi, VPN, and virtual adapters. Multicast
// addresses are not device identities either.
func universalMAC(mac string) bool {
	if mac == "" {
		return false
	}
	v, err := strconv.ParseUint(mac[:2], 16, 8)
	if err != nil {
		return false
	}
	return v&0x03 == 0
}

func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSuffix(s, ".local")
	if s == "" || isPlaceholder(s, hostPlaceholders) {
		return ""
	}
	return s
}

func hostsEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

func normalizeUser(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || isPlaceholder(s, userPlaceholders) {
		return ""
	}
	return s
}

func usersEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	la, lb := localUser(a), localUser(b)
	if la == "" || la != lb {
		return false
	}
	return a == la || b == lb
}

func localUser(s string) string {
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	return s
}

func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return s != ""
}

func allSameRune(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return s != ""
}

func isPlaceholder(s string, list []string) bool {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.Join(strings.Fields(n), " ")
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
