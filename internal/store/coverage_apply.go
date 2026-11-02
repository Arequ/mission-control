package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/jackc/pgx/v5"
)

type deviceFacts struct {
	ID       string
	Name     string
	Serial   string
	UUID     string
	MAC      string
	Hostname string
	User     string
	OS       string
	IP       string
	Agent    string
	Model    string
	LastSeen time.Time
}

type snapRow struct {
	ID         string
	NativeID   string
	DeviceID   string
	SubjectID  string
	GhostKey   string
	Fields     map[string]string
	MatchedOn  []string
	Confidence string
	Note       string
	LastSeen   time.Time
}

type applyOpts struct {
	full       bool
	events     bool
	keepBefore time.Time
}

// ApplyObservations upserts one source's latest view of each device.
// full removes snapshots the source no longer reports. An empty batch never
// deletes: a failed or empty poll must not mark the fleet missing. events
// records sightings, losses, disagreements, and rematches.
func (s *Store) ApplyObservations(ctx context.Context, source string, obs []coverage.Observation, full, events bool) error {
	return s.applyObservations(ctx, source, obs, applyOpts{full: full, events: events})
}

func (s *Store) applyObservations(ctx context.Context, source string, obs []coverage.Observation, opts applyOpts) error {
	if !coverage.KnownSource(source) {
		return invalid("unknown coverage source")
	}
	facts, err := s.loadDeviceFacts(ctx)
	if err != nil {
		return err
	}
	byID := map[string]deviceFacts{}
	var candidates []coverage.Candidate
	for _, f := range facts {
		byID[f.ID] = f
		candidates = append(candidates, coverage.Candidate{ID: f.ID, Keys: coverage.Keys{
			Serial: f.Serial, HardwareUUID: f.UUID, MAC: f.MAC, Hostname: f.Hostname, PrimaryUser: f.User,
		}})
	}
	existing, err := s.loadSourceSnapshots(ctx, source)
	if err != nil {
		return err
	}
	anchors, err := s.loadGhostAnchors(ctx, source)
	if err != nil {
		return err
	}
	ev := coverage.Evidence{SerialUUIDs: map[string]map[string]struct{}{}}
	for _, o := range obs {
		addEvidence(&ev, o.Keys.Serial, o.Keys.HardwareUUID)
	}
	type pendingObs struct {
		obs   coverage.Observation
		match coverage.Match
	}
	var pending []pendingObs
	seenNative := map[string]bool{}
	for _, o := range obs {
		if strings.TrimSpace(o.NativeID) == "" || seenNative[o.NativeID] {
			continue
		}
		seenNative[o.NativeID] = true
		pending = append(pending, pendingObs{obs: o, match: coverage.ResolveObserved(o.Keys, candidates, ev)})
	}
	// A failed or empty poll must not mark everything missing.
	if len(pending) == 0 {
		return nil
	}
	records := make([]coverage.IdentityRecord, 0, len(anchors)+len(pending))
	records = append(records, anchors...)
	unmatchedAt := make([]int, 0)
	for i, p := range pending {
		if p.match.DeviceID != "" {
			continue
		}
		unmatchedAt = append(unmatchedAt, i)
		records = append(records, coverage.IdentityRecord{
			Source: source, NativeID: p.obs.NativeID, Keys: p.obs.Keys,
			Conflict: p.match.Confidence == "conflict",
		})
	}
	assigned := coverage.AssignGhostKeys(records)
	ghostFor := map[int]string{}
	for j, idx := range unmatchedAt {
		ghostFor[idx] = assigned[len(anchors)+j]
	}

	had := map[string]bool{}
	for _, row := range existing {
		had[row.SubjectID] = true
	}
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	remaining := map[string]int{}
	full, events := opts.full, opts.events
	for i, p := range pending {
		o := p.obs
		match := p.match
		conflict := match.Confidence == "conflict"
		ghostKey := ""
		deviceID := match.DeviceID
		if deviceID == "" {
			ghostKey = ghostFor[i]
		}
		subject := coverage.SubjectID(deviceID, ghostKey)
		fields := o.NormalizedFields()
		prev := existing[o.NativeID]
		id := prev.ID
		if id == "" {
			id = newID()
		}
		raw, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		var last any
		if !o.LastSeen.IsZero() {
			last = o.LastSeen.UTC()
		}
		matched := match.MatchedOn
		if matched == nil {
			matched = []string{}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO source_snapshots (
				id, source, native_id, device_id, subject_id, ghost_key,
				serial, hardware_uuid, mac, hostname, primary_user, os_version, ip_address, agent_version,
				fields, matched_on, confidence, match_note, last_seen_at, updated_at)
			VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18,$19,$20)
			ON CONFLICT (source, native_id) DO UPDATE SET
				device_id=EXCLUDED.device_id, subject_id=EXCLUDED.subject_id, ghost_key=EXCLUDED.ghost_key,
				serial=EXCLUDED.serial, hardware_uuid=EXCLUDED.hardware_uuid, mac=EXCLUDED.mac,
				hostname=EXCLUDED.hostname, primary_user=EXCLUDED.primary_user, os_version=EXCLUDED.os_version,
				ip_address=EXCLUDED.ip_address, agent_version=EXCLUDED.agent_version, fields=EXCLUDED.fields,
				matched_on=EXCLUDED.matched_on, confidence=EXCLUDED.confidence, match_note=EXCLUDED.match_note,
				last_seen_at=EXCLUDED.last_seen_at, updated_at=EXCLUDED.updated_at`,
			id, source, o.NativeID, deviceID, subject, ghostKey,
			o.Keys.Serial, o.Keys.HardwareUUID, o.Keys.MAC, o.Keys.Hostname, o.Keys.PrimaryUser,
			o.OSVersion, o.IPAddress, o.AgentVersion, string(raw), matched, emptyConf(match.Confidence), match.Note, last, now)
		if err != nil {
			return err
		}
		remaining[subject]++
		if !events {
			continue
		}
		if prev.ID == "" {
			if !had[subject] {
				if err := s.insertCoverageEvent(ctx, tx, subject, source, "source_seen", map[string]any{
					"native_id": o.NativeID, "confidence": emptyConf(match.Confidence), "matched_on": matched,
				}, now); err != nil {
					return err
				}
				had[subject] = true
			}
		} else if prev.DeviceID != deviceID {
			if err := s.insertCoverageEvent(ctx, tx, subject, source, "rematched", map[string]any{
				"from_device": prev.DeviceID, "to_device": deviceID, "matched_on": matched, "native_id": o.NativeID,
			}, now); err != nil {
				return err
			}
			if prev.SubjectID != "" && prev.SubjectID != subject {
				if err := s.insertCoverageEvent(ctx, tx, prev.SubjectID, source, "rematched", map[string]any{
					"from_device": prev.DeviceID, "to_device": deviceID, "native_id": o.NativeID,
				}, now); err != nil {
					return err
				}
			}
		}
		if conflict && (prev.ID == "" || prev.Note != match.Note) {
			if err := s.insertCoverageEvent(ctx, tx, subject, source, "identity_conflict", map[string]any{
				"note": match.Note, "candidates": match.Candidates, "native_id": o.NativeID,
			}, now); err != nil {
				return err
			}
		}
		unified := unifiedFields(byID[deviceID])
		for _, field := range compareFields {
			value := fields[field]
			base := unified[field]
			if value == "" || base == "" || strings.EqualFold(value, base) {
				continue
			}
			if prev.Fields[field] == value {
				continue
			}
			if err := s.insertCoverageEvent(ctx, tx, subject, source, "field_disagreement", map[string]any{
				"field": field, "unified": base, "value": value,
			}, now); err != nil {
				return err
			}
		}
	}
	if full {
		lost := map[string]bool{}
		for native, prev := range existing {
			if seenNative[native] {
				continue
			}
			// Elastic windows age out. Keep the snapshot so the device stays
			// stale instead of flipping to missing when the event leaves the query.
			if !opts.keepBefore.IsZero() && !prev.LastSeen.IsZero() && prev.LastSeen.Before(opts.keepBefore) {
				continue
			}
			if _, err := tx.Exec(ctx, `DELETE FROM source_snapshots WHERE source=$1 AND native_id=$2`, source, native); err != nil {
				return err
			}
			if events && remaining[prev.SubjectID] == 0 && !lost[prev.SubjectID] {
				lost[prev.SubjectID] = true
				if err := s.insertCoverageEvent(ctx, tx, prev.SubjectID, source, "source_lost", map[string]any{
					"native_id": native,
				}, now); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit(ctx)
}

func emptyConf(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

var compareFields = []string{"hostname", "os_version", "serial", "primary_user", "ip_address"}

func unifiedFields(f deviceFacts) map[string]string {
	return map[string]string{
		"hostname": f.Hostname, "os_version": f.OS, "serial": f.Serial,
		"primary_user": f.User, "ip_address": f.IP,
	}
}

func (s *Store) insertCoverageEvent(ctx context.Context, tx pgx.Tx, subject, source, kind string, detail map[string]any, at time.Time) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO coverage_events (subject_id, source, kind, detail, at)
		VALUES ($1,$2,$3,$4::jsonb,$5)`, subject, source, kind, string(b), at)
	return err
}

func (s *Store) loadDeviceFacts(ctx context.Context) ([]deviceFacts, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, computer_name, serial, hardware_uuid, primary_mac, hostname, username,
			os_version, primary_ip, osquery_version, hardware_model, last_seen_at
		FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deviceFacts
	for rows.Next() {
		var f deviceFacts
		var last *time.Time
		if err := rows.Scan(&f.ID, &f.Name, &f.Serial, &f.UUID, &f.MAC, &f.Hostname, &f.User, &f.OS, &f.IP, &f.Agent, &f.Model, &last); err != nil {
			return nil, err
		}
		if last != nil {
			f.LastSeen = last.UTC()
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func addEvidence(ev *coverage.Evidence, serial, uuid string) {
	k := coverage.NormalizeKeys(coverage.Keys{Serial: serial, HardwareUUID: uuid})
	if k.Serial == "" || k.HardwareUUID == "" {
		return
	}
	if ev.SerialUUIDs == nil {
		ev.SerialUUIDs = map[string]map[string]struct{}{}
	}
	if ev.SerialUUIDs[k.Serial] == nil {
		ev.SerialUUIDs[k.Serial] = map[string]struct{}{}
	}
	ev.SerialUUIDs[k.Serial][k.HardwareUUID] = struct{}{}
}

func (s *Store) loadGhostAnchors(ctx context.Context, source string) ([]coverage.IdentityRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT source, native_id, serial, hardware_uuid, mac, hostname, primary_user, confidence
		FROM source_snapshots WHERE device_id IS NULL AND source <> $1`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []coverage.IdentityRecord
	for rows.Next() {
		var rec coverage.IdentityRecord
		var confidence string
		if err := rows.Scan(&rec.Source, &rec.NativeID, &rec.Keys.Serial, &rec.Keys.HardwareUUID, &rec.Keys.MAC, &rec.Keys.Hostname, &rec.Keys.PrimaryUser, &confidence); err != nil {
			return nil, err
		}
		rec.Conflict = confidence == "conflict"
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) loadSourceSnapshots(ctx context.Context, source string) (map[string]snapRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, native_id, COALESCE(device_id,''), subject_id, ghost_key, fields, matched_on, confidence, match_note, last_seen_at
		FROM source_snapshots WHERE source=$1`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]snapRow{}
	for rows.Next() {
		row, err := scanSnap(rows)
		if err != nil {
			return nil, err
		}
		out[row.NativeID] = row
	}
	return out, rows.Err()
}

func scanSnap(row scannable) (snapRow, error) {
	var s snapRow
	var raw []byte
	var last *time.Time
	if err := row.Scan(&s.ID, &s.NativeID, &s.DeviceID, &s.SubjectID, &s.GhostKey, &raw, &s.MatchedOn, &s.Confidence, &s.Note, &last); err != nil {
		return snapRow{}, err
	}
	if last != nil {
		s.LastSeen = last.UTC()
	}
	s.Fields = map[string]string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &s.Fields)
	}
	if s.MatchedOn == nil {
		s.MatchedOn = []string{}
	}
	return s, nil
}

// ProjectOsquery copies the enrolled fleet into osquery snapshots.
func (s *Store) ProjectOsquery(ctx context.Context) error {
	facts, err := s.loadDeviceFacts(ctx)
	if err != nil {
		return err
	}
	obs := make([]coverage.Observation, 0, len(facts))
	for _, f := range facts {
		obs = append(obs, coverage.Observation{
			NativeID: f.ID,
			Keys: coverage.Keys{
				Serial: f.Serial, HardwareUUID: f.UUID, MAC: f.MAC, Hostname: f.Hostname, PrimaryUser: f.User,
			},
			OSVersion: f.OS, IPAddress: f.IP, AgentVersion: f.Agent, LastSeen: f.LastSeen,
		})
	}
	return s.ApplyObservations(ctx, "osquery", obs, true, true)
}
