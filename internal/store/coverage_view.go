package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/Arequ/mission-control/internal/model"
)

type viewSnap struct {
	Source     string
	NativeID   string
	DeviceID   string
	SubjectID  string
	GhostKey   string
	Hostname   string
	Serial     string
	User       string
	OS         string
	IP         string
	Fields     map[string]string
	MatchedOn  []string
	Confidence string
	Note       string
	LastSeen   time.Time
}

func (s *Store) CoverageMatrix(ctx context.Context, kind, source, q string, staleDays, limit, offset int) (model.CoverageMatrix, error) {
	rows, err := s.coverageRows(ctx)
	if err != nil {
		return model.CoverageMatrix{}, err
	}
	now := s.now()
	gaps := 0
	for _, row := range rows {
		if coverage.HasGaps(cellsOf(row)) {
			gaps++
		}
	}
	filtered := rows[:0:0]
	needle := strings.ToLower(strings.TrimSpace(q))
	for _, row := range rows {
		if needle != "" && !strings.Contains(strings.ToLower(row.Name+" "+row.Hostname+" "+row.Serial+" "+row.User), needle) {
			continue
		}
		if !coverage.Keep(cellsOf(row), coverage.Filter{Kind: kind, Source: source, StaleDays: staleDays}, now) {
			continue
		}
		filtered = append(filtered, row)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Seen != filtered[j].Seen {
			return filtered[i].Seen < filtered[j].Seen
		}
		return strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name)
	})
	total := len(filtered)
	limit, offset = clampPage(limit, offset)
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page := append([]model.CoverageRow(nil), filtered[offset:end]...)
	thresholds, err := s.thresholds(ctx)
	if err != nil {
		return model.CoverageMatrix{}, err
	}
	cols := make([]model.CoverageSourceColumn, 0, len(coverage.Sources))
	for _, src := range coverage.Sources {
		seen := 0
		for _, row := range rows {
			for _, cell := range row.Cells {
				if cell.Source == src.Key && cell.State == coverage.Seen {
					seen++
				}
			}
		}
		cols = append(cols, model.CoverageSourceColumn{
			Key: src.Key, Name: src.Name, Short: src.Short,
			Percent: coverage.Percent(seen, len(rows)), StaleAfterSeconds: int(thresholds[src.Key] / time.Second),
		})
	}
	if page == nil {
		page = []model.CoverageRow{}
	}
	return model.CoverageMatrix{Sources: cols, Rows: page, Total: total, Gaps: gaps, Limit: limit, Offset: offset}, nil
}

func clampPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (s *Store) CoverageDevice(ctx context.Context, id string) (model.CoverageDevice, error) {
	rows, err := s.coverageRows(ctx)
	if err != nil {
		return model.CoverageDevice{}, err
	}
	var row model.CoverageRow
	found := false
	for _, candidate := range rows {
		if candidate.ID == id {
			row = candidate
			found = true
			break
		}
	}
	if !found {
		return model.CoverageDevice{}, ErrNotFound
	}
	snaps, err := s.loadAllSnapshots(ctx)
	if err != nil {
		return model.CoverageDevice{}, err
	}
	facts, err := s.loadDeviceFacts(ctx)
	if err != nil {
		return model.CoverageDevice{}, err
	}
	var fact deviceFacts
	for _, f := range facts {
		if f.ID == id {
			fact = f
		}
	}
	mine := snapsFor(snaps, id)
	out := model.CoverageDevice{
		ID: row.ID, Kind: row.Kind, Name: row.Name, Hostname: row.Hostname, Serial: row.Serial,
		User: row.User, OSVersion: row.OSVersion, Seen: row.Seen, Total: row.Total,
		DeviceID: fact.ID, Model: fact.Model, Match: explainMatch(row.Kind, mine),
	}
	if fact.ID == "" {
		out.DeviceID = ""
	}
	for _, src := range coverage.Sources {
		tile := model.CoverageTile{Key: src.Key, Name: src.Name, Short: src.Short, State: coverage.Missing}
		for _, cell := range row.Cells {
			if cell.Source == src.Key {
				tile.State = cell.State
				tile.LastSeen = cell.LastSeen
				tile.NativeID = cell.NativeID
			}
		}
		for _, snap := range mine {
			if snap.Source == src.Key {
				tile.Confidence = snap.Confidence
				tile.MatchedOn = snap.MatchedOn
			}
		}
		out.Sources = append(out.Sources, tile)
	}
	unified := unifiedFields(fact)
	if fact.ID == "" {
		unified = majorityFields(mine)
	}
	labels := []struct{ field, label string }{
		{"hostname", "Hostname"},
		{"os_version", "OS version"},
		{"serial", "Serial"},
		{"primary_user", "Primary user"},
		{"ip_address", "IP address"},
	}
	for _, item := range labels {
		field := model.CoverageField{Field: item.field, Label: item.label, Unified: unified[item.field]}
		for _, src := range coverage.Sources {
			value := ""
			for _, snap := range mine {
				if snap.Source != src.Key {
					continue
				}
				if v := snap.Fields[item.field]; v != "" {
					value = v
				}
			}
			if value == "" {
				continue
			}
			field.Values = append(field.Values, model.CoverageFieldValue{
				Source: src.Key, Value: value,
				Disagrees: field.Unified != "" && !strings.EqualFold(field.Unified, value),
			})
		}
		if field.Values == nil {
			field.Values = []model.CoverageFieldValue{}
		}
		out.Fields = append(out.Fields, field)
	}
	events, err := s.loadCoverageEvents(ctx, id)
	if err != nil {
		return model.CoverageDevice{}, err
	}
	out.Events = events
	return out, nil
}

// DeviceCoverageCount is the chip on the general device page.
func (s *Store) DeviceCoverageCount(ctx context.Context, id string) (model.DeviceCoverage, error) {
	dev, err := s.CoverageDevice(ctx, id)
	if err != nil {
		return model.DeviceCoverage{}, err
	}
	return model.DeviceCoverage{Seen: dev.Seen, Total: dev.Total}, nil
}

func explainMatch(kind string, snaps []viewSnap) model.CoverageMatch {
	best := ""
	rank := map[string]int{"strong": 3, "weak": 2, "conflict": 1, "none": 0}
	var on []string
	note := ""
	seen := map[string]bool{}
	for _, snap := range snaps {
		if snap.Source == "osquery" {
			continue
		}
		if rank[snap.Confidence] > rank[best] {
			best = snap.Confidence
		}
		if snap.Note != "" && note == "" {
			note = snap.Note
		}
		for _, key := range snap.MatchedOn {
			if !seen[key] {
				seen[key] = true
				on = append(on, key)
			}
		}
	}
	if best == "" {
		best = "none"
	}
	switch {
	case kind == "conflict":
		if note == "" {
			note = "Strong keys point at different devices, so this record was not merged."
		}
	case kind == "ghost":
		note = "Seen by a security tool and not by osquery."
	case best == "strong":
		note = "Matched on " + humanKeys(on) + "."
	case best == "weak":
		note = "Weak match on " + humanKeys(on) + ". Serial and hardware UUID were absent or placeholders."
	default:
		if note == "" {
			note = "Enrolled in osquery."
		}
	}
	if on == nil {
		on = []string{}
	}
	return model.CoverageMatch{Confidence: best, MatchedOn: on, Note: note}
}

func humanKeys(keys []string) string {
	if len(keys) == 0 {
		return "the enrolled record"
	}
	labels := map[string]string{
		"serial": "serial number", "hardware_uuid": "hardware UUID", "mac": "MAC address",
		"hostname": "hostname", "primary_user": "primary user",
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if label := labels[k]; label != "" {
			out = append(out, label)
		}
	}
	return strings.Join(out, " and ")
}

func majorityFields(snaps []viewSnap) map[string]string {
	out := map[string]string{}
	for _, field := range compareFields {
		counts := map[string]int{}
		for _, snap := range snaps {
			v := snap.Fields[field]
			if v == "" {
				continue
			}
			counts[v]++
			if out[field] == "" || counts[v] > counts[out[field]] {
				out[field] = v
			}
		}
	}
	return out
}

func (s *Store) coverageRows(ctx context.Context) ([]model.CoverageRow, error) {
	facts, err := s.loadDeviceFacts(ctx)
	if err != nil {
		return nil, err
	}
	snaps, err := s.loadAllSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	thresholds, err := s.thresholds(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	type bucket struct {
		id       string
		kind     string
		fact     deviceFacts
		ghost    viewSnap
		bySource map[string]viewSnap
	}
	buckets := map[string]*bucket{}
	for _, f := range facts {
		buckets[f.ID] = &bucket{id: f.ID, kind: "device", fact: f, bySource: map[string]viewSnap{}}
	}
	for _, snap := range snaps {
		id := snap.SubjectID
		if snap.DeviceID != "" {
			id = snap.DeviceID
		}
		b := buckets[id]
		if b == nil {
			kind := "ghost"
			if strings.HasPrefix(snap.GhostKey, "conflict:") || snap.Confidence == "conflict" {
				kind = "conflict"
			}
			b = &bucket{id: id, kind: kind, ghost: snap, bySource: map[string]viewSnap{}}
			buckets[id] = b
		}
		prev, ok := b.bySource[snap.Source]
		if !ok || snap.LastSeen.After(prev.LastSeen) {
			b.bySource[snap.Source] = snap
		}
	}
	rows := make([]model.CoverageRow, 0, len(buckets))
	for _, b := range buckets {
		row := model.CoverageRow{ID: b.id, Kind: b.kind, Total: len(coverage.Sources)}
		if b.kind == "device" {
			row.Name = b.fact.Name
			if row.Name == "" {
				row.Name = b.fact.Hostname
			}
			row.Hostname = b.fact.Hostname
			row.Serial = b.fact.Serial
			row.User = b.fact.User
			row.OSVersion = b.fact.OS
		} else {
			row.Name = b.ghost.Hostname
			if row.Name == "" {
				row.Name = b.ghost.Serial
			}
			if row.Name == "" {
				row.Name = "Unmatched device"
			}
			row.Hostname = b.ghost.Hostname
			row.Serial = b.ghost.Serial
			row.User = b.ghost.User
			row.OSVersion = b.ghost.OS
		}
		for _, src := range coverage.Sources {
			cell := model.CoverageCell{Source: src.Key, State: coverage.Missing}
			if snap, ok := b.bySource[src.Key]; ok {
				cell.State = coverage.Classify(true, snap.LastSeen, now, thresholds[src.Key])
				cell.NativeID = snap.NativeID
				if !snap.LastSeen.IsZero() {
					t := snap.LastSeen
					cell.LastSeen = &t
				}
			} else if src.Key == "osquery" && b.kind == "device" {
				cell.State = coverage.Classify(true, b.fact.LastSeen, now, thresholds[src.Key])
				cell.NativeID = b.fact.ID
				if !b.fact.LastSeen.IsZero() {
					t := b.fact.LastSeen
					cell.LastSeen = &t
				}
			}
			row.Cells = append(row.Cells, cell)
		}
		row.Seen = coverage.SeenCount(cellsOf(row))
		rows = append(rows, row)
	}
	return rows, nil
}

func cellsOf(row model.CoverageRow) []coverage.Cell {
	out := make([]coverage.Cell, 0, len(row.Cells))
	for _, c := range row.Cells {
		cell := coverage.Cell{Source: c.Source, State: c.State, Present: c.State != coverage.Missing}
		if c.LastSeen != nil {
			cell.LastSeen = *c.LastSeen
		}
		out = append(out, cell)
	}
	return out
}

func (s *Store) loadAllSnapshots(ctx context.Context) ([]viewSnap, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT source, native_id, COALESCE(device_id,''), subject_id, ghost_key,
			hostname, serial, primary_user, os_version, ip_address, fields,
			matched_on, confidence, match_note, last_seen_at
		FROM source_snapshots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []viewSnap
	for rows.Next() {
		var snap viewSnap
		var raw []byte
		var last *time.Time
		if err := rows.Scan(&snap.Source, &snap.NativeID, &snap.DeviceID, &snap.SubjectID, &snap.GhostKey,
			&snap.Hostname, &snap.Serial, &snap.User, &snap.OS, &snap.IP, &raw,
			&snap.MatchedOn, &snap.Confidence, &snap.Note, &last); err != nil {
			return nil, err
		}
		snap.Fields = map[string]string{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &snap.Fields)
		}
		if last != nil {
			snap.LastSeen = last.UTC()
		}
		if snap.MatchedOn == nil {
			snap.MatchedOn = []string{}
		}
		out = append(out, snap)
	}
	return out, rows.Err()
}

func snapsFor(all []viewSnap, id string) []viewSnap {
	var out []viewSnap
	for _, snap := range all {
		if snap.SubjectID == id || snap.DeviceID == id {
			out = append(out, snap)
		}
	}
	return out
}

func (s *Store) loadCoverageEvents(ctx context.Context, subject string) ([]model.CoverageEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, source, kind, detail FROM coverage_events
		WHERE subject_id=$1 ORDER BY at DESC, id DESC LIMIT 40`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.CoverageEvent{}
	for rows.Next() {
		var ev model.CoverageEvent
		var raw []byte
		if err := rows.Scan(&ev.ID, &ev.At, &ev.Source, &ev.Kind, &raw); err != nil {
			return nil, err
		}
		ev.Detail = map[string]any{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &ev.Detail)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
