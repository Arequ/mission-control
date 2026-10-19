package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/jackc/pgx/v5"
)

const osqueryActorName = "osquery"

func osqueryActor() model.Principal {
	return model.Principal{Kind: "system", ID: "osquery", Name: osqueryActorName}
}

type storedDevice struct {
	model.Device
	nodeKeyHash     string
	appsInitialized bool
}

const deviceCols = `id, node_key_hash, node_invalid, host_identifier, hardware_uuid, serial, hostname, computer_name, platform, os_name, os_version, os_build, hardware_model, hardware_vendor, cpu_brand, cpu_type, cpu_physical_cores, cpu_logical_cores, physical_memory, primary_ip, primary_mac, username, disk_encrypted, uptime_seconds, osquery_version, apps_initialized, enrolled_at, last_enrolled_at, last_seen_at, created_at, updated_at`

func scanStoredDevice(row pgx.Row) (storedDevice, error) {
	var d storedDevice
	err := row.Scan(
		&d.ID, &d.nodeKeyHash, &d.NodeInvalid, &d.HostIdentifier, &d.HardwareUUID, &d.Serial,
		&d.Hostname, &d.ComputerName, &d.Platform, &d.OSName, &d.OSVersion, &d.OSBuild,
		&d.HardwareModel, &d.HardwareVendor, &d.CPUBrand, &d.CPUType, &d.CPUPhysicalCores, &d.CPULogicalCores,
		&d.PhysicalMemory, &d.PrimaryIP, &d.PrimaryMAC, &d.Username, &d.DiskEncrypted, &d.UptimeSeconds,
		&d.OsqueryVersion, &d.appsInitialized, &d.EnrolledAt, &d.LastEnrolledAt, &d.LastSeenAt, &d.CreatedAt, &d.UpdatedAt,
	)
	return d, err
}

func newNodeKey() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(buf)
	return raw, auth.Hash(raw), nil
}

type hostIdentity struct {
	HostIdentifier string
	UUID           string
	Serial         string
	Hostname       string
	ComputerName   string
	Platform       string
	OSName         string
	OSVersion      string
	OSBuild        string
	Model          string
	Vendor         string
	CPUBrand       string
	CPUType        string
	CPUPhysical    int
	CPULogical     int
	Memory         int64
	OsqueryVersion string
}

func identityFrom(hostID string, details map[string]any) hostIdentity {
	sys := asMap(details["system_info"])
	osv := asMap(details["os_version"])
	info := asMap(details["osquery_info"])
	plat := asMap(details["platform_info"])
	id := hostIdentity{HostIdentifier: strings.TrimSpace(hostID)}
	id.UUID = firstStr(sys["uuid"])
	id.Serial = firstStr(sys["hardware_serial"])
	id.Hostname = firstStr(sys["hostname"], sys["local_hostname"])
	id.ComputerName = firstStr(sys["computer_name"], id.Hostname, id.HostIdentifier)
	if id.Hostname == "" {
		id.Hostname = id.HostIdentifier
	}
	id.OSName = firstStr(osv["name"])
	id.OSVersion = firstStr(osv["version"])
	if id.OSVersion == "" {
		id.OSVersion = strings.Trim(strings.Join([]string{firstStr(osv["major"]), firstStr(osv["minor"]), firstStr(osv["patch"])}, "."), ".")
	}
	id.OSBuild = firstStr(osv["build"])
	id.Platform = platformFamily(firstStr(osv["platform"]), id.OSName)
	id.Model = firstStr(sys["hardware_model"])
	id.Vendor = firstStr(sys["hardware_vendor"], plat["vendor"])
	id.CPUBrand = firstStr(sys["cpu_brand"])
	id.CPUType = firstStr(sys["cpu_type"])
	id.CPUPhysical = atoi(firstStr(sys["cpu_physical_cores"]))
	id.CPULogical = atoi(firstStr(sys["cpu_logical_cores"]))
	id.Memory = atoi64(firstStr(sys["physical_memory"]))
	id.OsqueryVersion = firstStr(info["version"])
	return id
}

// EnrollHost checks the enroll secret and returns a node key. A host that presents
// the same hardware UUID or serial keeps its device id.
func (s *Store) EnrollHost(ctx context.Context, secret, hostIdentifier string, details map[string]any) (string, string, error) {
	ok, err := s.enrollSecretOK(ctx, secret)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", ErrEnrollRejected
	}
	id := identityFrom(hostIdentifier, details)
	var deviceID, nodeKey string
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		deviceID, nodeKey, last = s.enrollOnce(ctx, id)
		if last == nil || !isConflict(last) {
			return deviceID, nodeKey, last
		}
	}
	return "", "", last
}

func isConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

func (s *Store) enrollOnce(ctx context.Context, id hostIdentity) (string, string, error) {
	raw, hash, err := newNodeKey()
	if err != nil {
		return "", "", err
	}
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var deviceID string
	found := false
	if id.UUID != "" {
		err = tx.QueryRow(ctx, `SELECT id FROM devices WHERE hardware_uuid=$1 FOR UPDATE`, id.UUID).Scan(&deviceID)
		if err == nil {
			found = true
		} else if !isNoRows(err) {
			return "", "", err
		}
	}
	if !found && id.Serial != "" {
		err = tx.QueryRow(ctx, `SELECT id FROM devices WHERE serial=$1 FOR UPDATE`, id.Serial).Scan(&deviceID)
		if err == nil {
			found = true
		} else if !isNoRows(err) {
			return "", "", err
		}
	}

	action := "enrolled"
	if found {
		action = "reenrolled"
		uuid, serial := id.UUID, id.Serial
		if uuid != "" {
			var other string
			err = tx.QueryRow(ctx, `SELECT id FROM devices WHERE hardware_uuid=$1 AND id<>$2`, uuid, deviceID).Scan(&other)
			if err == nil {
				uuid = ""
			} else if !isNoRows(err) {
				return "", "", err
			}
		}
		if serial != "" {
			var other string
			err = tx.QueryRow(ctx, `SELECT id FROM devices WHERE serial=$1 AND id<>$2`, serial, deviceID).Scan(&other)
			if err == nil {
				serial = ""
			} else if !isNoRows(err) {
				return "", "", err
			}
		}
		_, err = tx.Exec(ctx, `
			UPDATE devices SET
				node_key_hash=$2, node_invalid=false, host_identifier=$3,
				hardware_uuid=CASE WHEN $4 <> '' THEN $4 ELSE hardware_uuid END,
				serial=CASE WHEN $5 <> '' THEN $5 ELSE serial END,
				hostname=CASE WHEN $6 <> '' THEN $6 ELSE hostname END,
				computer_name=CASE WHEN $7 <> '' THEN $7 ELSE computer_name END,
				platform=CASE WHEN $8 <> '' THEN $8 ELSE platform END,
				os_name=CASE WHEN $9 <> '' THEN $9 ELSE os_name END,
				os_version=CASE WHEN $10 <> '' THEN $10 ELSE os_version END,
				os_build=CASE WHEN $11 <> '' THEN $11 ELSE os_build END,
				hardware_model=CASE WHEN $12 <> '' THEN $12 ELSE hardware_model END,
				hardware_vendor=CASE WHEN $13 <> '' THEN $13 ELSE hardware_vendor END,
				cpu_brand=CASE WHEN $14 <> '' THEN $14 ELSE cpu_brand END,
				cpu_type=CASE WHEN $15 <> '' THEN $15 ELSE cpu_type END,
				cpu_physical_cores=CASE WHEN $16 > 0 THEN $16 ELSE cpu_physical_cores END,
				cpu_logical_cores=CASE WHEN $17 > 0 THEN $17 ELSE cpu_logical_cores END,
				physical_memory=CASE WHEN $18 > 0 THEN $18 ELSE physical_memory END,
				osquery_version=CASE WHEN $19 <> '' THEN $19 ELSE osquery_version END,
				last_enrolled_at=$20, last_seen_at=$20, updated_at=$20
			WHERE id=$1`,
			deviceID, hash, id.HostIdentifier, uuid, serial, id.Hostname, id.ComputerName, id.Platform,
			id.OSName, id.OSVersion, id.OSBuild, id.Model, id.Vendor, id.CPUBrand, id.CPUType,
			id.CPUPhysical, id.CPULogical, id.Memory, id.OsqueryVersion, now)
		if err != nil {
			return "", "", mapWriteErr(err)
		}
	} else {
		deviceID = newID()
		_, err = tx.Exec(ctx, `
			INSERT INTO devices (
				id, node_key_hash, node_invalid, host_identifier, hardware_uuid, serial, hostname, computer_name,
				platform, os_name, os_version, os_build, hardware_model, hardware_vendor, cpu_brand, cpu_type,
				cpu_physical_cores, cpu_logical_cores, physical_memory, osquery_version,
				enrolled_at, last_enrolled_at, last_seen_at, created_at, updated_at)
			VALUES ($1,$2,false,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$20,$20,$20,$20)`,
			deviceID, hash, id.HostIdentifier, id.UUID, id.Serial, id.Hostname, id.ComputerName, id.Platform,
			id.OSName, id.OSVersion, id.OSBuild, id.Model, id.Vendor, id.CPUBrand, id.CPUType,
			id.CPUPhysical, id.CPULogical, id.Memory, id.OsqueryVersion, now)
		if err != nil {
			return "", "", mapWriteErr(err)
		}
	}
	serial := id.Serial
	if err := tx.QueryRow(ctx, `SELECT serial FROM devices WHERE id=$1`, deviceID).Scan(&serial); err != nil {
		return "", "", err
	}
	if err := s.syncDeviceManualLabels(ctx, tx, deviceID, serial); err != nil {
		return "", "", err
	}
	if err := s.audit(ctx, tx, osqueryActor(), action, "device", deviceID, map[string]any{
		"hostname": id.Hostname, "serial": serial, "hardware_uuid": id.UUID, "os_version": id.OSVersion,
	}); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return deviceID, raw, nil
}

func isNoRows(err error) bool {
	return err != nil && (err == pgx.ErrNoRows || strings.Contains(err.Error(), "no rows"))
}

func (s *Store) loadByNodeKey(ctx context.Context, tx pgx.Tx, nodeKey string) (storedDevice, bool, error) {
	if strings.TrimSpace(nodeKey) == "" {
		return storedDevice{}, false, nil
	}
	d, err := scanStoredDevice(tx.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE node_key_hash=$1 FOR UPDATE`, auth.Hash(nodeKey)))
	if isNoRows(err) {
		return storedDevice{}, false, nil
	}
	if err != nil {
		return storedDevice{}, false, err
	}
	if d.NodeInvalid {
		return d, false, nil
	}
	return d, true, nil
}

func (s *Store) touch(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE devices SET last_seen_at=$2, updated_at=$2 WHERE id=$1`, id, s.now())
	return err
}

// OsqueryConfig builds the TLS config for a node. Invalid node keys report invalid=true.
func (s *Store) OsqueryConfig(ctx context.Context, nodeKey string, interval time.Duration) (map[string]any, bool, error) {
	if interval < time.Second {
		interval = 5 * time.Minute
	}
	sec := int(interval.Seconds())
	if sec < 1 {
		sec = 1
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	dev, ok, err := s.loadByNodeKey(ctx, tx, nodeKey)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, true, nil
	}
	if err := s.touch(ctx, tx, dev.ID); err != nil {
		return nil, false, err
	}
	members, err := s.memberNames(ctx, tx, dev.ID)
	if err != nil {
		return nil, false, err
	}
	schedule := map[string]any{}
	for _, q := range osquery.InventoryQueries() {
		schedule[q.Name] = scheduleEntry(q.SQL, sec, q.Platform, true, false)
	}
	labels, err := s.listLabelsTx(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	for _, l := range labels {
		if l.Kind != "dynamic" {
			continue
		}
		schedule[osquery.LabelQueryName(l.Name)] = scheduleEntry(l.SQL, sec, l.Platform, true, false)
	}
	queries, err := s.listQueriesTx(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	byID := map[string]model.OsqueryQuery{}
	for _, q := range queries {
		byID[q.ID] = q
		if q.Scheduled {
			schedule[q.Name] = scheduleEntry(q.SQL, q.Interval, q.Platform, q.Snapshot, q.Removed)
		}
	}
	packs, err := s.listPacksTx(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	packDoc := map[string]any{}
	for _, pack := range packs {
		if !pack.Enabled || !packVisible(pack.Labels, members) {
			continue
		}
		qs := map[string]any{}
		for _, ref := range pack.Queries {
			q, ok := byID[ref.ID]
			if !ok {
				continue
			}
			interval := q.Interval
			if pack.Interval != nil {
				interval = *pack.Interval
			}
			qs[q.Name] = scheduleEntry(q.SQL, interval, q.Platform, q.Snapshot, q.Removed)
		}
		body := map[string]any{"queries": qs}
		if pack.Platform != "" {
			body["platform"] = pack.Platform
		}
		if pack.Shard != nil {
			body["shard"] = *pack.Shard
		}
		if len(pack.Discovery) > 0 {
			body["discovery"] = pack.Discovery
		}
		packDoc[pack.Name] = body
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	cfg := map[string]any{
		"node_invalid": false,
		"schedule":     schedule,
		"packs":        packDoc,
		"options": map[string]any{
			"logger_tls_period":    10,
			"distributed_interval": 10,
			"config_refresh":       30,
		},
	}
	return cfg, false, nil
}

func scheduleEntry(sql string, interval int, platform string, snapshot, removed bool) map[string]any {
	if interval < 1 {
		interval = 1
	}
	entry := map[string]any{
		"query":    sql,
		"interval": interval,
		"snapshot": snapshot,
		"removed":  removed,
	}
	if platform != "" {
		entry["platform"] = platform
	}
	return entry
}

func packVisible(packLabels, members []string) bool {
	if len(packLabels) == 0 {
		return true
	}
	set := map[string]bool{}
	for _, m := range members {
		set[m] = true
	}
	for _, l := range packLabels {
		if set[l] {
			return true
		}
	}
	return false
}

func (s *Store) memberNames(ctx context.Context, tx pgx.Tx, deviceID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT l.name FROM osquery_label_members m
		JOIN osquery_labels l ON l.id = m.label_id
		WHERE m.device_id=$1 ORDER BY l.name`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (s *Store) listLabelsTx(ctx context.Context, tx pgx.Tx) ([]model.OsqueryLabel, error) {
	rows, err := tx.Query(ctx, `SELECT `+labelCols+` FROM osquery_labels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.OsqueryLabel{}
	for rows.Next() {
		l, err := scanLabel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) listQueriesTx(ctx context.Context, tx pgx.Tx) ([]model.OsqueryQuery, error) {
	rows, err := tx.Query(ctx, `SELECT `+queryCols+` FROM osquery_queries ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.OsqueryQuery{}
	for rows.Next() {
		q, err := scanQuery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

func (s *Store) listPacksTx(ctx context.Context, tx pgx.Tx) ([]model.OsqueryPack, error) {
	rows, err := tx.Query(ctx, `SELECT `+packCols+` FROM osquery_packs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.OsqueryPack{}
	for rows.Next() {
		p, err := scanPack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		qrows, err := tx.Query(ctx, `
			SELECT q.id, q.name, q.interval_seconds, q.platform, q.snapshot
			FROM osquery_pack_queries pq JOIN osquery_queries q ON q.id = pq.query_id
			WHERE pq.pack_id=$1 ORDER BY pq.position`, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].QueryIDs = []string{}
		out[i].Queries = []model.OsqueryPackQuery{}
		for qrows.Next() {
			var q model.OsqueryPackQuery
			if err := qrows.Scan(&q.ID, &q.Name, &q.Interval, &q.Platform, &q.Snapshot); err != nil {
				qrows.Close()
				return nil, err
			}
			out[i].QueryIDs = append(out[i].QueryIDs, q.ID)
			out[i].Queries = append(out[i].Queries, q)
		}
		if err := qrows.Err(); err != nil {
			qrows.Close()
			return nil, err
		}
		qrows.Close()
	}
	return out, nil
}

// IngestLogs stores status or result logs and updates inventory. events are safe to forward after commit.
func (s *Store) IngestLogs(ctx context.Context, nodeKey, logType string, data json.RawMessage) ([]osquery.ResultEvent, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	dev, ok, err := s.loadByNodeKey(ctx, tx, nodeKey)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, true, nil
	}
	if err := s.touch(ctx, tx, dev.ID); err != nil {
		return nil, false, err
	}
	now := s.now()
	var events []osquery.ResultEvent
	switch logType {
	case "status":
		rows, err := parseStatusLogs(data)
		if err != nil {
			return nil, false, invalid("invalid status log")
		}
		if err := insertStatusLogs(ctx, tx, dev.ID, rows, now); err != nil {
			return nil, false, err
		}
	case "result":
		parsed, err := parseResultLogs(data)
		if err != nil {
			return nil, false, invalid("invalid result log")
		}
		events, err = s.applyResults(ctx, tx, &dev, parsed, now)
		if err != nil {
			return nil, false, err
		}
	default:
		return nil, false, invalid("log_type must be status or result")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return events, false, nil
}

func (s *Store) applyResults(ctx context.Context, tx pgx.Tx, dev *storedDevice, items []parsedResult, now time.Time) ([]osquery.ResultEvent, error) {
	groups := map[string][]parsedResult{}
	order := []string{}
	var logRows []resultInsert
	var events []osquery.ResultEvent
	for _, it := range items {
		if _, ok := groups[it.Name]; !ok {
			order = append(order, it.Name)
		}
		groups[it.Name] = append(groups[it.Name], it)
		if it.Snapshot {
			for _, row := range it.Rows {
				logRows = append(logRows, resultInsert{Query: it.Name, Action: "snapshot", Columns: row, Unix: it.Unix})
			}
			continue
		}
		logRows = append(logRows, resultInsert{Query: it.Name, Action: it.Action, Columns: it.Columns, Unix: it.Unix})
	}
	if err := insertResultLogs(ctx, tx, dev.ID, logRows, now); err != nil {
		return nil, err
	}
	for _, row := range logRows {
		cols := row.Columns
		if cols == nil {
			cols = map[string]string{}
		}
		events = append(events, osquery.ResultEvent{
			DeviceID: dev.ID, Hostname: dev.Hostname, QueryName: row.Query, Action: row.Action,
			Columns: cols, UnixTime: row.Unix, ReceivedAt: now,
		})
	}
	for _, name := range order {
		prev, err := loadQueryRows(ctx, tx, dev.ID, name)
		if err != nil {
			return nil, err
		}
		rows := prev
		for _, it := range groups[name] {
			if it.Snapshot {
				rows = it.Rows
				continue
			}
			if it.Action == "removed" {
				rows = removeColumnRow(rows, it.Columns)
			} else {
				rows = append(rows, it.Columns)
			}
		}
		if rows == nil {
			rows = []map[string]string{}
		}
		if err := saveQueryRows(ctx, tx, dev.ID, name, rows, now); err != nil {
			return nil, err
		}
		if err := s.interpretQuery(ctx, tx, dev, name, rows); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (s *Store) interpretQuery(ctx context.Context, tx pgx.Tx, dev *storedDevice, name string, rows []map[string]string) error {
	if label, ok := osquery.LabelFromQuery(name); ok {
		return s.setDynamicMembership(ctx, tx, label, dev.ID, len(rows) > 0)
	}
	if !osquery.IsInventory(name) {
		return nil
	}
	return s.applyInventory(ctx, tx, dev, name, rows)
}

// DistributedRead returns pending live queries for the node.
func (s *Store) DistributedRead(ctx context.Context, nodeKey string) (map[string]string, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.expireLiveQueriesTx(ctx, tx); err != nil {
		return nil, false, err
	}
	dev, ok, err := s.loadByNodeKey(ctx, tx, nodeKey)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, true, nil
	}
	if err := s.touch(ctx, tx, dev.ID); err != nil {
		return nil, false, err
	}
	rows, err := tx.Query(ctx, `
		SELECT q.id, q.sql FROM live_query_targets t
		JOIN live_queries q ON q.id = t.live_query_id
		WHERE t.device_id=$1 AND t.status IN ('pending','sent')
		ORDER BY q.created_at`, dev.ID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := map[string]string{}
	ids := []string{}
	for rows.Next() {
		var id, sql string
		if err := rows.Scan(&id, &sql); err != nil {
			return nil, false, err
		}
		out[id] = sql
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE live_query_targets SET status='sent', sent_at=COALESCE(sent_at, $3)
			WHERE device_id=$1 AND live_query_id = ANY($2) AND status IN ('pending','sent')`,
			dev.ID, ids, s.now()); err != nil {
			return nil, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return out, false, nil
}

// DistributedWrite records live query results from a node.
func (s *Store) DistributedWrite(ctx context.Context, nodeKey string, results map[string][]map[string]string, statuses map[string]int, messages map[string]string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	dev, ok, err := s.loadByNodeKey(ctx, tx, nodeKey)
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}
	if err := s.touch(ctx, tx, dev.ID); err != nil {
		return false, err
	}
	now := s.now()
	seen := map[string]bool{}
	for id := range results {
		seen[id] = true
	}
	for id := range statuses {
		seen[id] = true
	}
	for id := range seen {
		rows := results[id]
		if rows == nil {
			rows = []map[string]string{}
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			return false, err
		}
		code := statuses[id]
		status := "complete"
		msg := messages[id]
		if code != 0 {
			status = "error"
			if msg == "" {
				msg = "osquery status " + itoa(code)
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE live_query_targets
			SET status=$3, status_code=$4, error=$5, result_rows=$6::jsonb, completed_at=$7
			WHERE live_query_id=$1 AND device_id=$2 AND status IN ('pending','sent')`,
			id, dev.ID, status, code, msg, string(raw), now); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE live_queries SET status='complete', finished_at=$2
			WHERE id=$1 AND finished_at IS NULL
			  AND NOT EXISTS (
			    SELECT 1 FROM live_query_targets WHERE live_query_id=$1 AND status IN ('pending','sent')
			  )`, id, now); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return false, nil
}

// InvalidateNode marks the current node key invalid. The next request asks osquery to re-enroll.
func (s *Store) InvalidateNode(ctx context.Context, p model.Principal, id string) (model.Device, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Device{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE devices SET node_invalid=true, updated_at=$2 WHERE id=$1`, id, s.now())
	if err != nil {
		return model.Device{}, err
	}
	if tag.RowsAffected() == 0 {
		return model.Device{}, ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "invalidate_node", "device", id, map[string]any{}); err != nil {
		return model.Device{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Device{}, err
	}
	return s.GetDevice(ctx, id, time.Hour)
}
