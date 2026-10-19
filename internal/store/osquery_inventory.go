package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/osquery"
	"github.com/jackc/pgx/v5"
)

type resultInsert struct {
	Query   string
	Action  string
	Columns map[string]string
	Unix    int64
}

func insertResultLogs(ctx context.Context, tx pgx.Tx, deviceID string, rows []resultInsert, now time.Time) error {
	const chunk = 400
	for i := 0; i < len(rows); i += chunk {
		j := i + chunk
		if j > len(rows) {
			j = len(rows)
		}
		part := rows[i:j]
		names := make([]string, len(part))
		actions := make([]string, len(part))
		cols := make([]string, len(part))
		unixes := make([]int64, len(part))
		times := make([]time.Time, len(part))
		ids := make([]string, len(part))
		for k, row := range part {
			ids[k] = deviceID
			names[k] = row.Query
			actions[k] = row.Action
			if row.Columns == nil {
				row.Columns = map[string]string{}
			}
			b, err := json.Marshal(row.Columns)
			if err != nil {
				return err
			}
			cols[k] = string(b)
			unixes[k] = row.Unix
			times[k] = now
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO osquery_result_logs (device_id, query_name, action, columns, unix_time, received_at)
			SELECT device_id, query_name, action, columns::jsonb, unix_time, received_at
			FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[], $6::timestamptz[])
			AS t(device_id, query_name, action, columns, unix_time, received_at)`,
			ids, names, actions, cols, unixes, times); err != nil {
			return err
		}
	}
	return nil
}

func insertStatusLogs(ctx context.Context, tx pgx.Tx, deviceID string, rows []parsedStatus, now time.Time) error {
	const chunk = 400
	for i := 0; i < len(rows); i += chunk {
		j := i + chunk
		if j > len(rows) {
			j = len(rows)
		}
		part := rows[i:j]
		ids := make([]string, len(part))
		sev := make([]string, len(part))
		file := make([]string, len(part))
		line := make([]int32, len(part))
		msg := make([]string, len(part))
		ver := make([]string, len(part))
		times := make([]time.Time, len(part))
		for k, row := range part {
			ids[k] = deviceID
			sev[k] = row.Severity
			file[k] = row.Filename
			line[k] = int32(row.Line)
			msg[k] = row.Message
			ver[k] = row.Version
			times[k] = now
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO osquery_status_logs (device_id, severity, filename, line, message, version, received_at)
			SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::int[], $5::text[], $6::text[], $7::timestamptz[])`,
			ids, sev, file, line, msg, ver, times); err != nil {
			return err
		}
	}
	return nil
}

type queryState struct {
	Rows    []map[string]string
	Counter int64
	Open    bool
}

// snapshotBatchLimit is the osquery logger_tls_max_lines default. A batch that
// fills it may be a partial event-mode snapshot continued in the next POST.
var snapshotBatchLimit = 1024

type interpretStep struct {
	rows      []map[string]string
	widenApps bool
}

func loadQueryState(ctx context.Context, tx pgx.Tx, deviceID, name string) (queryState, error) {
	var raw []byte
	var counter int64
	var open bool
	err := tx.QueryRow(ctx, `SELECT result_rows, snapshot_counter, snapshot_open FROM device_query_results WHERE device_id=$1 AND query_name=$2`, deviceID, name).Scan(&raw, &counter, &open)
	if isNoRows(err) {
		return queryState{Rows: []map[string]string{}}, nil
	}
	if err != nil {
		return queryState{}, err
	}
	rows, err := rowsFromJSON(raw)
	if err != nil {
		return queryState{}, err
	}
	return queryState{Rows: rows, Counter: counter, Open: open}, nil
}

func saveQueryState(ctx context.Context, tx pgx.Tx, deviceID, name string, state queryState, now time.Time) error {
	if state.Rows == nil {
		state.Rows = []map[string]string{}
	}
	b, err := json.Marshal(state.Rows)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO device_query_results (device_id, query_name, result_rows, snapshot_counter, snapshot_open, updated_at)
		VALUES ($1,$2,$3::jsonb,$4,$5,$6)
		ON CONFLICT (device_id, query_name) DO UPDATE SET
			result_rows=EXCLUDED.result_rows,
			snapshot_counter=EXCLUDED.snapshot_counter,
			snapshot_open=EXCLUDED.snapshot_open,
			updated_at=EXCLUDED.updated_at`,
		deviceID, name, string(b), state.Counter, state.Open, now)
	return err
}

// reduceQueryResults folds one query's logs into the stored generation.
// A single snapshot object replaces the previous rows. Several snapshot
// objects that share a counter are one event-mode generation: under the line
// limit they are complete, and at the limit they stay open so a later POST
// can finish the set. An empty mc_apps snapshot is ignored so a failed or
// partial inventory does not emit app_removed.
func reduceQueryResults(name string, prev queryState, items []parsedResult) (queryState, []interpretStep) {
	state := prev
	if state.Rows == nil {
		state.Rows = []map[string]string{}
	}
	var steps []interpretStep
	changed := false
	for i := 0; i < len(items); {
		if !items[i].Snapshot {
			if items[i].Action == "removed" {
				state.Rows = removeColumnRow(state.Rows, items[i].Columns)
			} else {
				state.Rows = append(state.Rows, items[i].Columns)
			}
			state.Open = false
			changed = true
			i++
			continue
		}
		if changed {
			steps = append(steps, interpretStep{rows: cloneRows(state.Rows)})
			changed = false
		}
		j := i + 1
		for j < len(items) && items[j].Snapshot {
			j++
		}
		var more []interpretStep
		state, more = applySnapshotGroup(name, state, items[i:j])
		steps = append(steps, more...)
		i = j
	}
	if changed {
		steps = append(steps, interpretStep{rows: cloneRows(state.Rows)})
	}
	if state.Rows == nil {
		state.Rows = []map[string]string{}
	}
	return state, steps
}

func applySnapshotGroup(name string, state queryState, snaps []parsedResult) (queryState, []interpretStep) {
	var steps []interpretStep
	for _, group := range groupSnapsByCounter(snaps) {
		var more []interpretStep
		state, more = applyOneCounter(name, state, group)
		steps = append(steps, more...)
	}
	return state, steps
}

func groupSnapsByCounter(snaps []parsedResult) [][]parsedResult {
	var out [][]parsedResult
	for _, snap := range snaps {
		if len(out) == 0 || out[len(out)-1][0].Counter != snap.Counter {
			out = append(out, []parsedResult{snap})
			continue
		}
		out[len(out)-1] = append(out[len(out)-1], snap)
	}
	return out
}

func applyOneCounter(name string, state queryState, snaps []parsedResult) (queryState, []interpretStep) {
	batch := concatSnapRows(snaps)
	if name == osquery.QApps && snapRowsEmpty(snaps) {
		return state, nil
	}
	counter := snaps[0].Counter
	continuation := state.Open && state.Counter == counter
	if continuation {
		acc := joinRows(state.Rows, batch)
		if len(snaps) >= snapshotBatchLimit {
			return queryState{Rows: acc, Counter: counter, Open: true}, []interpretStep{{rows: cloneRows(acc), widenApps: true}}
		}
		return queryState{Rows: acc, Counter: counter, Open: false}, []interpretStep{{rows: cloneRows(acc)}}
	}
	var steps []interpretStep
	if state.Open {
		steps = append(steps, interpretStep{rows: cloneRows(state.Rows)})
	}
	if len(snaps) >= snapshotBatchLimit {
		steps = append(steps, interpretStep{rows: cloneRows(batch), widenApps: true})
		return queryState{Rows: cloneRows(batch), Counter: counter, Open: true}, steps
	}
	steps = append(steps, interpretStep{rows: cloneRows(batch)})
	return queryState{Rows: cloneRows(batch), Counter: counter, Open: false}, steps
}

func snapRowsEmpty(snaps []parsedResult) bool {
	for _, snap := range snaps {
		if len(snap.Rows) > 0 {
			return false
		}
	}
	return true
}

func concatSnapRows(snaps []parsedResult) []map[string]string {
	rows := []map[string]string{}
	for _, snap := range snaps {
		rows = append(rows, snap.Rows...)
	}
	return rows
}

func joinRows(a, b []map[string]string) []map[string]string {
	out := make([]map[string]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func cloneRows(rows []map[string]string) []map[string]string {
	if len(rows) == 0 {
		return []map[string]string{}
	}
	out := make([]map[string]string, len(rows))
	copy(out, rows)
	return out
}

func appsToRows(apps []model.DeviceApp) []map[string]string {
	rows := make([]map[string]string, len(apps))
	for i, app := range apps {
		rows[i] = map[string]string{
			"name": app.Name, "path": app.Path,
			"bundle_identifier": app.BundleID, "bundle_short_version": app.Version,
		}
	}
	return rows
}

func unionAppRows(base, extra []map[string]string) []map[string]string {
	return joinRows(base, extra)
}

func removeColumnRow(rows []map[string]string, target map[string]string) []map[string]string {
	for i, row := range rows {
		if columnsEqual(row, target) {
			return append(rows[:i], rows[i+1:]...)
		}
	}
	return rows
}

func columnsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (s *Store) setDynamicMembership(ctx context.Context, tx pgx.Tx, labelName, deviceID string, member bool) error {
	var labelID string
	err := tx.QueryRow(ctx, `SELECT id FROM osquery_labels WHERE name=$1 AND kind='dynamic'`, labelName).Scan(&labelID)
	if isNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if member {
		_, err = tx.Exec(ctx, `
			INSERT INTO osquery_label_members (label_id, device_id, source, updated_at)
			VALUES ($1,$2,'sql',$3)
			ON CONFLICT (label_id, device_id, source) DO UPDATE SET updated_at=EXCLUDED.updated_at`,
			labelID, deviceID, s.now())
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM osquery_label_members WHERE label_id=$1 AND device_id=$2 AND source='sql'`, labelID, deviceID)
	return err
}

func (s *Store) applyInventory(ctx context.Context, tx pgx.Tx, dev *storedDevice, name string, rows []map[string]string) error {
	var changes []map[string]any
	switch name {
	case osquery.QSystemInfo:
		if len(rows) == 0 {
			return nil
		}
		row := rows[0]
		noteStr(&dev.Hostname, firstStr(row["hostname"], row["local_hostname"]), "hostname_changed", &changes)
		setStr(&dev.ComputerName, firstStr(row["computer_name"]))
		setStr(&dev.HardwareModel, firstStr(row["hardware_model"]))
		setStr(&dev.HardwareVendor, firstStr(row["hardware_vendor"]))
		setStr(&dev.CPUBrand, firstStr(row["cpu_brand"]))
		setStr(&dev.CPUType, firstStr(row["cpu_type"]))
		if n := atoi(firstStr(row["cpu_physical_cores"])); n > 0 {
			dev.CPUPhysicalCores = n
		}
		if n := atoi(firstStr(row["cpu_logical_cores"])); n > 0 {
			dev.CPULogicalCores = n
		}
		if n := atoi64(firstStr(row["physical_memory"])); n > 0 {
			dev.PhysicalMemory = n
		}
		if dev.HardwareUUID == "" {
			setStr(&dev.HardwareUUID, usableHardwareID(firstStr(row["uuid"])))
		}
		if dev.Serial == "" {
			setStr(&dev.Serial, usableHardwareID(firstStr(row["hardware_serial"])))
		}
	case osquery.QOSVersion:
		if len(rows) == 0 {
			return nil
		}
		row := rows[0]
		setStr(&dev.OSName, firstStr(row["name"]))
		prev := dev.OSVersion
		next := firstStr(row["version"])
		if next == "" {
			next = strings.Trim(strings.Join([]string{firstStr(row["major"]), firstStr(row["minor"]), firstStr(row["patch"])}, "."), ".")
		}
		if next != "" && next != prev {
			if prev != "" {
				changes = append(changes, map[string]any{"action": "os_version_changed", "from": prev, "to": next, "build": firstStr(row["build"])})
			}
			dev.OSVersion = next
		}
		setStr(&dev.OSBuild, firstStr(row["build"]))
		if p := platformFamily(firstStr(row["platform"]), dev.OSName); p != "" {
			dev.Platform = p
		}
	case osquery.QOsqueryInfo:
		if len(rows) > 0 {
			setStr(&dev.OsqueryVersion, firstStr(rows[0]["version"]))
		}
	case osquery.QInterfaceAddresses:
		if ip := pickIP(rows); ip != "" {
			dev.PrimaryIP = ip
		}
	case osquery.QInterfaceDetails:
		if mac := pickMAC(rows); mac != "" {
			dev.PrimaryMAC = mac
		}
	case osquery.QLoggedInUsers:
		if user := pickUser(rows); user != "" && user != dev.Username {
			if dev.Username != "" {
				changes = append(changes, map[string]any{"action": "user_changed", "from": dev.Username, "to": user})
			}
			dev.Username = user
		}
	case osquery.QUptime:
		if len(rows) > 0 {
			if n := atoi64(firstStr(rows[0]["total_seconds"])); n > 0 {
				dev.UptimeSeconds = n
			}
		}
	case osquery.QDiskEncryption:
		enc, known := encryptionFrom(rows)
		if known && (dev.DiskEncrypted == nil || *dev.DiskEncrypted != enc) {
			if dev.DiskEncrypted != nil {
				changes = append(changes, map[string]any{"action": "disk_encryption_changed", "from": *dev.DiskEncrypted, "to": enc})
			}
			dev.DiskEncrypted = &enc
		}
	case osquery.QApps:
		next := normalizeApps(rows)
		if !dev.appsInitialized {
			if err := saveApps(ctx, tx, dev.ID, next); err != nil {
				return err
			}
			dev.appsInitialized = true
		} else {
			prev, err := loadApps(ctx, tx, dev.ID)
			if err != nil {
				return err
			}
			next = retainVersions(prev, next)
			changes = append(changes, diffApps(prev, next)...)
			if err := saveApps(ctx, tx, dev.ID, next); err != nil {
				return err
			}
		}
	}
	if err := s.saveDeviceInventory(ctx, tx, dev); err != nil {
		return err
	}
	for _, ch := range changes {
		action, _ := ch["action"].(string)
		if action == "" {
			continue
		}
		delete(ch, "action")
		if err := s.audit(ctx, tx, osqueryActor(), action, "device", dev.ID, ch); err != nil {
			return err
		}
	}
	return nil
}

func noteStr(cur *string, next, action string, changes *[]map[string]any) {
	next = strings.TrimSpace(next)
	if next == "" || next == *cur {
		return
	}
	if *cur != "" {
		*changes = append(*changes, map[string]any{"action": action, "from": *cur, "to": next})
	}
	*cur = next
}

func setStr(cur *string, next string) {
	next = strings.TrimSpace(next)
	if next == "" {
		return
	}
	*cur = next
}

func pickIP(rows []map[string]string) string {
	var v6 string
	for _, row := range rows {
		addr := strings.TrimSpace(row["address"])
		if addr == "" || addr == "127.0.0.1" || addr == "::1" || addr == "0.0.0.0" || strings.HasPrefix(addr, "fe80:") || strings.HasPrefix(addr, "169.254.") {
			continue
		}
		if strings.Contains(addr, ":") {
			if v6 == "" {
				v6 = addr
			}
			continue
		}
		return addr
	}
	return v6
}

func pickMAC(rows []map[string]string) string {
	for _, row := range rows {
		mac := strings.TrimSpace(row["mac"])
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		return mac
	}
	return ""
}

func pickUser(rows []map[string]string) string {
	var fallback string
	for _, row := range rows {
		user := firstStr(row["user"], row["username"])
		if user == "" || user == "root" {
			continue
		}
		kind := strings.ToLower(row["type"])
		if kind == "user" || kind == "console" || kind == "" {
			return user
		}
		if fallback == "" {
			fallback = user
		}
	}
	return fallback
}

func encryptionFrom(rows []map[string]string) (bool, bool) {
	if len(rows) == 0 {
		return false, false
	}
	for _, row := range rows {
		if truthy(firstStr(row["encrypted"], row["enabled"])) {
			return true, true
		}
	}
	return false, true
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "t", "yes", "on":
		return true
	default:
		return false
	}
}

func normalizeApps(rows []map[string]string) []model.DeviceApp {
	seen := map[string]int{}
	out := []model.DeviceApp{}
	for _, row := range rows {
		app := model.DeviceApp{
			Name:          firstStr(row["name"], row["bundle_name"]),
			Path:          firstStr(row["path"]),
			BundleID:      firstStr(row["bundle_identifier"], row["bundle_id"]),
			BundleVersion: firstStr(row["bundle_version"]),
			Version:       firstStr(row["bundle_short_version"], row["version"]),
		}
		if app.Version == "" {
			app.Version = app.BundleVersion
		}
		if app.Path == "" {
			app.Path = app.BundleID
		}
		if app.Path == "" {
			continue
		}
		if app.Name == "" {
			app.Name = app.Path
		}
		if i, ok := seen[app.Path]; ok {
			if app.Version == "" {
				app.Version = out[i].Version
			}
			if app.BundleVersion == "" {
				app.BundleVersion = out[i].BundleVersion
			}
			if app.Name == "" {
				app.Name = out[i].Name
			}
			out[i] = app
			continue
		}
		seen[app.Path] = len(out)
		out = append(out, app)
	}
	return out
}

func diffApps(prev, next []model.DeviceApp) []map[string]any {
	old := map[string]model.DeviceApp{}
	for _, a := range prev {
		old[a.Path] = a
	}
	newSet := map[string]model.DeviceApp{}
	var changes []map[string]any
	for _, a := range next {
		newSet[a.Path] = a
		if was, ok := old[a.Path]; !ok {
			changes = append(changes, map[string]any{"action": "app_installed", "name": a.Name, "path": a.Path, "version": a.Version, "bundle_id": a.BundleID})
		} else if a.Version != "" && was.Version != a.Version {
			changes = append(changes, map[string]any{"action": "app_updated", "name": a.Name, "path": a.Path, "from": was.Version, "to": a.Version, "bundle_id": a.BundleID})
		}
	}
	for _, a := range prev {
		if _, ok := newSet[a.Path]; !ok {
			changes = append(changes, map[string]any{"action": "app_removed", "name": a.Name, "path": a.Path, "version": a.Version, "bundle_id": a.BundleID})
		}
	}
	return changes
}

func retainVersions(prev, next []model.DeviceApp) []model.DeviceApp {
	old := map[string]model.DeviceApp{}
	for _, app := range prev {
		old[app.Path] = app
	}
	for i, app := range next {
		if app.Version == "" {
			if was, ok := old[app.Path]; ok && was.Version != "" {
				next[i].Version = was.Version
			}
		}
		if app.BundleVersion == "" {
			if was, ok := old[app.Path]; ok && was.BundleVersion != "" {
				next[i].BundleVersion = was.BundleVersion
			}
		}
	}
	return next
}

func loadApps(ctx context.Context, tx pgx.Tx, deviceID string) ([]model.DeviceApp, error) {
	rows, err := tx.Query(ctx, `SELECT name, path, bundle_id, version, bundle_version FROM device_apps WHERE device_id=$1 ORDER BY path`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.DeviceApp{}
	for rows.Next() {
		var a model.DeviceApp
		if err := rows.Scan(&a.Name, &a.Path, &a.BundleID, &a.Version, &a.BundleVersion); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func saveApps(ctx context.Context, tx pgx.Tx, deviceID string, apps []model.DeviceApp) error {
	if _, err := tx.Exec(ctx, `DELETE FROM device_apps WHERE device_id=$1`, deviceID); err != nil {
		return err
	}
	if len(apps) == 0 {
		return nil
	}
	names := make([]string, len(apps))
	paths := make([]string, len(apps))
	bundles := make([]string, len(apps))
	versions := make([]string, len(apps))
	bundleVersions := make([]string, len(apps))
	ids := make([]string, len(apps))
	for i, a := range apps {
		ids[i] = deviceID
		names[i] = a.Name
		paths[i] = a.Path
		bundles[i] = a.BundleID
		versions[i] = a.Version
		bundleVersions[i] = a.BundleVersion
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, path, bundle_id, version, bundle_version)
		SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])`,
		ids, names, paths, bundles, versions, bundleVersions)
	return err
}

func (s *Store) saveDeviceInventory(ctx context.Context, tx pgx.Tx, dev *storedDevice) error {
	_, err := tx.Exec(ctx, `
		UPDATE devices SET
			hostname=$2, computer_name=$3, platform=$4, os_name=$5, os_version=$6, os_build=$7,
			hardware_model=$8, hardware_vendor=$9, cpu_brand=$10, cpu_type=$11,
			cpu_physical_cores=$12, cpu_logical_cores=$13, physical_memory=$14,
			primary_ip=$15, primary_mac=$16, username=$17, disk_encrypted=$18,
			uptime_seconds=$19, osquery_version=$20, apps_initialized=$21,
			hardware_uuid=CASE WHEN $22 <> '' THEN $22 ELSE hardware_uuid END,
			serial=CASE WHEN $23 <> '' THEN $23 ELSE serial END,
			updated_at=$24
		WHERE id=$1`,
		dev.ID, dev.Hostname, dev.ComputerName, dev.Platform, dev.OSName, dev.OSVersion, dev.OSBuild,
		dev.HardwareModel, dev.HardwareVendor, dev.CPUBrand, dev.CPUType, dev.CPUPhysicalCores, dev.CPULogicalCores,
		dev.PhysicalMemory, dev.PrimaryIP, dev.PrimaryMAC, dev.Username, dev.DiskEncrypted, dev.UptimeSeconds,
		dev.OsqueryVersion, dev.appsInitialized, dev.HardwareUUID, dev.Serial, s.now())
	return mapWriteErr(err)
}

// PurgeOsqueryLogs deletes result and status rows older than keep, measured
// from the server clock. keep <= 0 leaves the tables alone.
func (s *Store) PurgeOsqueryLogs(ctx context.Context, keep time.Duration) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}
	cutoff := s.now().Add(-keep)
	tag, err := s.pool.Exec(ctx, `DELETE FROM osquery_result_logs WHERE received_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	tag2, err := s.pool.Exec(ctx, `DELETE FROM osquery_status_logs WHERE received_at < $1`, cutoff)
	if err != nil {
		return tag.RowsAffected(), err
	}
	return tag.RowsAffected() + tag2.RowsAffected(), nil
}
