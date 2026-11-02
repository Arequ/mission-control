package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
)

func presentDevice(d *model.Device, offline time.Duration, now time.Time) {
	d.OSDisplay = osDisplay(d.Platform, d.OSName, d.OSVersion)
	d.ModelName = friendlyModel(d.HardwareModel)
	if d.Labels == nil {
		d.Labels = []string{}
	}
	d.Status = "offline"
	if d.LastSeenAt != nil && offline > 0 && !d.LastSeenAt.Before(now.Add(-offline)) {
		d.Status = "online"
	}
}

func osDisplay(platform, osName, version string) string {
	version = strings.TrimSpace(version)
	if platform == "darwin" {
		return strings.TrimSpace(strings.Join(strings.Fields("macOS "+version+" "+macMarketing(version)), " "))
	}
	if osName != "" && version != "" && !strings.Contains(osName, version) {
		return strings.TrimSpace(osName + " " + version)
	}
	if osName != "" {
		return osName
	}
	return version
}

func macMarketing(version string) string {
	major, _, _ := strings.Cut(version, ".")
	switch major {
	case "26":
		return "Tahoe"
	case "15":
		return "Sequoia"
	case "14":
		return "Sonoma"
	case "13":
		return "Ventura"
	case "12":
		return "Monterey"
	default:
		return ""
	}
}

func friendlyModel(modelID string) string {
	if name, ok := macModels[modelID]; ok {
		return name
	}
	return modelID
}

var macModels = map[string]string{
	"Mac16,1":        "MacBook Pro 14-inch",
	"Mac16,5":        "MacBook Pro 16-inch",
	"Mac16,6":        "MacBook Pro 14-inch",
	"Mac16,7":        "MacBook Pro 16-inch",
	"Mac16,8":        "MacBook Pro 14-inch",
	"Mac16,12":       "MacBook Air 13-inch",
	"Mac16,13":       "MacBook Air 15-inch",
	"Mac15,3":        "MacBook Air 15-inch",
	"Mac15,12":       "MacBook Air 13-inch",
	"Mac14,7":        "MacBook Pro 13-inch",
	"Mac14,10":       "MacBook Pro 16-inch",
	"Mac14,13":       "Mac Studio",
	"Mac14,14":       "Mac Studio",
	"Mac14,3":        "Mac mini",
	"Mac16,10":       "Mac mini",
	"Mac16,11":       "Mac mini",
	"MacBookPro16,2": "MacBook Pro 13-inch",
	"MacBookPro16,1": "MacBook Pro 16-inch",
}

func likePattern(q string) string {
	q = strings.ReplaceAll(q, `\`, `\\`)
	q = strings.ReplaceAll(q, `%`, `\%`)
	q = strings.ReplaceAll(q, `_`, `\_`)
	return "%" + q + "%"
}

// ListDevices returns a page of devices and the total matching the filter.
func (s *Store) ListDevices(ctx context.Context, f model.DeviceListFilter) ([]model.Device, int, error) {
	limit, offset := pageWindow(f.Limit, f.Offset)
	where, args := deviceWhere(f, s.now())
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	qargs := append(append([]any{}, args...), limit, offset)
	rows, err := s.pool.Query(ctx, `SELECT `+deviceCols+` FROM devices WHERE `+where+` ORDER BY last_seen_at DESC NULLS LAST, hostname LIMIT $`+itoa(len(args)+1)+` OFFSET $`+itoa(len(args)+2), qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.Device{}
	now := s.now()
	for rows.Next() {
		d, err := scanStoredDevice(rows)
		if err != nil {
			return nil, 0, err
		}
		presentDevice(&d.Device, f.OfflineAfter, now)
		out = append(out, d.Device)
	}
	return out, total, rows.Err()
}

func deviceWhere(f model.DeviceListFilter, now time.Time) (string, []any) {
	clauses := []string{"TRUE"}
	args := []any{}
	if q := strings.TrimSpace(f.Q); q != "" {
		args = append(args, likePattern(q))
		n := len(args)
		clauses = append(clauses, `(hostname ILIKE $`+itoa(n)+` ESCAPE '\' OR computer_name ILIKE $`+itoa(n)+` ESCAPE '\' OR serial ILIKE $`+itoa(n)+` ESCAPE '\' OR username ILIKE $`+itoa(n)+` ESCAPE '\' OR hardware_model ILIKE $`+itoa(n)+` ESCAPE '\')`)
	}
	if p := strings.TrimSpace(f.Platform); p != "" {
		args = append(args, strings.ToLower(p))
		clauses = append(clauses, `platform = $`+itoa(len(args)))
	}
	switch f.Status {
	case "online":
		args = append(args, now.Add(-f.OfflineAfter))
		clauses = append(clauses, `last_seen_at IS NOT NULL AND last_seen_at >= $`+itoa(len(args)))
	case "offline":
		args = append(args, now.Add(-f.OfflineAfter))
		clauses = append(clauses, `(last_seen_at IS NULL OR last_seen_at < $`+itoa(len(args))+`)`)
	}
	if label := strings.TrimSpace(f.Label); label != "" {
		args = append(args, label)
		n := len(args)
		clauses = append(clauses, `EXISTS (SELECT 1 FROM osquery_label_members m JOIN osquery_labels l ON l.id=m.label_id WHERE m.device_id=devices.id AND l.name=$`+itoa(n)+`)`)
	}
	return strings.Join(clauses, " AND "), args
}

// GetDevice loads one device with apps, labels, and recent change events.
func (s *Store) GetDevice(ctx context.Context, id string, offline time.Duration) (model.Device, error) {
	d, err := scanStoredDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE id=$1`, id))
	if err != nil {
		return model.Device{}, notFound(err)
	}
	apps, err := s.pool.Query(ctx, `SELECT name, path, bundle_id, version FROM device_apps WHERE device_id=$1 ORDER BY lower(name), path`, id)
	if err != nil {
		return model.Device{}, err
	}
	defer apps.Close()
	d.Apps = []model.DeviceApp{}
	for apps.Next() {
		var a model.DeviceApp
		if err := apps.Scan(&a.Name, &a.Path, &a.BundleID, &a.Version); err != nil {
			return model.Device{}, err
		}
		d.Apps = append(d.Apps, a)
	}
	if err := apps.Err(); err != nil {
		return model.Device{}, err
	}
	labels, err := s.pool.Query(ctx, `
		SELECT DISTINCT l.name FROM osquery_label_members m
		JOIN osquery_labels l ON l.id=m.label_id
		WHERE m.device_id=$1 ORDER BY l.name`, id)
	if err != nil {
		return model.Device{}, err
	}
	defer labels.Close()
	d.Labels = []string{}
	for labels.Next() {
		var name string
		if err := labels.Scan(&name); err != nil {
			return model.Device{}, err
		}
		d.Labels = append(d.Labels, name)
	}
	if err := labels.Err(); err != nil {
		return model.Device{}, err
	}
	ev, err := s.pool.Query(ctx, `
		SELECT id, at, actor, actor_kind, action, resource_type, resource_id, detail
		FROM audit_log
		WHERE resource_type='device' AND resource_id=$1
		  AND action IN ('enrolled','reenrolled','os_version_changed','hostname_changed','user_changed','disk_encryption_changed','app_installed','app_updated','app_removed','invalidate_node')
		ORDER BY id DESC LIMIT 8`, id)
	if err != nil {
		return model.Device{}, err
	}
	defer ev.Close()
	d.Events = []model.AuditEntry{}
	for ev.Next() {
		var e model.AuditEntry
		var detail []byte
		if err := ev.Scan(&e.ID, &e.At, &e.Actor, &e.ActorKind, &e.Action, &e.ResourceType, &e.ResourceID, &detail); err != nil {
			return model.Device{}, err
		}
		e.Detail = detail
		d.Events = append(d.Events, e)
	}
	if err := ev.Err(); err != nil {
		return model.Device{}, err
	}
	presentDevice(&d.Device, offline, s.now())
	return d.Device, nil
}

// ListResultLogs returns a page of raw result rows for a device.
func (s *Store) ListResultLogs(ctx context.Context, deviceID, queryName string, limit, offset int) ([]model.ResultLog, int, error) {
	if _, err := s.GetDevice(ctx, deviceID, time.Hour); err != nil {
		return nil, 0, err
	}
	limit, offset = pageWindow(limit, offset)
	where := `device_id=$1`
	args := []any{deviceID}
	if queryName != "" {
		args = append(args, queryName)
		where += ` AND query_name=$2`
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM osquery_result_logs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	qargs := append(append([]any{}, args...), limit, offset)
	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, query_name, action, columns, unix_time, received_at
		FROM osquery_result_logs WHERE `+where+`
		ORDER BY id DESC LIMIT $`+itoa(len(args)+1)+` OFFSET $`+itoa(len(args)+2), qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.ResultLog{}
	for rows.Next() {
		var item model.ResultLog
		var raw []byte
		if err := rows.Scan(&item.ID, &item.DeviceID, &item.QueryName, &item.Action, &raw, &item.UnixTime, &item.ReceivedAt); err != nil {
			return nil, 0, err
		}
		item.Columns = map[string]string{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &item.Columns)
		}
		out = append(out, item)
	}
	return out, total, rows.Err()
}

// FleetSummary aggregates inventory and a small AutoPKG status.
func (s *Store) FleetSummary(ctx context.Context, offline time.Duration) (model.FleetSummary, error) {
	now := s.now()
	var sum model.FleetSummary
	sum.OfflineAfterSeconds = int(offline.Seconds())
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&sum.TotalDevices); err != nil {
		return sum, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE last_seen_at IS NOT NULL AND last_seen_at >= $1`, now.Add(-offline)).Scan(&sum.OnlineDevices); err != nil {
		return sum, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE enrolled_at >= $1`, now.Add(-7*24*time.Hour)).Scan(&sum.EnrolledThisWeek); err != nil {
		return sum, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT os_version, count(*) FROM devices
		WHERE platform='darwin' AND os_version <> ''
		GROUP BY os_version
		ORDER BY count(*) DESC, os_version DESC`)
	if err != nil {
		return sum, err
	}
	defer rows.Close()
	sum.MacOSVersions = []model.VersionCount{}
	for rows.Next() {
		var v model.VersionCount
		if err := rows.Scan(&v.Version, &v.Count); err != nil {
			return sum, err
		}
		v.Name = macMarketing(v.Version)
		sum.MacOSVersions = append(sum.MacOSVersions, v)
	}
	if err := rows.Err(); err != nil {
		return sum, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE enabled) FROM recipes`).Scan(&sum.AutoPkg.Recipes, &sum.AutoPkg.Enabled); err != nil {
		return sum, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE catalog='testing'), count(*) FILTER (WHERE catalog='production') FROM packages`).Scan(&sum.AutoPkg.TestingPackages, &sum.AutoPkg.ProductionPackages); err != nil {
		return sum, err
	}
	var finished *time.Time
	err = s.pool.QueryRow(ctx, `
		SELECT r.name, j.result, j.finished_at
		FROM jobs j JOIN recipes r ON r.id = j.recipe_id
		WHERE j.finished_at IS NOT NULL
		ORDER BY j.finished_at DESC LIMIT 1`).Scan(&sum.AutoPkg.LastRecipe, &sum.AutoPkg.LastResult, &finished)
	if err != nil && !isNoRows(err) {
		return sum, err
	}
	sum.AutoPkg.LastFinishedAt = finished
	return sum, nil
}

// CreateLiveQuery fans a SELECT out to the devices in the target set.
func (s *Store) CreateLiveQuery(ctx context.Context, p model.Principal, in model.LiveQueryRequest) (model.LiveQuery, error) {
	if err := checkQuerySQL(in.SQL); err != nil {
		return model.LiveQuery{}, err
	}
	in.DeviceIDs = normStrings(in.DeviceIDs)
	in.Labels = normStrings(in.Labels)
	if len(in.DeviceIDs) == 0 && len(in.Labels) == 0 {
		return model.LiveQuery{}, invalid("select devices or labels")
	}
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = 30
	}
	if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 3600 {
		return model.LiveQuery{}, invalid("timeout_seconds must be between 1 and 3600")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.LiveQuery{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT d.id, d.hostname, d.computer_name FROM devices d
		WHERE d.id = ANY($1) OR EXISTS (
			SELECT 1 FROM osquery_label_members m
			JOIN osquery_labels l ON l.id = m.label_id
			WHERE m.device_id = d.id AND l.name = ANY($2)
		)`, in.DeviceIDs, in.Labels)
	if err != nil {
		return model.LiveQuery{}, err
	}
	type target struct{ id, host, name string }
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.host, &t.name); err != nil {
			rows.Close()
			return model.LiveQuery{}, err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return model.LiveQuery{}, err
	}
	if len(targets) == 0 {
		return model.LiveQuery{}, invalid("no devices matched")
	}
	if len(targets) > 2000 {
		return model.LiveQuery{}, invalid("too many devices")
	}
	now := s.now()
	q := model.LiveQuery{
		ID: newID(), SQL: strings.TrimSpace(in.SQL), Status: "running", CreatedBy: p.Name,
		TimeoutSeconds: in.TimeoutSeconds, CreatedAt: now, DeviceIDs: in.DeviceIDs, Labels: in.Labels,
	}
	if q.CreatedBy == "" {
		q.CreatedBy = p.ID
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO live_queries (id, sql, status, created_by, timeout_seconds, created_at)
		VALUES ($1,$2,'running',$3,$4,$5)`,
		q.ID, q.SQL, q.CreatedBy, q.TimeoutSeconds, now); err != nil {
		return model.LiveQuery{}, err
	}
	ids := make([]string, len(targets))
	devs := make([]string, len(targets))
	for i, t := range targets {
		ids[i] = q.ID
		devs[i] = t.id
		q.Targets = append(q.Targets, model.LiveQueryTarget{DeviceID: t.id, Hostname: t.host, ComputerName: t.name, Status: "pending"})
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO live_query_targets (live_query_id, device_id, status)
		SELECT * FROM unnest($1::text[], $2::text[], $3::text[])`,
		ids, devs, repeatString("pending", len(targets))); err != nil {
		return model.LiveQuery{}, err
	}
	if err := s.audit(ctx, tx, p, "create", "live_query", q.ID, map[string]any{
		"sql": q.SQL, "devices": len(targets), "labels": in.Labels, "timeout_seconds": q.TimeoutSeconds,
	}); err != nil {
		return model.LiveQuery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.LiveQuery{}, err
	}
	return q, nil
}

func repeatString(v string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// GetLiveQuery returns the query and any results received so far.
func (s *Store) GetLiveQuery(ctx context.Context, id string) (model.LiveQuery, error) {
	if err := s.ExpireLiveQueries(ctx); err != nil {
		return model.LiveQuery{}, err
	}
	var q model.LiveQuery
	err := s.pool.QueryRow(ctx, `
		SELECT id, sql, status, created_by, timeout_seconds, created_at, finished_at
		FROM live_queries WHERE id=$1`, id).Scan(&q.ID, &q.SQL, &q.Status, &q.CreatedBy, &q.TimeoutSeconds, &q.CreatedAt, &q.FinishedAt)
	if err != nil {
		return model.LiveQuery{}, notFound(err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT t.device_id, d.hostname, d.computer_name, t.status, t.status_code, t.error, t.result_rows, t.completed_at
		FROM live_query_targets t JOIN devices d ON d.id = t.device_id
		WHERE t.live_query_id=$1
		ORDER BY d.hostname`, id)
	if err != nil {
		return model.LiveQuery{}, err
	}
	defer rows.Close()
	q.Targets = []model.LiveQueryTarget{}
	q.Rows = []map[string]string{}
	for rows.Next() {
		var t model.LiveQueryTarget
		var raw []byte
		if err := rows.Scan(&t.DeviceID, &t.Hostname, &t.ComputerName, &t.Status, &t.StatusCode, &t.Error, &raw, &t.CompletedAt); err != nil {
			return model.LiveQuery{}, err
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &t.Rows)
		}
		if t.Rows == nil {
			t.Rows = []map[string]string{}
		}
		for _, row := range t.Rows {
			flat := make(map[string]string, len(row)+1)
			for k, v := range row {
				flat[k] = v
			}
			if _, ok := flat["mc_device"]; !ok {
				name := t.ComputerName
				if name == "" {
					name = t.Hostname
				}
				flat["mc_device"] = name
			}
			q.Rows = append(q.Rows, flat)
		}
		q.Targets = append(q.Targets, t)
	}
	return q, rows.Err()
}

// ExpireLiveQueries marks targets past their timeout and completes the parent query.
func (s *Store) ExpireLiveQueries(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.expireLiveQueriesTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) expireLiveQueriesTx(ctx context.Context, tx pgx.Tx) error {
	now := s.now()
	if _, err := tx.Exec(ctx, `
		UPDATE live_query_targets t
		SET status='timeout', completed_at=$1
		FROM live_queries q
		WHERE t.live_query_id = q.id
		  AND t.status IN ('pending','sent')
		  AND q.created_at + make_interval(secs => q.timeout_seconds) <= $1`, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		UPDATE live_queries q
		SET status='complete', finished_at=$1
		WHERE q.finished_at IS NULL
		  AND EXISTS (SELECT 1 FROM live_query_targets t WHERE t.live_query_id = q.id)
		  AND NOT EXISTS (
		    SELECT 1 FROM live_query_targets t WHERE t.live_query_id = q.id AND t.status IN ('pending','sent')
		  )`, now)
	return err
}
