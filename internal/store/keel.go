package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/keel"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// KeelRunsKept is how many reports are kept per serial. Older runs are
	// pruned in the same transaction as the insert.
	KeelRunsKept = 50
	// KeelStaleAfter is when a device that stopped reporting is called stale.
	// Keel runs every 30 minutes, so this is four missed runs.
	KeelStaleAfter = 2 * time.Hour
)

// ErrKeelKeyMismatch means the serial is bound to a different public key.
// An admin must clear the key before the device can enroll again.
var ErrKeelKeyMismatch = errors.New("serial is enrolled with a different key")

// ErrKeelReplay means the report timestamp is not after the last accepted one,
// or the key changed between verification and insert.
var ErrKeelReplay = errors.New("keel report replayed")

// CreateKeelEnrollSecret stores a hashed enroll secret. The raw value is not persisted.
func (s *Store) CreateKeelEnrollSecret(ctx context.Context, p model.Principal, in model.KeelEnrollSecret) (model.KeelEnrollSecret, error) {
	if err := checkOsqueryName(in.Name); err != nil {
		return model.KeelEnrollSecret{}, err
	}
	secret := strings.TrimSpace(in.Secret)
	if len(secret) < 8 {
		return model.KeelEnrollSecret{}, invalid("secret must be at least 8 characters")
	}
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	in.Secret = ""
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.KeelEnrollSecret{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO keel_enroll_secrets (id, name, secret_hash, enabled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$6)`,
		in.ID, in.Name, auth.Hash(secret), in.Enabled, in.ManagedBy, now)
	if err != nil {
		return model.KeelEnrollSecret{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "keel_enroll_secret", in.ID, map[string]any{"name": in.Name, "enabled": in.Enabled}); err != nil {
		return model.KeelEnrollSecret{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.KeelEnrollSecret{}, err
	}
	return in, nil
}

const keelSecretCols = `id, name, enabled, managed_by, created_at, updated_at`

func scanKeelSecret(row pgx.Row) (model.KeelEnrollSecret, error) {
	var e model.KeelEnrollSecret
	err := row.Scan(&e.ID, &e.Name, &e.Enabled, &e.ManagedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

// ListKeelEnrollSecrets returns secrets without hashes.
func (s *Store) ListKeelEnrollSecrets(ctx context.Context) ([]model.KeelEnrollSecret, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+keelSecretCols+` FROM keel_enroll_secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.KeelEnrollSecret{}
	for rows.Next() {
		e, err := scanKeelSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetKeelEnrollSecret loads one secret record. The raw secret is never returned.
func (s *Store) GetKeelEnrollSecret(ctx context.Context, id string) (model.KeelEnrollSecret, error) {
	e, err := scanKeelSecret(s.pool.QueryRow(ctx, `SELECT `+keelSecretCols+` FROM keel_enroll_secrets WHERE id=$1`, id))
	if err != nil {
		return model.KeelEnrollSecret{}, notFound(err)
	}
	return e, nil
}

// UpdateKeelEnrollSecret rotates or disables a secret. An empty secret keeps the current hash.
func (s *Store) UpdateKeelEnrollSecret(ctx context.Context, p model.Principal, id string, in model.KeelEnrollSecret) (model.KeelEnrollSecret, error) {
	cur, err := s.GetKeelEnrollSecret(ctx, id)
	if err != nil {
		return model.KeelEnrollSecret{}, err
	}
	if err := checkOsqueryName(in.Name); err != nil {
		return model.KeelEnrollSecret{}, err
	}
	secret := strings.TrimSpace(in.Secret)
	if secret != "" && len(secret) < 8 {
		return model.KeelEnrollSecret{}, invalid("secret must be at least 8 characters")
	}
	now := s.now()
	in.ID = cur.ID
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = cur.CreatedAt, now
	in.Secret = ""
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.KeelEnrollSecret{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if secret == "" {
		_, err = tx.Exec(ctx, `UPDATE keel_enroll_secrets SET name=$2, enabled=$3, managed_by=$4, updated_at=$5 WHERE id=$1`,
			id, in.Name, in.Enabled, in.ManagedBy, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE keel_enroll_secrets SET name=$2, secret_hash=$3, enabled=$4, managed_by=$5, updated_at=$6 WHERE id=$1`,
			id, in.Name, auth.Hash(secret), in.Enabled, in.ManagedBy, now)
	}
	if err != nil {
		return model.KeelEnrollSecret{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "keel_enroll_secret", id, map[string]any{"name": in.Name, "enabled": in.Enabled, "rotated": secret != ""}); err != nil {
		return model.KeelEnrollSecret{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.KeelEnrollSecret{}, err
	}
	return in, nil
}

// DeleteKeelEnrollSecret removes a secret. Enrolled keys stay bound.
func (s *Store) DeleteKeelEnrollSecret(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM keel_enroll_secrets WHERE id=$1`, id)
	if err != nil {
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "keel_enroll_secret", id, map[string]any{}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// keelEnrollSecretID returns the id of the enabled secret that matches.
// Every enabled hash is compared in constant time, the same way osquery
// enroll secrets are, so a lookup miss does not return early.
func (s *Store) keelEnrollSecretID(ctx context.Context, secret string) (string, bool, error) {
	if strings.TrimSpace(secret) == "" {
		return "", false, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id, secret_hash FROM keel_enroll_secrets WHERE enabled`)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	got := auth.Hash(secret)
	match := ""
	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			return "", false, err
		}
		if auth.EqualHash(got, hash) {
			match = id
		}
	}
	return match, match != "", rows.Err()
}

// EnrollKeelDevice binds a public key to a serial on first use.
// It returns created=true for a new binding and created=false when the same
// key was already bound. A different key is ErrKeelKeyMismatch. A bad secret
// is ErrEnrollRejected.
func (s *Store) EnrollKeelDevice(ctx context.Context, secret, serial, hostname string, pub ed25519.PublicKey) (bool, error) {
	secretID, ok, err := s.keelEnrollSecretID(ctx, secret)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrEnrollRejected
	}
	if !keel.ValidSerial(serial) {
		return false, invalid("serial must be 4-64 letters, numbers, '_' or '-'")
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, invalid("public_key must be a 32-byte Ed25519 key")
	}
	hostname = pgText(hostname, 255)
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		INSERT INTO keel_device_keys (serial, hostname, public_key, enroll_secret_id, enrolled_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (serial) DO NOTHING`,
		serial, hostname, []byte(pub), secretID, now)
	if err != nil {
		return false, mapWriteErr(err)
	}
	actor := model.Principal{Kind: "keel", ID: serial, Name: serial}
	if tag.RowsAffected() == 1 {
		if err := s.audit(ctx, tx, actor, "keel_enrolled", "keel_device", serial, map[string]any{"hostname": hostname, "enroll_secret_id": secretID}); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}
	// The row exists. Lock it so a concurrent admin clear cannot interleave.
	var bound []byte
	if err := tx.QueryRow(ctx, `SELECT public_key FROM keel_device_keys WHERE serial=$1 FOR UPDATE`, serial).Scan(&bound); err != nil {
		return false, err
	}
	if !bytes.Equal(bound, pub) {
		return false, ErrKeelKeyMismatch
	}
	if hostname != "" {
		if _, err := tx.Exec(ctx, `UPDATE keel_device_keys SET hostname=$2 WHERE serial=$1`, serial, hostname); err != nil {
			return false, err
		}
	}
	return false, tx.Commit(ctx)
}

// KeelPublicKey returns the key bound to serial, or ErrNotFound.
func (s *Store) KeelPublicKey(ctx context.Context, serial string) (ed25519.PublicKey, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT public_key FROM keel_device_keys WHERE serial=$1`, serial).Scan(&raw)
	if err != nil {
		return nil, notFound(err)
	}
	return ed25519.PublicKey(raw), nil
}

// RecordKeelReport stores a verified report. The replay floor moves and the
// run is inserted in one transaction. The UPDATE re-checks the key and the
// timestamp under the row lock, so of two concurrent reports with the same
// timestamp exactly one succeeds; the other sees the new floor and gets
// ErrKeelReplay. A repeated run_id with a fresh timestamp is accepted and
// does not add a second row.
func (s *Store) RecordKeelReport(ctx context.Context, pub ed25519.PublicKey, ts int64, r keel.Report, body []byte) error {
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	hostname := pgText(r.Device.Hostname, 255)
	tag, err := tx.Exec(ctx, `
		UPDATE keel_device_keys
		SET last_timestamp=$3, last_report_at=$4,
			hostname=CASE WHEN $5 <> '' THEN $5 ELSE hostname END
		WHERE serial=$1 AND public_key=$2 AND last_timestamp < $3`,
		r.Device.Serial, []byte(pub), ts, now, hostname)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrKeelReplay
	}
	if err := insertKeelRun(ctx, tx, r, ts, now, body); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM keel_runs WHERE serial=$1 AND id NOT IN (
			SELECT id FROM keel_runs WHERE serial=$1 ORDER BY id DESC LIMIT $2)`,
		r.Device.Serial, KeelRunsKept); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// insertKeelRun writes one run row. A repeated run_id for the serial is a no-op.
func insertKeelRun(ctx context.Context, tx pgx.Tx, r keel.Report, ts int64, received time.Time, body []byte) error {
	roles := r.RoleNames()
	for i := range roles {
		roles[i] = pgText(roles[i], 255)
	}
	warnings := []string{}
	for _, w := range r.Warnings {
		if len(warnings) == 100 {
			break
		}
		warnings = append(warnings, pgText(w, 2000))
	}
	sum := r.Summary
	_, err := tx.Exec(ctx, `
		INSERT INTO keel_runs (
			serial, run_id, report_timestamp, received_at, started_at, mode, keel_version, duration_ms,
			hostname, leaf_role, roles, total, ok, changed, would_change, failed, skipped, body,
			leaf_match, warnings, compile_error)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21)
		ON CONFLICT (serial, run_id) DO NOTHING`,
		r.Device.Serial, pgText(r.RunID, 128), ts, received, r.StartedAt, r.Mode, pgText(r.KeelVersion, 128), r.DurationMS,
		pgText(r.Device.Hostname, 255), pgText(r.LeafRole(), 255), roles,
		sum.Total, sum.OK, sum.Changed, sum.WouldChange, sum.Failed, sum.Skipped, string(body),
		pgText(r.LeafMatch(), 255), warnings, r.CompileFailed())
	if err != nil {
		var pgErr *pgconn.PgError
		// 22P05: jsonb cannot hold \u0000. 22021: invalid UTF-8 for a text column.
		if errors.As(err, &pgErr) && (pgErr.Code == "22P05" || pgErr.Code == "22021" || pgErr.Code == "22P02") {
			return invalid("report body cannot be stored as JSON")
		}
		return mapWriteErr(err)
	}
	return nil
}

// DeleteKeelKey clears the key bound to serial so the device can enroll again.
// Run history is kept.
func (s *Store) DeleteKeelKey(ctx context.Context, p model.Principal, serial string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM keel_device_keys WHERE serial=$1`, serial)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "keel_key_cleared", "keel_device", serial, map[string]any{}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// pgText makes an agent-supplied string safe for a TEXT column: NUL is not
// storable in Postgres text, and the column widths are bounded.
func pgText(s string, n int) string {
	return clipString(strings.TrimSpace(strings.ReplaceAll(s, "\x00", "")), n)
}

func clipString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// keelLatest is the latest run per serial, joined to the key binding and the
// unified device with the same serial. Serials with a key and no run appear
// with a NULL run.
const keelLatest = `
	WITH latest AS (
		SELECT DISTINCT ON (serial) * FROM keel_runs ORDER BY serial, id DESC
	)
	SELECT COALESCE(k.serial, r.serial),
		COALESCE(NULLIF(r.hostname, ''), k.hostname, ''),
		k.serial IS NOT NULL, k.enrolled_at,
		COALESCE((SELECT d.id FROM devices d WHERE d.serial = COALESCE(k.serial, r.serial) AND d.serial <> ''
			ORDER BY d.last_seen_at DESC NULLS LAST LIMIT 1), ''),
		r.run_id, r.mode, r.keel_version, r.started_at, r.received_at, r.duration_ms, r.leaf_role, r.roles,
		r.total, r.ok, r.changed, r.would_change, r.failed, r.skipped,
		r.leaf_match, r.warnings, r.compile_error`

const keelLatestFrom = `
	FROM keel_device_keys k
	FULL OUTER JOIN latest r ON r.serial = k.serial`

func scanKeelDevice(row pgx.Row, extra ...any) (model.KeelDevice, error) {
	var d model.KeelDevice
	var runID, mode, version, leaf *string
	var started, received *time.Time
	var duration *int64
	var roles []string
	var total, ok, changed, would, failed, skipped *int
	var leafMatch *string
	var warnings []string
	var compileErr *bool
	dest := []any{&d.Serial, &d.Hostname, &d.Enrolled, &d.EnrolledAt, &d.DeviceID,
		&runID, &mode, &version, &started, &received, &duration, &leaf, &roles,
		&total, &ok, &changed, &would, &failed, &skipped, &leafMatch, &warnings, &compileErr}
	dest = append(dest, extra...)
	if err := row.Scan(dest...); err != nil {
		return model.KeelDevice{}, err
	}
	if runID != nil {
		run := &model.KeelRun{
			RunID: *runID, Serial: d.Serial, Hostname: d.Hostname, Mode: deref(mode), KeelVersion: deref(version),
			DurationMS: derefInt64(duration), LeafRole: deref(leaf), LeafMatch: deref(leafMatch), Roles: roles,
			Warnings: warnings, CompileError: compileErr != nil && *compileErr,
			Summary: model.KeelSummary{
				Total: derefInt(total), OK: derefInt(ok), Changed: derefInt(changed),
				WouldChange: derefInt(would), Failed: derefInt(failed), Skipped: derefInt(skipped),
			},
		}
		if started != nil {
			run.StartedAt = started.UTC()
		}
		if received != nil {
			run.ReceivedAt = received.UTC()
		}
		if run.Roles == nil {
			run.Roles = []string{}
		}
		if run.Warnings == nil {
			run.Warnings = []string{}
		}
		d.LastRun = run
	}
	return d, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func (s *Store) markKeelStale(d *model.KeelDevice, now time.Time) {
	if d.LastRun == nil {
		// Enrolled and never reported: stale once the enrollment is old.
		d.Stale = d.EnrolledAt != nil && d.EnrolledAt.Before(now.Add(-KeelStaleAfter))
		return
	}
	d.Stale = d.LastRun.ReceivedAt.Before(now.Add(-KeelStaleAfter))
}

// KeelDeviceFilter narrows ListKeelDevices.
type KeelDeviceFilter struct {
	Role   string
	Status string // failed, pending, stale, warnings
	Q      string
	Limit  int
	Offset int
}

// ListKeelDevices returns every serial Keel knows, newest report first.
func (s *Store) ListKeelDevices(ctx context.Context, f KeelDeviceFilter) ([]model.KeelDevice, int, error) {
	all, err := s.loadKeelDevices(ctx)
	if err != nil {
		return nil, 0, err
	}
	q := strings.ToLower(strings.TrimSpace(f.Q))
	out := []model.KeelDevice{}
	for _, d := range all {
		if f.Role != "" && (d.LastRun == nil || !contains(d.LastRun.Roles, f.Role)) {
			continue
		}
		switch f.Status {
		case "failed":
			if !d.LastRun.Failing() {
				continue
			}
		case "warnings":
			if d.LastRun == nil || len(d.LastRun.Warnings) == 0 {
				continue
			}
		case "pending":
			if !keelPending(d) {
				continue
			}
		case "stale":
			if !d.Stale {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(d.Serial+" "+d.Hostname), q) {
			continue
		}
		out = append(out, d)
	}
	total := len(out)
	limit, offset := pageWindow(f.Limit, f.Offset)
	if offset >= len(out) {
		return []model.KeelDevice{}, total, nil
	}
	end := min(offset+limit, len(out))
	return out[offset:end], total, nil
}

func keelPending(d model.KeelDevice) bool {
	return d.LastRun != nil && d.LastRun.Mode == "plan" && d.LastRun.Summary.WouldChange > 0
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func (s *Store) loadKeelDevices(ctx context.Context) ([]model.KeelDevice, error) {
	rows, err := s.pool.Query(ctx, keelLatest+keelLatestFrom+`
		ORDER BY r.received_at DESC NULLS LAST, 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := s.now()
	out := []model.KeelDevice{}
	for rows.Next() {
		d, err := scanKeelDevice(rows)
		if err != nil {
			return nil, err
		}
		s.markKeelStale(&d, now)
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetKeelDevice returns one serial and the body of its latest report.
// Report is JSON null when the serial enrolled and has not reported yet.
func (s *Store) GetKeelDevice(ctx context.Context, serial string) (model.KeelDeviceDetail, error) {
	var body []byte
	row := s.pool.QueryRow(ctx, keelLatest+`, r.body`+keelLatestFrom+`
		WHERE COALESCE(k.serial, r.serial) = $1`, serial)
	d, err := scanKeelDevice(row, &body)
	if err != nil {
		return model.KeelDeviceDetail{}, notFound(err)
	}
	s.markKeelStale(&d, s.now())
	out := model.KeelDeviceDetail{KeelDevice: d, Report: json.RawMessage("null")}
	if len(body) > 0 {
		out.Report = body
	}
	return out, nil
}

// ListKeelRuns returns the stored history for a serial, newest first.
func (s *Store) ListKeelRuns(ctx context.Context, serial string) ([]model.KeelRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT run_id, serial, hostname, mode, keel_version, started_at, received_at, duration_ms, leaf_role, roles,
			total, ok, changed, would_change, failed, skipped, leaf_match, warnings, compile_error
		FROM keel_runs WHERE serial=$1 ORDER BY id DESC LIMIT $2`, serial, KeelRunsKept)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.KeelRun{}
	for rows.Next() {
		var r model.KeelRun
		if err := rows.Scan(&r.RunID, &r.Serial, &r.Hostname, &r.Mode, &r.KeelVersion, &r.StartedAt, &r.ReceivedAt,
			&r.DurationMS, &r.LeafRole, &r.Roles, &r.Summary.Total, &r.Summary.OK, &r.Summary.Changed,
			&r.Summary.WouldChange, &r.Summary.Failed, &r.Summary.Skipped, &r.LeafMatch, &r.Warnings, &r.CompileError); err != nil {
			return nil, err
		}
		r.StartedAt, r.ReceivedAt = r.StartedAt.UTC(), r.ReceivedAt.UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		if _, err := s.GetKeelDevice(ctx, serial); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// KeelOverview summarizes roles, the profiles they enable, and fleet health
// from each serial's latest report.
func (s *Store) KeelOverview(ctx context.Context) (model.KeelOverview, error) {
	devices, err := s.loadKeelDevices(ctx)
	if err != nil {
		return model.KeelOverview{}, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (serial) serial,
			CASE WHEN jsonb_typeof(body->'roles') = 'array' THEN body->'roles' ELSE '[]'::jsonb END,
			COALESCE((
				SELECT jsonb_agg(p->>'name') FROM jsonb_array_elements(
					CASE WHEN jsonb_typeof(body->'profiles') = 'array' THEN body->'profiles' ELSE '[]'::jsonb END) p
				WHERE jsonb_typeof(p) = 'object' AND p->'enabled' = 'true'::jsonb AND p->>'name' <> ''
			), '[]'::jsonb)
		FROM keel_runs ORDER BY serial, id DESC`)
	if err != nil {
		return model.KeelOverview{}, err
	}
	defer rows.Close()
	type roleAcc struct {
		role     model.KeelRole
		parents  map[string]int
		profiles map[string]int
	}
	acc := map[string]*roleAcc{}
	for rows.Next() {
		var serial string
		var rolesRaw, profilesRaw []byte
		if err := rows.Scan(&serial, &rolesRaw, &profilesRaw); err != nil {
			return model.KeelOverview{}, err
		}
		var roles []keel.Role
		_ = json.Unmarshal(rolesRaw, &roles)
		var enabled []string
		_ = json.Unmarshal(profilesRaw, &enabled)
		chain := []string{}
		for i, role := range roles {
			if role.Name == "" {
				continue
			}
			chain = append(chain, role.Name)
			a := acc[role.Name]
			if a == nil {
				a = &roleAcc{
					role:     model.KeelRole{Name: role.Name, Chain: append([]string{}, chain...)},
					parents:  map[string]int{},
					profiles: map[string]int{},
				}
				acc[role.Name] = a
			}
			a.parents[strings.Join(role.Parents, "\x00")]++
			a.role.Inherited++
			if i == len(roles)-1 {
				a.role.Devices++
				for _, name := range enabled {
					a.profiles[name]++
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return model.KeelOverview{}, err
	}
	list := make([]*roleAcc, 0, len(acc))
	for _, a := range acc {
		best, bestN := "", -1
		for key, n := range a.parents {
			if n > bestN || (n == bestN && key < best) {
				best, bestN = key, n
			}
		}
		a.role.Parents = []string{}
		if best != "" {
			a.role.Parents = strings.Split(best, "\x00")
		}
		a.role.Profiles = []model.KeelRoleProfile{}
		for name, n := range a.profiles {
			a.role.Profiles = append(a.role.Profiles, model.KeelRoleProfile{Name: name, Devices: n})
		}
		sort.Slice(a.role.Profiles, func(i, j int) bool { return a.role.Profiles[i].Name < a.role.Profiles[j].Name })
		list = append(list, a)
	}
	// Roots first, then deeper roles; names break ties.
	sort.Slice(list, func(i, j int) bool {
		if len(list[i].role.Chain) != len(list[j].role.Chain) {
			return len(list[i].role.Chain) < len(list[j].role.Chain)
		}
		return strings.Join(list[i].role.Chain, "/") < strings.Join(list[j].role.Chain, "/")
	})
	out := model.KeelOverview{
		Devices:           len(devices),
		StaleAfterSeconds: int(KeelStaleAfter / time.Second),
		Roles:             make([]model.KeelRole, 0, len(list)),
		Failed:            []model.KeelDevice{},
		Pending:           []model.KeelDevice{},
		Warned:            []model.KeelDevice{},
		Stale:             []model.KeelDevice{},
	}
	for _, a := range list {
		out.Roles = append(out.Roles, a.role)
	}
	for _, d := range devices {
		if d.LastRun != nil && !d.Stale {
			out.Reporting++
		}
		if d.LastRun.Failing() {
			out.Failed = append(out.Failed, d)
		}
		if d.LastRun != nil && len(d.LastRun.Warnings) > 0 {
			out.Warned = append(out.Warned, d)
		}
		if keelPending(d) {
			out.Pending = append(out.Pending, d)
		}
		if d.Stale {
			out.Stale = append(out.Stale, d)
		}
	}
	return out, nil
}

// KeelRoleSettings groups the effective settings of one profile across the
// latest reports of devices whose leaf role is role. Identical settings
// (compared as JSON values, so key order does not matter) are one variant.
func (s *Store) KeelRoleSettings(ctx context.Context, role, profile string) (model.KeelRoleSettings, error) {
	out := model.KeelRoleSettings{Role: role, Profile: profile, Variants: []model.KeelSettingsVariant{}}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM (SELECT DISTINCT ON (serial) leaf_role FROM keel_runs ORDER BY serial, id DESC) l
		WHERE leaf_role=$1`, role).Scan(&out.Devices); err != nil {
		return out, err
	}
	if out.Devices == 0 {
		return out, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (serial) serial, leaf_role, body FROM keel_runs ORDER BY serial, id DESC
		), entries AS (
			SELECT DISTINCT ON (l.serial) l.serial,
				COALESCE(p->'enabled' = 'true'::jsonb, false) AS enabled,
				COALESCE(p->'settings', 'null'::jsonb) AS settings
			FROM latest l, jsonb_array_elements(
				CASE WHEN jsonb_typeof(l.body->'profiles') = 'array' THEN l.body->'profiles' ELSE '[]'::jsonb END) p
			WHERE l.leaf_role=$1 AND jsonb_typeof(p) = 'object' AND p->>'name' = $2
			ORDER BY l.serial
		)
		SELECT enabled, settings, count(*), (array_agg(serial ORDER BY serial))[1:50]
		FROM entries GROUP BY enabled, settings ORDER BY count(*) DESC, enabled DESC`, role, profile)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var v model.KeelSettingsVariant
		var settings []byte
		if err := rows.Scan(&v.Enabled, &settings, &v.Devices, &v.Serials); err != nil {
			return out, err
		}
		v.Settings = settings
		seen += v.Devices
		out.Variants = append(out.Variants, v)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Missing = out.Devices - seen
	return out, nil
}
