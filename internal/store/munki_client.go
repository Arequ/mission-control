package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/munki"
	"github.com/jackc/pgx/v5"
)

// MunkiSkew is how far a client clock may disagree with the server.
const MunkiSkew = 5 * time.Minute

// MunkiAuth is the client identity established for a repo or check-in request.
type MunkiAuth struct {
	Serial       string
	Manifest     string
	EnrollmentID string
	PerDevice    bool
}

// CreateMunkiEnrollment stores a shared client secret. The raw value is not returned.
func (s *Store) CreateMunkiEnrollment(ctx context.Context, p model.Principal, in model.MunkiEnrollment) (model.MunkiEnrollment, error) {
	if err := checkName("name", in.Name); err != nil {
		return model.MunkiEnrollment{}, err
	}
	secret := strings.TrimSpace(in.Secret)
	if len(secret) < 8 {
		return model.MunkiEnrollment{}, invalid("secret must be at least 8 characters")
	}
	manifest := strings.TrimSpace(in.Manifest)
	if manifest == "" {
		manifest = "site_default"
	}
	if err := checkName("manifest", manifest); err != nil {
		return model.MunkiEnrollment{}, err
	}
	now := s.now()
	in.ID = newID()
	in.Secret = ""
	in.Manifest = manifest
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.MunkiEnrollment{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO munki_enrollments (id, name, secret, manifest, enabled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`,
		in.ID, in.Name, secret, manifest, in.Enabled, in.ManagedBy, now)
	if err != nil {
		return model.MunkiEnrollment{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "munki_enrollment", in.ID, map[string]any{"name": in.Name, "manifest": manifest, "enabled": in.Enabled}); err != nil {
		return model.MunkiEnrollment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.MunkiEnrollment{}, err
	}
	return in, nil
}

const enrollmentCols = `id, name, manifest, enabled, managed_by, created_at, updated_at`

func scanEnrollment(row pgx.Row) (model.MunkiEnrollment, error) {
	var e model.MunkiEnrollment
	err := row.Scan(&e.ID, &e.Name, &e.Manifest, &e.Enabled, &e.ManagedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

// ListMunkiEnrollments returns enrollments without secrets.
func (s *Store) ListMunkiEnrollments(ctx context.Context) ([]model.MunkiEnrollment, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+enrollmentCols+` FROM munki_enrollments ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.MunkiEnrollment{}
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetMunkiEnrollment loads one enrollment. The secret is not included.
func (s *Store) GetMunkiEnrollment(ctx context.Context, id string) (model.MunkiEnrollment, error) {
	e, err := scanEnrollment(s.pool.QueryRow(ctx, `SELECT `+enrollmentCols+` FROM munki_enrollments WHERE id=$1`, id))
	if err != nil {
		return model.MunkiEnrollment{}, notFound(err)
	}
	return e, nil
}

// UpdateMunkiEnrollment rotates or edits an enrollment. An empty secret keeps the stored value.
func (s *Store) UpdateMunkiEnrollment(ctx context.Context, p model.Principal, id string, in model.MunkiEnrollment) (model.MunkiEnrollment, error) {
	cur, err := s.GetMunkiEnrollment(ctx, id)
	if err != nil {
		return model.MunkiEnrollment{}, err
	}
	if err := checkName("name", in.Name); err != nil {
		return model.MunkiEnrollment{}, err
	}
	secret := strings.TrimSpace(in.Secret)
	if secret != "" && len(secret) < 8 {
		return model.MunkiEnrollment{}, invalid("secret must be at least 8 characters")
	}
	manifest := strings.TrimSpace(in.Manifest)
	if manifest == "" {
		manifest = "site_default"
	}
	if err := checkName("manifest", manifest); err != nil {
		return model.MunkiEnrollment{}, err
	}
	now := s.now()
	in.ID = cur.ID
	in.Secret = ""
	in.Manifest = manifest
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = cur.CreatedAt, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.MunkiEnrollment{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if secret == "" {
		_, err = tx.Exec(ctx, `UPDATE munki_enrollments SET name=$2, manifest=$3, enabled=$4, managed_by=$5, updated_at=$6 WHERE id=$1`,
			id, in.Name, manifest, in.Enabled, in.ManagedBy, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE munki_enrollments SET name=$2, secret=$3, manifest=$4, enabled=$5, managed_by=$6, updated_at=$7 WHERE id=$1`,
			id, in.Name, secret, manifest, in.Enabled, in.ManagedBy, now)
	}
	if err != nil {
		return model.MunkiEnrollment{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "munki_enrollment", id, map[string]any{"name": in.Name, "manifest": manifest, "enabled": in.Enabled, "secret_rotated": secret != ""}); err != nil {
		return model.MunkiEnrollment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.MunkiEnrollment{}, err
	}
	return in, nil
}

// DeleteMunkiEnrollment removes an enrollment and its client rows.
func (s *Store) DeleteMunkiEnrollment(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM munki_enrollments WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "munki_enrollment", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CreateMunkiClient stores a per-device binding. Token is hashed and not returned.
func (s *Store) CreateMunkiClient(ctx context.Context, p model.Principal, in model.MunkiClient) (model.MunkiClient, error) {
	serial := strings.TrimSpace(in.Serial)
	if !validClientSerial(serial) {
		return model.MunkiClient{}, invalid("serial must be 4–64 letters, numbers, '_' or '-'")
	}
	if strings.TrimSpace(in.EnrollmentID) == "" {
		return model.MunkiClient{}, invalid("enrollment_id is required")
	}
	if _, err := s.GetMunkiEnrollment(ctx, in.EnrollmentID); err != nil {
		return model.MunkiClient{}, err
	}
	manifest := strings.TrimSpace(in.Manifest)
	if manifest != "" {
		if err := checkName("manifest", manifest); err != nil {
			return model.MunkiClient{}, err
		}
	}
	token := strings.TrimSpace(in.Token)
	hash := ""
	if token != "" {
		if len(token) < 8 {
			return model.MunkiClient{}, invalid("token must be at least 8 characters")
		}
		hash = auth.Hash(token)
	}
	now := s.now()
	in.ID = newID()
	in.Serial = serial
	in.Token = ""
	in.Manifest = manifest
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.MunkiClient{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO munki_clients (id, serial, enrollment_id, token_hash, manifest, enabled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)`,
		in.ID, serial, in.EnrollmentID, hash, manifest, in.Enabled, in.ManagedBy, now)
	if err != nil {
		return model.MunkiClient{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "munki_client", in.ID, map[string]any{"serial": serial, "enrollment_id": in.EnrollmentID}); err != nil {
		return model.MunkiClient{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.MunkiClient{}, err
	}
	return in, nil
}

const clientCols = `id, serial, enrollment_id, manifest, enabled, managed_by, created_at, updated_at`

func scanMunkiClient(row pgx.Row) (model.MunkiClient, error) {
	var c model.MunkiClient
	err := row.Scan(&c.ID, &c.Serial, &c.EnrollmentID, &c.Manifest, &c.Enabled, &c.ManagedBy, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// ListMunkiClients returns client bindings without tokens.
func (s *Store) ListMunkiClients(ctx context.Context) ([]model.MunkiClient, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+clientCols+` FROM munki_clients ORDER BY serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.MunkiClient{}
	for rows.Next() {
		c, err := scanMunkiClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetMunkiClient loads one client. The token is not included.
func (s *Store) GetMunkiClient(ctx context.Context, id string) (model.MunkiClient, error) {
	c, err := scanMunkiClient(s.pool.QueryRow(ctx, `SELECT `+clientCols+` FROM munki_clients WHERE id=$1`, id))
	if err != nil {
		return model.MunkiClient{}, notFound(err)
	}
	return c, nil
}

// UpdateMunkiClient edits a binding. An empty token keeps the stored hash.
func (s *Store) UpdateMunkiClient(ctx context.Context, p model.Principal, id string, in model.MunkiClient) (model.MunkiClient, error) {
	cur, err := s.GetMunkiClient(ctx, id)
	if err != nil {
		return model.MunkiClient{}, err
	}
	serial := strings.TrimSpace(in.Serial)
	if !validClientSerial(serial) {
		return model.MunkiClient{}, invalid("serial must be 4–64 letters, numbers, '_' or '-'")
	}
	if _, err := s.GetMunkiEnrollment(ctx, in.EnrollmentID); err != nil {
		return model.MunkiClient{}, err
	}
	manifest := strings.TrimSpace(in.Manifest)
	if manifest != "" {
		if err := checkName("manifest", manifest); err != nil {
			return model.MunkiClient{}, err
		}
	}
	token := strings.TrimSpace(in.Token)
	if token != "" && len(token) < 8 {
		return model.MunkiClient{}, invalid("token must be at least 8 characters")
	}
	now := s.now()
	in.ID = cur.ID
	in.Serial = serial
	in.Token = ""
	in.Manifest = manifest
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = cur.CreatedAt, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.MunkiClient{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if token == "" {
		_, err = tx.Exec(ctx, `
			UPDATE munki_clients SET serial=$2, enrollment_id=$3, manifest=$4, enabled=$5, managed_by=$6, updated_at=$7 WHERE id=$1`,
			id, serial, in.EnrollmentID, manifest, in.Enabled, in.ManagedBy, now)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE munki_clients SET serial=$2, enrollment_id=$3, token_hash=$4, manifest=$5, enabled=$6, managed_by=$7, updated_at=$8 WHERE id=$1`,
			id, serial, in.EnrollmentID, auth.Hash(token), manifest, in.Enabled, in.ManagedBy, now)
	}
	if err != nil {
		return model.MunkiClient{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "munki_client", id, map[string]any{"serial": serial, "token_rotated": token != ""}); err != nil {
		return model.MunkiClient{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.MunkiClient{}, err
	}
	return in, nil
}

// DeleteMunkiClient removes a per-device binding.
func (s *Store) DeleteMunkiClient(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM munki_clients WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "munki_client", id, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type enrollmentSecret struct {
	id       string
	secret   string
	manifest string
	enabled  bool
}

func (s *Store) loadEnrollmentSecrets(ctx context.Context) ([]enrollmentSecret, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, secret, manifest, enabled FROM munki_enrollments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []enrollmentSecret
	for rows.Next() {
		var e enrollmentSecret
		if err := rows.Scan(&e.id, &e.secret, &e.manifest, &e.enabled); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuthenticateMunki checks a shared enrollment secret, an enrollment-derived
// device token, or a per-device token. username is the HTTP basic username
// and may be empty for a bearer token.
func (s *Store) AuthenticateMunki(ctx context.Context, username, secret string) (MunkiAuth, bool, error) {
	secret = strings.TrimSpace(secret)
	username = strings.TrimSpace(username)
	if secret == "" {
		return MunkiAuth{}, false, nil
	}
	enrollments, err := s.loadEnrollmentSecrets(ctx)
	if err != nil {
		return MunkiAuth{}, false, err
	}
	if validClientSerial(username) && !genericMunkiUser(username) {
		for _, e := range enrollments {
			if !e.enabled {
				continue
			}
			if auth.SecretEqual(secret, munki.DeriveDeviceToken(e.secret, username)) {
				authn := MunkiAuth{Serial: username, Manifest: e.manifest, EnrollmentID: e.id, PerDevice: true}
				if over, ok, err := s.clientManifest(ctx, username); err != nil {
					return MunkiAuth{}, false, err
				} else if ok && over != "" {
					authn.Manifest = over
				}
				return authn, true, nil
			}
		}
	}
	var shared *enrollmentSecret
	for i := range enrollments {
		e := &enrollments[i]
		if e.enabled && auth.SecretEqual(secret, e.secret) && shared == nil {
			shared = e
		}
	}
	if shared != nil {
		authn := MunkiAuth{Manifest: shared.manifest, EnrollmentID: shared.id}
		if validClientSerial(username) && !genericMunkiUser(username) {
			authn.Serial = username
			if over, ok, err := s.clientManifest(ctx, username); err != nil {
				return MunkiAuth{}, false, err
			} else if ok && over != "" {
				authn.Manifest = over
			}
		}
		return authn, true, nil
	}
	var serial, manifest, enrollmentID string
	var enabled bool
	err = s.pool.QueryRow(ctx, `
		SELECT c.serial, c.manifest, c.enrollment_id, c.enabled AND e.enabled
		FROM munki_clients c
		JOIN munki_enrollments e ON e.id = c.enrollment_id
		WHERE c.token_hash=$1 AND c.token_hash<>''`, auth.Hash(secret)).Scan(&serial, &manifest, &enrollmentID, &enabled)
	if err == nil && enabled {
		if username != "" && !genericMunkiUser(username) && !strings.EqualFold(username, serial) {
			return MunkiAuth{}, false, nil
		}
		if manifest == "" {
			for _, e := range enrollments {
				if e.id == enrollmentID {
					manifest = e.manifest
				}
			}
		}
		return MunkiAuth{Serial: serial, Manifest: manifest, EnrollmentID: enrollmentID, PerDevice: true}, true, nil
	}
	if err != nil && !isNoRows(err) {
		return MunkiAuth{}, false, err
	}
	return MunkiAuth{}, false, nil
}

func genericMunkiUser(name string) bool {
	switch strings.ToLower(name) {
	case "munki", "repo", "missioncontrol", "user":
		return true
	default:
		return false
	}
}

func validClientSerial(s string) bool {
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

// ManifestForSerial returns the manifest a ClientIdentifier should include.
// A per-device row wins. fallback is the enrollment manifest. site_default is last.
func (s *Store) ManifestForSerial(ctx context.Context, serial, fallback string) (string, error) {
	over, ok, err := s.clientManifest(ctx, serial)
	if err != nil {
		return "", err
	}
	if ok && over != "" {
		return over, nil
	}
	if strings.TrimSpace(fallback) != "" {
		return fallback, nil
	}
	return "site_default", nil
}

func (s *Store) clientManifest(ctx context.Context, serial string) (string, bool, error) {
	var manifest string
	var enabled bool
	err := s.pool.QueryRow(ctx, `SELECT manifest, enabled FROM munki_clients WHERE serial=$1`, serial).Scan(&manifest, &enabled)
	if isNoRows(err) || !enabled {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return manifest, true, nil
}

// CheckinResult is the stored outcome of one report.
type CheckinResult struct {
	DeviceID string
	Replayed bool
	Card     model.MunkiCard
}

// ApplyMunkiReport stores a check-in and links it to a device.
// defaultManifest is the enrollment manifest used when the report has none.
func (s *Store) ApplyMunkiReport(ctx context.Context, report munki.Report, rawHash, idemKey, defaultManifest string) (CheckinResult, error) {
	if strings.TrimSpace(report.Serial) == "" && strings.TrimSpace(report.HardwareUUID) == "" {
		return CheckinResult{}, invalid("report needs a serial or hardware UUID")
	}
	if !validClientSerial(report.Serial) && report.Serial != "" {
		return CheckinResult{}, invalid("report serial is invalid")
	}
	now := s.now()
	if !report.End.IsZero() && report.End.After(now.Add(MunkiSkew)) {
		return CheckinResult{}, invalid("report end time is too far in the future")
	}
	if !report.Start.IsZero() && report.Start.After(now.Add(MunkiSkew)) {
		return CheckinResult{}, invalid("report start time is too far in the future")
	}
	if !report.Start.IsZero() && !report.End.IsZero() && report.End.Add(MunkiSkew).Before(report.Start) {
		return CheckinResult{}, invalid("report end time is before the start time")
	}
	idemKey = strings.TrimSpace(idemKey)
	if len(idemKey) > 200 {
		return CheckinResult{}, invalid("idempotency key is too long")
	}
	if defaultManifest == "" {
		defaultManifest = "site_default"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CheckinResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	deviceID, err := s.upsertMunkiDevice(ctx, tx, report, now)
	if err != nil {
		return CheckinResult{}, err
	}
	if idemKey != "" {
		var prev string
		err = tx.QueryRow(ctx, `SELECT report_hash FROM munki_reports WHERE device_id=$1 AND idempotency_key=$2`, deviceID, idemKey).Scan(&prev)
		if err == nil {
			if prev != rawHash {
				return CheckinResult{}, ErrIdempotencyReuse
			}
			card, err := loadMunkiCard(ctx, tx, deviceID)
			if err != nil {
				return CheckinResult{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return CheckinResult{}, err
			}
			return CheckinResult{DeviceID: deviceID, Replayed: true, Card: card}, nil
		}
		if !isNoRows(err) {
			return CheckinResult{}, err
		}
	}
	var existing string
	err = tx.QueryRow(ctx, `SELECT report_hash FROM munki_reports WHERE device_id=$1 AND report_hash=$2`, deviceID, rawHash).Scan(&existing)
	if err == nil {
		card, err := loadMunkiCard(ctx, tx, deviceID)
		if err != nil {
			return CheckinResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CheckinResult{}, err
		}
		return CheckinResult{DeviceID: deviceID, Replayed: true, Card: card}, nil
	}
	if !isNoRows(err) {
		return CheckinResult{}, err
	}
	var storedEnd *time.Time
	err = tx.QueryRow(ctx, `SELECT last_run_end FROM munki_device_state WHERE device_id=$1 FOR UPDATE`, deviceID).Scan(&storedEnd)
	if err != nil && !isNoRows(err) {
		return CheckinResult{}, err
	}
	if err == nil && storedEnd != nil && !report.End.IsZero() && report.End.Add(MunkiSkew).Before(storedEnd.UTC()) {
		return CheckinResult{}, ErrStaleReport
	}
	end := report.End
	if end.IsZero() {
		end = now
	}
	start := report.Start
	pending := pendingNames(report.Pending)
	removals := pendingNames(report.Removals)
	card := model.MunkiCard{
		Status: report.Status(), LastRunStart: utcPtr(start), LastRunEnd: utcPtr(end),
		Pending: len(pending) + len(removals), PendingInstalls: pending, PendingRemovals: removals,
		Errors: report.Errors, Warnings: report.Warnings, MunkiVersion: report.MunkiVersion,
		ConsoleUser: report.ConsoleUser, Manifest: firstNonEmptyStr(report.ManifestName, defaultManifest),
	}
	if card.PendingInstalls == nil {
		card.PendingInstalls = []string{}
	}
	if card.PendingRemovals == nil {
		card.PendingRemovals = []string{}
	}
	if card.Errors == nil {
		card.Errors = []string{}
	}
	if card.Warnings == nil {
		card.Warnings = []string{}
	}
	pendJSON, _ := json.Marshal(card.PendingInstalls)
	remJSON, _ := json.Marshal(card.PendingRemovals)
	errJSON, _ := json.Marshal(card.Errors)
	warnJSON, _ := json.Marshal(card.Warnings)
	_, err = tx.Exec(ctx, `
		INSERT INTO munki_device_state (
			device_id, last_run_start, last_run_end, status, pending_installs, pending_removals,
			errors, warnings, munki_version, console_user, manifest_name, report_hash, updated_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$11,$12,$13)
		ON CONFLICT (device_id) DO UPDATE SET
			last_run_start=EXCLUDED.last_run_start, last_run_end=EXCLUDED.last_run_end, status=EXCLUDED.status,
			pending_installs=EXCLUDED.pending_installs, pending_removals=EXCLUDED.pending_removals,
			errors=EXCLUDED.errors, warnings=EXCLUDED.warnings, munki_version=EXCLUDED.munki_version,
			console_user=EXCLUDED.console_user, manifest_name=EXCLUDED.manifest_name,
			report_hash=EXCLUDED.report_hash, updated_at=EXCLUDED.updated_at`,
		deviceID, optionalTime(start), end, card.Status, string(pendJSON), string(remJSON), string(errJSON), string(warnJSON),
		card.MunkiVersion, card.ConsoleUser, card.Manifest, rawHash, now)
	if err != nil {
		return CheckinResult{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM munki_installs WHERE device_id=$1`, deviceID); err != nil {
		return CheckinResult{}, err
	}
	for _, item := range report.Installed {
		if _, err := tx.Exec(ctx, `
			INSERT INTO munki_installs (device_id, name, version, display_name) VALUES ($1,$2,$3,$4)
			ON CONFLICT (device_id, name) DO UPDATE SET version=EXCLUDED.version, display_name=EXCLUDED.display_name`,
			deviceID, item.Name, item.Version, item.DisplayName); err != nil {
			return CheckinResult{}, err
		}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO munki_reports (
			id, device_id, report_hash, idempotency_key, start_time, end_time, received_at, status,
			munki_version, console_user, manifest_name, error_count, warning_count, pending_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		newID(), deviceID, rawHash, idemKey, optionalTime(start), end, now, card.Status,
		card.MunkiVersion, card.ConsoleUser, card.Manifest, len(card.Errors), len(card.Warnings), card.Pending)
	if err != nil {
		return CheckinResult{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, model.Principal{Kind: "munki", ID: deviceID, Name: report.Serial}, "checkin", "device", deviceID, map[string]any{
		"status": card.Status, "munki_version": card.MunkiVersion, "pending": card.Pending, "errors": len(card.Errors),
	}); err != nil {
		return CheckinResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CheckinResult{}, err
	}
	return CheckinResult{DeviceID: deviceID, Card: card}, nil
}

func (s *Store) upsertMunkiDevice(ctx context.Context, tx pgx.Tx, report munki.Report, now time.Time) (string, error) {
	var deviceID string
	found := false
	if report.HardwareUUID != "" {
		err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE hardware_uuid=$1 FOR UPDATE`, report.HardwareUUID).Scan(&deviceID)
		if err == nil {
			found = true
		} else if !isNoRows(err) {
			return "", err
		}
	}
	if !found && report.Serial != "" {
		err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE serial=$1 FOR UPDATE`, report.Serial).Scan(&deviceID)
		if err == nil {
			found = true
		} else if !isNoRows(err) {
			return "", err
		}
	}
	if found {
		_, err := tx.Exec(ctx, `
			UPDATE devices SET
				hostname=CASE WHEN $2 <> '' THEN $2 ELSE hostname END,
				computer_name=CASE WHEN $3 <> '' THEN $3 ELSE computer_name END,
				os_version=CASE WHEN $4 <> '' THEN $4 ELSE os_version END,
				hardware_model=CASE WHEN $5 <> '' THEN $5 ELSE hardware_model END,
				primary_ip=CASE WHEN $6 <> '' THEN $6 ELSE primary_ip END,
				username=CASE WHEN $7 <> '' THEN $7 ELSE username END,
				serial=CASE WHEN serial='' AND $8 <> '' THEN $8 ELSE serial END,
				hardware_uuid=CASE WHEN hardware_uuid='' AND $9 <> '' THEN $9 ELSE hardware_uuid END,
				platform=CASE WHEN platform='' THEN 'darwin' ELSE platform END,
				last_seen_at=$10, updated_at=$10
			WHERE id=$1`,
			deviceID, report.Hostname, report.ComputerName, report.OSVersion, report.Model, report.IP, report.ConsoleUser,
			report.Serial, report.HardwareUUID, now)
		return deviceID, err
	}
	_, hash, err := newNodeKey()
	if err != nil {
		return "", err
	}
	deviceID = newID()
	hostID := report.Serial
	if hostID == "" {
		hostID = report.HardwareUUID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO devices (
			id, node_key_hash, node_invalid, host_identifier, hardware_uuid, serial, hostname, computer_name,
			platform, os_version, hardware_model, primary_ip, username,
			enrolled_at, last_enrolled_at, last_seen_at, created_at, updated_at)
		VALUES ($1,$2,true,$3,$4,$5,$6,$7,'darwin',$8,$9,$10,$11,$12,$12,$12,$12,$12)`,
		deviceID, hash, hostID, report.HardwareUUID, report.Serial, report.Hostname, report.ComputerName,
		report.OSVersion, report.Model, report.IP, report.ConsoleUser, now)
	if err != nil {
		return "", mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, model.Principal{Kind: "munki", ID: deviceID, Name: report.Serial}, "enrolled", "device", deviceID, map[string]any{
		"serial": report.Serial, "hostname": report.Hostname, "source": "munki",
	}); err != nil {
		return "", err
	}
	return deviceID, nil
}

func pendingNames(items []munki.PendingItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item.Version != "" {
			out = append(out, item.Name+" "+item.Version)
		} else {
			out = append(out, item.Name)
		}
	}
	return out
}

func utcPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func optionalTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// MunkiCard loads the latest check-in summary. ok is false when the device has not checked in.
func (s *Store) MunkiCard(ctx context.Context, deviceID string) (model.MunkiCard, bool, error) {
	card, err := loadMunkiCard(ctx, s.pool, deviceID)
	if isNoRows(err) {
		return model.MunkiCard{}, false, nil
	}
	if err != nil {
		return model.MunkiCard{}, false, err
	}
	return card, true, nil
}

type rowQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadMunkiCard(ctx context.Context, q rowQueryer, deviceID string) (model.MunkiCard, error) {
	var card model.MunkiCard
	var start, end *time.Time
	var pend, rem, errs, warns []byte
	err := q.QueryRow(ctx, `
		SELECT last_run_start, last_run_end, status, pending_installs, pending_removals, errors, warnings,
			munki_version, console_user, manifest_name
		FROM munki_device_state WHERE device_id=$1`, deviceID).Scan(
		&start, &end, &card.Status, &pend, &rem, &errs, &warns, &card.MunkiVersion, &card.ConsoleUser, &card.Manifest)
	if err != nil {
		return model.MunkiCard{}, err
	}
	card.LastRunStart, card.LastRunEnd = start, end
	_ = json.Unmarshal(pend, &card.PendingInstalls)
	_ = json.Unmarshal(rem, &card.PendingRemovals)
	_ = json.Unmarshal(errs, &card.Errors)
	_ = json.Unmarshal(warns, &card.Warnings)
	if card.PendingInstalls == nil {
		card.PendingInstalls = []string{}
	}
	if card.PendingRemovals == nil {
		card.PendingRemovals = []string{}
	}
	if card.Errors == nil {
		card.Errors = []string{}
	}
	if card.Warnings == nil {
		card.Warnings = []string{}
	}
	card.Pending = len(card.PendingInstalls) + len(card.PendingRemovals)
	return card, nil
}

// ProjectMunki copies check-in state into Munki coverage snapshots.
func (s *Store) ProjectMunki(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.serial, d.hardware_uuid, d.primary_mac, d.hostname, d.username, d.os_version, d.primary_ip,
			st.munki_version, COALESCE(st.last_run_end, st.updated_at)
		FROM munki_device_state st
		JOIN devices d ON d.id = st.device_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var obs []coverage.Observation
	for rows.Next() {
		var id, serial, uuid, mac, host, user, osver, ip, agent string
		var seen time.Time
		if err := rows.Scan(&id, &serial, &uuid, &mac, &host, &user, &osver, &ip, &agent, &seen); err != nil {
			return err
		}
		obs = append(obs, coverage.Observation{
			NativeID: id,
			Keys: coverage.Keys{
				Serial: serial, HardwareUUID: uuid, MAC: mac, Hostname: host, PrimaryUser: user,
			},
			OSVersion: osver, IPAddress: ip, AgentVersion: agent, LastSeen: seen,
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return s.ApplyObservations(ctx, "munki", obs, true, true)
}

// PkginfoBody returns one pkginfo plist for the Munki repo.
func (s *Store) PkginfoBody(ctx context.Context, name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".plist")
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT pkginfo FROM packages
		WHERE name || '-' || version = $1 OR filename = $1 OR filename = $1 || '.pkg' OR filename = $1 || '.dmg'
		ORDER BY created_at DESC LIMIT 1`, name).Scan(&raw)
	if err != nil {
		return nil, notFound(err)
	}
	info, err := munki.ParsePkginfo(raw)
	if err != nil {
		return nil, err
	}
	return munki.MarshalPkginfoPlist(info)
}

// ReportHash is the SHA-256 of the raw report bytes, used for idempotency.
func ReportHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
