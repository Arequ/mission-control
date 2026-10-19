package store

import (
	"context"
	"strings"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
)

func checkQuerySQL(sql string) error {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return invalid("sql is required")
	}
	if strings.ContainsRune(sql, 0) {
		return invalid("sql is invalid")
	}
	trimmed := strings.TrimRight(sql, "; \t\r\n")
	if strings.Contains(trimmed, ";") {
		return invalid("sql must be a single statement")
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "select") && !strings.HasPrefix(lower, "with") {
		return invalid("sql must be a SELECT")
	}
	if len(sql) > 20000 {
		return invalid("sql is too long")
	}
	return nil
}

func checkOsqueryName(name string) error {
	if err := checkName("name", name); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(name), "mc_") {
		return invalid("name must not start with mc_")
	}
	return nil
}

func checkInterval(v int) error {
	if v < 1 || v > 604800 {
		return invalid("interval must be between 1 and 604800 seconds")
	}
	return nil
}

func normStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

const queryCols = `id, name, description, sql, platform, interval_seconds, snapshot, removed, scheduled, managed_by, created_at, updated_at`

func scanQuery(row pgx.Row) (model.OsqueryQuery, error) {
	var q model.OsqueryQuery
	err := row.Scan(&q.ID, &q.Name, &q.Description, &q.SQL, &q.Platform, &q.Interval, &q.Snapshot, &q.Removed, &q.Scheduled, &q.ManagedBy, &q.CreatedAt, &q.UpdatedAt)
	return q, err
}

// CreateOsqueryQuery inserts a query.
func (s *Store) CreateOsqueryQuery(ctx context.Context, p model.Principal, in model.OsqueryQuery) (model.OsqueryQuery, error) {
	if err := checkOsqueryName(in.Name); err != nil {
		return model.OsqueryQuery{}, err
	}
	if err := checkQuerySQL(in.SQL); err != nil {
		return model.OsqueryQuery{}, err
	}
	if in.Interval == 0 {
		in.Interval = 3600
	}
	if err := checkInterval(in.Interval); err != nil {
		return model.OsqueryQuery{}, err
	}
	in.Platform = strings.TrimSpace(in.Platform)
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.Description = strings.TrimSpace(in.Description)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.OsqueryQuery{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO osquery_queries (id, name, description, sql, platform, interval_seconds, snapshot, removed, scheduled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		in.ID, in.Name, in.Description, strings.TrimSpace(in.SQL), in.Platform, in.Interval, in.Snapshot, in.Removed, in.Scheduled, in.ManagedBy, now, now)
	if err != nil {
		return model.OsqueryQuery{}, mapWriteErr(err)
	}
	in.SQL = strings.TrimSpace(in.SQL)
	if err := s.audit(ctx, tx, p, "create", "osquery_query", in.ID, in); err != nil {
		return model.OsqueryQuery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.OsqueryQuery{}, err
	}
	return in, nil
}

// ListOsqueryQueries returns every query ordered by name.
func (s *Store) ListOsqueryQueries(ctx context.Context) ([]model.OsqueryQuery, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+queryCols+` FROM osquery_queries ORDER BY name`)
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

// GetOsqueryQuery loads one query.
func (s *Store) GetOsqueryQuery(ctx context.Context, id string) (model.OsqueryQuery, error) {
	q, err := scanQuery(s.pool.QueryRow(ctx, `SELECT `+queryCols+` FROM osquery_queries WHERE id=$1`, id))
	if err != nil {
		return model.OsqueryQuery{}, notFound(err)
	}
	return q, nil
}

// UpdateOsqueryQuery replaces a query.
func (s *Store) UpdateOsqueryQuery(ctx context.Context, p model.Principal, id string, in model.OsqueryQuery) (model.OsqueryQuery, error) {
	cur, err := s.GetOsqueryQuery(ctx, id)
	if err != nil {
		return model.OsqueryQuery{}, err
	}
	if err := checkOsqueryName(in.Name); err != nil {
		return model.OsqueryQuery{}, err
	}
	if err := checkQuerySQL(in.SQL); err != nil {
		return model.OsqueryQuery{}, err
	}
	if in.Interval == 0 {
		in.Interval = 3600
	}
	if err := checkInterval(in.Interval); err != nil {
		return model.OsqueryQuery{}, err
	}
	now := s.now()
	in.ID = cur.ID
	in.ManagedBy = managedBy(in.ManagedBy)
	in.Description = strings.TrimSpace(in.Description)
	in.SQL = strings.TrimSpace(in.SQL)
	in.Platform = strings.TrimSpace(in.Platform)
	in.CreatedAt, in.UpdatedAt = cur.CreatedAt, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.OsqueryQuery{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		UPDATE osquery_queries SET name=$2, description=$3, sql=$4, platform=$5, interval_seconds=$6, snapshot=$7, removed=$8, scheduled=$9, managed_by=$10, updated_at=$11
		WHERE id=$1`,
		id, in.Name, in.Description, in.SQL, in.Platform, in.Interval, in.Snapshot, in.Removed, in.Scheduled, in.ManagedBy, now)
	if err != nil {
		return model.OsqueryQuery{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "osquery_query", id, in); err != nil {
		return model.OsqueryQuery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.OsqueryQuery{}, err
	}
	return in, nil
}

// DeleteOsqueryQuery removes a query that is not referenced by a pack.
func (s *Store) DeleteOsqueryQuery(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM osquery_queries WHERE id=$1`, id)
	if err != nil {
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "osquery_query", id, map[string]any{}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) validatePackRefs(ctx context.Context, tx pgx.Tx, queryIDs, labelNames []string) error {
	if len(queryIDs) > 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM osquery_queries WHERE id = ANY($1)`, queryIDs).Scan(&n); err != nil {
			return err
		}
		if n != len(queryIDs) {
			return invalid("unknown query_id")
		}
	}
	if len(labelNames) > 0 {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM osquery_labels WHERE name = ANY($1)`, labelNames).Scan(&n); err != nil {
			return err
		}
		if n != len(labelNames) {
			return invalid("unknown label")
		}
	}
	return nil
}

func (s *Store) replacePackQueries(ctx context.Context, tx pgx.Tx, packID string, queryIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM osquery_pack_queries WHERE pack_id=$1`, packID); err != nil {
		return err
	}
	for i, qid := range queryIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO osquery_pack_queries (pack_id, query_id, position) VALUES ($1,$2,$3)`, packID, qid, i); err != nil {
			return mapWriteErr(err)
		}
	}
	return nil
}

const packCols = `id, name, description, platform, interval_seconds, shard, discovery, labels, enabled, managed_by, created_at, updated_at`

func scanPack(row pgx.Row) (model.OsqueryPack, error) {
	var p model.OsqueryPack
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Platform, &p.Interval, &p.Shard, &p.Discovery, &p.Labels, &p.Enabled, &p.ManagedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return p, err
	}
	p.Discovery = normKeep(p.Discovery)
	p.Labels = normKeep(p.Labels)
	return p, nil
}

// normKeep turns a NULL array into an empty slice without dropping duplicates
// that were already stored. Callers that accept input use normStrings.
func normKeep(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func (s *Store) loadPackQueries(ctx context.Context, pack *model.OsqueryPack) error {
	rows, err := s.pool.Query(ctx, `
		SELECT q.id, q.name, q.interval_seconds, q.platform, q.snapshot
		FROM osquery_pack_queries pq
		JOIN osquery_queries q ON q.id = pq.query_id
		WHERE pq.pack_id=$1
		ORDER BY pq.position`, pack.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	pack.QueryIDs = []string{}
	pack.Queries = []model.OsqueryPackQuery{}
	for rows.Next() {
		var q model.OsqueryPackQuery
		if err := rows.Scan(&q.ID, &q.Name, &q.Interval, &q.Platform, &q.Snapshot); err != nil {
			return err
		}
		pack.QueryIDs = append(pack.QueryIDs, q.ID)
		pack.Queries = append(pack.Queries, q)
	}
	return rows.Err()
}

func preparePack(in model.OsqueryPack) (model.OsqueryPack, error) {
	if err := checkOsqueryName(in.Name); err != nil {
		return in, err
	}
	in.Description = strings.TrimSpace(in.Description)
	in.Platform = strings.TrimSpace(in.Platform)
	in.Discovery = normStrings(in.Discovery)
	for _, d := range in.Discovery {
		if err := checkQuerySQL(d); err != nil {
			return in, invalid("discovery: " + err.Error())
		}
	}
	in.Labels = normStrings(in.Labels)
	in.QueryIDs = normStrings(in.QueryIDs)
	if in.Interval != nil {
		if err := checkInterval(*in.Interval); err != nil {
			return in, err
		}
	}
	if in.Shard != nil && (*in.Shard < 1 || *in.Shard > 100) {
		return in, invalid("shard must be between 1 and 100")
	}
	return in, nil
}

// CreateOsqueryPack inserts a pack and its query membership.
func (s *Store) CreateOsqueryPack(ctx context.Context, p model.Principal, in model.OsqueryPack) (model.OsqueryPack, error) {
	in, err := preparePack(in)
	if err != nil {
		return model.OsqueryPack{}, err
	}
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.OsqueryPack{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.validatePackRefs(ctx, tx, in.QueryIDs, in.Labels); err != nil {
		return model.OsqueryPack{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO osquery_packs (id, name, description, platform, interval_seconds, shard, discovery, labels, enabled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		in.ID, in.Name, in.Description, in.Platform, in.Interval, in.Shard, in.Discovery, in.Labels, in.Enabled, in.ManagedBy, now, now)
	if err != nil {
		return model.OsqueryPack{}, mapWriteErr(err)
	}
	if err := s.replacePackQueries(ctx, tx, in.ID, in.QueryIDs); err != nil {
		return model.OsqueryPack{}, err
	}
	if err := s.audit(ctx, tx, p, "create", "osquery_pack", in.ID, in); err != nil {
		return model.OsqueryPack{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.OsqueryPack{}, err
	}
	return s.GetOsqueryPack(ctx, in.ID)
}

// GetOsqueryPack loads a pack and its queries.
func (s *Store) GetOsqueryPack(ctx context.Context, id string) (model.OsqueryPack, error) {
	p, err := scanPack(s.pool.QueryRow(ctx, `SELECT `+packCols+` FROM osquery_packs WHERE id=$1`, id))
	if err != nil {
		return model.OsqueryPack{}, notFound(err)
	}
	if err := s.loadPackQueries(ctx, &p); err != nil {
		return model.OsqueryPack{}, err
	}
	return p, nil
}

// ListOsqueryPacks returns every pack.
func (s *Store) ListOsqueryPacks(ctx context.Context) ([]model.OsqueryPack, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+packCols+` FROM osquery_packs ORDER BY name`)
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
		if err := s.loadPackQueries(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// UpdateOsqueryPack replaces a pack.
func (s *Store) UpdateOsqueryPack(ctx context.Context, p model.Principal, id string, in model.OsqueryPack) (model.OsqueryPack, error) {
	cur, err := s.GetOsqueryPack(ctx, id)
	if err != nil {
		return model.OsqueryPack{}, err
	}
	in, err = preparePack(in)
	if err != nil {
		return model.OsqueryPack{}, err
	}
	now := s.now()
	in.ID = cur.ID
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = cur.CreatedAt, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.OsqueryPack{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.validatePackRefs(ctx, tx, in.QueryIDs, in.Labels); err != nil {
		return model.OsqueryPack{}, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE osquery_packs SET name=$2, description=$3, platform=$4, interval_seconds=$5, shard=$6, discovery=$7, labels=$8, enabled=$9, managed_by=$10, updated_at=$11
		WHERE id=$1`,
		id, in.Name, in.Description, in.Platform, in.Interval, in.Shard, in.Discovery, in.Labels, in.Enabled, in.ManagedBy, now)
	if err != nil {
		return model.OsqueryPack{}, mapWriteErr(err)
	}
	if err := s.replacePackQueries(ctx, tx, id, in.QueryIDs); err != nil {
		return model.OsqueryPack{}, err
	}
	if err := s.audit(ctx, tx, p, "update", "osquery_pack", id, in); err != nil {
		return model.OsqueryPack{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.OsqueryPack{}, err
	}
	return s.GetOsqueryPack(ctx, id)
}

// DeleteOsqueryPack removes a pack.
func (s *Store) DeleteOsqueryPack(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM osquery_packs WHERE id=$1`, id)
	if err != nil {
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "osquery_pack", id, map[string]any{}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const labelCols = `id, name, description, kind, sql, platform, serials, device_ids, managed_by, created_at, updated_at`

func scanLabel(row pgx.Row) (model.OsqueryLabel, error) {
	var l model.OsqueryLabel
	err := row.Scan(&l.ID, &l.Name, &l.Description, &l.Kind, &l.SQL, &l.Platform, &l.Serials, &l.DeviceIDs, &l.ManagedBy, &l.CreatedAt, &l.UpdatedAt)
	if err != nil {
		return l, err
	}
	l.Serials = normKeep(l.Serials)
	l.DeviceIDs = normKeep(l.DeviceIDs)
	return l, nil
}

func prepareLabel(in model.OsqueryLabel) (model.OsqueryLabel, error) {
	if err := checkOsqueryName(in.Name); err != nil {
		return in, err
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	in.Description = strings.TrimSpace(in.Description)
	in.Platform = strings.TrimSpace(in.Platform)
	in.SQL = strings.TrimSpace(in.SQL)
	in.Serials = normStrings(in.Serials)
	in.DeviceIDs = normStrings(in.DeviceIDs)
	switch in.Kind {
	case "dynamic":
		if err := checkQuerySQL(in.SQL); err != nil {
			return in, err
		}
		if len(in.Serials) > 0 || len(in.DeviceIDs) > 0 {
			return in, invalid("dynamic labels do not take serials or device_ids")
		}
	case "manual":
		if in.SQL != "" {
			return in, invalid("manual labels do not take sql")
		}
	default:
		return in, invalid("kind must be dynamic or manual")
	}
	return in, nil
}

// CreateOsqueryLabel inserts a label and manual memberships.
func (s *Store) CreateOsqueryLabel(ctx context.Context, p model.Principal, in model.OsqueryLabel) (model.OsqueryLabel, error) {
	in, err := prepareLabel(in)
	if err != nil {
		return model.OsqueryLabel{}, err
	}
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.OsqueryLabel{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO osquery_labels (id, name, description, kind, sql, platform, serials, device_ids, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		in.ID, in.Name, in.Description, in.Kind, in.SQL, in.Platform, in.Serials, in.DeviceIDs, in.ManagedBy, now, now)
	if err != nil {
		return model.OsqueryLabel{}, mapWriteErr(err)
	}
	if in.Kind == "manual" {
		if err := s.rebuildManualLabel(ctx, tx, in.ID, in.Serials, in.DeviceIDs); err != nil {
			return model.OsqueryLabel{}, err
		}
	}
	if err := s.audit(ctx, tx, p, "create", "osquery_label", in.ID, in); err != nil {
		return model.OsqueryLabel{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.OsqueryLabel{}, err
	}
	return s.GetOsqueryLabel(ctx, in.ID)
}

// GetOsqueryLabel loads a label and its member count.
func (s *Store) GetOsqueryLabel(ctx context.Context, id string) (model.OsqueryLabel, error) {
	l, err := scanLabel(s.pool.QueryRow(ctx, `SELECT `+labelCols+` FROM osquery_labels WHERE id=$1`, id))
	if err != nil {
		return model.OsqueryLabel{}, notFound(err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(DISTINCT device_id) FROM osquery_label_members WHERE label_id=$1`, id).Scan(&l.Members); err != nil {
		return model.OsqueryLabel{}, err
	}
	return l, nil
}

// ListOsqueryLabels returns every label.
func (s *Store) ListOsqueryLabels(ctx context.Context) ([]model.OsqueryLabel, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+labelCols+` FROM osquery_labels ORDER BY name`)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.pool.QueryRow(ctx, `SELECT count(DISTINCT device_id) FROM osquery_label_members WHERE label_id=$1`, out[i].ID).Scan(&out[i].Members); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// UpdateOsqueryLabel replaces a label. Changing a dynamic query drops SQL membership until the next snapshot.
func (s *Store) UpdateOsqueryLabel(ctx context.Context, p model.Principal, id string, in model.OsqueryLabel) (model.OsqueryLabel, error) {
	cur, err := s.GetOsqueryLabel(ctx, id)
	if err != nil {
		return model.OsqueryLabel{}, err
	}
	in, err = prepareLabel(in)
	if err != nil {
		return model.OsqueryLabel{}, err
	}
	now := s.now()
	in.ID = cur.ID
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = cur.CreatedAt, now
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.OsqueryLabel{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		UPDATE osquery_labels SET name=$2, description=$3, kind=$4, sql=$5, platform=$6, serials=$7, device_ids=$8, managed_by=$9, updated_at=$10
		WHERE id=$1`,
		id, in.Name, in.Description, in.Kind, in.SQL, in.Platform, in.Serials, in.DeviceIDs, in.ManagedBy, now)
	if err != nil {
		return model.OsqueryLabel{}, mapWriteErr(err)
	}
	if in.Kind == "manual" {
		if _, err := tx.Exec(ctx, `DELETE FROM osquery_label_members WHERE label_id=$1 AND source='sql'`, id); err != nil {
			return model.OsqueryLabel{}, err
		}
		if err := s.rebuildManualLabel(ctx, tx, id, in.Serials, in.DeviceIDs); err != nil {
			return model.OsqueryLabel{}, err
		}
	} else {
		if _, err := tx.Exec(ctx, `DELETE FROM osquery_label_members WHERE label_id=$1 AND source='manual'`, id); err != nil {
			return model.OsqueryLabel{}, err
		}
		if cur.SQL != in.SQL || cur.Name != in.Name || cur.Kind != in.Kind {
			if _, err := tx.Exec(ctx, `DELETE FROM osquery_label_members WHERE label_id=$1 AND source='sql'`, id); err != nil {
				return model.OsqueryLabel{}, err
			}
		}
	}
	if err := s.audit(ctx, tx, p, "update", "osquery_label", id, in); err != nil {
		return model.OsqueryLabel{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.OsqueryLabel{}, err
	}
	return s.GetOsqueryLabel(ctx, id)
}

// DeleteOsqueryLabel removes a label.
func (s *Store) DeleteOsqueryLabel(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM osquery_labels WHERE id=$1`, id)
	if err != nil {
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "osquery_label", id, map[string]any{}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) rebuildManualLabel(ctx context.Context, tx pgx.Tx, labelID string, serials, deviceIDs []string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM osquery_label_members WHERE label_id=$1 AND source='manual'`, labelID); err != nil {
		return err
	}
	if len(serials) == 0 && len(deviceIDs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO osquery_label_members (label_id, device_id, source, updated_at)
		SELECT $1, d.id, 'manual', $2 FROM devices d
		WHERE (cardinality($3::text[]) > 0 AND d.serial = ANY($3))
		   OR (cardinality($4::text[]) > 0 AND d.id = ANY($4))
		ON CONFLICT DO NOTHING`,
		labelID, s.now(), serials, deviceIDs)
	return err
}

func (s *Store) syncDeviceManualLabels(ctx context.Context, tx pgx.Tx, deviceID, serial string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM osquery_label_members WHERE device_id=$1 AND source='manual'`, deviceID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO osquery_label_members (label_id, device_id, source, updated_at)
		SELECT l.id, $1, 'manual', $3 FROM osquery_labels l
		WHERE l.kind='manual' AND (
			($2 <> '' AND $2 = ANY(l.serials)) OR ($1 = ANY(l.device_ids))
		)
		ON CONFLICT DO NOTHING`,
		deviceID, serial, s.now())
	return err
}

// CreateEnrollSecret stores a hashed enroll secret. The raw value is not persisted.
func (s *Store) CreateEnrollSecret(ctx context.Context, p model.Principal, in model.EnrollSecret) (model.EnrollSecret, error) {
	if err := checkOsqueryName(in.Name); err != nil {
		return model.EnrollSecret{}, err
	}
	secret := strings.TrimSpace(in.Secret)
	if len(secret) < 8 {
		return model.EnrollSecret{}, invalid("secret must be at least 8 characters")
	}
	now := s.now()
	in.ID = newID()
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = now, now
	in.Secret = ""
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.EnrollSecret{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO osquery_enroll_secrets (id, name, secret_hash, enabled, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		in.ID, in.Name, auth.Hash(secret), in.Enabled, in.ManagedBy, now, now)
	if err != nil {
		return model.EnrollSecret{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "create", "osquery_enroll_secret", in.ID, map[string]any{"name": in.Name, "enabled": in.Enabled}); err != nil {
		return model.EnrollSecret{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.EnrollSecret{}, err
	}
	return in, nil
}

const secretCols = `id, name, enabled, managed_by, created_at, updated_at`

func scanSecret(row pgx.Row) (model.EnrollSecret, error) {
	var e model.EnrollSecret
	err := row.Scan(&e.ID, &e.Name, &e.Enabled, &e.ManagedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

// ListEnrollSecrets returns secrets without hashes.
func (s *Store) ListEnrollSecrets(ctx context.Context) ([]model.EnrollSecret, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+secretCols+` FROM osquery_enroll_secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.EnrollSecret{}
	for rows.Next() {
		e, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEnrollSecret loads one secret record. The raw secret is never returned.
func (s *Store) GetEnrollSecret(ctx context.Context, id string) (model.EnrollSecret, error) {
	e, err := scanSecret(s.pool.QueryRow(ctx, `SELECT `+secretCols+` FROM osquery_enroll_secrets WHERE id=$1`, id))
	if err != nil {
		return model.EnrollSecret{}, notFound(err)
	}
	return e, nil
}

// UpdateEnrollSecret rotates or disables a secret. An empty secret keeps the current hash.
func (s *Store) UpdateEnrollSecret(ctx context.Context, p model.Principal, id string, in model.EnrollSecret) (model.EnrollSecret, error) {
	cur, err := s.GetEnrollSecret(ctx, id)
	if err != nil {
		return model.EnrollSecret{}, err
	}
	if err := checkOsqueryName(in.Name); err != nil {
		return model.EnrollSecret{}, err
	}
	secret := strings.TrimSpace(in.Secret)
	if secret != "" && len(secret) < 8 {
		return model.EnrollSecret{}, invalid("secret must be at least 8 characters")
	}
	now := s.now()
	in.ID = cur.ID
	in.ManagedBy = managedBy(in.ManagedBy)
	in.CreatedAt, in.UpdatedAt = cur.CreatedAt, now
	in.Secret = ""
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.EnrollSecret{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if secret == "" {
		_, err = tx.Exec(ctx, `UPDATE osquery_enroll_secrets SET name=$2, enabled=$3, managed_by=$4, updated_at=$5 WHERE id=$1`,
			id, in.Name, in.Enabled, in.ManagedBy, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE osquery_enroll_secrets SET name=$2, secret_hash=$3, enabled=$4, managed_by=$5, updated_at=$6 WHERE id=$1`,
			id, in.Name, auth.Hash(secret), in.Enabled, in.ManagedBy, now)
	}
	if err != nil {
		return model.EnrollSecret{}, mapWriteErr(err)
	}
	if err := s.audit(ctx, tx, p, "update", "osquery_enroll_secret", id, map[string]any{"name": in.Name, "enabled": in.Enabled, "rotated": secret != ""}); err != nil {
		return model.EnrollSecret{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.EnrollSecret{}, err
	}
	return in, nil
}

// DeleteEnrollSecret removes a secret. Enrolled nodes keep their node keys.
func (s *Store) DeleteEnrollSecret(ctx context.Context, p model.Principal, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM osquery_enroll_secrets WHERE id=$1`, id)
	if err != nil {
		return mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := s.audit(ctx, tx, p, "delete", "osquery_enroll_secret", id, map[string]any{}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) enrollSecretOK(ctx context.Context, secret string) (bool, error) {
	if strings.TrimSpace(secret) == "" {
		return false, nil
	}
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM osquery_enroll_secrets WHERE secret_hash=$1 AND enabled`, auth.Hash(secret)).Scan(&n)
	return n > 0, err
}
