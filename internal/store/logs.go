package store

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/logs"
	"github.com/Arequ/mission-control/internal/model"
	"github.com/jackc/pgx/v5"
)

var logNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.+\-]{0,80}$`)
var logFieldRE = regexp.MustCompile(`^@?[A-Za-z_][A-Za-z0-9_.]{0,120}$`)
var logColorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
var logLabelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,40}$`)

func (s *Store) CreateLogView(ctx context.Context, p model.Principal, in model.LogView) (model.LogView, error) {
	return s.insertLogView(ctx, p, in, "elastic")
}

func (s *Store) insertLogView(ctx context.Context, p model.Principal, in model.LogView, reader string) (model.LogView, error) {
	if err := s.normalizeLogView(ctx, &in, reader); err != nil {
		return model.LogView{}, err
	}
	now := s.now()
	id := newID()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.LogView{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO log_views (
			id, name, description, default_window, max_lines, device_scoped, time_zone,
			elastic_url, elastic_api_key, connector_id, reader, managed_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,''),$11,$12,$13,$13)`,
		id, in.Name, in.Description, in.DefaultWindow, in.MaxLines, in.DeviceScoped, in.TimeZone,
		in.ElasticURL, in.ElasticAPIKey, in.ConnectorID, reader, managedBy(in.ManagedBy), now)
	if err != nil {
		return model.LogView{}, mapWriteErr(err)
	}
	if err := insertLogSources(ctx, tx, id, in.Sources); err != nil {
		return model.LogView{}, err
	}
	if err := s.audit(ctx, tx, p, "create", "log_view", id, logViewAudit(in)); err != nil {
		return model.LogView{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.LogView{}, err
	}
	return s.GetLogView(ctx, id)
}

func (s *Store) UpdateLogView(ctx context.Context, p model.Principal, id string, in model.LogView) (model.LogView, error) {
	cur, err := s.loadLogView(ctx, id)
	if err != nil {
		return model.LogView{}, err
	}
	if strings.TrimSpace(in.ElasticAPIKey) == "" {
		in.ElasticAPIKey = cur.ElasticAPIKey
	}
	reader := "elastic"
	if cur.Reader == "seed" && strings.TrimSpace(in.ElasticURL) == "" && strings.TrimSpace(in.ConnectorID) == "" {
		reader = "seed"
	}
	if err := s.normalizeLogView(ctx, &in, reader); err != nil {
		return model.LogView{}, err
	}
	now := s.now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.LogView{}, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE log_views SET
			name=$2, description=$3, default_window=$4, max_lines=$5, device_scoped=$6, time_zone=$7,
			elastic_url=$8, elastic_api_key=$9, connector_id=NULLIF($10,''), reader=$11, managed_by=$12, updated_at=$13
		WHERE id=$1`,
		id, in.Name, in.Description, in.DefaultWindow, in.MaxLines, in.DeviceScoped, in.TimeZone,
		in.ElasticURL, in.ElasticAPIKey, in.ConnectorID, reader, managedBy(in.ManagedBy), now)
	if err != nil {
		return model.LogView{}, mapWriteErr(err)
	}
	if tag.RowsAffected() == 0 {
		return model.LogView{}, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM log_view_sources WHERE view_id=$1`, id); err != nil {
		return model.LogView{}, err
	}
	if err := insertLogSources(ctx, tx, id, in.Sources); err != nil {
		return model.LogView{}, err
	}
	if err := s.audit(ctx, tx, p, "update", "log_view", id, logViewAudit(in)); err != nil {
		return model.LogView{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.LogView{}, err
	}
	return s.GetLogView(ctx, id)
}

func (s *Store) GetLogView(ctx context.Context, id string) (model.LogView, error) {
	v, err := s.loadLogView(ctx, id)
	if err != nil {
		return model.LogView{}, err
	}
	return v.Public(), nil
}

func (s *Store) ListLogViews(ctx context.Context, name string) ([]model.LogView, error) {
	q := `SELECT id FROM log_views`
	args := []any{}
	if name != "" {
		q += ` WHERE name=$1`
		args = append(args, name)
	}
	q += ` ORDER BY name`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]model.LogView, 0, len(ids))
	for _, id := range ids {
		v, err := s.GetLogView(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Store) DeleteLogView(ctx context.Context, p model.Principal, id string) error {
	cur, err := s.loadLogView(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM log_views WHERE id=$1`, id); err != nil {
		return err
	}
	if err := s.audit(ctx, tx, p, "delete", "log_view", id, map[string]any{"name": cur.Name}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RunLogView executes a view. Secrets stay in the store.
func (s *Store) RunLogView(ctx context.Context, p model.Principal, id string, run model.LogRun) (logs.Page, error) {
	return s.execLog(ctx, p, id, run, "run")
}

// TailLogView returns lines strictly after a cursor, extending the window to now.
func (s *Store) TailLogView(ctx context.Context, p model.Principal, id string, run model.LogRun) (logs.Page, error) {
	run.Extend = true
	run.Dir = "forward"
	return s.execLog(ctx, p, id, run, "tail")
}

// ContextLogView returns neighboring lines around a line id.
func (s *Store) ContextLogView(ctx context.Context, p model.Principal, id, lineID, deviceID string, before, after int) (logs.Context, error) {
	view, eng, bind, err := s.prepareRun(ctx, id, deviceID)
	if err != nil {
		return logs.Context{}, err
	}
	out, err := eng.Context(ctx, view, bind, lineID, before, after)
	s.auditRun(ctx, p, id, view.Name, deviceID, "context", len(out.Lines), err)
	if err != nil {
		return logs.Context{}, mapLogErr(err)
	}
	return out, nil
}

func (s *Store) execLog(ctx context.Context, p model.Principal, id string, run model.LogRun, op string) (logs.Page, error) {
	stored, err := s.loadLogView(ctx, id)
	if err != nil {
		return logs.Page{}, err
	}
	if run.From.IsZero() || run.To.IsZero() {
		win, err := logs.ParseWindow(stored.DefaultWindow)
		if err != nil {
			return logs.Page{}, invalid(err.Error())
		}
		if run.To.IsZero() {
			run.To = s.now()
		}
		if run.From.IsZero() {
			run.From = run.To.Add(-win)
		}
	}
	view, eng, bind, err := s.prepareLoaded(ctx, stored, run.DeviceID)
	if err != nil {
		return logs.Page{}, err
	}
	page, err := eng.Run(ctx, logs.RunRequest{
		View: view, Bind: bind, From: run.From, To: run.To, Limit: run.Limit,
		Cursor: run.Cursor, Dir: run.Dir, Align: run.Align, Extend: run.Extend,
	})
	s.auditRun(ctx, p, id, stored.Name, run.DeviceID, op, len(page.Lines), err)
	if err != nil {
		return logs.Page{}, mapLogErr(err)
	}
	return page, nil
}

func (s *Store) prepareRun(ctx context.Context, id, deviceID string) (logs.View, *logs.Engine, *logs.Bind, error) {
	stored, err := s.loadLogView(ctx, id)
	if err != nil {
		return logs.View{}, nil, nil, err
	}
	return s.prepareLoaded(ctx, stored, deviceID)
}

func (s *Store) prepareLoaded(ctx context.Context, stored model.LogView, deviceID string) (logs.View, *logs.Engine, *logs.Bind, error) {
	var bind *logs.Bind
	if stored.DeviceScoped || logsNeedBind(stored) {
		if strings.TrimSpace(deviceID) == "" {
			return logs.View{}, nil, nil, invalid("device_id is required for this log view")
		}
		b, err := s.deviceBind(ctx, deviceID)
		if err != nil {
			return logs.View{}, nil, nil, err
		}
		bind = &b
	}
	view := logsView(stored)
	var reader logs.Reader
	if stored.Reader == "seed" {
		reader = logs.Seed{}
	} else {
		base, key, err := s.resolveElastic(ctx, stored)
		if err != nil {
			return logs.View{}, nil, nil, err
		}
		if base == "" {
			return logs.View{}, nil, nil, invalid("log view has no Elasticsearch connection")
		}
		reader = &logs.Elastic{Base: base, APIKey: key, HTTP: &http.Client{Timeout: 15 * time.Second}}
	}
	return view, &logs.Engine{Reader: reader, Now: s.now}, bind, nil
}

func logsNeedBind(v model.LogView) bool {
	for _, src := range v.Sources {
		if logs.UsesPlaceholder(src.KQL) {
			return true
		}
	}
	return false
}

func (s *Store) resolveElastic(ctx context.Context, v model.LogView) (string, string, error) {
	base := strings.TrimSpace(v.ElasticURL)
	key := v.ElasticAPIKey
	if v.ConnectorID != "" {
		c, err := s.loadConnector(ctx, v.ConnectorID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return "", "", invalid("connector_id was not found")
			}
			return "", "", err
		}
		if base == "" {
			base = c.ElasticURL
		}
		if key == "" {
			key = c.elasticAPIKey
		}
	}
	return base, key, nil
}

func (s *Store) deviceBind(ctx context.Context, id string) (logs.Bind, error) {
	var b logs.Bind
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(serial, ''), COALESCE(hostname, ''), COALESCE(hardware_uuid, '')
		FROM devices WHERE id=$1`, id).Scan(&b.Serial, &b.Hostname, &b.HardwareUUID)
	if err != nil {
		return logs.Bind{}, notFound(err)
	}
	return b, nil
}

func (s *Store) auditRun(ctx context.Context, p model.Principal, id, name, deviceID, op string, lines int, runErr error) {
	detail := map[string]any{"name": name, "op": op, "lines": lines}
	if deviceID != "" {
		detail["device_id"] = deviceID
	}
	if runErr != nil {
		detail["error"] = clipErr(runErr)
		detail["lines"] = 0
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if err := s.audit(ctx, tx, p, "run", "log_view", id, detail); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

func clipErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func mapLogErr(err error) error {
	var ve *logs.Error
	if errors.As(err, &ve) {
		return invalid(ve.Error())
	}
	if errors.Is(err, logs.ErrNotFound) {
		return ErrNotFound
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return invalid("log query timed out")
	}
	return err
}

func logsView(v model.LogView) logs.View {
	out := logs.View{
		ID: v.ID, Name: v.Name, TimeZone: v.TimeZone, MaxLines: v.MaxLines,
		DeviceScoped: v.DeviceScoped, ReaderName: v.Reader, ElasticURL: v.ElasticURL,
		Sources: make([]logs.Source, len(v.Sources)),
	}
	for i, src := range v.Sources {
		out.Sources[i] = logs.Source{
			Index: i, Label: src.Label, Color: src.Color, IndexPattern: src.IndexPattern,
			KQL: src.KQL, MessageField: src.MessageField, TimestampField: src.TimestampField,
			FileField: src.FileField, HostField: src.HostField, SequenceField: src.SequenceField,
		}
	}
	return out
}

func (s *Store) normalizeLogView(ctx context.Context, in *model.LogView, reader string) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.ElasticURL = strings.TrimSpace(in.ElasticURL)
	in.ConnectorID = strings.TrimSpace(in.ConnectorID)
	in.ElasticAPIKey = strings.TrimSpace(in.ElasticAPIKey)
	if !logNameRE.MatchString(in.Name) {
		return invalid("name must be 1–81 characters of letters, numbers, spaces, '.', '_', '+', or '-'")
	}
	if len(in.Description) > 500 {
		return invalid("description is too long")
	}
	if in.DefaultWindow == "" {
		in.DefaultWindow = "1h"
	}
	if _, err := logs.ParseWindow(in.DefaultWindow); err != nil {
		return invalid(err.Error())
	}
	if in.MaxLines == 0 {
		in.MaxLines = 5000
	}
	if in.MaxLines < 1 || in.MaxLines > logs.MaxViewLines {
		return invalid("max_lines must be between 1 and 100000")
	}
	if in.TimeZone == "" {
		in.TimeZone = "UTC"
	}
	if _, err := logs.LoadLocation(in.TimeZone); err != nil {
		return invalid(err.Error())
	}
	if err := checkHTTPURL("elastic_url", in.ElasticURL); err != nil {
		return err
	}
	if len(in.ElasticAPIKey) > 4000 {
		return invalid("credential is too long")
	}
	if in.ConnectorID != "" {
		if _, err := s.loadConnector(ctx, in.ConnectorID); err != nil {
			if errors.Is(err, ErrNotFound) {
				return invalid("connector_id was not found")
			}
			return err
		}
	}
	if reader != "seed" && in.ElasticURL == "" && in.ConnectorID == "" {
		return invalid("elastic_url or connector_id is required")
	}
	if len(in.Sources) < 1 || len(in.Sources) > logs.MaxSources {
		return invalid("a log view needs between 1 and 8 sources")
	}
	placeholders := false
	seen := map[string]bool{}
	for i := range in.Sources {
		src := &in.Sources[i]
		src.Label = strings.TrimSpace(src.Label)
		src.Color = strings.TrimSpace(src.Color)
		src.IndexPattern = strings.TrimSpace(src.IndexPattern)
		src.KQL = strings.TrimSpace(src.KQL)
		src.MessageField = strings.TrimSpace(src.MessageField)
		src.TimestampField = strings.TrimSpace(src.TimestampField)
		src.FileField = strings.TrimSpace(src.FileField)
		src.HostField = strings.TrimSpace(src.HostField)
		src.SequenceField = strings.TrimSpace(src.SequenceField)
		if !logLabelRE.MatchString(src.Label) {
			return invalid("source label must be 1–41 letters, numbers, spaces, or ._+-")
		}
		if seen[strings.ToLower(src.Label)] {
			return invalid("source labels must be unique in a view")
		}
		seen[strings.ToLower(src.Label)] = true
		if src.Color != "" && !logColorRE.MatchString(src.Color) {
			return invalid("source color must be a #rrggbb hex color")
		}
		if !indexOK(src.IndexPattern) {
			return invalid("index pattern must be a single pattern without a path")
		}
		if !logFieldRE.MatchString(src.MessageField) || !logFieldRE.MatchString(src.TimestampField) {
			return invalid("message_field and timestamp_field must be dotted paths")
		}
		for _, f := range []string{src.FileField, src.HostField, src.SequenceField} {
			if f != "" && !logFieldRE.MatchString(f) {
				return invalid("optional fields must be dotted paths")
			}
		}
		if len(src.KQL) > 4000 {
			return invalid("kql is too long")
		}
		if logs.UsesPlaceholder(src.KQL) {
			placeholders = true
		}
		check := src.KQL
		if strings.Contains(check, "{{") {
			var subErr error
			check, subErr = logs.Substitute(check, logs.Bind{Serial: "s", Hostname: "h", HardwareUUID: "u"})
			if subErr != nil {
				return invalid("source " + src.Label + ": " + subErr.Error())
			}
		}
		if _, err := logs.Compile(check, src.MessageField); err != nil {
			return invalid("source " + src.Label + ": " + err.Error())
		}
	}
	if in.DeviceScoped && !placeholders {
		return invalid("a device-scoped view must use {{serial}}, {{hostname}}, or {{hardware_uuid}}")
	}
	if !in.DeviceScoped && placeholders {
		return invalid("placeholders require device_scoped")
	}
	return nil
}

func indexOK(index string) bool {
	if index == "" || len(index) > 200 || strings.Contains(index, "..") {
		return false
	}
	for _, r := range index {
		switch {
		case r == '*' || r == '.' || r == '_' || r == '-' || r == '@':
			continue
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			continue
		default:
			return false
		}
	}
	return true
}

func logViewAudit(in model.LogView) map[string]any {
	labels := make([]string, len(in.Sources))
	for i, src := range in.Sources {
		labels[i] = src.Label
	}
	return map[string]any{
		"name": in.Name, "device_scoped": in.DeviceScoped, "default_window": in.DefaultWindow,
		"max_lines": in.MaxLines, "sources": labels, "connector_id": in.ConnectorID,
		"has_elastic_api_key": in.ElasticAPIKey != "",
	}
}

func (s *Store) loadLogView(ctx context.Context, id string) (model.LogView, error) {
	var v model.LogView
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, description, default_window, max_lines, device_scoped, time_zone,
			elastic_url, elastic_api_key, COALESCE(connector_id, ''), reader, managed_by, created_at, updated_at
		FROM log_views WHERE id=$1`, id).Scan(
		&v.ID, &v.Name, &v.Description, &v.DefaultWindow, &v.MaxLines, &v.DeviceScoped, &v.TimeZone,
		&v.ElasticURL, &v.ElasticAPIKey, &v.ConnectorID, &v.Reader, &v.ManagedBy, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return model.LogView{}, notFound(err)
	}
	v.HasElasticAPIKey = v.ElasticAPIKey != ""
	rows, err := s.pool.Query(ctx, `
		SELECT id, label, color, index_pattern, kql, message_field, timestamp_field, file_field, host_field, sequence_field
		FROM log_view_sources WHERE view_id=$1 ORDER BY position`, id)
	if err != nil {
		return model.LogView{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var src model.LogSource
		if err := rows.Scan(&src.ID, &src.Label, &src.Color, &src.IndexPattern, &src.KQL,
			&src.MessageField, &src.TimestampField, &src.FileField, &src.HostField, &src.SequenceField); err != nil {
			return model.LogView{}, err
		}
		v.Sources = append(v.Sources, src)
	}
	if v.Sources == nil {
		v.Sources = []model.LogSource{}
	}
	return v, rows.Err()
}

func insertLogSources(ctx context.Context, tx pgx.Tx, viewID string, sources []model.LogSource) error {
	for i, src := range sources {
		_, err := tx.Exec(ctx, `
			INSERT INTO log_view_sources (
				id, view_id, position, label, color, index_pattern, kql,
				message_field, timestamp_field, file_field, host_field, sequence_field)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			newID(), viewID, i, src.Label, src.Color, src.IndexPattern, src.KQL,
			src.MessageField, src.TimestampField, src.FileField, src.HostField, src.SequenceField)
		if err != nil {
			return mapWriteErr(err)
		}
	}
	return nil
}
