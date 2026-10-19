package store

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/Arequ/mission-control/internal/model"
)

// SyncDueConnectors polls connectors whose interval has elapsed.
// A connector error is stored on the row and does not fail the scheduler.
// Credentials are not written to the audit log or the process log.
func (s *Store) SyncDueConnectors(ctx context.Context) error {
	all, err := s.loadConnectors(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	for _, c := range all {
		if !c.Enabled {
			continue
		}
		if c.LastSyncAt != nil && now.Sub(c.LastSyncAt.UTC()) < time.Duration(c.IntervalSeconds)*time.Second {
			continue
		}
		s.syncConnector(ctx, c)
	}
	return nil
}

func (s *Store) syncConnector(ctx context.Context, c storedConnector) {
	locked, err := s.lockConnector(ctx, c.ID)
	if err != nil {
		slog.Error("connector sync lock", "connector", c.ID, "source", c.Source, "err", err.Error())
		return
	}
	if !locked {
		return
	}
	defer s.unlockConnector(ctx, c.ID)
	status := "ok"
	count := 0
	msg := ""
	switch {
	case c.Mode == "native" && c.Source == "osquery":
		err = s.ProjectOsquery(ctx)
		if err == nil {
			count, err = s.countSnapshots(ctx, c.Source)
		}
	case c.Mode == "native" && c.Source == "munki":
		err = s.ProjectMunki(ctx)
		if err == nil {
			count, err = s.countSnapshots(ctx, c.Source)
		}
	case c.Mode == "native":
		count, err = s.countSnapshots(ctx, c.Source)
	default:
		count, err = s.pollConnector(ctx, c)
	}
	if err != nil {
		status = "error"
		msg = redact(err.Error(), c.clientSecret, c.apiToken, c.elasticAPIKey, c.ClientID)
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	now := s.now()
	if _, dbErr := s.pool.Exec(ctx, `
		UPDATE source_connectors
		SET last_sync_at=$2, last_sync_status=$3, last_sync_error=$4, last_sync_count=$5, updated_at=$2
		WHERE id=$1`, c.ID, now, status, msg, count); dbErr != nil {
		slog.Error("connector sync status", "connector", c.ID, "source", c.Source, "err", dbErr.Error())
		return
	}
	tx, txErr := s.pool.Begin(ctx)
	if txErr == nil {
		_ = s.audit(ctx, tx, model.System, "sync", "source_connector", c.ID, map[string]any{
			"source": c.Source, "status": status, "count": count,
		})
		_ = tx.Commit(ctx)
	}
	if status != "ok" {
		slog.Info("connector sync", "connector", c.ID, "source", c.Source, "status", status, "err", msg)
	}
}

func (s *Store) pollConnector(ctx context.Context, c storedConnector) (int, error) {
	poller, err := coverage.PollerFor(c.Source, c.Mode)
	if err != nil {
		return 0, err
	}
	lookback := time.Duration(c.StaleAfterSeconds) * time.Second * 4
	if lookback < 14*24*time.Hour {
		lookback = 14 * 24 * time.Hour
	}
	hc := &http.Client{Timeout: 20 * time.Second}
	obs, err := poller.Poll(ctx, coverage.Config{
		Source: c.Source, Mode: c.Mode, BaseURL: c.BaseURL, ClientID: c.ClientID,
		ClientSecret: c.clientSecret, APIToken: c.apiToken, ElasticURL: c.ElasticURL,
		ElasticAPIKey: c.elasticAPIKey, IndexPattern: c.IndexPattern, Query: c.Query,
		QueryLanguage: c.QueryLanguage, TimeField: c.TimeField, TimeZone: c.TimeZone, FieldMap: c.FieldMap,
		Lookback: lookback, Now: s.now(),
	}, hc)
	if err != nil {
		return 0, err
	}
	opts := applyOpts{full: true, events: true}
	if c.Mode == "elastic" {
		opts.keepBefore = s.now().Add(-lookback)
	}
	if err := s.applyObservations(ctx, c.Source, obs, opts); err != nil {
		return 0, err
	}
	return len(obs), nil
}

func (s *Store) lockConnector(ctx context.Context, id string) (bool, error) {
	now := s.now()
	tag, err := s.pool.Exec(ctx, `
		UPDATE source_connectors
		SET sync_lock_until = $2
		WHERE id = $1 AND (sync_lock_until IS NULL OR sync_lock_until < $3)`,
		id, now.Add(2*time.Minute), now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) unlockConnector(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, `UPDATE source_connectors SET sync_lock_until = NULL WHERE id = $1`, id)
}

func (s *Store) countSnapshots(ctx context.Context, source string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM source_snapshots WHERE source=$1`, source).Scan(&n)
	return n, err
}

func redact(msg string, secrets ...string) string {
	for _, secret := range secrets {
		if len(secret) < 4 {
			continue
		}
		for _, form := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
			if form == "" {
				continue
			}
			msg = strings.ReplaceAll(msg, form, "[redacted]")
		}
	}
	return msg
}
