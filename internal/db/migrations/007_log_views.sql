-- Named log views. Credentials are write-only; the API never returns elastic_api_key.

CREATE TABLE log_views (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    default_window TEXT NOT NULL DEFAULT '1h',
    max_lines INT NOT NULL DEFAULT 5000,
    device_scoped BOOLEAN NOT NULL DEFAULT FALSE,
    time_zone TEXT NOT NULL DEFAULT 'UTC',
    elastic_url TEXT NOT NULL DEFAULT '',
    elastic_api_key TEXT NOT NULL DEFAULT '',
    connector_id TEXT REFERENCES source_connectors (id) ON DELETE SET NULL,
    reader TEXT NOT NULL DEFAULT 'elastic',
    managed_by TEXT NOT NULL DEFAULT 'terraform',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE log_view_sources (
    id TEXT PRIMARY KEY,
    view_id TEXT NOT NULL REFERENCES log_views (id) ON DELETE CASCADE,
    position INT NOT NULL,
    label TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '',
    index_pattern TEXT NOT NULL,
    kql TEXT NOT NULL DEFAULT '',
    message_field TEXT NOT NULL,
    timestamp_field TEXT NOT NULL,
    file_field TEXT NOT NULL DEFAULT '',
    host_field TEXT NOT NULL DEFAULT '',
    sequence_field TEXT NOT NULL DEFAULT '',
    UNIQUE (view_id, position)
);

CREATE INDEX log_view_sources_view_idx ON log_view_sources (view_id, position);
