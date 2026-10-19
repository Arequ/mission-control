-- Per-source snapshots, identity links, and Terraform-managed connectors.
-- Secrets live in this table and are never selected into API responses.

CREATE TABLE source_connectors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL CHECK (mode IN ('api', 'elastic', 'native')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    interval_seconds INT NOT NULL DEFAULT 900 CHECK (interval_seconds >= 60 AND interval_seconds <= 604800),
    stale_after_seconds INT NOT NULL DEFAULT 86400 CHECK (stale_after_seconds >= 60 AND stale_after_seconds <= 31536000),
    base_url TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    client_secret TEXT NOT NULL DEFAULT '',
    api_token TEXT NOT NULL DEFAULT '',
    elastic_url TEXT NOT NULL DEFAULT '',
    elastic_api_key TEXT NOT NULL DEFAULT '',
    index_pattern TEXT NOT NULL DEFAULT '',
    query_text TEXT NOT NULL DEFAULT '',
    query_language TEXT NOT NULL DEFAULT 'kql' CHECK (query_language IN ('kql', 'dsl')),
    time_field TEXT NOT NULL DEFAULT '@timestamp',
    field_map JSONB NOT NULL DEFAULT '{}'::jsonb,
    managed_by TEXT NOT NULL DEFAULT 'api',
    last_sync_at TIMESTAMPTZ,
    last_sync_status TEXT NOT NULL DEFAULT '',
    last_sync_error TEXT NOT NULL DEFAULT '',
    last_sync_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (source IN ('osquery', 'munki', 'crowdstrike', 'rapid7', 'netskope', 'proofpoint', 'blastshield', 'kolide'))
);

CREATE TABLE source_snapshots (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    native_id TEXT NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    subject_id TEXT NOT NULL,
    ghost_key TEXT NOT NULL DEFAULT '',
    serial TEXT NOT NULL DEFAULT '',
    hardware_uuid TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    primary_user TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    fields JSONB NOT NULL DEFAULT '{}'::jsonb,
    matched_on TEXT[] NOT NULL DEFAULT '{}',
    confidence TEXT NOT NULL DEFAULT 'none',
    match_note TEXT NOT NULL DEFAULT '',
    last_seen_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (source, native_id)
);
CREATE INDEX source_snapshots_subject_idx ON source_snapshots (subject_id);
CREATE INDEX source_snapshots_device_idx ON source_snapshots (device_id);
CREATE INDEX source_snapshots_source_idx ON source_snapshots (source);

CREATE TABLE coverage_events (
    id BIGSERIAL PRIMARY KEY,
    subject_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    at TIMESTAMPTZ NOT NULL
);
CREATE INDEX coverage_events_subject_idx ON coverage_events (subject_id, at DESC);
