-- Mission Control foundation schema.

CREATE TABLE api_tokens (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE TABLE devices (
    id UUID PRIMARY KEY,
    node_key_hash TEXT NOT NULL UNIQUE,
    host_identifier TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    computer_name TEXT NOT NULL DEFAULT '',
    uuid TEXT NOT NULL DEFAULT '',
    hardware_serial TEXT NOT NULL DEFAULT '',
    hardware_model TEXT NOT NULL DEFAULT '',
    hardware_vendor TEXT NOT NULL DEFAULT '',
    cpu_brand TEXT NOT NULL DEFAULT '',
    cpu_physical_cores INT NOT NULL DEFAULT 0,
    physical_memory BIGINT NOT NULL DEFAULT 0,
    platform TEXT NOT NULL DEFAULT '',
    os_name TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    os_build TEXT NOT NULL DEFAULT '',
    osquery_version TEXT NOT NULL DEFAULT '',
    primary_user TEXT NOT NULL DEFAULT '',
    config_hash TEXT NOT NULL DEFAULT '',
    labels TEXT[] NOT NULL DEFAULT '{}',
    inventory JSONB NOT NULL DEFAULT '{}',
    last_seen_at TIMESTAMPTZ,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX devices_serial_uidx ON devices (hardware_serial) WHERE hardware_serial <> '';
CREATE INDEX devices_host_identifier_idx ON devices (host_identifier);
CREATE INDEX devices_last_seen_idx ON devices (last_seen_at DESC);

CREATE TABLE device_apps (
    device_id UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    bundle_id TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, name, bundle_id, path)
);

CREATE INDEX device_apps_name_idx ON device_apps (name);

CREATE TABLE query_results (
    id BIGSERIAL PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    snapshot JSONB,
    added JSONB,
    removed JSONB
);

CREATE INDEX query_results_device_idx ON query_results (device_id, collected_at DESC);

CREATE TABLE resources (
    id UUID PRIMARY KEY,
    api_version TEXT NOT NULL,
    kind TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}',
    annotations JSONB NOT NULL DEFAULT '{}',
    spec JSONB NOT NULL,
    spec_hash TEXT NOT NULL,
    managed_by TEXT NOT NULL,
    source_path TEXT NOT NULL DEFAULT '',
    generation BIGINT NOT NULL DEFAULT 1,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, namespace, name)
);

CREATE TABLE distributed_queries (
    id UUID PRIMARY KEY,
    sql TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE distributed_targets (
    query_id UUID NOT NULL REFERENCES distributed_queries (id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    results JSONB,
    osquery_status INT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (query_id, device_id)
);

CREATE TABLE runners (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    labels JSONB NOT NULL DEFAULT '{}',
    autopkg_version TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE autopkg_jobs (
    id UUID PRIMARY KEY,
    pipeline_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    runner_id UUID REFERENCES runners (id),
    spec JSONB NOT NULL DEFAULT '{}',
    logs TEXT NOT NULL DEFAULT '',
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX autopkg_jobs_status_idx ON autopkg_jobs (status, created_at);
