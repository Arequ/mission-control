-- osquery fleet inventory: enroll, config, logs, labels, and live queries.

CREATE TABLE osquery_enroll_secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE osquery_queries (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    sql TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT '',
    interval_seconds INT NOT NULL DEFAULT 3600 CHECK (interval_seconds >= 1 AND interval_seconds <= 604800),
    snapshot BOOLEAN NOT NULL DEFAULT false,
    removed BOOLEAN NOT NULL DEFAULT true,
    scheduled BOOLEAN NOT NULL DEFAULT false,
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE osquery_labels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL CHECK (kind IN ('dynamic', 'manual')),
    sql TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    serials TEXT[] NOT NULL DEFAULT '{}',
    device_ids TEXT[] NOT NULL DEFAULT '{}',
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE osquery_packs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    interval_seconds INT CHECK (interval_seconds IS NULL OR (interval_seconds >= 1 AND interval_seconds <= 604800)),
    shard INT CHECK (shard IS NULL OR (shard >= 1 AND shard <= 100)),
    discovery TEXT[] NOT NULL DEFAULT '{}',
    labels TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE osquery_pack_queries (
    pack_id TEXT NOT NULL REFERENCES osquery_packs(id) ON DELETE CASCADE,
    query_id TEXT NOT NULL REFERENCES osquery_queries(id) ON DELETE RESTRICT,
    position INT NOT NULL,
    PRIMARY KEY (pack_id, query_id)
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    node_key_hash TEXT NOT NULL UNIQUE,
    node_invalid BOOLEAN NOT NULL DEFAULT false,
    host_identifier TEXT NOT NULL DEFAULT '',
    hardware_uuid TEXT NOT NULL DEFAULT '',
    serial TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    computer_name TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    os_name TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    os_build TEXT NOT NULL DEFAULT '',
    hardware_model TEXT NOT NULL DEFAULT '',
    hardware_vendor TEXT NOT NULL DEFAULT '',
    cpu_brand TEXT NOT NULL DEFAULT '',
    cpu_type TEXT NOT NULL DEFAULT '',
    cpu_physical_cores INT NOT NULL DEFAULT 0,
    cpu_logical_cores INT NOT NULL DEFAULT 0,
    physical_memory BIGINT NOT NULL DEFAULT 0,
    primary_ip TEXT NOT NULL DEFAULT '',
    primary_mac TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    disk_encrypted BOOLEAN,
    uptime_seconds BIGINT NOT NULL DEFAULT 0,
    osquery_version TEXT NOT NULL DEFAULT '',
    apps_initialized BOOLEAN NOT NULL DEFAULT false,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX devices_hardware_uuid_idx ON devices (hardware_uuid) WHERE hardware_uuid <> '';
CREATE UNIQUE INDEX devices_serial_idx ON devices (serial) WHERE serial <> '';
CREATE INDEX devices_last_seen_idx ON devices (last_seen_at DESC NULLS LAST);
CREATE INDEX devices_platform_idx ON devices (platform);
CREATE INDEX devices_hostname_idx ON devices (lower(hostname));

CREATE TABLE device_apps (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    bundle_id TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, path)
);
CREATE INDEX device_apps_name_idx ON device_apps (lower(name));

CREATE TABLE device_query_results (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    query_name TEXT NOT NULL,
    result_rows JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (device_id, query_name)
);

CREATE TABLE osquery_label_members (
    label_id TEXT NOT NULL REFERENCES osquery_labels(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('sql', 'manual')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (label_id, device_id, source)
);
CREATE INDEX osquery_label_members_device_idx ON osquery_label_members (device_id);

CREATE TABLE osquery_result_logs (
    id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    query_name TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    columns JSONB NOT NULL,
    unix_time BIGINT NOT NULL DEFAULT 0,
    received_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX osquery_result_logs_device_idx ON osquery_result_logs (device_id, received_at DESC);
CREATE INDEX osquery_result_logs_query_idx ON osquery_result_logs (query_name, received_at DESC);

CREATE TABLE osquery_status_logs (
    id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    severity TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL DEFAULT '',
    line INT NOT NULL DEFAULT 0,
    message TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    received_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX osquery_status_logs_device_idx ON osquery_status_logs (device_id, received_at DESC);

CREATE TABLE live_queries (
    id TEXT PRIMARY KEY,
    sql TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    timeout_seconds INT NOT NULL DEFAULT 30 CHECK (timeout_seconds >= 1 AND timeout_seconds <= 3600),
    created_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ
);
CREATE INDEX live_queries_created_idx ON live_queries (created_at DESC);

CREATE TABLE live_query_targets (
    live_query_id TEXT NOT NULL REFERENCES live_queries(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    status_code INT,
    error TEXT NOT NULL DEFAULT '',
    result_rows JSONB,
    sent_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (live_query_id, device_id)
);
CREATE INDEX live_query_targets_pending_idx ON live_query_targets (device_id) WHERE status IN ('pending', 'sent');
