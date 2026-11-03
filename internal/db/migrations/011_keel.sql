-- Keel configuration agent: enroll secrets, per-serial Ed25519 report keys,
-- and a bounded history of signed run reports.
-- Enroll secrets are stored as SHA-256 only and never selected into API
-- responses. last_timestamp is the replay floor for a serial's reports.

CREATE TABLE keel_enroll_secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'terraform',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE keel_device_keys (
    serial TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    enroll_secret_id TEXT NOT NULL DEFAULT '',
    enrolled_at TIMESTAMPTZ NOT NULL,
    last_timestamp BIGINT NOT NULL DEFAULT 0,
    last_report_at TIMESTAMPTZ
);

CREATE TABLE keel_runs (
    id BIGSERIAL PRIMARY KEY,
    serial TEXT NOT NULL,
    run_id TEXT NOT NULL,
    report_timestamp BIGINT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('apply', 'plan')),
    keel_version TEXT NOT NULL DEFAULT '',
    duration_ms BIGINT NOT NULL DEFAULT 0,
    hostname TEXT NOT NULL DEFAULT '',
    leaf_role TEXT NOT NULL DEFAULT '',
    leaf_match TEXT NOT NULL DEFAULT '',
    roles TEXT[] NOT NULL DEFAULT '{}',
    total INT NOT NULL DEFAULT 0,
    ok INT NOT NULL DEFAULT 0,
    changed INT NOT NULL DEFAULT 0,
    would_change INT NOT NULL DEFAULT 0,
    failed INT NOT NULL DEFAULT 0,
    skipped INT NOT NULL DEFAULT 0,
    -- warnings are policy decisions for a human; one starting "compile: "
    -- means the policy did not compile and the run is a failure.
    warnings TEXT[] NOT NULL DEFAULT '{}',
    compile_error BOOLEAN NOT NULL DEFAULT false,
    body JSONB NOT NULL,
    UNIQUE (serial, run_id)
);
CREATE INDEX keel_runs_serial_idx ON keel_runs (serial, id DESC);
