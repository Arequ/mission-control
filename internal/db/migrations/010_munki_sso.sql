-- Munki client enrollment, check-in state, and web SSO sessions.
-- Enrollment and OIDC client secrets are stored for server use and are never
-- selected into API responses. Per-device tokens are stored as SHA-256 only.

ALTER TABLE manifests ADD COLUMN conditional_items JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE munki_enrollments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL,
    manifest TEXT NOT NULL DEFAULT 'site_default',
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'terraform',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE munki_clients (
    id TEXT PRIMARY KEY,
    serial TEXT NOT NULL UNIQUE,
    enrollment_id TEXT NOT NULL REFERENCES munki_enrollments(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL DEFAULT '',
    manifest TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'terraform',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE munki_device_state (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    last_run_start TIMESTAMPTZ,
    last_run_end TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT '',
    pending_installs JSONB NOT NULL DEFAULT '[]'::jsonb,
    pending_removals JSONB NOT NULL DEFAULT '[]'::jsonb,
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    munki_version TEXT NOT NULL DEFAULT '',
    console_user TEXT NOT NULL DEFAULT '',
    manifest_name TEXT NOT NULL DEFAULT '',
    report_hash TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE munki_reports (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    report_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL DEFAULT '',
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    munki_version TEXT NOT NULL DEFAULT '',
    console_user TEXT NOT NULL DEFAULT '',
    manifest_name TEXT NOT NULL DEFAULT '',
    error_count INT NOT NULL DEFAULT 0,
    warning_count INT NOT NULL DEFAULT 0,
    pending_count INT NOT NULL DEFAULT 0,
    UNIQUE (device_id, report_hash)
);
CREATE UNIQUE INDEX munki_reports_idem_idx ON munki_reports (device_id, idempotency_key) WHERE idempotency_key <> '';
CREATE INDEX munki_reports_device_idx ON munki_reports (device_id, received_at DESC);

CREATE TABLE munki_installs (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, name)
);

CREATE TABLE sso_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL DEFAULT '',
    allowed_domains TEXT[] NOT NULL DEFAULT '{}',
    group_claim TEXT NOT NULL DEFAULT 'groups',
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'terraform',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sso_role_bindings (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    idp_group TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    managed_by TEXT NOT NULL DEFAULT 'terraform',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (provider_id, idp_group)
);

CREATE TABLE sso_login_states (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sso_login_states_expires_idx ON sso_login_states (expires_at);

CREATE TABLE sessions (
    id_hash TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    provider_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL,
    groups TEXT[] NOT NULL DEFAULT '{}',
    id_token TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
CREATE INDEX sessions_provider_idx ON sessions (provider_id) WHERE revoked_at IS NULL;
