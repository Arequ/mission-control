CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE bootstrap_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX audit_log_resource_idx ON audit_log (resource_type, resource_id);

CREATE TABLE runner_pools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    labels TEXT[] NOT NULL DEFAULT '{}',
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE recipe_repos (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    ref TEXT NOT NULL DEFAULT 'main',
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE recipes (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    repo_id TEXT REFERENCES recipe_repos(id) ON DELETE RESTRICT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    override_content TEXT NOT NULL DEFAULT '',
    trust_info JSONB NOT NULL DEFAULT '{}'::jsonb,
    runner_pool_id TEXT REFERENCES runner_pools(id) ON DELETE RESTRICT,
    labels TEXT[] NOT NULL DEFAULT '{}',
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE schedules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    recipe_id TEXT NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
    cron TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'api',
    last_enqueued_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pipeline_settings (
    id TEXT PRIMARY KEY,
    max_concurrency INT NOT NULL DEFAULT 4 CHECK (max_concurrency >= 1),
    per_runner_parallelism INT NOT NULL DEFAULT 1 CHECK (per_runner_parallelism >= 1),
    timeout_seconds INT NOT NULL DEFAULT 3600 CHECK (timeout_seconds >= 1),
    max_retries INT NOT NULL DEFAULT 2 CHECK (max_retries >= 0),
    lease_seconds INT NOT NULL DEFAULT 120 CHECK (lease_seconds >= 5),
    managed_by TEXT NOT NULL DEFAULT 'system',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO pipeline_settings (id, managed_by) VALUES ('default', 'system');

CREATE TABLE promotion_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    from_catalog TEXT NOT NULL,
    to_catalog TEXT NOT NULL,
    soak_days INT NOT NULL DEFAULT 7 CHECK (soak_days >= 0),
    manual_hold BOOLEAN NOT NULL DEFAULT false,
    enabled BOOLEAN NOT NULL DEFAULT true,
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (from_catalog <> to_catalog)
);

CREATE TABLE manifests (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    catalogs TEXT[] NOT NULL DEFAULT '{}',
    included_manifests TEXT[] NOT NULL DEFAULT '{}',
    managed_installs TEXT[] NOT NULL DEFAULT '{}',
    optional_installs TEXT[] NOT NULL DEFAULT '{}',
    managed_uninstalls TEXT[] NOT NULL DEFAULT '{}',
    managed_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE runners (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    pool_id TEXT REFERENCES runner_pools(id) ON DELETE SET NULL,
    labels TEXT[] NOT NULL DEFAULT '{}',
    token_hash TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    autopkg_version TEXT NOT NULL DEFAULT '',
    last_heartbeat_at TIMESTAMPTZ,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    recipe_id TEXT NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
    schedule_id TEXT REFERENCES schedules(id) ON DELETE SET NULL,
    trigger TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT '',
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    runner_id TEXT REFERENCES runners(id) ON DELETE SET NULL,
    lease_expires_at TIMESTAMPTZ,
    timeout_seconds INT NOT NULL DEFAULT 3600,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX jobs_status_idx ON jobs (status, created_at);
CREATE INDEX jobs_recipe_idx ON jobs (recipe_id, created_at DESC);
CREATE INDEX jobs_lease_idx ON jobs (status, lease_expires_at);
CREATE INDEX jobs_runner_active_idx ON jobs (runner_id) WHERE status IN ('leased', 'running');

CREATE TABLE job_logs (
    id BIGSERIAL PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    stream TEXT NOT NULL DEFAULT 'stdout',
    line TEXT NOT NULL,
    at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX job_logs_job_idx ON job_logs (job_id, id);

CREATE TABLE packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    catalog TEXT NOT NULL,
    pkginfo JSONB NOT NULL,
    pkg_key TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL,
    job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
    recipe_identifier TEXT NOT NULL DEFAULT '',
    soak_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    promoted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, version)
);
CREATE INDEX packages_catalog_idx ON packages (catalog, name, version);

CREATE TABLE catalogs (
    name TEXT PRIMARY KEY,
    item_count INT NOT NULL DEFAULT 0,
    generated_at TIMESTAMPTZ,
    body BYTEA NOT NULL
);

INSERT INTO catalogs (name, item_count, generated_at, body) VALUES
    ('testing', 0, now(), '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array></array>
</plist>
'),
    ('production', 0, now(), '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array></array>
</plist>
');
