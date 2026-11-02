ALTER TABLE device_apps ADD COLUMN bundle_version TEXT NOT NULL DEFAULT '';

CREATE TABLE vulnerability_settings (
    id TEXT PRIMARY KEY,
    nvd_enabled BOOLEAN NOT NULL DEFAULT true,
    kev_enabled BOOLEAN NOT NULL DEFAULT true,
    epss_enabled BOOLEAN NOT NULL DEFAULT true,
    apple_enabled BOOLEAN NOT NULL DEFAULT true,
    rapid7_enabled BOOLEAN NOT NULL DEFAULT false,
    sync_cron TEXT NOT NULL DEFAULT '20 3 * * *',
    timezone TEXT NOT NULL DEFAULT 'UTC',
    nvd_api_key TEXT NOT NULL DEFAULT '',
    sla_critical_days INT NOT NULL DEFAULT 7,
    sla_high_days INT NOT NULL DEFAULT 14,
    sla_medium_days INT NOT NULL DEFAULT 30,
    sla_low_days INT NOT NULL DEFAULT 90,
    sla_kev_days INT NOT NULL DEFAULT 14,
    managed_by TEXT NOT NULL DEFAULT 'system',
    last_sync_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sync_status TEXT NOT NULL DEFAULT '',
    last_sync_error TEXT NOT NULL DEFAULT '',
    nvd_cursor TEXT NOT NULL DEFAULT '',
    inventory_watermark TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO vulnerability_settings (id) VALUES ('default');

CREATE TABLE cpe_overrides (
    id TEXT PRIMARY KEY,
    position INT NOT NULL DEFAULT 0,
    bundle_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    part TEXT NOT NULL DEFAULT 'a',
    version_source TEXT NOT NULL DEFAULT 'short'
);

CREATE TABLE vuln_cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    cvss_vector TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'none',
    published TIMESTAMPTZ,
    last_modified TIMESTAMPTZ,
    kev BOOLEAN NOT NULL DEFAULT false,
    kev_date TIMESTAMPTZ,
    kev_due TIMESTAMPTZ,
    kev_name TEXT NOT NULL DEFAULT '',
    epss DOUBLE PRECISION NOT NULL DEFAULT 0,
    epss_percentile DOUBLE PRECISION NOT NULL DEFAULT 0,
    epss_known BOOLEAN NOT NULL DEFAULT false,
    source TEXT NOT NULL DEFAULT 'nvd',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vuln_ranges (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vuln_cves(cve_id) ON DELETE CASCADE,
    part TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    start_incl TEXT NOT NULL DEFAULT '',
    start_excl TEXT NOT NULL DEFAULT '',
    end_incl TEXT NOT NULL DEFAULT '',
    end_excl TEXT NOT NULL DEFAULT '',
    exact TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'nvd'
);

CREATE UNIQUE INDEX vuln_ranges_identity ON vuln_ranges (
    cve_id, part, vendor, product, start_incl, start_excl, end_incl, end_excl, exact
);

CREATE TABLE vuln_trains (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vuln_cves(cve_id) ON DELETE CASCADE,
    part TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    major INT NOT NULL,
    fixed_version TEXT NOT NULL,
    fixed_build TEXT NOT NULL DEFAULT '',
    train_mode TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'apple'
);

CREATE UNIQUE INDEX vuln_trains_identity ON vuln_trains (
    cve_id, part, vendor, product, major, fixed_version, fixed_build, train_mode
);

CREATE TABLE vuln_findings (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    software_key TEXT NOT NULL,
    software_name TEXT NOT NULL DEFAULT '',
    installed_version TEXT NOT NULL DEFAULT '',
    installed_build TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT 'inventory',
    active BOOLEAN NOT NULL DEFAULT true,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    UNIQUE (device_id, cve_id, software_key)
);

CREATE INDEX vuln_findings_active_idx ON vuln_findings (cve_id, software_key) WHERE active;
CREATE INDEX vuln_findings_device_idx ON vuln_findings (device_id) WHERE active;

CREATE TABLE vuln_issues (
    id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    software_key TEXT NOT NULL,
    software_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'risk_accepted', 'fixed')),
    assignee TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    risk_until TIMESTAMPTZ,
    opened_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    auto_resolved BOOLEAN NOT NULL DEFAULT false,
    revision INT NOT NULL DEFAULT 1,
    UNIQUE (cve_id, software_key)
);

CREATE INDEX vuln_issues_status_idx ON vuln_issues (status);

CREATE TABLE vuln_issue_events (
    id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES vuln_issues(id) ON DELETE CASCADE,
    at TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX vuln_issue_events_issue_idx ON vuln_issue_events (issue_id, at);

CREATE TABLE rapid7_findings (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    software_name TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    seen_at TIMESTAMPTZ NOT NULL,
    UNIQUE (device_id, cve_id, software_name)
);
