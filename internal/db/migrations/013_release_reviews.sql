-- One review per imported package. The CVE fields are computed by the server
-- from the vulnerability feeds; the notes_* fields come from the release-notes
-- advisor (a Claude CLI worker) and are advisory only. Only a person with
-- releases:update moves a review out of pending.
CREATE TABLE release_reviews (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL UNIQUE REFERENCES packages(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    baseline_version TEXT NOT NULL DEFAULT '',
    final_catalog TEXT NOT NULL DEFAULT '',
    software_key TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'low' CHECK (priority IN ('high', 'low')),
    reasons JSONB NOT NULL DEFAULT '[]',
    fixed JSONB NOT NULL DEFAULT '[]',
    still_open JSONB NOT NULL DEFAULT '[]',
    exposed_devices INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'rushed', 'normal', 'rejected', 'superseded')),
    decided_by TEXT NOT NULL DEFAULT '',
    decided_at TIMESTAMPTZ,
    decision_note TEXT NOT NULL DEFAULT '',
    notes_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (notes_status IN ('pending', 'leased', 'done', 'failed')),
    notes_lease_until TIMESTAMPTZ,
    notes_attempts INT NOT NULL DEFAULT 0,
    notes_summary TEXT NOT NULL DEFAULT '',
    notes_recommendation TEXT NOT NULL DEFAULT '' CHECK (notes_recommendation IN ('', 'high', 'low')),
    notes_rationale TEXT NOT NULL DEFAULT '',
    notes_security_fixes BOOLEAN NOT NULL DEFAULT false,
    notes_cves TEXT[] NOT NULL DEFAULT '{}',
    notes_sources TEXT[] NOT NULL DEFAULT '{}',
    notes_model TEXT NOT NULL DEFAULT '',
    notes_error TEXT NOT NULL DEFAULT '',
    notes_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX release_reviews_status_idx ON release_reviews (status, created_at DESC);
CREATE INDEX release_reviews_notes_idx ON release_reviews (notes_status, created_at) WHERE status = 'pending';
