-- One NVD CPE dictionary lookup per Munki item that has no product mapping.
-- These are suggestions only. A mapping takes effect when someone adds the
-- cpe_override block to the config repo; the server never applies one.
CREATE TABLE cpe_proposals (
    name TEXT PRIMARY KEY,
    display_name TEXT NOT NULL DEFAULT '',
    developer TEXT NOT NULL DEFAULT '',
    bundle_id TEXT NOT NULL DEFAULT '',
    keyword TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('proposed', 'no_match', 'error')),
    confidence TEXT NOT NULL DEFAULT 'none' CHECK (confidence IN ('high', 'medium', 'low', 'none')),
    part TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    evidence JSONB NOT NULL DEFAULT '[]',
    candidates JSONB NOT NULL DEFAULT '[]',
    error TEXT NOT NULL DEFAULT '',
    looked_up_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX cpe_proposals_looked_up_idx ON cpe_proposals (looked_up_at);
