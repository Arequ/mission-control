-- Connector time zone, overlap lock, and the snapshot lookup the matrix filters on.

ALTER TABLE source_connectors ADD COLUMN time_zone TEXT NOT NULL DEFAULT 'UTC';
ALTER TABLE source_connectors ADD COLUMN sync_lock_until TIMESTAMPTZ;

CREATE INDEX source_snapshots_source_seen_idx ON source_snapshots (source, last_seen_at DESC);
CREATE INDEX source_snapshots_unmatched_idx ON source_snapshots (source) WHERE device_id IS NULL;
