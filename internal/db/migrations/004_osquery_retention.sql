-- Snapshot generations, log retention, and device-list search indexes.

ALTER TABLE device_query_results
    ADD COLUMN snapshot_counter BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN snapshot_open BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX osquery_result_logs_received_idx ON osquery_result_logs (received_at);
CREATE INDEX osquery_status_logs_received_idx ON osquery_status_logs (received_at);

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX devices_hostname_trgm_idx ON devices USING gin (hostname gin_trgm_ops);
CREATE INDEX devices_computer_name_trgm_idx ON devices USING gin (computer_name gin_trgm_ops);
CREATE INDEX devices_serial_trgm_idx ON devices USING gin (serial gin_trgm_ops);
CREATE INDEX devices_username_trgm_idx ON devices USING gin (username gin_trgm_ops);
CREATE INDEX devices_hardware_model_trgm_idx ON devices USING gin (hardware_model gin_trgm_ops);
CREATE INDEX devices_platform_seen_idx ON devices (platform, last_seen_at DESC);

-- Hosts with no usable hardware id are distinct unless they share a real host identifier.
CREATE UNIQUE INDEX devices_host_identifier_fallback_idx ON devices (host_identifier)
    WHERE hardware_uuid = '' AND serial = '' AND host_identifier <> '';
