-- Terraform-defined roles. A binding may name one of these or a built-in role
-- (viewer, operator, admin); the store checks which, so the CHECK goes.
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    managed_by TEXT NOT NULL DEFAULT 'terraform',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE sso_role_bindings DROP CONSTRAINT IF EXISTS sso_role_bindings_role_check;
