-- ── Nexus IAM Database Schema ─────────────────────────────────────────────
-- This runs once on first container start.

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Roles / Permission Groups ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO roles (name, description, permissions) VALUES
    ('admin',     'Full system access',           '["users:read","users:write","users:delete","roles:manage","audit:read"]'),
    ('manager',   'Team management access',       '["users:read","users:write","audit:read"]'),
    ('developer', 'Read-only identity access',    '["users:read"]'),
    ('contractor','Limited temporary access',     '["users:read"]')
ON CONFLICT (name) DO NOTHING;

-- ── Users ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    -- bcrypt hash stored here, never plaintext
    password_hash   VARCHAR(255) NOT NULL,
    full_name       VARCHAR(255),
    role_id         UUID NOT NULL REFERENCES roles(id),
    status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE','SUSPENDED','PENDING','DEPROVISIONED')),
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret      VARCHAR(255),                -- TOTP secret (encrypted at app layer)
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for login lookups
CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_role   ON users(role_id);

-- ── Refresh Tokens ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) UNIQUE NOT NULL,  -- hashed, never stored raw
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address  INET,
    user_agent  TEXT
);

CREATE INDEX IF NOT EXISTS idx_rt_user    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rt_expires ON refresh_tokens(expires_at);

-- ── Audit Log ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    actor_id    UUID REFERENCES users(id),
    actor_email VARCHAR(255),              -- denormalized for immutability
    action      VARCHAR(100) NOT NULL,
    resource    VARCHAR(100),
    resource_id VARCHAR(255),
    outcome     VARCHAR(20) NOT NULL DEFAULT 'SUCCESS'
                    CHECK (outcome IN ('SUCCESS','FAILURE','DENIED')),
    ip_address  INET,
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log is append-only; prevent updates/deletes via trigger
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── Seed: default admin account ────────────────────────────────────────────
-- Password: "ChangeMe!9" — bcrypt hash. CHANGE THIS IN PRODUCTION.
INSERT INTO users (email, password_hash, full_name, role_id)
SELECT
    'admin@nexus.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lenf9e4CZ7m.MiKHy',
    'System Administrator',
    id
FROM roles WHERE name = 'admin'
ON CONFLICT (email) DO NOTHING;
