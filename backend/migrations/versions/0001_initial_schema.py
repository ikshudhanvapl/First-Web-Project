"""Initial schema — roles, users, refresh_tokens, audit_log

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-04-05
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Extensions ────────────────────────────────────────────────────────────
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # ── roles ─────────────────────────────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("uuid_generate_v4()"), primary_key=True),
        sa.Column("name", sa.String(50), nullable=False, unique=True),
        sa.Column("description", sa.Text),
        sa.Column("permissions", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.execute("""
        INSERT INTO roles (name, description, permissions) VALUES
            ('admin',     'Full system access',        '["users:read","users:write","users:delete","roles:manage","audit:read"]'),
            ('manager',   'Team management access',    '["users:read","users:write","audit:read"]'),
            ('developer', 'Read-only identity access', '["users:read"]'),
            ('contractor','Limited temporary access',  '["users:read"]')
        ON CONFLICT (name) DO NOTHING
    """)

    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("uuid_generate_v4()"), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255)),
        sa.Column("role_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False,
                  server_default="ACTIVE"),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("mfa_secret", sa.String(255)),
        sa.Column("failed_logins", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("locked_until", sa.TIMESTAMP(timezone=True)),
        sa.Column("last_login", sa.TIMESTAMP(timezone=True)),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.execute("""
        ALTER TABLE users ADD CONSTRAINT users_status_check
        CHECK (status IN ('ACTIVE','SUSPENDED','PENDING','DEPROVISIONED'))
    """)

    op.create_index("idx_users_email",  "users", ["email"])
    op.create_index("idx_users_status", "users", ["status"])
    op.create_index("idx_users_role",   "users", ["role_id"])

    # ── refresh_tokens ────────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("uuid_generate_v4()"), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("ip_address", postgresql.INET),
        sa.Column("user_agent", sa.Text),
    )

    op.create_index("idx_rt_user",    "refresh_tokens", ["user_id"])
    op.create_index("idx_rt_expires", "refresh_tokens", ["expires_at"])

    # ── audit_log ─────────────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("actor_email", sa.String(255)),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource", sa.String(100)),
        sa.Column("resource_id", sa.String(255)),
        sa.Column("outcome", sa.String(20), nullable=False,
                  server_default="SUCCESS"),
        sa.Column("ip_address", postgresql.INET),
        sa.Column("detail", postgresql.JSONB),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.execute("""
        ALTER TABLE audit_log ADD CONSTRAINT audit_outcome_check
        CHECK (outcome IN ('SUCCESS','FAILURE','DENIED'))
    """)

    # ── Immutable audit trigger ───────────────────────────────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_audit_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Audit log is immutable';
        END;
        $$ LANGUAGE plpgsql
    """)

    op.execute("""
        CREATE TRIGGER audit_no_update
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification()
    """)

    # ── Auto-update updated_at trigger ────────────────────────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    """)

    op.execute("""
        CREATE TRIGGER users_updated_at
            BEFORE UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION update_updated_at()
    """)

    # ── Seed admin account ────────────────────────────────────────────────────
    # Password: "ChangeMe!9" — bcrypt hash. CHANGE IN PRODUCTION.
    op.execute("""
        INSERT INTO users (email, password_hash, full_name, role_id)
        SELECT
            'admin@nexus.local',
            '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lenf9e4CZ7m.MiKHy',
            'System Administrator',
            id
        FROM roles WHERE name = 'admin'
        ON CONFLICT (email) DO NOTHING
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS users_updated_at ON users")
    op.execute("DROP TRIGGER IF EXISTS audit_no_update ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_modification()")
    op.execute("DROP FUNCTION IF EXISTS update_updated_at()")
    op.drop_table("audit_log")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
    op.drop_table("roles")
    op.execute('DROP EXTENSION IF EXISTS "uuid-ossp"')
    op.execute('DROP EXTENSION IF EXISTS "pgcrypto"')
