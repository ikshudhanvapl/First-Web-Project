"""Add mfa_attempts table and session_id to audit_log

Revision ID: 0002_mfa_and_sessions
Revises: 0001_initial_schema
Create Date: 2026-04-05

This migration demonstrates the Alembic pattern for Day 2 schema changes.
It adds:
  - mfa_attempts: tracks TOTP verification attempts per user (for rate limiting)
  - audit_log.session_id: links audit events to a login session

Without Alembic you would need to manually write and track these ALTER TABLE
statements. With Alembic:
  alembic upgrade head       → applies this migration
  alembic downgrade -1       → reverts it cleanly
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_mfa_and_sessions"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── mfa_attempts table ────────────────────────────────────────────────────
    op.create_table(
        "mfa_attempts",
        sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("success", sa.Boolean, nullable=False),
        sa.Column("ip_address", postgresql.INET),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("idx_mfa_user", "mfa_attempts", ["user_id"])
    op.create_index("idx_mfa_created", "mfa_attempts", ["created_at"])

    # ── Add session_id to audit_log ────────────────────────────────────────────
    # Demonstrates a non-destructive column addition — zero downtime
    op.add_column(
        "audit_log",
        sa.Column("session_id", sa.String(64), nullable=True),
    )

    # ── Add email_verified column to users ────────────────────────────────────
    op.add_column(
        "users",
        sa.Column("email_verified", sa.Boolean, nullable=False,
                  server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("users", "email_verified")
    op.drop_column("audit_log", "session_id")
    op.drop_index("idx_mfa_created", table_name="mfa_attempts")
    op.drop_index("idx_mfa_user",    table_name="mfa_attempts")
    op.drop_table("mfa_attempts")
