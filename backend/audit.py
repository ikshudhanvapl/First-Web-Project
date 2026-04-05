"""
audit.py v2 — Append-only audit writer with structured logging.

Replaces print() with get_logger() so audit failures appear in
the JSON log stream alongside trace_id for correlation.
"""

import asyncpg
import json
from typing import Any
from logging_config import get_logger

log = get_logger(__name__)


async def log_event(
    conn: asyncpg.Connection,
    *,
    actor_id: str | None,
    actor_email: str | None,
    action: str,
    resource: str | None = None,
    resource_id: str | None = None,
    outcome: str = "SUCCESS",
    ip_address: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """
    Write an immutable audit record to the database AND emit a structured
    log line so the event is captured by log aggregators even if the DB write
    fails for some reason.
    """
    # Always emit a log line — survives DB failures
    log.info(
        action,
        extra={
            "audit":       True,
            "actor_id":    actor_id,
            "actor_email": actor_email,
            "resource":    resource,
            "resource_id": resource_id,
            "outcome":     outcome,
            "ip_address":  ip_address,
            "detail":      detail,
        },
    )

    try:
        await conn.execute(
            """
            INSERT INTO audit_log
                (actor_id, actor_email, action, resource, resource_id,
                 outcome, ip_address, detail)
            VALUES ($1,$2,$3,$4,$5,$6,$7::inet,$8::jsonb)
            """,
            actor_id,
            actor_email,
            action,
            resource,
            resource_id,
            outcome,
            ip_address,
            json.dumps(detail) if detail else None,
        )
    except Exception as exc:
        log.error(
            "audit.db_write_failed",
            extra={"error": str(exc), "action": action},
        )
