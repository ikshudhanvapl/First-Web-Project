"""
logging_config.py — Structured JSON logging for distributed systems.

Every log line is a JSON object with consistent fields:
  timestamp, level, message, logger, trace_id, user_id, action, ...

This means log aggregators (Datadog, Splunk, ELK) can index and filter
on any field without regex parsing.

Usage:
    from logging_config import get_logger
    log = get_logger(__name__)
    log.info("user.login", extra={"user_id": uid, "ip": ip})
"""

import logging
import sys
import uuid
from contextvars import ContextVar
from pythonjsonlogger import jsonlogger

# ── Trace ID context var ─────────────────────────────────────────────────────
# Stored per-request via middleware; propagated through all log calls.
_trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")
_user_id_var:  ContextVar[str] = ContextVar("user_id",  default="")


def set_trace_id(tid: str) -> None:
    _trace_id_var.set(tid)


def set_user_id(uid: str) -> None:
    _user_id_var.set(uid)


def get_trace_id() -> str:
    return _trace_id_var.get() or str(uuid.uuid4())


# ── Custom JSON formatter ─────────────────────────────────────────────────────
class NexusJsonFormatter(jsonlogger.JsonFormatter):
    """Adds trace_id and user_id to every log record automatically."""

    def add_fields(self, log_record: dict, record: logging.LogRecord, message_dict: dict):
        super().add_fields(log_record, record, message_dict)

        # Rename default fields to match common log schemas
        log_record["timestamp"] = log_record.pop("asctime", None) or \
            self.formatTime(record, self.datefmt)
        log_record["level"]   = record.levelname
        log_record["logger"]  = record.name

        # Inject request-scoped context
        log_record["trace_id"] = _trace_id_var.get() or ""
        log_record["user_id"]  = _user_id_var.get()  or ""

        # Remove fields that are redundant after renaming
        for key in ("levelname", "name", "color_message"):
            log_record.pop(key, None)


def configure_logging(level: str = "INFO") -> None:
    """
    Set up root logger with JSON output to stdout.
    Call once at application startup.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        NexusJsonFormatter(
            fmt="%(timestamp)s %(level)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S.%fZ",
        )
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "asyncpg", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
