"""
database.py — Async connection pool with lifecycle management.

Uses a single pool shared across all requests (not one connection per request
like the Gemini version, which would exhaust DB connections immediately).
"""

import asyncpg
from contextlib import asynccontextmanager
from typing import AsyncIterator
from settings import get_settings

_pool: asyncpg.Pool | None = None


async def init_pool() -> None:
    """Create the connection pool. Called once at app startup."""
    global _pool
    settings = get_settings()
    _pool = await asyncpg.create_pool(
        dsn=settings.database_url,
        min_size=2,
        max_size=10,
        max_inactive_connection_lifetime=300,
        command_timeout=10,
    )


async def close_pool() -> None:
    """Drain and close the pool gracefully at shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def get_conn() -> AsyncIterator[asyncpg.Connection]:
    """
    Dependency / context manager that acquires a connection from the pool
    and releases it automatically when the block exits.

    Usage in a route:
        async with get_conn() as conn:
            rows = await conn.fetch("SELECT ...")
    """
    if _pool is None:
        raise RuntimeError("Database pool not initialised")
    async with _pool.acquire() as conn:
        yield conn


async def get_db() -> AsyncIterator[asyncpg.Connection]:
    """FastAPI dependency version of get_conn."""
    async with get_conn() as conn:
        yield conn
