"""
conftest.py — Shared pytest fixtures.

Test strategy:
  - Unit tests: test pure functions (password hashing, JWT creation/validation,
    UUID parsing) with no external dependencies.
  - Integration tests: spin up a real FastAPI TestClient against a mock DB
    and a stubbed OPA that always returns True, then override specific
    dependencies for denial / error cases.

We use dependency_overrides to swap out:
  - get_db → returns a mock connection
  - _check_opa → returns True (or False for denial tests)
"""

import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Initialise crypto keys before importing anything that uses them
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Point to a temp key dir so tests don't overwrite production keys
os.environ.setdefault("KEY_DIR", "/tmp/nexus_test_keys")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")

import crypto
crypto.init_keys()   # generates keys into /tmp/nexus_test_keys if needed

from main import app
from auth import hash_password, create_access_token
from database import get_db


# ── Mock DB connection ────────────────────────────────────────────────────────

def _make_mock_conn():
    """Return an AsyncMock that behaves like an asyncpg Connection."""
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=None)
    conn.fetch    = AsyncMock(return_value=[])
    conn.fetchval = AsyncMock(return_value=uuid.uuid4())
    conn.execute  = AsyncMock(return_value=None)
    return conn


@pytest.fixture
def mock_conn():
    return _make_mock_conn()


@pytest.fixture
def client(mock_conn):
    """
    FastAPI TestClient with DB dependency overridden.
    OPA is stubbed to ALLOW everything by default.
    """
    async def _override_db():
        yield mock_conn

    app.dependency_overrides[get_db] = _override_db

    # Stub OPA to always allow (unit test concern, not integration)
    with patch("auth._check_opa", return_value=True):
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

    app.dependency_overrides.clear()


@pytest.fixture
def admin_token() -> str:
    """A valid RS256 access token with admin permissions."""
    return create_access_token(
        user_id=str(uuid.uuid4()),
        email="admin@nexus.local",
        role="admin",
        permissions=["users:read", "users:write", "users:delete", "audit:read"],
        status_val="ACTIVE",
    )


@pytest.fixture
def developer_token() -> str:
    """A valid RS256 access token with read-only permissions."""
    return create_access_token(
        user_id=str(uuid.uuid4()),
        email="dev@nexus.local",
        role="developer",
        permissions=["users:read"],
        status_val="ACTIVE",
    )


@pytest.fixture
def suspended_token() -> str:
    """A token for a suspended user — should be denied by OPA."""
    return create_access_token(
        user_id=str(uuid.uuid4()),
        email="suspended@nexus.local",
        role="developer",
        permissions=["users:read"],
        status_val="SUSPENDED",
    )


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
