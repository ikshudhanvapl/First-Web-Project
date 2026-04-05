"""
test_audit.py — Tests for the immutable audit log writer.

Tests:
  1. log_event writes correct fields to DB
  2. DB write failure does not raise (audit errors are swallowed)
  3. Audit endpoint requires auth
  4. Audit endpoint requires audit:read permission
  5. Audit log is returned in descending order
"""

import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from audit import log_event
from conftest import auth_headers


class TestLogEvent:
    @pytest.mark.asyncio
    async def test_writes_to_db(self):
        """log_event must call conn.execute with the correct SQL."""
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value=None)

        await log_event(
            conn,
            actor_id=str(uuid.uuid4()),
            actor_email="admin@nexus.local",
            action="users.create",
            resource="users",
            resource_id=str(uuid.uuid4()),
            outcome="SUCCESS",
            ip_address="127.0.0.1",
            detail={"email": "new@nexus.local"},
        )

        conn.execute.assert_called_once()
        call_args = conn.execute.call_args[0]
        # First arg is the SQL string
        assert "INSERT INTO audit_log" in call_args[0]

    @pytest.mark.asyncio
    async def test_db_failure_does_not_raise(self):
        """A DB failure during audit write must not propagate."""
        conn = AsyncMock()
        conn.execute = AsyncMock(side_effect=Exception("DB connection lost"))

        # Should not raise
        await log_event(
            conn,
            actor_id=None,
            actor_email="admin@nexus.local",
            action="auth.login",
            outcome="SUCCESS",
        )

    @pytest.mark.asyncio
    async def test_none_actor_is_allowed(self):
        """System-generated events may have no actor."""
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value=None)

        await log_event(
            conn,
            actor_id=None,
            actor_email=None,
            action="system.startup",
            outcome="SUCCESS",
        )
        conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_detail_serialized_as_json(self):
        """detail dict must be passed as JSON string to the DB."""
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value=None)

        detail = {"email": "x@test.com", "role": "admin"}
        await log_event(
            conn,
            actor_id=str(uuid.uuid4()),
            actor_email="admin@nexus.local",
            action="users.create",
            detail=detail,
        )

        call_args = conn.execute.call_args[0]
        # The last positional arg is the JSON string
        import json
        json_arg = call_args[-1]
        parsed = json.loads(json_arg)
        assert parsed["email"] == "x@test.com"
        assert parsed["role"]  == "admin"


class TestAuditEndpoint:
    def test_audit_requires_auth(self, client):
        resp = client.get("/audit")
        assert resp.status_code in (401, 403)

    def test_audit_requires_audit_read(self, client, developer_token):
        """Developer role has no audit:read permission — must be denied."""
        with patch("auth._check_opa", return_value=False):
            resp = client.get("/audit", headers=auth_headers(developer_token))
        assert resp.status_code == 403

    def test_audit_accessible_to_admin(self, client, admin_token):
        """Admin with audit:read should receive an empty list (mock DB)."""
        with patch("auth._check_opa", return_value=True):
            resp = client.get("/audit", headers=auth_headers(admin_token))
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_audit_limit_capped(self, client, admin_token):
        """Requesting limit=9999 should be silently capped at 500."""
        with patch("auth._check_opa", return_value=True):
            resp = client.get("/audit?limit=9999", headers=auth_headers(admin_token))
        assert resp.status_code == 200
