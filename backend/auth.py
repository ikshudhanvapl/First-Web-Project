"""
auth.py v2 — RS256 JWT, OPA enforcement with status field, input hardening.

Changes from v1:
  - HS256 -> RS256 via crypto.py (sign with private key, verify with public)
  - OPA input now includes user.status so the deny rule actually fires
  - UUID path params validated cleanly (422 not 500 on bad input)
  - get_current_user injects user_id into logging context
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timezone, timedelta

import httpx
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from passlib.context import CryptContext

from settings import get_settings
from database import get_db
from logging_config import get_logger, set_user_id
import crypto
import asyncpg

settings = get_settings()
log = get_logger(__name__)

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()


# ── Password helpers ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


# ── JWT helpers (RS256) ──────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(
    user_id: str,
    email: str,
    role: str,
    permissions: list[str],
    status_val: str = "ACTIVE",
) -> str:
    """Sign a short-lived RS256 JWT. Embeds permissions AND status for OPA."""
    payload = {
        "sub":         user_id,
        "email":       email,
        "role":        role,
        "permissions": permissions,
        "status":      status_val,          # ← NEW: OPA deny rule needs this
        "jti":         str(uuid.uuid4()),
        "iat":         _now(),
        "exp":         _now() + timedelta(minutes=settings.jwt_access_expire_minutes),
        "type":        "access",
    }
    return crypto.sign_token(payload)


def create_refresh_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hash). Store hash only."""
    raw = secrets.token_urlsafe(48)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def decode_access_token(token: str) -> dict:
    """Verify RS256 signature and return payload. 401 on any failure."""
    try:
        payload = crypto.verify_token(token)
        if payload.get("type") != "access":
            raise JWTError("wrong token type")
        return payload
    except JWTError as exc:
        log.warning("token.invalid", extra={"error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── OPA enforcement ──────────────────────────────────────────────────────────

async def _check_opa(token_payload: dict, action: str, resource: str) -> bool:
    """
    Send structured input to OPA. Now includes user.status so the
    deny rule for SUSPENDED/DEPROVISIONED accounts actually fires.
    """
    opa_input = {
        "input": {
            "user": {
                "id":          token_payload["sub"],
                "email":       token_payload["email"],
                "role":        token_payload["role"],
                "permissions": token_payload.get("permissions", []),
                "status":      token_payload.get("status", "ACTIVE"),  # ← FIXED
            },
            "action":   action,
            "resource": resource,
        }
    }
    try:
        async with httpx.AsyncClient(timeout=settings.opa_timeout_seconds) as client:
            resp = await client.post(settings.opa_url, json=opa_input)
        result = resp.status_code == 200 and resp.json().get("result") is True
        log.debug(
            "opa.check",
            extra={
                "action": action,
                "resource": resource,
                "allowed": result,
            },
        )
        return result
    except httpx.TimeoutException:
        log.error("opa.timeout", extra={"action": action, "resource": resource})
        raise HTTPException(status_code=503, detail="Policy engine timeout")
    except Exception as exc:
        log.error("opa.error", extra={"error": str(exc)})
        raise HTTPException(status_code=503, detail="Policy engine unavailable")


# ── FastAPI dependencies ─────────────────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Validate RS256 JWT, inject user_id into log context."""
    payload = decode_access_token(credentials.credentials)
    set_user_id(payload.get("sub", ""))   # propagate to all log lines
    return payload


def require_permission(action: str, resource: str):
    """
    Dependency factory: JWT validation + OPA policy check.

    Usage:
        @router.post("/users", dependencies=[Depends(require_permission("write", "users"))])
    """
    async def _guard(
        request: Request,
        current_user: dict = Depends(get_current_user),
    ) -> dict:
        allowed = await _check_opa(current_user, action, resource)
        if not allowed:
            log.warning(
                "authz.denied",
                extra={"action": action, "resource": resource},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Zero Trust policy denied this request",
            )
        return current_user
    return _guard


# ── Validated UUID helper ────────────────────────────────────────────────────

def parse_uuid(value: str, field: str = "id") -> uuid.UUID:
    """
    Parse a UUID string and return a clean 422 (not 500) on bad input.
    Use this in route handlers instead of uuid.UUID(value) directly.
    """
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid {field}: '{value}' is not a valid UUID",
        )


# ── Login helper ─────────────────────────────────────────────────────────────

async def authenticate_user(
    email: str,
    password: str,
    conn: asyncpg.Connection,
    ip: str,
):
    """
    Verify credentials, enforce lockout, return user row on success.
    Generic error messages prevent user enumeration.
    """
    row = await conn.fetchrow(
        """
        SELECT u.id, u.email, u.password_hash, u.status,
               u.failed_logins, u.locked_until,
               r.name AS role, r.permissions
        FROM users u JOIN roles r ON u.role_id = r.id
        WHERE u.email = $1
        """,
        email,
    )

    INVALID = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )

    if not row:
        log.warning("auth.user_not_found", extra={"email": email, "ip": ip})
        raise INVALID

    if row["locked_until"] and row["locked_until"] > datetime.now(timezone.utc):
        log.warning("auth.account_locked", extra={"email": email, "ip": ip})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account temporarily locked. Try again later.",
        )

    if row["status"] != "ACTIVE":
        log.warning("auth.account_inactive", extra={"email": email, "status": row["status"]})
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active",
        )

    if not verify_password(password, row["password_hash"]):
        new_count = row["failed_logins"] + 1
        locked_until = None
        if new_count >= settings.max_failed_logins:
            locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
            log.warning("auth.account_locked_now", extra={"email": email, "ip": ip})
        await conn.execute(
            "UPDATE users SET failed_logins=$1, locked_until=$2 WHERE id=$3",
            new_count, locked_until, row["id"],
        )
        raise INVALID

    await conn.execute(
        "UPDATE users SET failed_logins=0, locked_until=NULL, last_login=NOW() WHERE id=$1",
        row["id"],
    )
    log.info("auth.success", extra={"email": email, "ip": ip})
    return row
