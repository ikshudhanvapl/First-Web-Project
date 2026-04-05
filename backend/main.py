"""
main.py v2 — Nexus IAM API

New in v2:
  - RS256 JWT signing via crypto.py
  - JWKS endpoint (/.well-known/jwks.json) for token verification by other services
  - Structured JSON logging via logging_config
  - TraceMiddleware: X-Request-ID on every response
  - UUID input hardening (422 not 500 on bad path params)
  - OPA input now includes user.status
  - /metrics stub (Prometheus-ready)
"""

import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, field_validator

from settings import get_settings
from database import init_pool, close_pool, get_db
import asyncpg
import crypto
from auth import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    require_permission,
    parse_uuid,
)
from audit import log_event
from middleware import TraceMiddleware
from logging_config import configure_logging, get_logger

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("nexus.startup", extra={"environment": settings.environment})
    crypto.init_keys()                     # Generate / load RSA keypair
    log.info("crypto.keys_loaded", extra={"kid": crypto.get_kid()})
    await init_pool()
    log.info("db.pool_ready")
    yield
    await close_pool()
    log.info("nexus.shutdown")


app = FastAPI(
    title="Nexus IAM API",
    version="2.0.0",
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url=None,
    lifespan=lifespan,
)

# ── Middleware (order matters: outermost first) ────────────────────────────────
app.add_middleware(TraceMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = settings.jwt_access_expire_minutes * 60
    algorithm: str = "RS256"

class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        errors = []
        if len(v) < 10:
            errors.append("at least 10 characters")
        if not any(c.isupper() for c in v):
            errors.append("one uppercase letter")
        if not any(c.isdigit() for c in v):
            errors.append("one digit")
        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")
        return v

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: str) -> str:
        allowed = {"admin", "manager", "developer", "contractor"}
        if v.lower() not in allowed:
            raise ValueError(f"Role must be one of {allowed}")
        return v.lower()

class UpdateUserRequest(BaseModel):
    role: str | None = None
    status: str | None = None
    full_name: str | None = None


# ── Well-known / discovery ────────────────────────────────────────────────────

@app.get("/.well-known/jwks.json", tags=["discovery"], include_in_schema=False)
async def jwks():
    """
    JSON Web Key Set endpoint.
    Any microservice can GET this URL to retrieve the public key needed
    to verify RS256 tokens — without ever seeing the private key.

    Standard pattern: cache this response, refresh on 'kid' mismatch.
    """
    return JSONResponse(content=crypto.get_jwks())


@app.get("/.well-known/openid-configuration", tags=["discovery"], include_in_schema=False)
async def openid_configuration(request: Request):
    """OpenID Connect discovery document stub."""
    base = str(request.base_url).rstrip("/")
    return {
        "issuer":                 base,
        "jwks_uri":               f"{base}/.well-known/jwks.json",
        "token_endpoint":         f"{base}/auth/login",
        "id_token_signing_alg":   "RS256",
        "subject_types_supported": ["public"],
    }


# ── Ops ───────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok", "version": "2.0.0", "algorithm": "RS256"}


@app.get("/metrics", tags=["ops"])
async def metrics():
    """
    Prometheus metrics stub.
    In production: use prometheus-fastapi-instrumentator to auto-expose
    http_requests_total, http_request_duration_seconds, etc.
    """
    return {"info": "Install prometheus-fastapi-instrumentator for full metrics"}


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(
    req: LoginRequest,
    request: Request,
    conn: asyncpg.Connection = Depends(get_db),
):
    ip = request.client.host if request.client else "unknown"
    user = await authenticate_user(req.email, req.password, conn, ip)

    perms = user["permissions"]
    if isinstance(perms, str):
        perms = json.loads(perms)

    access_token = create_access_token(
        user_id=str(user["id"]),
        email=user["email"],
        role=user["role"],
        permissions=perms,
        status_val=user["status"],          # embedded so OPA deny rule works
    )

    raw_refresh, hashed_refresh = create_refresh_token()
    await conn.execute(
        """
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
        VALUES ($1, $2, $3, $4::inet, $5)
        """,
        user["id"],
        hashed_refresh,
        datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_expire_days),
        ip,
        request.headers.get("user-agent", ""),
    )

    await log_event(
        conn,
        actor_id=str(user["id"]),
        actor_email=user["email"],
        action="auth.login",
        outcome="SUCCESS",
        ip_address=ip,
    )
    return TokenResponse(access_token=access_token)


@app.post("/auth/logout", tags=["auth"])
async def logout(
    current_user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    await conn.execute(
        "UPDATE refresh_tokens SET revoked=TRUE WHERE user_id=$1",
        uuid.UUID(current_user["sub"]),
    )
    await log_event(
        conn,
        actor_id=current_user["sub"],
        actor_email=current_user["email"],
        action="auth.logout",
    )
    return {"status": "logged out"}


# ── Users ─────────────────────────────────────────────────────────────────────

@app.get("/users", tags=["users"])
async def list_users(
    current_user: dict = Depends(require_permission("read", "users")),
    conn: asyncpg.Connection = Depends(get_db),
    skip: int = 0,
    limit: int = 50,
):
    limit = min(limit, 200)
    rows = await conn.fetch(
        """
        SELECT u.id, u.email, u.full_name, u.status, u.last_login,
               u.created_at, r.name AS role
        FROM users u JOIN roles r ON u.role_id = r.id
        ORDER BY u.created_at DESC
        OFFSET $1 LIMIT $2
        """,
        skip, limit,
    )
    return [dict(r) for r in rows]


@app.post("/users", status_code=status.HTTP_201_CREATED, tags=["users"])
async def create_user(
    body: CreateUserRequest,
    request: Request,
    current_user: dict = Depends(require_permission("write", "users")),
    conn: asyncpg.Connection = Depends(get_db),
):
    role_row = await conn.fetchrow("SELECT id FROM roles WHERE name=$1", body.role)
    if not role_row:
        raise HTTPException(status_code=400, detail="Unknown role")

    try:
        new_id = await conn.fetchval(
            """
            INSERT INTO users (email, password_hash, full_name, role_id)
            VALUES ($1, $2, $3, $4) RETURNING id
            """,
            body.email,
            hash_password(body.password),
            body.full_name,
            role_row["id"],
        )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="Email already registered")

    await log_event(
        conn,
        actor_id=current_user["sub"],
        actor_email=current_user["email"],
        action="users.create",
        resource="users",
        resource_id=str(new_id),
        ip_address=request.client.host if request.client else None,
        detail={"email": body.email, "role": body.role},
    )
    log.info("users.created", extra={"new_user_email": body.email, "role": body.role})
    return {"id": str(new_id), "email": body.email, "status": "ACTIVE"}


@app.put("/users/{user_id}", tags=["users"])
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    request: Request,
    current_user: dict = Depends(require_permission("write", "users")),
    conn: asyncpg.Connection = Depends(get_db),
):
    uid = parse_uuid(user_id, "user_id")   # clean 422 on bad UUID

    updates, params, i = [], [], 1

    if body.role:
        role_row = await conn.fetchrow("SELECT id FROM roles WHERE name=$1", body.role)
        if not role_row:
            raise HTTPException(400, "Unknown role")
        updates.append(f"role_id=${i}"); params.append(role_row["id"]); i += 1

    if body.status:
        valid = {"ACTIVE", "SUSPENDED", "PENDING", "DEPROVISIONED"}
        if body.status not in valid:
            raise HTTPException(400, f"Status must be one of {valid}")
        updates.append(f"status=${i}"); params.append(body.status); i += 1

    if body.full_name:
        updates.append(f"full_name=${i}"); params.append(body.full_name); i += 1

    if not updates:
        raise HTTPException(400, "No fields to update")

    params.append(uid)
    await conn.execute(
        f"UPDATE users SET {', '.join(updates)} WHERE id=${i}", *params
    )
    await log_event(
        conn,
        actor_id=current_user["sub"],
        actor_email=current_user["email"],
        action="users.update",
        resource="users",
        resource_id=user_id,
        detail=body.model_dump(exclude_none=True),
    )
    return {"status": "updated"}


@app.delete("/users/{user_id}", tags=["users"])
async def deprovision_user(
    user_id: str,
    request: Request,
    current_user: dict = Depends(require_permission("delete", "users")),
    conn: asyncpg.Connection = Depends(get_db),
):
    uid = parse_uuid(user_id, "user_id")   # clean 422 on bad UUID
    await conn.execute(
        "UPDATE users SET status='DEPROVISIONED' WHERE id=$1", uid
    )
    await log_event(
        conn,
        actor_id=current_user["sub"],
        actor_email=current_user["email"],
        action="users.deprovision",
        resource="users",
        resource_id=user_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "deprovisioned"}


# ── Audit ─────────────────────────────────────────────────────────────────────

@app.get("/audit", tags=["audit"])
async def get_audit_log(
    current_user: dict = Depends(require_permission("read", "audit")),
    conn: asyncpg.Connection = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
):
    rows = await conn.fetch(
        """
        SELECT id, actor_email, action, resource, resource_id,
               outcome, ip_address, detail, created_at
        FROM audit_log
        ORDER BY created_at DESC
        OFFSET $1 LIMIT $2
        """,
        skip, min(limit, 500),
    )
    return [dict(r) for r in rows]
