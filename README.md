<div align="center">

# Nexus IAM

**Enterprise Identity & Access Management Platform**

![CI](https://github.com/YOUR_ORG/nexus-iam/actions/workflows/ci.yml/badge.svg)
![Coverage](https://codecov.io/gh/YOUR_ORG/nexus-iam/branch/main/graph/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)

React · FastAPI · PostgreSQL · Open Policy Agent · Nginx · RS256 · Alembic

</div>

---

## Overview

Nexus IAM is a production-grade Identity & Access Management system.
It implements Zero Trust authorisation, asymmetric JWT signing, versioned
database migrations, structured observability, and a full CI/CD pipeline.

```
Browser
  └─► Nginx Gateway (:80)
        ├─► /                          → React SPA (Vite build)
        ├─► /api/*                     → FastAPI (RS256 · OPA · asyncpg pool)
        ├─► /.well-known/jwks.json     → RSA public key for token verification
        └─► /.well-known/openid-configuration

Backend
  ├─► PostgreSQL  (internal network · Alembic-managed schema)
  └─► OPA         (Zero Trust · deny rule checks user.status)
```

---

## Features

| Layer | Implementation |
|---|---|
| **Auth** | RS256 JWT (RSA-2048) · bcrypt passwords · refresh token rotation |
| **Authorisation** | Open Policy Agent · RBAC permission strings · status-aware deny |
| **Token discovery** | JWKS endpoint · OIDC configuration stub |
| **Schema** | Alembic migrations · UUID PKs · immutable audit log (DB trigger) |
| **Observability** | Structured JSON logs · trace_id per request · X-Request-ID header |
| **Security** | Account lockout · rate limiting · security headers · Trivy CVE scanning |
| **CI/CD** | GitHub Actions: lint → test → migration check → OPA test → image scan → GHCR release |

---

## Quick Start

### Prerequisites
- Docker Desktop ≥ 4.x
- `make` (optional but recommended)

### 1. Clone
```bash
git clone https://github.com/YOUR_ORG/nexus-iam.git
cd nexus-iam
```

### 2. Generate secrets
```bash
make secrets
# or: chmod +x setup-secrets.sh && ./setup-secrets.sh
```

### 3. Start
```bash
make up
# or: docker-compose up --build -d
```

Alembic runs `upgrade head` automatically on backend startup.

### 4. Verify
```bash
# RSA public key
make jwks
# or: curl http://localhost/.well-known/jwks.json

# Health
curl http://localhost/api/health
```

### 5. Open dashboard
**http://localhost** → `admin@nexus.local` / `ChangeMe!9`

> ⚠️ Change the default password immediately.

---

## Development

```bash
# Hot-reload backend (docker-compose.override.yml applied automatically)
make up

# Run tests
make test

# Run OPA policy tests (requires opa binary)
make opa-test

# Lint
make lint

# Format
make format

# All make targets
make help
```

---

## Database Migrations

```bash
# Apply all pending migrations
make migrate

# Roll back one migration
make migrate-down

# Create a new migration
make new-migration MSG="add_mfa_enforcement_table"

# Show history
make migrate-history
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full migration workflow.

---

## API Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/.well-known/jwks.json` | Public | RSA public key set |
| `GET` | `/.well-known/openid-configuration` | Public | OIDC discovery |
| `GET` | `/api/health` | Public | Liveness probe |
| `POST` | `/api/auth/login` | Public | Authenticate → RS256 JWT |
| `POST` | `/api/auth/logout` | JWT | Revoke refresh tokens |
| `GET` | `/api/users` | JWT + `users:read` | List identities |
| `POST` | `/api/users` | JWT + `users:write` | Provision identity |
| `PUT` | `/api/users/:id` | JWT + `users:write` | Update identity |
| `DELETE` | `/api/users/:id` | JWT + `users:delete` | Deprovision (soft delete) |
| `GET` | `/api/audit` | JWT + `audit:read` | Immutable audit log |

Interactive docs available at `http://localhost/api/docs` (development only).

---

## Permissions Matrix

| Permission | admin | manager | developer | contractor |
|---|:---:|:---:|:---:|:---:|
| `users:read` | ✓ | ✓ | ✓ | ✓ |
| `users:write` | ✓ | ✓ | | |
| `users:delete` | ✓ | | | |
| `roles:manage` | ✓ | | | |
| `audit:read` | ✓ | ✓ | | |

---

## RS256 / JWKS Token Flow

```
1. POST /api/auth/login
   → Backend signs JWT with RSA PRIVATE key (never leaves the server)
   → Client stores token in memory (not localStorage)

2. Subsequent requests
   → Client sends: Authorization: Bearer <token>
   → Backend verifies with RSA PUBLIC key

3. Other microservices
   → GET /.well-known/jwks.json  (public endpoint)
   → Cache the public key (refresh on kid mismatch)
   → Verify any Nexus token independently
```

---

## JSON Log Format

```json
{
  "timestamp": "2026-04-05T12:00:00.000000Z",
  "level": "INFO",
  "logger": "auth",
  "message": "auth.success",
  "trace_id": "a1b2c3d4-e5f6-...",
  "user_id": "550e8400-e29b-...",
  "email": "admin@nexus.local",
  "ip": "10.0.0.1"
}
```

Every line emitted to stdout is valid JSON — pipe directly to Datadog,
Splunk, or ELK with zero parsing configuration.

---

## CI Pipeline

```
Push / PR
  ├── Lint (Ruff)
  ├── Tests (pytest ≥ 70% coverage)
  ├── Alembic chain validation
  ├── OPA policy tests (opa test)
  └── [main/develop only]
        ├── Trivy CVE scan (blocks on HIGH/CRITICAL)
        └── [on tag] Push to GHCR + GitHub Release
```

---

## Production Hardening Checklist

- [ ] Change default admin password
- [ ] Enable HTTPS (TLS cert in `nginx/default.conf`)
- [ ] Set `ENVIRONMENT=production` (disables `/docs`)
- [ ] Restrict `ALLOWED_ORIGINS` to your domain
- [ ] Mount RSA private key from Vault / K8s Secret
- [ ] Enable PostgreSQL SSL (`sslmode=require`)
- [ ] Add log shipper (Datadog agent / Fluent Bit)
- [ ] Enforce MFA for admin/manager roles (`mfa_secret` column ready)
- [ ] Add OIDC provider (Azure AD / Okta) — discovery stub present
- [ ] Set up database backups
- [ ] Add pgBouncer for read-replica connection pooling

---

## Project Structure

```
nexus-iam/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # lint → test → scan → release
│   │   ├── release.yml         # push to GHCR on version tags
│   │   └── dependency-review.yml
│   ├── ISSUE_TEMPLATE/
│   └── pull_request_template.md
├── backend/
│   ├── migrations/
│   │   ├── versions/
│   │   │   ├── 0001_initial_schema.py
│   │   │   └── 0002_mfa_and_sessions.py
│   │   ├── env.py
│   │   └── script.py.mako
│   ├── auth.py           # RS256 JWT · OPA enforcement · lockout
│   ├── crypto.py         # RSA keygen · JWKS · sign/verify
│   ├── audit.py          # Immutable audit writer
│   ├── database.py       # asyncpg connection pool
│   ├── logging_config.py # Structured JSON logger · trace_id
│   ├── main.py           # FastAPI app · all routes · JWKS endpoint
│   ├── middleware.py      # TraceMiddleware · X-Request-ID
│   ├── settings.py       # Pydantic settings · secret file support
│   ├── entrypoint.sh     # alembic upgrade head → uvicorn
│   ├── alembic.ini
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx       # Login · dashboard · users · audit views
│       ├── api.js        # In-memory token · auto-logout on 401
│       └── index.css     # Dark enterprise theme
├── nginx/
│   ├── nginx.conf        # Rate limiting zones · upstreams
│   └── default.conf      # Security headers · routing
├── policies/
│   ├── authz.rego        # RBAC · status-aware deny rule
│   └── authz_test.rego   # OPA unit tests
├── tests/
│   ├── conftest.py       # Fixtures · mock DB · token helpers
│   ├── test_crypto.py    # RS256 keygen · sign/verify · JWKS
│   ├── test_auth.py      # JWT · OPA · UUID hardening · endpoints
│   ├── test_audit.py     # Audit write · failure swallowing
│   └── test_migrations.py # Alembic chain integrity
├── docker-compose.yml
├── docker-compose.override.yml  # Dev: hot-reload · exposed ports
├── Makefile
├── pyproject.toml        # Ruff config · coverage settings
├── pytest.ini
├── .env.example
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```

---

## License

MIT © Your Organisation
