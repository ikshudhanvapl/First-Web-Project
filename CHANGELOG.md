# Changelog

All notable changes to Nexus IAM are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2026-04-05

### Added
- **RS256 JWT signing** — tokens are now signed with an RSA-2048 private key;
  any service can verify using the public key only
- **JWKS endpoint** (`/.well-known/jwks.json`) — standard public key discovery
  for microservice token verification
- **OpenID Connect discovery** (`/.well-known/openid-configuration`) — OIDC
  metadata stub for future federation support
- **Alembic migrations** — versioned, reversible schema management replacing
  the one-shot `init.sql` approach; two migrations included:
  - `0001_initial_schema` — full schema with triggers and seed data
  - `0002_mfa_and_sessions` — MFA attempts table, session_id, email_verified
- **Structured JSON logging** — every log line is a JSON object with
  `trace_id`, `user_id`, `timestamp`, and action fields; ready for Datadog/ELK
- **TraceMiddleware** — `X-Request-ID` propagated through every request;
  `trace_id` set in context var so all log lines for a request are correlated
- **pytest test suite** — 40+ tests covering crypto, auth, audit, migrations,
  OPA enforcement, and API endpoints
- **GitHub Actions CI** — lint → tests → migration validation → OPA tests →
  Trivy CVE scan → GHCR release on version tags
- **Dependency review** — GitHub's OSV-based dependency scanner on every PR
- **Makefile** — `make up`, `make test`, `make migrate`, `make jwks`, etc.
- **`docker-compose.override.yml`** — hot-reload dev mode, exposed ports for
  local DB/OPA inspection
- **`pyproject.toml`** — Ruff lint/format config, coverage settings

### Fixed
- **OPA deny rule** — `input.user.status` was never sent to OPA in v1; suspended
  and deprovisioned accounts were not being denied at the policy layer
- **UUID path params** — `uuid.UUID(val)` on bad input raised unhandled 500;
  replaced with `parse_uuid()` returning a clean 422 with field name
- **Audit logging** — replaced `print()` with structured logger so failures
  appear in the JSON log stream with trace context

### Changed
- JWT algorithm: HS256 → RS256 (breaking for v1 tokens)
- Backend `CMD` → `ENTRYPOINT` via `entrypoint.sh` (runs migrations first)
- `docker-compose.yml` adds `nexus_keys` named volume for RSA key persistence
- `settings.py` removes `jwt_secret` (HS256); adds `key_dir`

### Security
- Private key never leaves the `nexus_keys` volume; public key freely distributed
- `status` field embedded in JWT and forwarded to OPA — suspended admins now
  correctly denied even before token expires

---

## [1.0.0] — 2026-04-04

### Added
- Initial release: FastAPI backend, React frontend, PostgreSQL, OPA, Nginx
- HS256 JWT authentication with bcrypt password hashing
- Connection pooling via asyncpg
- Immutable audit log with PostgreSQL trigger
- Account lockout after failed logins
- Non-root Docker containers with multi-stage builds
- Nginx rate limiting and security headers
