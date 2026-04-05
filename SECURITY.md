# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.x (current) | ✅ Active |
| 1.x | ❌ End of life |

## Reporting a Vulnerability

**Do not open a public GitHub Issue for security vulnerabilities.**

Email **security@your-org.com** with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- (Optional) Suggested fix

We will acknowledge receipt within **48 hours** and aim to release a patch
within **14 days** for critical issues. We follow a **90-day responsible
disclosure** policy.

## Security Design

### Authentication
- Passwords hashed with bcrypt (cost factor 12)
- JWT tokens signed with RSA-2048 private key (RS256)
- Access tokens expire after 15 minutes
- Refresh tokens stored as SHA-256 hashes — raw token never persisted
- Account locked after 5 consecutive failed logins (15-minute cooldown)

### Authorisation
- Every API request evaluated against Open Policy Agent (Zero Trust)
- Permissions embedded in JWT — no DB hit per request
- `SUSPENDED` and `DEPROVISIONED` accounts denied at OPA layer

### Secrets
- No credentials in source code or Docker images
- DB password read from Docker secret file at runtime
- RSA private key generated at boot, stored in named Docker volume
- Production: mount keys from Vault / K8s Secret

### Network
- Database and OPA not exposed to host network
- Nginx rate-limits `/api/auth/` to 5 req/min per IP
- Security headers on all responses (CSP, X-Frame-Options, etc.)
- Audit log is append-only (DB trigger prevents UPDATE/DELETE)

### CI/CD
- Trivy scans Docker images for HIGH/CRITICAL CVEs on every push to main
- OPA policy tests run in CI (`opa test policies/`)
- No merge to main without passing lint + tests + scan
