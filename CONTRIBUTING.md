# Contributing to Nexus IAM

## Local Development Setup

### Prerequisites
- Docker Desktop ≥ 4.x
- Python 3.12+
- Node 20+
- Git

### 1. Clone and configure
```bash
git clone https://github.com/YOUR_ORG/nexus-iam.git
cd nexus-iam
cp .env.example .env
```

### 2. Generate secrets
```bash
chmod +x setup-secrets.sh && ./setup-secrets.sh
```

### 3. Start the stack
```bash
# docker-compose.override.yml is picked up automatically
docker-compose up --build
```

The backend runs with `--reload` in development. Edit any Python file and
the server restarts automatically.

### 4. Run tests
```bash
pip install -r backend/requirements.txt psycopg2-binary
export KEY_DIR=/tmp/nexus_test_keys
pytest tests/ -v
```

### 5. Run OPA policy tests
```bash
# Install OPA: https://www.openpolicyagent.org/docs/latest/#1-download-opa
opa test policies/ --verbose
```

---

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Production-ready, protected — PRs only |
| `develop` | Integration branch for features |
| `feature/*` | Individual feature branches |
| `hotfix/*` | Urgent production fixes |

## Commit Convention (Conventional Commits)

```
feat: add TOTP MFA enforcement for admin accounts
fix: send user.status to OPA input (deny rule was never firing)
chore: upgrade asyncpg to 0.30.0
docs: add JWKS verification example to README
test: add migration chain integrity tests
```

## Opening a Pull Request

1. Branch from `develop`: `git checkout -b feature/my-feature`
2. Write tests for any new behaviour
3. Ensure `pytest tests/` passes with ≥ 70% coverage
4. Ensure `ruff check backend/ tests/` passes
5. PR title follows Conventional Commits format
6. Fill in the PR template

## Database Schema Changes

Always use Alembic — never write raw SQL migrations by hand:

```bash
# 1. Inside the backend container or virtualenv:
alembic revision --autogenerate -m "describe_your_change"

# 2. Review the generated file in backend/migrations/versions/
# 3. Commit the migration file alongside your code changes
# 4. Test upgrade AND downgrade:
alembic upgrade head
alembic downgrade -1
alembic upgrade head
```

## Security Issues

Do **not** open a GitHub Issue for security vulnerabilities.  
Email: security@your-org.com  
We follow a 90-day responsible disclosure policy.
