# Makefile — common developer tasks
# Usage: make <target>

.PHONY: help up down build logs test lint format clean migrate shell-backend shell-db jwks

COMPOSE   = docker-compose
BACKEND   = nexus-v2-backend-1
DB        = nexus-v2-db-1

help:           ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Docker ────────────────────────────────────────────────────────────────────

up:             ## Start all services (dev mode with override)
	$(COMPOSE) up --build -d

down:           ## Stop all services
	$(COMPOSE) down

build:          ## Rebuild images without cache
	$(COMPOSE) build --no-cache

logs:           ## Follow logs from all services
	$(COMPOSE) logs -f

logs-backend:   ## Follow backend logs only
	$(COMPOSE) logs -f backend

# ── Database migrations ───────────────────────────────────────────────────────

migrate:        ## Apply all pending Alembic migrations
	docker exec $(BACKEND) alembic upgrade head

migrate-down:   ## Roll back one migration
	docker exec $(BACKEND) alembic downgrade -1

migrate-history: ## Show migration history
	docker exec $(BACKEND) alembic history --verbose

migrate-current: ## Show current DB revision
	docker exec $(BACKEND) alembic current

new-migration:  ## Generate a new migration (usage: make new-migration MSG="add_mfa_table")
	docker exec $(BACKEND) alembic revision --autogenerate -m "$(MSG)"

# ── Testing ───────────────────────────────────────────────────────────────────

test:           ## Run full test suite with coverage
	KEY_DIR=/tmp/nexus_test_keys \
	DATABASE_URL=postgresql://test:test@localhost/test \
	pytest tests/ -v --cov=backend --cov-report=term-missing

test-fast:      ## Run tests without coverage (faster)
	KEY_DIR=/tmp/nexus_test_keys pytest tests/ -v

opa-test:       ## Run OPA policy tests
	opa test policies/ --verbose

# ── Linting ───────────────────────────────────────────────────────────────────

lint:           ## Run Ruff linter
	ruff check backend/ tests/

format:         ## Auto-format with Ruff
	ruff format backend/ tests/

format-check:   ## Check formatting without modifying files
	ruff format --check backend/ tests/

# ── Secrets & Setup ───────────────────────────────────────────────────────────

secrets:        ## Generate Docker secrets (run once)
	chmod +x setup-secrets.sh && ./setup-secrets.sh

# ── Utils ─────────────────────────────────────────────────────────────────────

shell-backend:  ## Open a shell inside the backend container
	docker exec -it $(BACKEND) bash

shell-db:       ## Open psql inside the DB container
	docker exec -it $(DB) psql -U nexus_user -d nexus_iam

jwks:           ## Print the current JWKS public key
	curl -s http://localhost/.well-known/jwks.json | python3 -m json.tool

clean:          ## Remove all containers, volumes and built images
	$(COMPOSE) down -v --rmi local
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf coverage_html/ coverage.xml .coverage .pytest_cache/
