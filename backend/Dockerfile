# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .

# psycopg2-binary needed by Alembic (sync driver)
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt \
 && pip install --no-cache-dir --prefix=/install psycopg2-binary==2.9.9

# ── Stage 2: production image ────────────────────────────────────────────────
FROM python:3.12-slim AS production

# Non-root user
RUN groupadd -r nexus && useradd -r -g nexus -d /app nexus

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=nexus:nexus . .

# Keys directory — writable by nexus user so RSA keypair can be generated
RUN mkdir -p /app/keys && chown nexus:nexus /app/keys

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

USER nexus

EXPOSE 8000

# Entrypoint: migrate → start
ENTRYPOINT ["/app/entrypoint.sh"]
