#!/bin/bash
# entrypoint.sh — Run Alembic migrations then start the API server.
#
# Why run migrations at startup instead of in a separate job?
#   For a single-instance deployment this is fine and keeps the setup simple.
#   For multi-replica K8s deployments, use an initContainer or a separate
#   migration Job to avoid race conditions between replicas.

set -e

echo "[entrypoint] Running Alembic migrations..."
cd /app
alembic upgrade head
echo "[entrypoint] Migrations complete."

echo "[entrypoint] Starting Nexus IAM API..."
exec uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --loop uvloop \
    --http h11 \
    --no-access-log
