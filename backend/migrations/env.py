"""
migrations/env.py — Alembic migration environment.

Key decisions:
  - DATABASE_URL is read from environment (not hardcoded in alembic.ini)
  - Uses synchronous psycopg2 driver for Alembic (asyncpg doesn't work with Alembic)
  - `compare_type=True` so column type changes are detected automatically
  - `include_schemas=True` for future multi-schema support

Running migrations:
    # Inside the backend container:
    alembic upgrade head               # apply all pending migrations
    alembic downgrade -1               # roll back one migration
    alembic revision --autogenerate -m "add_mfa_table"  # generate new migration
    alembic history                    # show migration history
    alembic current                    # show current DB revision
"""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Alembic Config object (gives access to alembic.ini values)
config = context.config

# Override sqlalchemy.url from environment
db_url = os.getenv("DATABASE_URL", config.get_main_option("sqlalchemy.url"))
# Alembic uses psycopg2 (sync); swap asyncpg DSN prefix if needed
db_url = db_url.replace("postgresql+asyncpg://", "postgresql://")
config.set_main_option("sqlalchemy.url", db_url)

# Set up Python logging from alembic.ini [loggers] section
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# target_metadata = None means Alembic won't autogenerate from models.
# If you add SQLAlchemy ORM models later, import their Base.metadata here.
target_metadata = None


def run_migrations_offline() -> None:
    """
    Run migrations without a live DB connection.
    Outputs SQL to stdout — useful for review before applying.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations with a live DB connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,     # No pooling in migration runner
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            include_schemas=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
