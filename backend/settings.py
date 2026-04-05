"""
settings.py — Centralised configuration with secret-file support.
v2: adds RS256 key directory, log level, OTel collector URL.
"""

import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret(env_var: str, secret_file_env: str, default: str = "") -> str:
    file_path = os.getenv(secret_file_env)
    if file_path and os.path.exists(file_path):
        return open(file_path).read().strip()
    return os.getenv(env_var, default)


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql://nexus_user:dev_password@db:5432/nexus_iam"

    # JWT (RS256) — HS256 removed; sign with RSA private key
    jwt_algorithm: str = "RS256"
    jwt_access_expire_minutes: int = 15
    jwt_refresh_expire_days: int = 7
    key_dir: str = "/app/keys"

    # OPA
    opa_url: str = "http://opa:8181/v1/data/nexus/authz/allow"
    opa_timeout_seconds: float = 2.0

    # CORS
    allowed_origins: list[str] = ["http://localhost", "http://localhost:80"]

    # Account lockout
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # Observability
    log_level: str = "INFO"
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "nexus-iam"

    # Environment
    environment: str = "development"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    def model_post_init(self, __context):
        db_pass = _read_secret("DB_PASSWORD", "DB_PASSWORD_FILE")
        if db_pass:
            url = self.database_url.replace("dev_password", db_pass)
            object.__setattr__(self, "database_url", url)
        key_dir = os.getenv("KEY_DIR")
        if key_dir:
            object.__setattr__(self, "key_dir", key_dir)


@lru_cache
def get_settings() -> Settings:
    return Settings()
