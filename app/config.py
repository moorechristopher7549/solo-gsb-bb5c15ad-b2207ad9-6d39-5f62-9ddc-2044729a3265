"""Application configuration loaded from environment variables.

No third-party accounts are required: the only secret is the HMAC key used
to sign tokens. If it is not provided an ephemeral random key is generated at
startup (tokens then become invalid across restarts).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"Environment variable {name} must be an integer, got {raw!r}") from exc
    return value


@dataclass(frozen=True)
class Settings:
    #: HMAC signing key (env: CAPABILITY_SECRET).
    secret_key: bytes
    #: SQLite database file path (env: CAPABILITY_DB_PATH).
    db_path: str
    #: Directory that backs the guarded GET /files/{name} resource.
    files_dir: str
    #: Default token lifetime in seconds.
    default_ttl: int
    #: Hard upper bound for token lifetime in seconds.
    max_ttl: int
    #: Optional shared key guarding POST /tokens/issue (header X-Issuer-Key).
    issuer_key: str | None
    #: Optional shared key guarding the revocation admin endpoints
    #: (header X-Admin-Key). When unset those endpoints are disabled (503).
    admin_key: str | None
    #: True when no CAPABILITY_SECRET was configured and a random key is used.
    ephemeral: bool


def load_settings() -> Settings:
    secret = os.environ.get("CAPABILITY_SECRET", "").strip()
    ephemeral = not secret
    if ephemeral:
        # 32-byte URL-safe random key for this process only.
        secret = secrets.token_urlsafe(32)

    issuer_key = os.environ.get("CAPABILITY_ISSUER_KEY", "").strip() or None
    admin_key = os.environ.get("CAPABILITY_ADMIN_KEY", "").strip() or None
    files_dir = os.environ.get("CAPABILITY_FILES_DIR", os.path.join(os.getcwd(), "files"))

    default_ttl = _int_env("CAPABILITY_DEFAULT_TTL", 300)
    max_ttl = _int_env("CAPABILITY_MAX_TTL", 3600)
    if default_ttl <= 0 or max_ttl <= 0 or default_ttl > max_ttl:
        raise RuntimeError(
            "CAPABILITY_DEFAULT_TTL and CAPABILITY_MAX_TTL must be positive and "
            "default <= max"
        )

    return Settings(
        secret_key=secret.encode("utf-8"),
        db_path=os.environ.get(
            "CAPABILITY_DB_PATH", os.path.join(os.getcwd(), "data", "capabilities.db")
        ),
        files_dir=files_dir,
        default_ttl=default_ttl,
        max_ttl=max_ttl,
        issuer_key=issuer_key,
        admin_key=admin_key,
        ephemeral=ephemeral,
    )
