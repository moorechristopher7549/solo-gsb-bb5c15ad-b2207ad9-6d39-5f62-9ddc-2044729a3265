"""Application configuration loaded from environment variables.

No third-party accounts are required. The HMAC keys used to sign tokens come
from an ordered *keyring* that supports non-disruptive rotation:

* ``CAPABILITY_KEYRING`` — comma-separated ordered ``kid:secret`` list; the
  first entry signs new tokens and every entry verifies tokens by exact
  ``kid``. Keep retired kids to keep validating still-unexpired old tokens;
  remove one to reject its tokens immediately.
* ``CAPABILITY_LEGACY_SECRET`` — the one and only key accepted for tokens
  issued before keyring support (payload without ``kid``). It never matches
  kid'd tokens and the keyring is never searched by trial signature.

For backwards compatibility ``CAPABILITY_SECRET`` keeps working: when no
keyring is configured it becomes both the current signing key (kid
``default``) and the legacy verification key. If no key is provided at all
an ephemeral random key is generated at startup (tokens then become invalid
across restarts).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from .tokens import (
    DEFAULT_KID,
    EPHEMERAL_KID,
    KeyConfigError,
    Keyring,
    parse_keyring,
)


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
    #: Ordered keyring: first entry signs, every entry verifies by exact kid.
    keyring: Keyring
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
    #: True when no signing key was configured and a random key is used.
    ephemeral: bool

    @property
    def secret_key(self) -> bytes:
        """Current signing key (first keyring entry)."""
        return self.keyring.current_key

    @property
    def current_kid(self) -> str:
        """kid stamped onto newly issued tokens."""
        return self.keyring.current_kid


def _build_keyring() -> tuple[Keyring, bool]:
    """Construct the keyring from the environment.

    Returns ``(keyring, ephemeral)``. Conflicting or malformed configuration
    raises RuntimeError so the process refuses to start (fail closed).
    """
    keyring_raw = os.environ.get("CAPABILITY_KEYRING")
    keyring_set = keyring_raw is not None and keyring_raw != ""
    legacy_raw = os.environ.get("CAPABILITY_LEGACY_SECRET", "").strip()
    single_raw = os.environ.get("CAPABILITY_SECRET", "").strip()

    legacy_key = legacy_raw.encode("utf-8") if legacy_raw else None

    if keyring_set:
        if single_raw:
            raise RuntimeError(
                "CAPABILITY_KEYRING and the deprecated CAPABILITY_SECRET are "
                "both set. Put the current key first in CAPABILITY_KEYRING "
                "(kid 'default' to keep old tokens verifiable) and remove "
                "CAPABILITY_SECRET."
            )
        try:
            keys = parse_keyring(keyring_raw)
        except KeyConfigError as exc:
            raise RuntimeError(str(exc)) from exc
        return Keyring(keys=keys, legacy_key=legacy_key), False

    # Backwards-compatible single-key mode.
    if single_raw:
        if legacy_raw:
            raise RuntimeError(
                "CAPABILITY_LEGACY_SECRET only applies with CAPABILITY_KEYRING; "
                "in single-key (CAPABILITY_SECRET) mode that secret is already "
                "used for kid-less legacy tokens."
            )
        key = single_raw.encode("utf-8")
        return Keyring(keys=((DEFAULT_KID, key),), legacy_key=key), False

    # Nothing configured: an ephemeral random key for this process only.
    if legacy_raw:
        raise RuntimeError(
            "CAPABILITY_LEGACY_SECRET is set but there is no keyring to pair "
            "it with: set CAPABILITY_KEYRING (kid:secret list) as well."
        )
    random_key = secrets.token_urlsafe(32).encode("utf-8")
    return Keyring(keys=((EPHEMERAL_KID, random_key),), legacy_key=None), True


def load_settings() -> Settings:
    keyring, ephemeral = _build_keyring()

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
        keyring=keyring,
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
