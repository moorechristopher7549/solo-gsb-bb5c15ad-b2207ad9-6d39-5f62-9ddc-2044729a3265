"""Capability token issuing and verification (HMAC-SHA256).

Token wire format (URL-safe, no padding)::

    <base64url(payload)>.<base64url(hmac_sha256(payload, secret))>

``payload`` is a compact JSON object with sorted keys::

    {
      "v":   1,                 # token version
      "kid": "2026-09",         # key id of the signing key in the keyring
      "m":   "GET",             # bound HTTP method (canonical, upper case)
      "p":   "/files/report",   # bound canonical path
      "iat": 1727000000,        # issued-at, unix seconds
      "exp": 1727000300,        # expiry, unix seconds
      "jti": "u0m...",          # unique token id (also the replay nonce)
      "one": true,              # one-time use?
      "sub": "alice",           # optional subject / caller identity
      "ext": {...}              # optional arbitrary JSON claims
    }

The signature covers the method and path as part of the payload, so a token
cannot be moved to another endpoint or verb without breaking the MAC.

Key rotation
------------

Every newly issued token carries the ``kid`` of the *first* key in the
keyring, and verification selects **exactly one** key by that id — the
keyring is never searched by trial signature. Tokens without a ``kid``
(issued before keyring support existed) are verified only against the
dedicated legacy key. An unknown or unprovisioned ``kid`` fails with
``unknown_key``; dropping a retired id therefore invalidates its tokens
immediately, while keeping it lets still-unexpired old tokens validate.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import posixpath
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .db import Database

TOKEN_VERSION = 1
_ALGORITHM = "sha256"
SEP_RUN_RE = re.compile(r"/+")

#: Key ids are conservative tokens so they can appear in env configs and logs.
KID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
KEYRING_SEP_RE = re.compile(r"\s*,\s*")

#: kid used when a deployment is upgraded without CAPABILITY_KEYRING and the
#: legacy CAPABILITY_SECRET doubles as the current signing key.
DEFAULT_KID = "default"

#: kid assigned to the random key generated when nothing is configured at all.
EPHEMERAL_KID = "ephemeral"


class KeyConfigError(ValueError):
    """Invalid CAPABILITY_KEYRING / key configuration (fail-closed at startup)."""


class TokenError(Exception):
    """Raised when a token fails verification.

    ``code`` is a stable machine-readable string returned by the HTTP API:

    malformed / bad_signature / bad_payload / expired / unknown_key /
    method_mismatch / path_mismatch / nonce_replayed / subject_revoked
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Keyring:
    """Ordered set of HMAC keys.

    ``keys`` is ordered for signing/rotation: the first entry is the current
    signing key, the rest are retired keys kept only for verification of
    still-unexpired tokens. ``legacy_key`` is the one and only key used for
    old tokens that carry no ``kid`` claim — such tokens never trigger a
    search over the keyring.
    """

    keys: tuple[tuple[str, bytes], ...]
    legacy_key: bytes | None = None

    @property
    def current_kid(self) -> str:
        return self.keys[0][0]

    @property
    def current_key(self) -> bytes:
        return self.keys[0][1]

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(kid for kid, _ in self.keys)

    def key_for(self, kid: str) -> bytes | None:
        """Exact kid lookup; no trial signing against other keys."""
        for candidate, secret in self.keys:
            if candidate == kid:
                return secret
        return None


def parse_keyring(raw: str) -> tuple[tuple[str, bytes], ...]:
    """Parse the CAPABILITY_KEYRING value into ordered ``(kid, secret)`` pairs.

    Format: a comma-separated ordered list of ``kid:secret`` entries, first
    entry being the current signing key, e.g.::

        2026-09:<new-secret>,2026-01:<old-secret>

    Commas separate entries and the *first* colon separates kid from secret,
    so secrets may themselves contain colons. Duplicate kids and empty
    secrets/kids raise :class:`KeyConfigError`.
    """
    stripped = raw.strip()
    if not stripped:
        raise KeyConfigError(
            "CAPABILITY_KEYRING is set but empty: provide at least one 'kid:secret' entry"
        )
    entries: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for index, entry in enumerate(KEYRING_SEP_RE.split(stripped), start=1):
        if not entry:
            raise KeyConfigError(
                f"CAPABILITY_KEYRING entry #{index} is empty "
                "(expected 'kid:secret'; check for stray commas)"
            )
        if ":" not in entry:
            raise KeyConfigError(
                f"CAPABILITY_KEYRING entry {entry[:16]!r} is missing the 'kid:secret' separator"
            )
        kid, _, secret = entry.partition(":")
        if not kid or not KID_RE.fullmatch(kid):
            raise KeyConfigError(
                f"CAPABILITY_KEYRING entry #{index} has an invalid kid {kid!r}: "
                "use 1-128 characters from [A-Za-z0-9._-]"
            )
        if not secret:
            raise KeyConfigError(
                f"CAPABILITY_KEYRING entry {kid!r} has an empty secret"
            )
        if kid in seen:
            raise KeyConfigError(f"CAPABILITY_KEYRING contains duplicate kid {kid!r}")
        seen.add(kid)
        entries.append((kid, secret.encode("utf-8")))
    return tuple(entries)


def canonical_path(path: str) -> str:
    """Canonicalise a URL *path* for signing / verification.

    The input is expected to be the percent-decoded path (FastAPI's
    ``request.url.path``). We:

    * collapse repeated slashes (including leading ``//``),
    * resolve ``.`` / ``..`` segments,
    * drop any trailing slash (except the root).

    Issuer and verifier therefore agree on one unambiguous string even for
    inputs such as ``//files/../files/x/``.
    """
    if not path:
        return "/"
    # posixpath.normpath deliberately preserves a leading '//'; collapse it
    # (and any other duplicate slashes) ourselves first.
    collapsed = SEP_RUN_RE.sub("/", path)
    normalised = posixpath.normpath(collapsed)
    if normalised != "/" and normalised.endswith("/"):
        normalised = normalised.rstrip("/") or "/"
    return normalised


def canonical_method(method: str) -> str:
    return method.strip().upper()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed", "token segment is not valid base64url") from exc


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def build_payload(
    *,
    kid: str | None,
    method: str,
    path: str,
    expires_at: int,
    issued_at: int,
    nonce: str,
    one_time: bool,
    subject: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "v": TOKEN_VERSION,
        "m": canonical_method(method),
        "p": canonical_path(path),
        "iat": int(issued_at),
        "exp": int(expires_at),
        "jti": nonce,
        "one": bool(one_time),
    }
    # kid=None reproduces the pre-rotation (kid-less) token format.
    if kid is not None:
        payload["kid"] = kid
    if subject is not None:
        payload["sub"] = str(subject)
    if extra:
        payload["ext"] = extra
    return payload


def _payload_to_bytes(payload: dict[str, Any]) -> bytes:
    # sort_keys makes the canonical encoding stable for everyone.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@dataclass
class IssuedToken:
    token: str
    payload: dict[str, Any]
    kid: str | None
    method: str
    path: str
    expires_at: int
    expires_in: int
    one_time: bool
    nonce: str


def issue_token(
    secret_key: bytes,
    *,
    kid: str | None = None,
    method: str,
    path: str,
    ttl_seconds: int,
    one_time: bool = False,
    subject: str | None = None,
    extra: dict[str, Any] | None = None,
    now: int | None = None,
    nonce: str | None = None,
) -> IssuedToken:
    now = int(time.time()) if now is None else now
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    method = canonical_method(method)
    path = canonical_path(path)
    nonce = nonce or new_nonce()
    expires_at = now + int(ttl_seconds)
    payload = build_payload(
        kid=kid,
        method=method,
        path=path,
        expires_at=expires_at,
        issued_at=now,
        nonce=nonce,
        one_time=one_time,
        subject=subject,
        extra=extra,
    )
    payload_b = _payload_to_bytes(payload)
    signature = hmac.new(secret_key, payload_b, hashlib.sha256).digest()
    token = f"{_b64url_encode(payload_b)}.{_b64url_encode(signature)}"
    return IssuedToken(
        token=token,
        payload=payload,
        kid=kid,
        method=method,
        path=path,
        expires_at=expires_at,
        expires_in=ttl_seconds,
        one_time=one_time,
        nonce=nonce,
    )


@dataclass
class VerifiedToken:
    payload: dict[str, Any]
    method: str
    path: str
    expires_at: int
    nonce: str
    one_time: bool
    subject: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    #: id of the key that verified the token; None for kid-less legacy tokens.
    kid: str | None = None


def parse_token(token: str) -> tuple[dict[str, Any], bytes, bytes]:
    """Split and decode an unverified token into (payload, payload_b, sig).

    ``payload_b`` are the exact canonical JSON bytes that were signed.
    """
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed", "token must be '<payload>.<signature>'")
    payload_part, signature_part = token.split(".", 1)
    if not payload_part or not signature_part:
        raise TokenError("malformed", "token has an empty segment")
    payload_b = _b64url_decode(payload_part)
    signature = _b64url_decode(signature_part)
    try:
        payload = json.loads(payload_b.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenError("malformed", "token payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise TokenError("malformed", "token payload must be a JSON object")
    return payload, payload_b, signature


def _require_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise TokenError("bad_payload", f"claim {key!r} must be a non-empty string")
    return value


def _require_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenError("bad_payload", f"claim {key!r} must be an integer")
    return value


def _select_verification_key(
    payload: dict[str, Any], keyring: Keyring
) -> tuple[bytes, str | None]:
    """Pick exactly one verification key — never by trying signatures.

    * A token with a ``kid`` claim is verified with that exact key id; an
      unknown id fails with ``unknown_key`` instead of falling through to
      another key.
    * A token without ``kid`` (pre-rotation format) is verified **only** with
      the dedicated legacy key. When no legacy key is configured there is no
      key to try: fail with ``unknown_key``.

    Returns ``(secret_key, kid)`` where ``kid`` is ``None`` for legacy tokens.
    """
    if "kid" in payload:
        kid = payload["kid"]
        if not isinstance(kid, str) or not kid:
            raise TokenError("bad_payload", "claim 'kid' must be a non-empty string")
        secret_key = keyring.key_for(kid)
        if secret_key is None:
            raise TokenError(
                "unknown_key",
                f"token references unknown or retired key id {kid!r}",
            )
        return secret_key, kid

    if keyring.legacy_key is None:
        raise TokenError(
            "unknown_key",
            "token has no 'kid' claim and no legacy key is configured",
        )
    return keyring.legacy_key, None


def verify_token(
    token: str,
    *,
    keyring: Keyring,
    method: str,
    path: str,
    db: Database,
    consume: bool = True,
    now: int | None = None,
) -> VerifiedToken:
    """Verify a capability token for *method* + *path*.

    Verification order:

    1. structure (parse / base64 / JSON),
    2. key selection by the signed ``kid`` claim (exact match; legacy kid-less
       tokens use the dedicated legacy key only — the keyring is never
       searched by trial signature),
    3. HMAC signature (constant-time compare),
    4. payload claim types and version,
    5. expiry,
    6. method binding,
    7. path binding,
    8. subject revocation + one-time nonce consumption, decided inside a
       single SQLite transaction: a token whose ``iat`` is not after the
       subject's revocation cutoff is rejected with ``subject_revoked``
       and its nonce is *not* burned.

    ``consume=False`` performs a stateless dry run: a valid one-time token
    is *not* burned, which is useful for HTTP ``HEAD`` preflights. The
    revocation check still applies — a revoked subject fails even a dry run.
    """
    now = int(time.time()) if now is None else now
    payload, payload_b, signature = parse_token(token)

    secret_key, kid = _select_verification_key(payload, keyring)

    expected = hmac.new(secret_key, payload_b, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise TokenError("bad_signature", "token signature does not match")

    if payload.get("v") != TOKEN_VERSION:
        raise TokenError("bad_payload", f"unsupported token version: {payload.get('v')!r}")
    token_method = _require_str(payload, "m")
    token_path = _require_str(payload, "p")
    issued_at = _require_int(payload, "iat")
    expires_at = _require_int(payload, "exp")
    nonce = _require_str(payload, "jti")
    one_time = payload.get("one")
    if not isinstance(one_time, bool):
        raise TokenError("bad_payload", "claim 'one' must be a boolean")
    if issued_at > expires_at:
        raise TokenError("bad_payload", "claim 'iat' must not be after 'exp'")

    subject = payload.get("sub")
    if subject is not None and not isinstance(subject, str):
        raise TokenError("bad_payload", "claim 'sub' must be a string")
    extra = payload.get("ext", {})
    if not isinstance(extra, dict):
        raise TokenError("bad_payload", "claim 'ext' must be a JSON object")

    if now >= expires_at:
        raise TokenError("expired", "token has expired")

    if token_method != canonical_method(method):
        raise TokenError(
            "method_mismatch",
            f"token is bound to {token_method}, request used {canonical_method(method)}",
        )

    if token_path != canonical_path(path):
        raise TokenError(
            "path_mismatch",
            f"token is bound to {token_path!r}, request path was {canonical_path(path)!r}",
        )

    outcome = db.check_revocation_and_consume_nonce(
        subject=subject,
        issued_at=issued_at,
        nonce=nonce,
        expires_at=expires_at,
        consume=one_time and consume,
    )
    if outcome == "subject_revoked":
        raise TokenError(
            "subject_revoked",
            f"subject {subject!r} is revoked for tokens issued at or before the cutoff",
        )
    if outcome == "nonce_replayed":
        raise TokenError("nonce_replayed", "one-time token has already been used")

    return VerifiedToken(
        payload=payload,
        method=token_method,
        path=token_path,
        expires_at=expires_at,
        nonce=nonce,
        one_time=one_time,
        subject=subject,
        extra=extra,
        kid=kid,
    )
