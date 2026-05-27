"""JWT (HS256) sign/verify with zero third-party deps.

Used by the auth layer to issue bearer tokens after a successful
password + TOTP login. Tokens carry the account UUID in ``sub`` plus
``iat`` and ``exp`` epoch timestamps.

Secret resolution:
  1. ``AETHERIX_JWT_SECRET`` environment variable (preferred for prod).
  2. A per-process random secret with a stderr warning so dev still
     works but tokens do not survive a server restart.

Swap to RS256 (or a managed KMS-signed key) before the platform handles
real customer credentials at scale.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from typing import Any


_ALGO = "HS256"
_HEADER = {"alg": _ALGO, "typ": "JWT"}
_DEFAULT_TTL_SECONDS = 8 * 60 * 60  # 8 hours
_DEV_SECRET: str | None = None


class JwtError(ValueError):
    """Raised for any decode/validation failure (expired, bad sig, etc)."""


def _secret() -> str:
    secret = os.environ.get("AETHERIX_JWT_SECRET")
    if secret:
        return secret
    global _DEV_SECRET
    if _DEV_SECRET is None:
        _DEV_SECRET = secrets.token_urlsafe(48)
        sys.stderr.write(
            "[aetherix] WARNING: AETHERIX_JWT_SECRET is not set; using a "
            "process-local random secret. Tokens will be invalidated on "
            "restart. Set AETHERIX_JWT_SECRET before production use.\n"
        )
    return _DEV_SECRET


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def issue(subject: str, *, ttl_seconds: int = _DEFAULT_TTL_SECONDS, extra: dict[str, Any] | None = None) -> tuple[str, int]:
    """Return (token, exp_epoch_seconds)."""

    now = int(time.time())
    exp = now + ttl_seconds
    payload: dict[str, Any] = {"sub": subject, "iat": now, "exp": exp}
    if extra:
        payload.update(extra)
    header_b64 = _b64url(json.dumps(_HEADER, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    digest = hmac.new(_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url(digest)
    return f"{header_b64}.{payload_b64}.{sig_b64}", exp


def verify(token: str) -> dict[str, Any]:
    """Return claims dict; raise ``JwtError`` on any failure."""

    if not token or token.count(".") != 2:
        raise JwtError("malformed token")
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        provided = _b64url_decode(sig_b64)
    except Exception as error:  # noqa: BLE001
        raise JwtError("malformed signature") from error
    if not hmac.compare_digest(expected, provided):
        raise JwtError("signature mismatch")
    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as error:  # noqa: BLE001
        raise JwtError("malformed payload") from error
    if header.get("alg") != _ALGO:
        raise JwtError("unsupported alg")
    exp = claims.get("exp")
    if not isinstance(exp, int) or exp < int(time.time()):
        raise JwtError("token expired")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise JwtError("missing subject")
    return claims
