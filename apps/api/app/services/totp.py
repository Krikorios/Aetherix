"""RFC 6238 TOTP (Time-based One-Time Password) — stdlib only.

Generates a 20-byte secret, exposes a Google Authenticator–compatible
``otpauth://`` URL, and verifies 6-digit codes with a small clock skew
window. Keep this module dependency-free so we don't pull in ``pyotp``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote


_DIGITS = 6
_PERIOD = 30
_DRIFT_WINDOW = 1  # accept previous, current, and next step


def generate_secret() -> str:
    """Return a fresh base32-encoded 20-byte (160-bit) TOTP secret."""

    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    # base32 requires padding to a multiple of 8 chars.
    padding = (-len(cleaned)) % 8
    return base64.b32decode(cleaned + "=" * padding, casefold=True)


def _hotp(secret_bytes: bytes, counter: int) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(truncated % (10**_DIGITS)).zfill(_DIGITS)


def now_code(secret: str, *, at: float | None = None) -> str:
    """Compute the current TOTP code (used by tests)."""

    ts = at if at is not None else time.time()
    counter = int(ts // _PERIOD)
    return _hotp(_decode_secret(secret), counter)


def verify(secret: str, code: str, *, at: float | None = None) -> bool:
    """Return True if ``code`` matches the secret within the drift window."""

    if not code or not secret:
        return False
    cleaned = code.strip().replace(" ", "")
    if len(cleaned) != _DIGITS or not cleaned.isdigit():
        return False
    try:
        secret_bytes = _decode_secret(secret)
    except Exception:  # noqa: BLE001 — malformed secret should not raise
        return False
    ts = at if at is not None else time.time()
    counter = int(ts // _PERIOD)
    for delta in range(-_DRIFT_WINDOW, _DRIFT_WINDOW + 1):
        expected = _hotp(secret_bytes, counter + delta)
        if hmac.compare_digest(expected, cleaned):
            return True
    return False


def otpauth_url(*, account_name: str, secret: str, issuer: str) -> str:
    """Return a Google-Authenticator-compatible provisioning URL.

    Spec: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    """

    label = f"{issuer}:{account_name}"
    return (
        "otpauth://totp/"
        + quote(label, safe="")
        + "?secret="
        + quote(secret, safe="")
        + "&issuer="
        + quote(issuer, safe="")
        + f"&algorithm=SHA1&digits={_DIGITS}&period={_PERIOD}"
    )
