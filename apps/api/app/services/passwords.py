"""Password hashing helpers (stdlib only).

Format: ``pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>``. Using
``hashlib.pbkdf2_hmac`` keeps the dependency surface zero while still
producing a salted, slow hash suitable for our threat model. Swap in
Argon2/bcrypt once the platform takes a real password storage hardening
pass.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 240_000
_SALT_BYTES = 16
_HASH_BYTES = 32


def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _ITERATIONS, dklen=_HASH_BYTES
    )
    return "${}${}${}${}".format(
        _ALGO,
        _ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    ).lstrip("$")


def verify_password(password: str, stored: str | None) -> bool:
    if not stored or not password:
        return False
    try:
        algo, iter_s, salt_b64, hash_b64 = stored.split("$", 3)
    except ValueError:
        return False
    if algo != _ALGO:
        return False
    try:
        iterations = int(iter_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
    )
    return hmac.compare_digest(candidate, expected)
