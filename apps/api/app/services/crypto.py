"""Shared cryptographic utilities for policy signing and hashing."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any


PLACEHOLDER_SIGNING_KEY = "aetherix-dev-placeholder-key"

_LOGGER = logging.getLogger(__name__)
_DEV_KEY_WARNING_EMITTED = False


def _is_production() -> bool:
    env = (os.getenv("AETHERIX_ENV") or "").strip().lower()
    return env in {"production", "prod"}


def signing_key_id() -> str:
    return os.getenv("AETHERIX_POLICY_SIGNING_KEY_ID", "control-plane-dev")


def _signing_key() -> bytes:
    key = os.getenv("AETHERIX_POLICY_SIGNING_KEY")
    if key:
        return key.encode()
    if _is_production():
        raise RuntimeError(
            "AETHERIX_POLICY_SIGNING_KEY must be set when AETHERIX_ENV=production; "
            "refusing to fall back to the dev placeholder key."
        )
    global _DEV_KEY_WARNING_EMITTED
    if not _DEV_KEY_WARNING_EMITTED:
        _LOGGER.warning(
            "AETHERIX_POLICY_SIGNING_KEY not set; using dev placeholder key. "
            "Do not use this in production."
        )
        _DEV_KEY_WARNING_EMITTED = True
    return PLACEHOLDER_SIGNING_KEY.encode()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
