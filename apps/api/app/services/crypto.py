"""Shared cryptographic utilities for policy signing and hashing."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any


PLACEHOLDER_SIGNING_KEY = "aetherix-dev-placeholder-key"


def signing_key_id() -> str:
    return os.getenv("AETHERIX_POLICY_SIGNING_KEY_ID", "control-plane-dev")


def _signing_key() -> bytes:
    key = os.getenv("AETHERIX_POLICY_SIGNING_KEY", PLACEHOLDER_SIGNING_KEY)
    return key.encode()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
