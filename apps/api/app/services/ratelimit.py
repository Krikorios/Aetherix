"""In-process fixed-window rate limiter.

Lightweight stdlib-only limiter used to throttle auth endpoints. For
multi-process / multi-host deployments swap the in-memory store for
Redis (the ``RateLimiter`` interface is the only thing callers depend
on).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    window_start: float
    count: int


class RateLimiter:
    """Fixed-window counter keyed on an arbitrary string."""

    def __init__(self, max_hits: int, window_seconds: float) -> None:
        if max_hits <= 0:
            raise ValueError("max_hits must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max = max_hits
        self._window = float(window_seconds)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or (now - bucket.window_start) >= self._window:
                self._buckets[key] = _Bucket(window_start=now, count=1)
                self._gc(now)
                return True
            if bucket.count >= self._max:
                return False
            bucket.count += 1
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def _gc(self, now: float) -> None:
        if len(self._buckets) < 1024:
            return
        stale = [k for k, b in self._buckets.items() if (now - b.window_start) >= self._window]
        for k in stale:
            self._buckets.pop(k, None)


# Shared limiters tuned for auth flows. Tighten via deployment-specific
# wrappers if needed.
login_limiter = RateLimiter(max_hits=10, window_seconds=300.0)
totp_limiter = RateLimiter(max_hits=5, window_seconds=300.0)
recovery_limiter = RateLimiter(max_hits=5, window_seconds=900.0)
